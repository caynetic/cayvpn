from __future__ import annotations

import hashlib
import io
import json
import platform
import sqlite3
import subprocess
import tarfile
import tempfile
import unittest
from contextlib import closing
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, call, patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from cayvpn.components import COMPONENT_NAMES, ComponentError
from cayvpn.cli import (
    _cmd_restore,
    _copy_path_ownership,
    _db,
    _restart_units,
    _restore_state_paths,
    _run_release_migrations,
    _snapshot_state_paths,
    _stop_units_for_upgrade,
    cmd_rollback,
    cmd_restore,
    cmd_upgrade,
    cmd_verify,
    main,
)
from cayvpn.config import Settings
from cayvpn.db import Database
from cayvpn.update_runner import recover_interrupted_update
from cayvpn.worker_service import record_reconciliation_completion
from cayvpn.updates import (
    ReleaseAsset,
    ReleaseInfo,
    ReleaseRepository,
    UpdateError,
    UpdateManager,
    Version,
    _release_metadata,
    parse_manifest,
    prune_update_history,
    verify_installed_release,
    write_update_state,
)


class MemoryFetcher:
    def __init__(self, files: dict[str, bytes] | None = None, payload: dict | None = None):
        self.files = files or {}
        self.payload = payload or {}

    def json(self, _url: str) -> dict:
        return self.payload

    def download(self, url: str, destination: Path, max_bytes: int, expected_size: int | None = None) -> str:
        data = self.files[url]
        if len(data) > max_bytes or (expected_size is not None and len(data) != expected_size):
            raise UpdateError("release_length_mismatch", "fixture length mismatch")
        destination.write_bytes(data)
        return hashlib.sha256(data).hexdigest()


class MemoryRepository:
    def __init__(self, release: ReleaseInfo, fetcher: MemoryFetcher):
        self.info = release
        self.fetcher = fetcher

    def latest(self) -> ReleaseInfo:
        return self.info

    def release(self, version: str) -> ReleaseInfo:
        if version != self.info.version:
            raise UpdateError("release_not_found", "fixture release missing")
        return self.info


class UpdateTests(unittest.TestCase):
    def test_cli_expected_update_refusals_are_concise(self):
        for command, function, label in (
            (["upgrade", "--confirm"], "cmd_upgrade", "Upgrade stopped safely"),
            (["rollback", "--confirm"], "cmd_rollback", "Rollback stopped safely"),
        ):
            with self.subTest(command=command[0]), patch("cayvpn.cli.Settings.from_env", return_value=object()), patch(
                f"cayvpn.cli.{function}", side_effect=RuntimeError("signed verification metadata is missing")
            ), patch("sys.stderr", new_callable=io.StringIO) as stderr:
                self.assertEqual(main(command), 1)
                self.assertIn(label, stderr.getvalue())
                self.assertIn("signed verification metadata is missing", stderr.getvalue())
                self.assertNotIn("Traceback", stderr.getvalue())

    def setUp(self):
        self.os_patch = patch("cayvpn.updates._operating_system", return_value="ubuntu-24.04")
        self.os_patch.start()
        self.addCleanup(self.os_patch.stop)
        self.disk_patch = patch(
            "cayvpn.updates.shutil.disk_usage",
            return_value=SimpleNamespace(total=4 * 1024**3, used=1024**3, free=3 * 1024**3),
        )
        self.disk_patch.start()
        self.addCleanup(self.disk_patch.stop)

    def settings(self, root: Path) -> Settings:
        base = Settings.from_env(root)
        return replace(
            base,
            state_dir=root / "state",
            config_dir=root / "config",
            db_path=root / "state" / "cayvpn.db",
            wg_dir=root / "wireguard",
            release_dir=root / "opt" / "releases",
            active_release=root / "opt" / "current",
            release_trust_key=root / "config" / "release.pub",
            update_state_path=root / "state" / "update-status.json",
            update_metadata_path=root / "config" / "update-metadata.json",
        )

    def test_cli_database_context_closes_after_an_error(self):
        settings = self.settings(Path("/tmp/cayvpn-cli-context-fixture"))
        database = MagicMock()
        database.__enter__.return_value = database
        with patch("cayvpn.cli.Database", return_value=database):
            with self.assertRaisesRegex(RuntimeError, "fixture error"):
                with _db(settings) as opened:
                    self.assertIs(opened, database)
                    raise RuntimeError("fixture error")
        database.initialize_defaults.assert_called_once_with(settings)
        database.__exit__.assert_called_once()

    def test_restore_requires_explicit_confirmation_before_any_password_prompt(self):
        with patch("cayvpn.cli.getpass.getpass") as prompt, patch("sys.stderr", new_callable=io.StringIO) as stderr:
            self.assertEqual(cmd_restore(object(), "/tmp/fixture.backup"), 2)
        prompt.assert_not_called()
        self.assertIn("Re-run with --confirm", stderr.getvalue())

    def test_confirmed_restore_validates_snapshots_pauses_migrates_reconciles_and_verifies(self):
        with tempfile.TemporaryDirectory() as directory:
            settings = self.settings(Path(directory))
            settings.state_dir.mkdir(parents=True)
            active = settings.release_dir / "2.0.1"
            source = Path(directory) / "fixture.backup"
            with (
                patch("cayvpn.cli._active_release_path", return_value=active),
                patch("cayvpn.cli.getpass.getpass", return_value="long-test-passphrase"),
                patch("cayvpn.cli._validate_restore_backup") as validate,
                patch("cayvpn.cli._snapshot_state_paths") as snapshot_state,
                patch("cayvpn.cli._snapshot_restore_extras") as snapshot_extras,
                patch("cayvpn.cli._stop_units_for_upgrade") as stop,
                patch("cayvpn.cli.restore_backup") as restore,
                patch("cayvpn.cli._run_release_migrations") as migrate,
                patch("cayvpn.cli._request_runtime_reconciliation", return_value="request-id") as request,
                patch("cayvpn.cli._restart_units") as restart,
                patch("cayvpn.cli._wait_for_runtime_reconciliation") as wait,
                patch("cayvpn.cli.cmd_verify", return_value=0) as verify,
                patch("sys.stdout", new_callable=io.StringIO),
            ):
                self.assertEqual(_cmd_restore(settings, source), 0)

            validate.assert_called_once_with(settings, "long-test-passphrase", source)
            snapshot_state.assert_called_once()
            snapshot_extras.assert_called_once()
            stop.assert_called_once()
            restore.assert_called_once_with(settings, "long-test-passphrase", source)
            migrate.assert_called_once_with(active, settings)
            request.assert_called_once_with(settings)
            restart.assert_called_once()
            wait.assert_called_once_with(settings, "request-id")
            verify.assert_called_once_with(settings)

    def test_failed_restore_returns_to_the_complete_pre_restore_snapshot(self):
        self._assert_failed_restore_recovery(verification_succeeds=True)

    def test_failed_restore_does_not_report_recovery_when_health_verification_fails(self):
        self._assert_failed_restore_recovery(verification_succeeds=False)

    def _assert_failed_restore_recovery(self, *, verification_succeeds):
        with tempfile.TemporaryDirectory() as directory:
            settings = self.settings(Path(directory))
            settings.state_dir.mkdir(parents=True)
            active = settings.release_dir / "2.0.1"
            source = Path(directory) / "fixture.backup"
            with (
                patch("cayvpn.cli._active_release_path", return_value=active),
                patch("cayvpn.cli.getpass.getpass", return_value="long-test-passphrase"),
                patch("cayvpn.cli._validate_restore_backup"),
                patch("cayvpn.cli._snapshot_state_paths"),
                patch("cayvpn.cli._snapshot_restore_extras"),
                patch("cayvpn.cli._stop_units_for_upgrade") as stop,
                patch("cayvpn.cli.restore_backup"),
                patch("cayvpn.cli._run_release_migrations", side_effect=RuntimeError("migration fixture failure")),
                patch("cayvpn.cli._restore_state_paths") as restore_state,
                patch("cayvpn.cli._restore_restore_extras") as restore_extras,
                patch("cayvpn.cli._request_runtime_reconciliation", return_value="rollback-request"),
                patch("cayvpn.cli._restart_units") as restart,
                patch("cayvpn.cli._wait_for_runtime_reconciliation") as wait,
                patch("cayvpn.cli.cmd_verify", return_value=0 if verification_succeeds else 1) as verify,
            ):
                message = "previous state was restored" if verification_succeeds else "automatic recovery also failed"
                with self.assertRaisesRegex(RuntimeError, message):
                    _cmd_restore(settings, source)

            self.assertEqual(stop.call_count, 2)
            restore_state.assert_called_once()
            restore_extras.assert_called_once()
            restart.assert_called_once()
            wait.assert_called_once_with(settings, "rollback-request")
            verify.assert_called_once_with(settings)

    def test_release_migrations_do_not_use_a_moved_console_script_shebang(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            settings = self.settings(root)
            release = settings.release_dir / "2.0.1"
            python = release / ".venv" / "bin" / "python"
            python.parent.mkdir(parents=True)
            python.touch()
            (release / "alembic.ini").write_text("[alembic]\nscript_location = migrations\n")

            completed = subprocess.CompletedProcess([], 0, "", "")
            with patch("cayvpn.cli.subprocess.run", return_value=completed) as run:
                _run_release_migrations(release, settings)

            argv = run.call_args.args[0]
            self.assertEqual(
                argv,
                [str(python), "-m", "alembic", "-c", str(release / "alembic.ini"), "upgrade", "head"],
            )
            self.assertEqual(run.call_args.kwargs["cwd"], release)
            self.assertEqual(run.call_args.kwargs["env"]["CAYVPN_DB_PATH"], str(settings.db_path))

    def test_upgrade_pauses_and_restores_short_lived_certificate_renewal(self):
        succeeded = subprocess.CompletedProcess([], 0, "", "")
        with patch("cayvpn.cli._run_fixed", return_value=succeeded) as run:
            _stop_units_for_upgrade()
            _restart_units()

        self.assertEqual(
            run.call_args_list[0].args[0],
            [
                "systemctl",
                "stop",
                "cayvpn-remote-admin-renew.timer",
                "cayvpn-remote-admin-renew.service",
                "cayvpn-web",
                "cayvpn-worker",
                "cayvpn-agent",
            ],
        )
        self.assertEqual(
            run.call_args_list[1].args[0],
            ["systemctl", "restart", "cayvpn-agent", "cayvpn-worker", "cayvpn-web", "nginx"],
        )
        self.assertEqual(
            run.call_args_list[2].args[0],
            ["systemctl", "start", "cayvpn-remote-admin-renew.timer"],
        )

    def test_state_snapshot_ownership_copy_includes_nested_service_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            destination = root / "destination"
            (source / "adblock").mkdir(parents=True)
            (destination / "adblock").mkdir(parents=True)
            source_file = source / "adblock" / "filter.txt"
            destination_file = destination / "adblock" / "filter.txt"
            source_file.write_text("source")
            destination_file.write_text("destination")
            source_stat = source.stat()
            directory_stat = (source / "adblock").stat()
            file_stat = source_file.stat()

            with patch("cayvpn.cli.os.geteuid", return_value=0), patch("cayvpn.cli.os.chown") as chown:
                _copy_path_ownership(source, destination)

            chown.assert_has_calls(
                [
                    call(destination, source_stat.st_uid, source_stat.st_gid, follow_symlinks=False),
                    call(destination / "adblock", directory_stat.st_uid, directory_stat.st_gid, follow_symlinks=False),
                    call(destination_file, file_stat.st_uid, file_stat.st_gid, follow_symlinks=False),
                ]
            )

    def test_state_restore_removes_stale_sqlite_sidecars_before_opening_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            settings = self.settings(Path(directory))
            settings.state_dir.mkdir(parents=True)
            with closing(sqlite3.connect(settings.db_path)) as database:
                database.execute("CREATE TABLE fixture (value TEXT)")
                database.execute("INSERT INTO fixture VALUES ('snapshot value')")
                database.commit()
            snapshot = settings.state_dir / "upgrade-snapshots" / "fixture"
            _snapshot_state_paths(settings, snapshot)
            with closing(sqlite3.connect(settings.db_path)) as database:
                database.execute("UPDATE fixture SET value = 'new live value'")
                database.commit()
            sidecars = [
                settings.db_path.with_name(settings.db_path.name + suffix)
                for suffix in ("-journal", "-wal", "-shm")
            ]
            for sidecar in sidecars:
                sidecar.write_bytes(b"stale database journal")

            _restore_state_paths(settings, snapshot)

            self.assertTrue(all(not sidecar.exists() for sidecar in sidecars))
            with closing(sqlite3.connect(settings.db_path)) as database:
                self.assertEqual(
                    database.execute("SELECT value FROM fixture").fetchone(),
                    ("snapshot value",),
                )

    def test_state_restore_preserves_systemd_writable_directory_anchors(self):
        with tempfile.TemporaryDirectory() as directory:
            settings = self.settings(Path(directory))
            settings.state_dir.mkdir(parents=True)
            anchors = (settings.config_dir, settings.wg_dir)
            for path in anchors:
                path.mkdir(parents=True)
                (path / "saved").write_text("snapshot value")
            snapshot = settings.state_dir / "upgrade-snapshots" / "fixture"
            _snapshot_state_paths(settings, snapshot)
            inodes = {path: path.stat().st_ino for path in anchors}
            for path in anchors:
                (path / "saved").write_text("later value")
                (path / "stale").write_text("remove me")
            _restore_state_paths(settings, snapshot)
            for path in anchors:
                self.assertEqual(path.stat().st_ino, inodes[path])
                self.assertEqual((path / "saved").read_text(), "snapshot value")
                self.assertFalse((path / "stale").exists())

    def release_fixture(self, settings: Settings, version: str = "2.0.1", signing_key: Ed25519PrivateKey | None = None):
        key = signing_key or Ed25519PrivateKey.generate()
        public = key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        settings.release_trust_key.parent.mkdir(parents=True, exist_ok=True)
        settings.release_trust_key.write_bytes(public)
        settings.release_trust_key.chmod(0o644)
        architecture = "arm64" if platform.machine().lower() in {"arm64", "aarch64"} else "amd64"
        release_metadata = {
            "schema_version": 1,
            "version": version,
            "channel": "stable",
            "supported_os": ["ubuntu-24.04"],
            "supported_architectures": ["amd64", "arm64"],
            "minimum_cayvpn_version": "2.0.0-dev",
            "offline_dependencies": True,
            "offline_optional_components": True,
        }
        component_lock = {
            "schema_version": 1,
            "release_version": version,
            "architectures": {},
        }
        component_files = {}
        for component_architecture in ("amd64", "arm64"):
            component_lock["architectures"][component_architecture] = {}
            for name in COMPONENT_NAMES:
                payload = f"{version}:{component_architecture}:{name}".encode()
                component_files[f"components/{component_architecture}/{name}"] = payload
                component_lock["architectures"][component_architecture][name] = {
                    "path": f"components/{component_architecture}/{name}",
                    "sha256": hashlib.sha256(payload).hexdigest(),
                }
        files = {
            "app.py": b"print('verified release')\n",
            "requirements.txt": b"example==1.0\n",
            "requirements.lock": b"example==1.0\n",
            "scripts/validate-python-source.py": (Path(__file__).resolve().parents[1] / "scripts" / "validate-python-source.py").read_bytes(),
            "scripts/relocate-venv.py": (Path(__file__).resolve().parents[1] / "scripts" / "relocate-venv.py").read_bytes(),
            f"wheelhouse/{architecture}/example-1.0-py3-none-any.whl": b"signed wheel fixture",
            "release.json": json.dumps(release_metadata, sort_keys=True).encode(),
            "components.lock.json": json.dumps(component_lock, sort_keys=True).encode(),
            **component_files,
        }
        manifest = "".join(f"{hashlib.sha256(data).hexdigest()}  {name}\n" for name, data in sorted(files.items())).encode()
        archive_io = io.BytesIO()
        with tarfile.open(fileobj=archive_io, mode="w:gz") as archive:
            for name, data in files.items():
                member = tarfile.TarInfo(f"cayvpn-{version}/{name}")
                member.size = len(data)
                member.mode = 0o755 if name == "app.py" else 0o644
                archive.addfile(member, io.BytesIO(data))
        archive_data = archive_io.getvalue()
        signature = key.sign(manifest)
        names = {
            f"cayvpn-{version}.tar.gz": archive_data,
            f"cayvpn-{version}.sha256": manifest,
            f"cayvpn-{version}.sha256.sig": signature,
            "cayvpn-release.pub": public,
        }
        base = f"https://github.com/caynetic/cayvpn/releases/download/v{version}"
        remote_files = {f"{base}/{name}": data for name, data in names.items()}
        assets = {
            name: ReleaseAsset(name, f"{base}/{name}", len(data), hashlib.sha256(data).hexdigest())
            for name, data in names.items()
        }
        release = ReleaseInfo(
            version=version,
            tag=f"v{version}",
            title=f"CayVPN {version}",
            notes="Safe update fixture",
            page_url=f"https://github.com/caynetic/cayvpn/releases/tag/v{version}",
            published_at=(datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat(),
            immutable=True,
            assets=assets,
        )
        return release, MemoryFetcher(remote_files), names

    def test_semver_orders_prereleases_before_stable(self):
        versions = ["1.0.0", "1.0.0-beta.11", "1.0.0-alpha", "1.0.0-rc.1", "1.0.0-beta.2"]
        self.assertEqual(
            [str(value) for value in sorted(Version.parse(item) for item in versions)],
            ["1.0.0-alpha", "1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0"],
        )

    def test_signed_release_is_staged_with_offline_dependencies(self):
        with tempfile.TemporaryDirectory() as directory:
            settings = self.settings(Path(directory))
            release, fetcher, _files = self.release_fixture(settings)
            runner_calls = []

            def runner(argv, **_kwargs):
                runner_calls.append(argv)
                return subprocess.CompletedProcess(argv, 0, "", "")

            result = UpdateManager(settings, MemoryRepository(release, fetcher), runner).stage("2.0.1", "2.0.0")

            self.assertEqual(result["state"], "staged")
            self.assertTrue((settings.release_dir / "2.0.1" / "app.py").is_file())
            self.assertIn("--no-index", runner_calls[2])
            self.assertIn("--no-deps", runner_calls[2])
            self.assertEqual(len(runner_calls), 5)
            self.assertEqual(Path(runner_calls[0][1]).name, "validate-python-source.py")
            self.assertEqual(Path(runner_calls[4][1]).name, "relocate-venv.py")
            self.assertEqual(Path(runner_calls[4][2]).name, ".venv")
            self.assertEqual(Path(runner_calls[4][4]), settings.release_dir / "2.0.1")
            self.assertEqual(Path(runner_calls[0][2]).name, "cayvpn-2.0.1")
            self.assertEqual(Path(runner_calls[0][1]).parent.parent, settings.active_release)
            self.assertNotIn(str(settings.release_dir / "2.0.1" / "scripts"), str(runner_calls[0][1]))
            self.assertEqual(json.loads(settings.update_metadata_path.read_text())["highest_staged_release"], "2.0.1")
            self.assertEqual(result["release_metadata"]["version"], "2.0.1")

    def test_staging_rejects_source_validation_failure_before_installing_target(self):
        with tempfile.TemporaryDirectory() as directory:
            settings = self.settings(Path(directory))
            release, fetcher, _files = self.release_fixture(settings)

            def runner(argv, **_kwargs):
                if any(str(item).endswith("validate-python-source.py") for item in argv):
                    return subprocess.CompletedProcess(argv, 1, "", "broken migration.py")
                return subprocess.CompletedProcess(argv, 0, "", "")

            with self.assertRaises(UpdateError) as raised:
                UpdateManager(
                    settings,
                    MemoryRepository(release, fetcher),
                    runner,
                ).stage("2.0.1", "2.0.0")

            self.assertEqual(raised.exception.code, "release_runtime_failed")
            self.assertFalse((settings.release_dir / "2.0.1").exists())
            self.assertEqual(
                json.loads(settings.update_state_path.read_text())["state"],
                "stage_failed",
            )

    def test_staging_rejects_invalid_component_lock_before_runtime_commands(self):
        with tempfile.TemporaryDirectory() as directory:
            settings = self.settings(Path(directory))
            release, fetcher, _files = self.release_fixture(settings)
            runner = MagicMock(return_value=subprocess.CompletedProcess([], 0, "", ""))

            with patch(
                "cayvpn.updates.validate_release_components",
                side_effect=ComponentError("component_lock_invalid", "fixture component lock failed"),
            ):
                with self.assertRaises(UpdateError) as raised:
                    UpdateManager(settings, MemoryRepository(release, fetcher), runner).stage("2.0.1", "2.0.0")

            self.assertEqual(raised.exception.code, "offline_components_invalid")
            runner.assert_not_called()
            self.assertFalse((settings.release_dir / "2.0.1").exists())

    def test_staging_refuses_low_disk_before_downloading_release_assets(self):
        with tempfile.TemporaryDirectory() as directory:
            settings = self.settings(Path(directory))
            release, fetcher, _files = self.release_fixture(settings)
            repository = MemoryRepository(release, fetcher)
            with patch(
                "cayvpn.updates.shutil.disk_usage",
                return_value=SimpleNamespace(total=1024**3, used=1024**3 - 1, free=1),
            ):
                with self.assertRaises(UpdateError) as raised:
                    UpdateManager(settings, repository).stage("2.0.1", "2.0.0")
            self.assertEqual(raised.exception.code, "insufficient_disk_space")
            self.assertFalse(settings.release_dir.exists())

    def test_release_impact_metadata_is_allowlisted_and_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            release = Path(directory)
            (release / "release.json").write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "version": "2.0.1",
                        "channel": "stable",
                        "supported_os": ["ubuntu-24.04"],
                        "supported_architectures": ["amd64", "arm64"],
                        "minimum_cayvpn_version": "2.0.0-dev",
                        "offline_dependencies": True,
                        "offline_optional_components": True,
                        "summary": "Safer owner-approved updates",
                        "component_changes": ["Refreshes the bundled runtime"],
                        "expected_interruption_seconds": 45,
                        "requires_reboot": False,
                        "security_fixes": True,
                    }
                )
            )
            metadata = _release_metadata(release, "2.0.1", "2.0.0")
            self.assertTrue(metadata["security_fixes"])
            self.assertEqual(metadata["expected_interruption_seconds"], 45)
            (release / "release.json").write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "version": "2.0.1",
                        "channel": "stable",
                        "supported_os": ["ubuntu-24.04"],
                        "supported_architectures": ["amd64", "arm64"],
                        "minimum_cayvpn_version": "2.0.0-dev",
                        "offline_dependencies": True,
                        "offline_optional_components": True,
                        "unexpected": "not allowed",
                    }
                )
            )
            with self.assertRaises(UpdateError) as raised:
                _release_metadata(release, "2.0.1", "2.0.0")
            self.assertEqual(raised.exception.code, "release_metadata_invalid")

    def test_staged_release_rejects_an_unsigned_extra_source_file(self):
        with tempfile.TemporaryDirectory() as directory:
            settings = self.settings(Path(directory))
            release, fetcher, _files = self.release_fixture(settings)
            runner = lambda argv, **_kwargs: subprocess.CompletedProcess(argv, 0, "", "")
            UpdateManager(settings, MemoryRepository(release, fetcher), runner).stage("2.0.1", "2.0.0")
            target = settings.release_dir / "2.0.1"
            (target / "unsigned.py").write_text("raise RuntimeError('should never load')\n")

            with self.assertRaises(UpdateError) as raised:
                verify_installed_release(settings, target, "2.0.0", "2.0.1")
            self.assertEqual(raised.exception.code, "release_inventory_mismatch")

    def test_staging_rejects_a_release_older_than_the_highest_trusted_version(self):
        with tempfile.TemporaryDirectory() as directory:
            settings = self.settings(Path(directory))
            release, fetcher, _files = self.release_fixture(settings, version="2.0.1")
            settings.update_metadata_path.parent.mkdir(parents=True, exist_ok=True)
            settings.update_metadata_path.write_text(json.dumps({"schema_version": 1, "highest_seen_release": "2.0.2"}))

            with self.assertRaises(UpdateError) as raised:
                UpdateManager(settings, MemoryRepository(release, fetcher)).stage("2.0.1", "2.0.0")
            self.assertEqual(raised.exception.code, "release_rollback_detected")

    def test_default_upgrade_selection_uses_semver_not_lexical_order(self):
        with tempfile.TemporaryDirectory() as directory:
            settings = self.settings(Path(directory))
            for version in ("2.0.8", "2.0.9", "2.0.10"):
                release = settings.release_dir / version
                release.mkdir(parents=True, exist_ok=True)
                (release / "requirements.txt").write_text("fixture==1\n")
            settings.active_release.parent.mkdir(parents=True, exist_ok=True)
            settings.active_release.symlink_to(settings.release_dir / "2.0.9", target_is_directory=True)

            with (
                patch("cayvpn.cli._snapshot_state_paths"),
                patch("cayvpn.cli._verify_release_bundle"),
                patch("cayvpn.cli._stop_units_for_upgrade"),
                patch("cayvpn.cli._run_release_migrations"),
                patch("cayvpn.cli.sync_release_components") as sync_components,
                patch("cayvpn.cli._restart_units"),
                patch("cayvpn.cli._request_runtime_reconciliation", return_value="fixture"),
                patch("cayvpn.cli._wait_for_runtime_reconciliation"),
                patch("cayvpn.cli.cmd_verify", return_value=0),
            ):
                self.assertEqual(cmd_upgrade(settings, None, True), 0)

            self.assertEqual(settings.active_release.resolve().name, "2.0.10")
            sync_components.assert_called_once_with(settings, (settings.release_dir / "2.0.10").resolve())
            self.assertEqual((settings.state_dir / "last-good-release").read_text().strip(), str((settings.release_dir / "2.0.9").resolve()))

    def test_upgrade_refuses_an_unverified_active_release_before_snapshotting(self):
        with tempfile.TemporaryDirectory() as directory:
            settings = self.settings(Path(directory))
            for version in ("2.0.0", "2.0.1"):
                release = settings.release_dir / version
                release.mkdir(parents=True, exist_ok=True)
                (release / "requirements.txt").write_text("fixture==1\n")
            settings.active_release.parent.mkdir(parents=True, exist_ok=True)
            settings.active_release.symlink_to(settings.release_dir / "2.0.0", target_is_directory=True)

            with (
                patch("cayvpn.cli._verify_release_bundle", side_effect=RuntimeError("untrusted active release")),
                patch("cayvpn.cli._snapshot_state_paths") as snapshot,
            ):
                with self.assertRaisesRegex(RuntimeError, "untrusted active release"):
                    cmd_upgrade(settings, "2.0.1", True)

            snapshot.assert_not_called()

    def test_failed_upgrade_restores_routes_and_verifies_the_previous_release(self):
        with tempfile.TemporaryDirectory() as directory:
            settings = self.settings(Path(directory))
            previous = settings.release_dir / "2.0.0"
            target = settings.release_dir / "2.0.1"
            for release in (previous, target):
                release.mkdir(parents=True, exist_ok=True)
                (release / "requirements.txt").write_text("fixture==1\n")
            settings.active_release.parent.mkdir(parents=True, exist_ok=True)
            settings.active_release.symlink_to(previous, target_is_directory=True)

            with (
                patch("cayvpn.cli._verify_release_bundle"),
                patch("cayvpn.cli._snapshot_state_paths"),
                patch("cayvpn.cli._stop_units_for_upgrade") as stop_units,
                patch("cayvpn.cli._run_release_migrations", side_effect=RuntimeError("migration failed")),
                patch("cayvpn.cli._restore_state_paths") as restore_state,
                patch("cayvpn.cli._atomic_active_link") as activate_release,
                patch("cayvpn.cli._request_runtime_reconciliation", return_value="restore-routes") as request_reconciliation,
                patch("cayvpn.cli._restart_units") as restart_units,
                patch("cayvpn.cli._wait_for_runtime_reconciliation") as wait_for_reconciliation,
                patch("cayvpn.cli.cmd_verify", return_value=0) as verify,
            ):
                with self.assertRaisesRegex(RuntimeError, "migration failed"):
                    cmd_upgrade(settings, "2.0.1", True)

            self.assertEqual(stop_units.call_count, 2)
            restore_state.assert_called_once()
            activate_release.assert_called_once_with(settings, previous.resolve())
            request_reconciliation.assert_called_once_with(settings)
            restart_units.assert_called_once_with()
            wait_for_reconciliation.assert_called_once_with(settings, "restore-routes")
            verify.assert_called_once_with(settings)
            state = json.loads(settings.update_state_path.read_text())
            self.assertEqual(state["phase"], "rolled_back")
            self.assertTrue(state["rolled_back"])

    def test_component_rotation_failure_restores_previous_native_binaries(self):
        with tempfile.TemporaryDirectory() as directory:
            settings = self.settings(Path(directory))
            previous = settings.release_dir / "2.0.0"
            target = settings.release_dir / "2.0.1"
            for release in (previous, target):
                release.mkdir(parents=True, exist_ok=True)
                (release / "requirements.txt").write_text("fixture==1\n")
            settings.active_release.parent.mkdir(parents=True, exist_ok=True)
            settings.active_release.symlink_to(previous, target_is_directory=True)
            installed = (
                settings.config_dir
                / "components/amneziawg/amd64/awg"
            )
            installed.parent.mkdir(parents=True)
            installed.write_bytes(b"trusted previous component")

            def interrupted_sync(_settings, _target):
                installed.write_bytes(b"partially rotated component")
                raise RuntimeError("component rotation failed")

            with (
                patch("cayvpn.cli._verify_release_bundle"),
                patch("cayvpn.cli._stop_units_for_upgrade") as stop_units,
                patch("cayvpn.cli._run_release_migrations"),
                patch("cayvpn.cli.sync_release_components", side_effect=interrupted_sync),
                patch("cayvpn.cli._request_runtime_reconciliation", return_value="restore-components"),
                patch("cayvpn.cli._restart_units"),
                patch("cayvpn.cli._wait_for_runtime_reconciliation"),
                patch("cayvpn.cli.cmd_verify", return_value=0),
            ):
                with self.assertRaisesRegex(RuntimeError, "component rotation failed"):
                    cmd_upgrade(settings, "2.0.1", True)

            self.assertEqual(installed.read_bytes(), b"trusted previous component")
            self.assertEqual(settings.active_release.resolve(), previous.resolve())
            self.assertEqual(stop_units.call_count, 2)
            state = json.loads(settings.update_state_path.read_text())
            self.assertEqual(state["phase"], "rolled_back")
            self.assertTrue(state["rolled_back"])

    def test_maintenance_verify_checks_the_signed_active_release(self):
        with tempfile.TemporaryDirectory() as directory:
            settings = self.settings(Path(directory))
            settings.state_dir.mkdir(parents=True)
            settings.db_path.touch()
            settings.wg_dir.mkdir(parents=True)

            with patch("cayvpn.cli._active_release_path", side_effect=RuntimeError("signed release changed")) as verify_release:
                self.assertEqual(cmd_verify(settings), 1)

            verify_release.assert_called_once_with(settings)

    def test_retention_preserves_active_last_good_staged_and_recent_recovery(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            settings = self.settings(root)
            settings.release_dir.mkdir(parents=True)
            settings.state_dir.mkdir(parents=True)
            settings.config_dir.mkdir(parents=True)
            for version in ("2.0.1", "2.0.2", "2.0.3", "2.0.4"):
                release = settings.release_dir / version
                release.mkdir()
                (release / "requirements.txt").write_text("fixture==1\n")
            settings.active_release.parent.mkdir(parents=True, exist_ok=True)
            settings.active_release.symlink_to(settings.release_dir / "2.0.4", target_is_directory=True)
            (settings.state_dir / "last-good-release").write_text(str(settings.release_dir / "2.0.3") + "\n")
            write_update_state(settings, "staged", target_release="2.0.2")
            for root_name in ("upgrade-snapshots", "rollback-snapshots"):
                snapshot_root = settings.state_dir / root_name
                snapshot_root.mkdir()
                for index in range(4):
                    snapshot = snapshot_root / f"snapshot-{index}"
                    snapshot.mkdir()
                    (snapshot / "manifest.json").write_text("{}")

            result = prune_update_history(settings, keep_releases=1, keep_snapshots=1)

            self.assertFalse((settings.release_dir / "2.0.1").exists())
            for version in ("2.0.2", "2.0.3", "2.0.4"):
                self.assertTrue((settings.release_dir / version).exists())
            self.assertEqual(len(result["removed_releases"]), 1)
            self.assertEqual(len(result["removed_snapshots"]), 6)

    def test_rollback_requires_the_exact_pre_upgrade_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            settings = self.settings(Path(directory))
            for version in ("2.0.0", "2.0.1"):
                release = settings.release_dir / version
                release.mkdir(parents=True, exist_ok=True)
                (release / "requirements.txt").write_text("fixture==1\n")
            settings.active_release.parent.mkdir(parents=True, exist_ok=True)
            settings.active_release.symlink_to(settings.release_dir / "2.0.1", target_is_directory=True)
            settings.state_dir.mkdir(parents=True, exist_ok=True)
            (settings.state_dir / "last-good-release").write_text(str(settings.release_dir / "2.0.0") + "\n")

            with (
                patch("cayvpn.cli._verify_release_bundle"),
                patch("cayvpn.cli._snapshot_state_paths") as snapshot,
                patch("cayvpn.cli._stop_units_for_upgrade") as stop_units,
            ):
                with self.assertRaisesRegex(RuntimeError, "matching pre-upgrade snapshot"):
                    cmd_rollback(settings, True)

            snapshot.assert_not_called()
            stop_units.assert_not_called()

    def test_failed_rollback_restores_and_verifies_the_release_that_was_active(self):
        with tempfile.TemporaryDirectory() as directory:
            settings = self.settings(Path(directory))
            target = settings.release_dir / "2.0.0"
            current = settings.release_dir / "2.0.1"
            for release in (target, current):
                release.mkdir(parents=True, exist_ok=True)
                (release / "requirements.txt").write_text("fixture==1\n")
            settings.active_release.parent.mkdir(parents=True, exist_ok=True)
            settings.active_release.symlink_to(current, target_is_directory=True)
            settings.state_dir.mkdir(parents=True, exist_ok=True)
            (settings.state_dir / "last-good-release").write_text(str(target) + "\n")
            restore_snapshot = settings.state_dir / "upgrade-snapshots" / "matching"
            restore_snapshot.mkdir(parents=True)

            with (
                patch("cayvpn.cli._matching_upgrade_snapshot", return_value=restore_snapshot),
                patch("cayvpn.cli._verify_release_bundle"),
                patch("cayvpn.cli._snapshot_state_paths"),
                patch("cayvpn.cli._stop_units_for_upgrade") as stop_units,
                patch("cayvpn.cli._restore_state_paths", side_effect=[RuntimeError("restore failed"), None]) as restore_state,
                patch("cayvpn.cli._atomic_active_link") as activate_release,
                patch("cayvpn.cli._request_runtime_reconciliation", return_value="restore-current") as request_reconciliation,
                patch("cayvpn.cli._restart_units") as restart_units,
                patch("cayvpn.cli._wait_for_runtime_reconciliation") as wait_for_reconciliation,
                patch("cayvpn.cli.cmd_verify", return_value=0) as verify,
            ):
                with self.assertRaisesRegex(RuntimeError, "restore failed"):
                    cmd_rollback(settings, True)

            self.assertEqual(stop_units.call_count, 2)
            self.assertEqual(restore_state.call_count, 2)
            activate_release.assert_called_once_with(settings, current.resolve())
            request_reconciliation.assert_called_once_with(settings)
            restart_units.assert_called_once_with()
            wait_for_reconciliation.assert_called_once_with(settings, "restore-current")
            verify.assert_called_once_with(settings)
            state = json.loads(settings.update_state_path.read_text())
            self.assertEqual(state["state"], "rollback_failed")
            self.assertEqual(state["phase"], "previous_release_restored")
            self.assertFalse(state["rolled_back"])

    def test_release_cannot_replace_the_original_trust_key(self):
        with tempfile.TemporaryDirectory() as directory:
            settings = self.settings(Path(directory))
            trusted_release, _trusted_fetcher, _files = self.release_fixture(settings)
            attacker = Ed25519PrivateKey.generate()
            hostile_release, hostile_fetcher, _hostile_files = self.release_fixture(settings, signing_key=attacker)
            # Restore the original trust anchor after constructing the hostile bundle.
            original_public = trusted_release.assets["cayvpn-release.pub"].url
            settings.release_trust_key.write_bytes(_trusted_fetcher.files[original_public])

            with self.assertRaisesRegex(UpdateError, "different key") as raised:
                UpdateManager(settings, MemoryRepository(hostile_release, hostile_fetcher), lambda *args, **kwargs: subprocess.CompletedProcess(args, 0)).stage("2.0.1", "2.0.0")
            self.assertEqual(raised.exception.code, "release_key_mismatch")

    def test_manifest_rejects_parent_and_normalized_paths(self):
        digest = "0" * 64
        for name in ("../app.py", "folder/../app.py", "folder//app.py", "./app.py"):
            with self.subTest(name=name), self.assertRaises(UpdateError):
                parse_manifest(f"{digest}  {name}\n".encode())

    def test_mutable_github_release_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            settings = self.settings(Path(directory))
            payload = {
                "draft": False,
                "prerelease": False,
                "immutable": False,
                "tag_name": "v2.0.1",
            }
            with self.assertRaises(UpdateError) as raised:
                ReleaseRepository(settings, MemoryFetcher(payload=payload)).latest()
            self.assertEqual(raised.exception.code, "mutable_release")

    def test_stable_channel_rejects_prerelease_or_build_tags(self):
        with tempfile.TemporaryDirectory() as directory:
            settings = self.settings(Path(directory))
            for tag in ("v2.0.1-rc.1", "v2.0.1+rebuilt"):
                payload = {
                    "draft": False,
                    "prerelease": False,
                    "immutable": True,
                    "tag_name": tag,
                }
                with self.subTest(tag=tag), self.assertRaises(UpdateError) as raised:
                    ReleaseRepository(settings, MemoryFetcher(payload=payload)).latest()
                self.assertEqual(raised.exception.code, "unsupported_release_channel")

    def test_release_for_a_different_operating_system_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            settings = self.settings(Path(directory))
            release, fetcher, _files = self.release_fixture(settings)
            runner = lambda argv, **_kwargs: subprocess.CompletedProcess(argv, 0, "", "")
            with patch("cayvpn.updates._operating_system", return_value="debian-12"):
                with self.assertRaises(UpdateError) as raised:
                    UpdateManager(settings, MemoryRepository(release, fetcher), runner).stage("2.0.1", "2.0.0")
            self.assertEqual(raised.exception.code, "release_incompatible")

    def test_boot_recovery_restores_interrupted_upgrade_snapshot(self):
        self._assert_boot_recovery_restores_snapshot(rollback=False)

    def test_root_update_status_inherits_the_service_directory_group(self):
        with tempfile.TemporaryDirectory() as directory:
            settings = self.settings(Path(directory))
            settings.state_dir.mkdir(parents=True)
            with patch("cayvpn.updates.os.geteuid", return_value=0), patch("cayvpn.updates.os.chown") as chown:
                write_update_state(settings, "staged", target_release="2.0.1")
            self.assertEqual(chown.call_args.args[1:], (-1, settings.state_dir.stat().st_gid))
            self.assertEqual(settings.update_state_path.stat().st_mode & 0o777, 0o640)

    def test_worker_requires_root_agent_verification_before_completing_boot_recovery(self):
        from cayvpn.protocol import AgentResponse
        with tempfile.TemporaryDirectory() as directory:
            settings = replace(self.settings(Path(directory)), apply_network=True)
            with Database(settings) as database:
                database.initialize_defaults(settings)
                database.set_setting("runtime_reconciliation_request", "fixture-request")
                write_update_state(settings, "install_interrupted", phase="rollback_restored_pending_reconciliation", reconciliation_request="fixture-request", rolled_back=False)
                with patch("cayvpn.worker_service.AgentClient") as agent, patch("cayvpn.cli.cmd_verify") as local_verify:
                    agent.return_value.execute.return_value = AgentResponse("fixture", "succeeded", result={"verified": False})
                    self.assertFalse(record_reconciliation_completion(settings, database, "fixture-request"))
                    self.assertEqual(database.get_setting("runtime_reconciliation_completed", ""), "")
                    agent.return_value.execute.return_value = AgentResponse("fixture", "succeeded", result={"verified": True})
                    self.assertTrue(record_reconciliation_completion(settings, database, "fixture-request"))
                    self.assertEqual(agent.return_value.execute.call_args.args[0].action, "system.verify")
                    local_verify.assert_not_called()
                self.assertTrue(json.loads(settings.update_state_path.read_text())["rolled_back"])

    def test_worker_reads_an_older_root_only_update_journal_through_the_agent(self):
        from cayvpn.protocol import AgentResponse
        with tempfile.TemporaryDirectory() as directory:
            settings = replace(self.settings(Path(directory)), apply_network=True)
            with Database(settings) as database:
                database.initialize_defaults(settings)
                database.set_setting("runtime_reconciliation_request", "fixture-request")
                state = write_update_state(settings, "installing", phase="services_restarted")
                with patch("cayvpn.worker_service.read_update_state", return_value={}), patch("cayvpn.worker_service.AgentClient") as agent:
                    for response in (
                        AgentResponse("fixture", "queued"),
                        AgentResponse("fixture", "succeeded", result={"schema_version": 1, "state": "idle"}),
                    ):
                        agent.return_value.execute.return_value = response
                        self.assertFalse(record_reconciliation_completion(settings, database, "fixture-request"))
                        self.assertEqual(database.get_setting("runtime_reconciliation_completed", ""), "")
                    agent.return_value.execute.return_value = AgentResponse("fixture", "succeeded", result=state)
                    self.assertTrue(record_reconciliation_completion(settings, database, "fixture-request"))
                    self.assertEqual(agent.return_value.execute.call_args.args[0].action, "update.status")
                    self.assertEqual(database.get_setting("runtime_reconciliation_completed"), "fixture-request")

    def test_boot_recovery_restores_interrupted_rollback_snapshot(self):
        self._assert_boot_recovery_restores_snapshot(rollback=True)

    def test_failed_boot_recovery_retains_rollback_journal_and_retries_safely(self):
        self._assert_boot_recovery_restores_snapshot(rollback=True, retry=True)

    def _assert_boot_recovery_restores_snapshot(self, *, rollback, retry=False):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            settings = self.settings(root)
            previous_version, target_version = ("2.0.1", "2.0.0") if rollback else ("2.0.0", "2.0.1")
            _release, _fetcher, files = self.release_fixture(settings, version=previous_version)
            previous = settings.release_dir / previous_version
            target = settings.release_dir / target_version
            settings.release_dir.mkdir(parents=True)
            with tarfile.open(fileobj=io.BytesIO(files[f"cayvpn-{previous_version}.tar.gz"]), mode="r:gz") as archive:
                archive.extractall(settings.release_dir)
            (settings.release_dir / f"cayvpn-{previous_version}").rename(previous)
            (previous / "release.manifest").write_bytes(files[f"cayvpn-{previous_version}.sha256"])
            (previous / "release.signature").write_bytes(files[f"cayvpn-{previous_version}.sha256.sig"])
            (previous / "release.pub").write_bytes(files["cayvpn-release.pub"])
            target.mkdir()
            settings.active_release.parent.mkdir(parents=True, exist_ok=True)
            settings.active_release.symlink_to(previous, target_is_directory=True)
            settings.state_dir.mkdir(parents=True, exist_ok=True)
            settings.config_dir.mkdir(parents=True, exist_ok=True)
            settings.wg_dir.mkdir(parents=True, exist_ok=True)
            with closing(sqlite3.connect(settings.db_path)) as database:
                database.execute("CREATE TABLE fixture (value TEXT)")
                database.execute("INSERT INTO fixture VALUES ('old database')")
                database.commit()
            (settings.config_dir / "value").write_text("old config")
            snapshot = settings.state_dir / ("rollback-snapshots" if rollback else "upgrade-snapshots") / "fixture"
            _snapshot_state_paths(settings, snapshot)
            with closing(sqlite3.connect(settings.db_path)) as database:
                database.execute("UPDATE fixture SET value = 'new database'")
                database.commit()
            (settings.config_dir / "value").write_text("new config")
            settings.active_release.unlink()
            settings.active_release.symlink_to(target, target_is_directory=True)
            write_update_state(settings, "installing", phase="rollback_restoring" if rollback else "switched", target_release=target_version, previous_release=str(previous), snapshot=str(snapshot), rollback=rollback)

            if retry:
                with patch("cayvpn.update_runner._restore_state_paths", side_effect=OSError("read-only parent")):
                    self.assertEqual(recover_interrupted_update(settings), 1)
                failed = json.loads(settings.update_state_path.read_text())
                self.assertTrue(failed["rollback"])
                self.assertEqual(failed["phase"], "recovery_required")
            self.assertEqual(recover_interrupted_update(settings), 0)
            self.assertEqual(settings.active_release.resolve(), previous.resolve())
            with closing(sqlite3.connect(settings.db_path)) as database:
                self.assertEqual(database.execute("SELECT value FROM fixture").fetchone(), ("old database",))
            self.assertEqual((settings.config_dir / "value").read_text(), "old config")
            pending = json.loads(settings.update_state_path.read_text())
            self.assertEqual(
                pending["phase"], "rollback_restored_pending_reconciliation"
            )
            self.assertFalse(pending["rolled_back"])
            request_id = pending["reconciliation_request"]
            database = Database(settings)
            database.initialize_defaults(settings)
            with patch("cayvpn.cli.cmd_verify", return_value=1):
                self.assertFalse(
                    record_reconciliation_completion(
                        settings, database, request_id
                    )
                )
            self.assertEqual(
                database.get_setting("runtime_reconciliation_completed", ""), ""
            )
            with patch("cayvpn.cli.cmd_verify", return_value=0):
                self.assertTrue(
                    record_reconciliation_completion(
                        settings, database, request_id
                    )
                )
            recovered = json.loads(settings.update_state_path.read_text())
            self.assertEqual(recovered["phase"], "rolled_back_on_boot")
            self.assertTrue(recovered["rolled_back"])
            database.engine.dispose()

    def test_boot_recovery_does_not_restore_before_mutation_started(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            settings = self.settings(root)
            settings.state_dir.mkdir(parents=True, exist_ok=True)
            settings.config_dir.mkdir(parents=True, exist_ok=True)
            settings.wg_dir.mkdir(parents=True, exist_ok=True)
            with closing(sqlite3.connect(settings.db_path)) as database:
                database.execute("CREATE TABLE fixture (value TEXT)")
                database.execute("INSERT INTO fixture VALUES ('snapshot value')")
                database.commit()
            snapshot = settings.state_dir / "upgrade-snapshots" / "fixture"
            _snapshot_state_paths(settings, snapshot)
            with closing(sqlite3.connect(settings.db_path)) as database:
                database.execute("UPDATE fixture SET value = 'new committed value'")
                database.commit()
            write_update_state(settings, "installing", phase="release_verified", target_release="2.0.1", snapshot=str(snapshot))

            self.assertEqual(recover_interrupted_update(settings), 0)
            with closing(sqlite3.connect(settings.db_path)) as database:
                self.assertEqual(database.execute("SELECT value FROM fixture").fetchone(), ("new committed value",))
            state = json.loads(settings.update_state_path.read_text())
            self.assertEqual(state["phase"], "no_active_change")
            self.assertFalse(state["rolled_back"])

    def test_boot_recovery_rejects_snapshot_from_the_other_operation_tree(self):
        for rollback, folder in ((True, "upgrade-snapshots"), (False, "rollback-snapshots")):
            with self.subTest(rollback=rollback), tempfile.TemporaryDirectory() as directory:
                settings = self.settings(Path(directory))
                previous = settings.release_dir / "2.0.0"
                previous.mkdir(parents=True)
                (previous / "release.manifest").touch()
                snapshot = settings.state_dir / folder / "fixture"
                snapshot.mkdir(parents=True)
                (snapshot / "manifest.json").write_text("{}")
                write_update_state(
                    settings, "installing", phase="rollback_restoring" if rollback else "switched",
                    previous_release=str(previous), snapshot=str(snapshot), rollback=rollback,
                )
                with (
                    patch("cayvpn.update_runner.verify_installed_release") as verify,
                    patch("cayvpn.update_runner._restore_state_paths") as restore,
                ):
                    self.assertEqual(recover_interrupted_update(settings), 1)
                verify.assert_not_called()
                restore.assert_not_called()
                state = json.loads(settings.update_state_path.read_text())
                self.assertEqual(state["error_code"], "invalid_recovery_journal")

    def test_incomplete_snapshot_is_refused_without_deleting_live_state(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            settings = self.settings(root)
            settings.config_dir.mkdir(parents=True)
            settings.wg_dir.mkdir(parents=True)
            settings.db_path.parent.mkdir(parents=True)
            settings.db_path.write_bytes(b"live database bytes")
            (settings.config_dir / "value").write_text("live config")
            incomplete = settings.state_dir / "upgrade-snapshots" / "incomplete"
            incomplete.mkdir(parents=True)
            (incomplete / "config").mkdir()

            with self.assertRaises(RuntimeError):
                _restore_state_paths(settings, incomplete)
            self.assertEqual(settings.db_path.read_bytes(), b"live database bytes")
            self.assertEqual((settings.config_dir / "value").read_text(), "live config")


if __name__ == "__main__":
    unittest.main()
