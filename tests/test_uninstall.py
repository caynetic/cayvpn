import json
import os
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import Mock, patch

from cayvpn.cli import (
    _parsed_service_states,
    _preserve_uninstall_backup,
    _recorded_service_units,
    _restore_install_snapshot,
    _restore_service_states,
    _restore_snapshot_item,
    _snapshot_inventory,
    _validated_install_snapshot,
    cmd_uninstall,
)
from cayvpn.config import Settings


class UninstallTests(unittest.TestCase):
    def _fixture(self, root: Path):
        root = root.resolve()
        install_root = root / "opt" / "cayvpn"
        state = root / "var" / "lib" / "cayvpn"
        config = root / "etc" / "cayvpn"
        wireguard = root / "etc" / "wireguard"
        backups = root / "var" / "backups" / "cayvpn"
        base = Settings.from_env(root)
        settings = replace(
            base,
            state_dir=state,
            config_dir=config,
            db_path=state / "cayvpn.db",
            wg_dir=wireguard,
            release_dir=install_root / "releases",
            active_release=install_root / "current",
        )
        release = settings.release_dir / "2.0.0-test"
        release.mkdir(parents=True)
        settings.active_release.symlink_to(release)
        state.mkdir(parents=True)
        backups.mkdir(parents=True)
        snapshot = backups / "install-20260822T120000Z-123"
        snapshot.mkdir()
        units = (
            "cayvpn-update-recovery.service",
            "cayvpn-agent.service",
            "cayvpn-worker.service",
            "cayvpn-web.service",
            "cayvpn-remote-admin-renew.service",
            "cayvpn-remote-admin-renew.timer",
            f"wg-quick@{settings.user_interface}.service",
            f"wg-quick@{settings.admin_interface}.service",
            "AdGuardHome.service",
            "dnsmasq.service",
            "nftables.service",
            "nginx.service",
            "unattended-upgrades.service",
        )
        (snapshot / "service-state.txt").write_text("".join(f"{unit} enabled=not-found active=inactive\n" for unit in units))
        manifest = {
            "format": 1,
            "paths": {
                "install_root": str(install_root),
                "active_release": str(install_root / "current"),
                "state_dir": str(state),
                "config_dir": str(config),
                "wireguard_dir": str(wireguard),
                "snapshot_root": str(backups),
            },
            "interfaces": {"user": settings.user_interface, "amnezia": settings.amnezia_interface, "admin": settings.admin_interface},
            "inventory": _snapshot_inventory(snapshot),
        }
        (snapshot / "snapshot-manifest.json").write_text(json.dumps(manifest))
        (state / "last-install-snapshot").write_text(str(snapshot) + "\n")
        return settings, backups, snapshot

    def test_validated_snapshot_requires_matching_integrity_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            settings, backups, snapshot = self._fixture(Path(directory))
            self.assertEqual(_validated_install_snapshot(settings, backups), snapshot)
            (snapshot / "service-state.txt").write_text("tampered\n")
            with self.assertRaisesRegex(RuntimeError, "integrity"):
                _validated_install_snapshot(settings, backups)

    def test_validated_snapshot_refuses_preexisting_install_root(self):
        with tempfile.TemporaryDirectory() as directory:
            settings, backups, snapshot = self._fixture(Path(directory))
            (snapshot / "install-root-present").touch()
            manifest = json.loads((snapshot / "snapshot-manifest.json").read_text())
            manifest["inventory"] = _snapshot_inventory(snapshot)
            (snapshot / "snapshot-manifest.json").write_text(json.dumps(manifest))
            with self.assertRaisesRegex(RuntimeError, "existed before"):
                _validated_install_snapshot(settings, backups)

    def test_validated_snapshot_refuses_active_release_outside_versioned_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            settings, backups, _snapshot = self._fixture(root)
            outside = root / "outside-release"
            outside.mkdir()
            settings.active_release.unlink()
            settings.active_release.symlink_to(outside)

            with self.assertRaisesRegex(RuntimeError, "active CayVPN release link"):
                _validated_install_snapshot(settings, backups)

    def test_validated_snapshot_refuses_non_symlink_active_release(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            settings, backups, _snapshot = self._fixture(root)
            settings.active_release.unlink()
            settings.active_release.mkdir()

            with self.assertRaisesRegex(RuntimeError, "active CayVPN release link"):
                _validated_install_snapshot(settings, backups)

    def test_snapshot_pointer_cannot_escape_backup_root(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            settings, backups, _snapshot = self._fixture(root)
            outside = root / "outside" / "install-20260822T120000Z-999"
            outside.mkdir(parents=True)
            (settings.state_dir / "last-install-snapshot").write_text(str(outside))
            with self.assertRaisesRegex(RuntimeError, "outside"):
                _validated_install_snapshot(settings, backups)

    def test_preserved_backup_is_independent_and_mode_0600(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "state" / "backup"
            source.parent.mkdir()
            source.write_bytes(b"encrypted recovery material")
            destination = _preserve_uninstall_backup(source, root / "protected")
            source.unlink()
            self.assertEqual(destination.read_bytes(), b"encrypted recovery material")
            self.assertEqual(destination.stat().st_mode & 0o777, 0o600)

    def test_uninstall_keeps_agent_dependency_running_until_egress_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            settings, _backups, snapshot = self._fixture(Path(directory))
            database = Mock()
            events = []

            def record_command(arguments, timeout=60):
                events.append(("command", arguments, timeout))

            def record_cleanup(_settings, _database):
                events.append(("egress", None, None))

            with (
                patch("cayvpn.cli.os.geteuid", return_value=0),
                patch("cayvpn.cli._validated_install_snapshot", return_value=snapshot),
                patch("cayvpn.cli.getpass.getpass", return_value="long-test-passphrase"),
                patch("cayvpn.cli.Database", return_value=database),
                patch("cayvpn.cli.create_backup", return_value=Path(directory) / "backup"),
                patch("cayvpn.cli._preserve_uninstall_backup", return_value=Path(directory) / "preserved"),
                patch("cayvpn.cli._run_required", side_effect=record_command),
                patch("cayvpn.cli._deactivate_all_egress", side_effect=record_cleanup),
                patch("cayvpn.cli._command_succeeded", return_value=False),
                patch("cayvpn.cli._restore_install_snapshot"),
            ):
                self.assertEqual(cmd_uninstall(settings, confirm=True), 0)

            pause = events[0][1]
            self.assertEqual(pause[:2], ["systemctl", "stop"])
            self.assertNotIn("cayvpn-update-recovery", pause)
            cleanup_index = events.index(("egress", None, None))
            disable_index = next(
                index
                for index, event in enumerate(events)
                if event[0] == "command" and event[1][:3] == ["systemctl", "disable", "--now"]
            )
            self.assertLess(cleanup_index, disable_index)

    def test_restore_snapshot_item_preserves_symlinks_and_absence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "available"
            target.write_text("original")
            source = root / "snapshot-link"
            source.symlink_to(target)
            destination = root / "enabled"
            destination.write_text("CayVPN replacement")
            _restore_snapshot_item(source, destination)
            self.assertTrue(destination.is_symlink())
            self.assertEqual(os.readlink(destination), str(target))
            _restore_snapshot_item(root / "absent", destination)
            self.assertFalse(destination.exists() or destination.is_symlink())

    def test_service_state_rejects_unexpected_units_before_systemctl(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            settings, _backups, snapshot = self._fixture(root)
            with (snapshot / "service-state.txt").open("a") as output:
                output.write("attacker.service enabled=enabled active=active\n")
            with patch("cayvpn.cli._run_fixed") as run:
                with self.assertRaisesRegex(RuntimeError, "unexpected"):
                    _restore_service_states(settings, snapshot)
                run.assert_not_called()

    def test_uninstall_disables_services_added_by_installed_packages(self):
        with tempfile.TemporaryDirectory() as directory:
            settings, _backups, snapshot = self._fixture(Path(directory))
            with patch("cayvpn.cli._run_fixed", return_value=Mock(returncode=0)) as run:
                _restore_service_states(settings, snapshot)
            run.assert_any_call(["systemctl", "disable", "dnsmasq.service"], timeout=60)
            run.assert_any_call(["systemctl", "stop", "dnsmasq.service"], timeout=60)

    def test_failure_to_disable_new_service_is_tolerated_only_when_unit_is_absent(self):
        for load_state in ("loaded", "not-found"):
            with self.subTest(load_state=load_state), tempfile.TemporaryDirectory() as directory:
                settings, _backups, snapshot = self._fixture(Path(directory))
                def command(argv, timeout=60):
                    if argv[1] == "disable":
                        return Mock(returncode=1, stderr="disable failed", stdout="")
                    if argv[1] == "show":
                        return Mock(returncode=0, stdout=load_state)
                    return Mock(returncode=0)
                with patch("cayvpn.cli._run_fixed", side_effect=command):
                    if load_state == "loaded":
                        with self.assertRaisesRegex(RuntimeError, "disable failed"):
                            _restore_service_states(settings, snapshot)
                    else:
                        _restore_service_states(settings, snapshot)

    def test_legacy_snapshot_may_omit_only_later_cayvpn_remote_access_units(self):
        with tempfile.TemporaryDirectory() as directory:
            settings, backups, snapshot = self._fixture(Path(directory))
            state_path = snapshot / "service-state.txt"
            state_path.write_text(
                "\n".join(
                    line
                    for line in state_path.read_text().splitlines()
                    if not line.startswith("cayvpn-remote-admin-renew")
                )
                + "\n"
            )
            manifest = json.loads((snapshot / "snapshot-manifest.json").read_text())
            manifest["inventory"] = _snapshot_inventory(snapshot)
            (snapshot / "snapshot-manifest.json").write_text(json.dumps(manifest))

            with (
                patch("cayvpn.cli._run_required"),
                patch("cayvpn.cli._run_fixed") as run,
            ):
                run.return_value.returncode = 0
                _restore_service_states(settings, snapshot)

            self.assertEqual(_validated_install_snapshot(settings, backups), snapshot)

    def test_snapshot_validation_rejects_other_missing_service_state_before_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            settings, backups, snapshot = self._fixture(Path(directory))
            state_path = snapshot / "service-state.txt"
            state_path.write_text(
                "\n".join(
                    line
                    for line in state_path.read_text().splitlines()
                    if not line.startswith("nginx.service ")
                )
                + "\n"
            )
            manifest = json.loads((snapshot / "snapshot-manifest.json").read_text())
            manifest["inventory"] = _snapshot_inventory(snapshot)
            (snapshot / "snapshot-manifest.json").write_text(json.dumps(manifest))

            with self.assertRaisesRegex(RuntimeError, "service state is incomplete"):
                _validated_install_snapshot(settings, backups)

    def test_remote_https_units_are_part_of_the_verified_restore_inventory(self):
        with tempfile.TemporaryDirectory() as directory:
            settings, _backups, _snapshot = self._fixture(Path(directory))
            units = _recorded_service_units(settings)
            self.assertIn("cayvpn-remote-admin-renew.service", units)
            self.assertIn("cayvpn-remote-admin-renew.timer", units)

    def test_current_snapshot_omits_adguard_and_uninstall_leaves_owner_install_alone(self):
        with tempfile.TemporaryDirectory() as directory:
            settings, backups, snapshot = self._fixture(Path(directory))
            state_path = snapshot / "service-state.txt"
            state_path.write_text(
                "\n".join(
                    line
                    for line in state_path.read_text().splitlines()
                    if not line.startswith("AdGuardHome.service ")
                )
                + "\n"
            )
            manifest = json.loads((snapshot / "snapshot-manifest.json").read_text())
            manifest["inventory"] = _snapshot_inventory(snapshot)
            (snapshot / "snapshot-manifest.json").write_text(json.dumps(manifest))

            self.assertNotIn("AdGuardHome.service", _parsed_service_states(settings, snapshot))
            self.assertEqual(_validated_install_snapshot(settings, backups), snapshot)

            command_result = Mock(returncode=0, stdout="", stderr="")
            with (
                patch("cayvpn.cli._restore_snapshot_item") as restore,
                patch("cayvpn.cli._remove_exact_path"),
                patch("cayvpn.cli._run_required"),
                patch("cayvpn.cli._run_fixed", return_value=command_result),
                patch("cayvpn.cli._command_succeeded", return_value=False),
                patch("cayvpn.cli._restore_service_states"),
                patch("cayvpn.cli.shutil.which", return_value=None),
                patch("cayvpn.cli.os.chdir"),
            ):
                _restore_install_snapshot(settings, snapshot, backups)

            destinations = {call.args[1] for call in restore.call_args_list}
            self.assertNotIn(Path("/opt/AdGuardHome"), destinations)
            self.assertNotIn(Path("/etc/systemd/system/AdGuardHome.service"), destinations)


if __name__ == "__main__":
    unittest.main()
