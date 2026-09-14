import sqlite3
import os
import signal
import sys
import tarfile
import tempfile
import unittest
from contextlib import closing
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from cayvpn.backup import MAX_ENCRYPTED_BACKUP_BYTES, _age_decrypt, _run_age, _snapshot_database, _validate_archive_member, create_backup, restore_backup
from cayvpn.config import Settings
from cayvpn.db import Database


class BackupTests(unittest.TestCase):
    def test_age_handles_passphrase_prompts_split_across_terminal_reads(self):
        for confirmations, chunks in (
            (1, [b"Enter pass", b"phrase:", b""]),
            (2, [b"Enter pass", b"phrase:", b"\r\nConfirm passph", b"rase:", b""]),
        ):
            with (
                self.subTest(confirmations=confirmations),
                patch("cayvpn.backup.pty.fork", return_value=(1234, 9)),
                patch("cayvpn.backup.select.select", return_value=([9], [], [])),
                patch("cayvpn.backup.os.read", side_effect=chunks),
                patch("cayvpn.backup.os.write") as write,
                patch("cayvpn.backup.os.waitpid", return_value=(1234, 0)) as wait,
                patch("cayvpn.backup.os.close"),
                patch("cayvpn.backup.os.kill") as kill,
                patch("cayvpn.backup._wait_for_secret_input") as ready,
            ):
                _run_age("/fixture/age", [], "fixture-secret", confirmations)
                self.assertEqual(write.call_count, confirmations)
                self.assertEqual(ready.call_count, confirmations)
                write.assert_called_with(9, b"fixture-secret\n")
                wait.assert_called_once_with(1234, 0)
                kill.assert_not_called()

    def test_age_waits_until_the_terminal_disables_echo_before_sending_a_secret(self):
        with tempfile.TemporaryDirectory() as directory:
            script = Path(directory) / "slow-terminal.py"
            script.write_text(
                "import os, sys, termios, time\n"
                "for prompt in (b'Enter passphrase: ', b'Confirm passphrase: '):\n"
                "    original = termios.tcgetattr(0)\n"
                "    os.write(1, prompt)\n"
                "    time.sleep(0.05)\n"
                "    private = termios.tcgetattr(0)\n"
                "    private[3] &= ~termios.ECHO\n"
                "    termios.tcsetattr(0, termios.TCSAFLUSH, private)\n"
                "    assert sys.stdin.readline().strip() == 'long-test-passphrase'\n"
                "    termios.tcsetattr(0, termios.TCSANOW, original)\n"
                "    os.write(1, b'\\r\\n')\n"
            )
            _run_age(sys.executable, [str(script)], "long-test-passphrase", 2)

    def test_timed_out_age_child_is_terminated_and_reaped(self):
        with (
            patch("cayvpn.backup.pty.fork", return_value=(1234, 9)),
            patch("cayvpn.backup.select.select", return_value=([], [], [])),
            patch("cayvpn.backup.os.waitpid", return_value=(1234, 9)) as wait,
            patch("cayvpn.backup.os.close") as close,
            patch("cayvpn.backup.os.kill") as kill,
        ):
            with self.assertRaisesRegex(RuntimeError, "age operation timed out"):
                _run_age("/fixture/age", [], "fixture-secret", 1)
            kill.assert_called_once_with(1234, signal.SIGKILL)
            wait.assert_called_once_with(1234, 0)
            close.assert_called_once_with(9)

    def test_age_allows_slow_silent_processing_after_private_input(self):
        # Model an actual observed phase: age has accepted both prompts but
        # remains busy with scrypt past the old 60-second inactivity cutoff.
        delays = iter((0, 0, 90))

        def terminal_ready(readers, _writers, _errors, timeout):
            return (readers, [], []) if timeout >= next(delays) else ([], [], [])

        with (
            patch("cayvpn.backup.pty.fork", return_value=(1234, 9)),
            patch("cayvpn.backup.select.select", side_effect=terminal_ready),
            patch("cayvpn.backup.os.read", side_effect=(b"Enter passphrase:", b"Confirm passphrase:", b"")),
            patch("cayvpn.backup.os.write"),
            patch("cayvpn.backup._wait_for_secret_input"),
            patch("cayvpn.backup.os.waitpid", return_value=(1234, 0)),
            patch("cayvpn.backup.os.close"),
            patch("cayvpn.backup.os.kill") as kill,
        ):
            _run_age("/fixture/age", [], "fixture-secret", 2)
        kill.assert_not_called()

    def test_age_output_cannot_extend_the_overall_operation_deadline(self):
        with (
            patch("cayvpn.backup.pty.fork", return_value=(1234, 9)),
            patch("cayvpn.backup.time.monotonic", side_effect=(0, 300)),
            patch("cayvpn.backup.select.select", return_value=([9], [], [])) as ready,
            patch("cayvpn.backup.os.waitpid", return_value=(1234, 9)),
            patch("cayvpn.backup.os.close"),
            patch("cayvpn.backup.os.kill") as kill,
        ):
            with self.assertRaisesRegex(RuntimeError, "age operation timed out"):
                _run_age("/fixture/age", [], "fixture-secret", 2)
        ready.assert_not_called()
        kill.assert_called_once_with(1234, signal.SIGKILL)

    def test_archive_owner_names_cannot_override_numeric_ownership(self):
        member = tarfile.TarInfo("config/value")
        member.size = 1
        member.mode = 0o600
        member.uid = 4242
        member.gid = 4343
        member.uname = "root"
        member.gname = "root"
        with self.assertRaisesRegex(ValueError, "inconsistent file owner"):
            _validate_archive_member(
                member,
                {4242},
                {4343},
                {"root"},
                {"root"},
            )
        member.uid = 9999
        with self.assertRaisesRegex(ValueError, "unsupported file owner"):
            _validate_archive_member(
                member,
                {os.geteuid()},
                {4343},
                {"root"},
                {"root"},
            )

    def test_age_decrypt_uses_the_supported_auto_detected_passphrase_flow(self):
        def fake_run(binary, arguments, passphrase, confirmations):
            self.assertEqual(binary, "/usr/bin/age")
            self.assertEqual(arguments[0], "--decrypt")
            self.assertNotIn("--passphrase", arguments)
            self.assertEqual(passphrase, "long-test-passphrase")
            self.assertEqual(confirmations, 1)
            output = Path(arguments[arguments.index("--output") + 1])
            output.write_bytes(b"restored-state")

        with patch("cayvpn.backup.shutil.which", return_value="/usr/bin/age"), patch("cayvpn.backup._run_age", side_effect=fake_run):
            self.assertEqual(_age_decrypt(b"encrypted-state", "long-test-passphrase"), b"restored-state")

    def test_database_snapshot_preserves_the_service_owner_when_run_as_root(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.db"
            destination = root / "snapshot.db"
            with closing(sqlite3.connect(source)) as database:
                database.execute("CREATE TABLE fixture (value TEXT)")
                database.commit()
            observed = source.stat()
            with patch("cayvpn.backup.os.geteuid", return_value=0), patch("cayvpn.backup.os.chown") as chown:
                self.assertTrue(_snapshot_database(source, destination))
            chown.assert_called_once_with(destination, observed.st_uid, observed.st_gid, follow_symlinks=False)

    def test_encrypted_backup_round_trip(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            base = Settings.from_env(root)
            settings = replace(base, state_dir=root / "state", config_dir=root / "config", db_path=root / "state" / "cayvpn.db", wg_dir=root / "wireguard")
            settings.ensure_directories()
            settings.wg_dir.mkdir(parents=True, exist_ok=True)
            (settings.wg_dir / "server.pub").write_text("public")
            (settings.config_dir / "cayvpn.env").write_text("redacted-test-secret")
            db = Database(settings)
            db.initialize_defaults(settings)
            backup = create_backup(settings, db, "long-test-passphrase")
            self.assertTrue(backup.exists())
            self.assertNotIn(b"redacted-test-secret", backup.read_bytes())
            (settings.wg_dir / "server.pub").write_text("changed")
            db.engine.dispose()
            restore_backup(settings, "long-test-passphrase", backup)
            self.assertEqual((settings.wg_dir / "server.pub").read_text(), "public")

    def test_restore_discards_newer_wal_pages_instead_of_replaying_them_over_backup(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            settings = replace(Settings.from_env(root), state_dir=root / "state", config_dir=root / "config", db_path=root / "state" / "cayvpn.db", wg_dir=root / "wireguard")
            settings.ensure_directories()
            with Database(settings) as db:
                db.initialize_defaults(settings)
                db.set_setting("restore_canary", "backup value")
                with patch("cayvpn.backup._age_encrypt", return_value=None):
                    backup = create_backup(settings, db, "long-test-passphrase")
            with closing(sqlite3.connect(settings.db_path)) as database:
                database.execute("PRAGMA journal_mode=WAL")
                database.execute("PRAGMA wal_autocheckpoint=0")
                database.execute("UPDATE settings SET value = 'newer live value' WHERE key = 'restore_canary'")
                database.commit()
                sidecars = {settings.db_path.with_name(settings.db_path.name + suffix): settings.db_path.with_name(settings.db_path.name + suffix).read_bytes() for suffix in ("-wal", "-shm")}
            # Model journals surviving abrupt service termination. Every DB
            # connection is closed before restoration, as the CLI requires.
            for path, contents in sidecars.items():
                path.write_bytes(contents)
            restore_backup(settings, "long-test-passphrase", backup)
            self.assertTrue(all(not path.exists() for path in sidecars))
            with Database(settings) as db:
                self.assertEqual(db.get_setting("restore_canary"), "backup value")

    def test_directory_restore_removes_files_that_are_not_in_the_backup(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            base = Settings.from_env(root)
            settings = replace(
                base,
                state_dir=root / "state",
                config_dir=root / "config",
                db_path=root / "state" / "cayvpn.db",
                wg_dir=root / "wireguard",
            )
            settings.ensure_directories()
            (settings.config_dir / "saved.conf").write_text("saved")
            (settings.wg_dir / "saved.conf").write_text("saved")
            db = Database(settings)
            db.initialize_defaults(settings)
            backup = create_backup(settings, db, "long-test-passphrase")
            db.engine.dispose()
            (settings.config_dir / "stale.conf").write_text("must disappear")
            (settings.wg_dir / "stale.conf").write_text("must disappear")

            restore_backup(settings, "long-test-passphrase", backup)

            self.assertFalse((settings.config_dir / "stale.conf").exists())
            self.assertFalse((settings.wg_dir / "stale.conf").exists())
            self.assertEqual((settings.config_dir / "saved.conf").read_text(), "saved")
            self.assertEqual((settings.wg_dir / "saved.conf").read_text(), "saved")

    def test_backup_captures_committed_state_still_in_wal(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source_root = root / "source"
            destination_root = root / "destination"
            source_base = Settings.from_env(source_root)
            source = replace(source_base, state_dir=source_root / "state", config_dir=source_root / "config", db_path=source_root / "state" / "cayvpn.db", wg_dir=source_root / "wireguard")
            source.ensure_directories()
            db = Database(source)
            db.initialize_defaults(source)
            db.engine.dispose()

            writer = sqlite3.connect(source.db_path)
            try:
                writer.execute("PRAGMA journal_mode=WAL")
                writer.execute("PRAGMA wal_autocheckpoint=0")
                writer.execute("CREATE TABLE backup_wal_probe (value TEXT NOT NULL)")
                writer.commit()
                writer.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                writer.execute("INSERT INTO backup_wal_probe(value) VALUES (?)", ("latest-committed-state",))
                writer.commit()
                self.assertTrue(source.db_path.with_name(f"{source.db_path.name}-wal").is_file())
                backup = create_backup(source, db, "long-test-passphrase")
            finally:
                writer.close()
                db.engine.dispose()

            destination_base = Settings.from_env(destination_root)
            destination = replace(destination_base, state_dir=destination_root / "state", config_dir=destination_root / "config", db_path=destination_root / "state" / "cayvpn.db", wg_dir=destination_root / "wireguard")
            destination.ensure_directories()
            restore_backup(destination, "long-test-passphrase", backup)
            with closing(sqlite3.connect(destination.db_path)) as restored:
                self.assertEqual(restored.execute("SELECT value FROM backup_wal_probe").fetchone()[0], "latest-committed-state")

    def test_restore_preserves_service_readability_and_component_execution_modes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            base = Settings.from_env(root)
            settings = replace(base, state_dir=root / "state", config_dir=root / "config", db_path=root / "state" / "cayvpn.db", wg_dir=root / "wireguard")
            settings.ensure_directories()
            adblock = settings.config_dir / "adblock"
            component_dir = settings.config_dir / "components" / "hev-socks5-tunnel" / "amd64"
            adblock.mkdir(parents=True)
            component_dir.mkdir(parents=True)
            filter_path = adblock / "adguard-dns-filter.txt"
            component = component_dir / "hev-socks5-tunnel"
            filter_path.write_text("||tracker.example^\n")
            component.write_bytes(b"test executable")
            adblock.chmod(0o750)
            filter_path.chmod(0o640)
            component_dir.chmod(0o755)
            component.chmod(0o755)

            db = Database(settings)
            db.initialize_defaults(settings)
            backup = create_backup(settings, db, "long-test-passphrase")
            db.engine.dispose()

            adblock.chmod(0o700)
            filter_path.chmod(0o600)
            component_dir.chmod(0o700)
            component.chmod(0o600)
            restore_backup(settings, "long-test-passphrase", backup)

            self.assertEqual(adblock.stat().st_mode & 0o777, 0o750)
            self.assertEqual(filter_path.stat().st_mode & 0o777, 0o640)
            self.assertEqual(component_dir.stat().st_mode & 0o777, 0o755)
            self.assertEqual(component.stat().st_mode & 0o777, 0o755)

    def test_restore_replaces_an_existing_child_link_without_writing_through_it(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            base = Settings.from_env(root)
            settings = replace(base, state_dir=root / "state", config_dir=root / "config", db_path=root / "state" / "cayvpn.db", wg_dir=root / "wireguard")
            settings.ensure_directories()
            adblock = settings.config_dir / "adblock"
            adblock.mkdir()
            (adblock / "filter.txt").write_text("safe backup content")
            db = Database(settings)
            db.initialize_defaults(settings)
            backup = create_backup(settings, db, "long-test-passphrase")
            db.engine.dispose()

            outside = root / "outside"
            outside.mkdir()
            marker = outside / "filter.txt"
            marker.write_text("must not change")
            (adblock / "filter.txt").unlink()
            adblock.rmdir()
            adblock.symlink_to(outside, target_is_directory=True)

            restore_backup(settings, "long-test-passphrase", backup)

            self.assertEqual(marker.read_text(), "must not change")
            self.assertFalse(adblock.is_symlink())
            self.assertEqual((adblock / "filter.txt").read_text(), "safe backup content")

    def test_restore_refuses_a_backup_path_link(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            base = Settings.from_env(root)
            settings = replace(base, state_dir=root / "state", config_dir=root / "config", db_path=root / "state" / "cayvpn.db", wg_dir=root / "wireguard")
            settings.ensure_directories()
            db = Database(settings)
            db.initialize_defaults(settings)
            backup = create_backup(settings, db, "long-test-passphrase")
            db.engine.dispose()
            linked = root / "linked.backup"
            linked.symlink_to(backup)

            with self.assertRaisesRegex(ValueError, "regular file, not a link"):
                restore_backup(settings, "long-test-passphrase", linked)

    def test_restore_refuses_an_oversized_backup_before_reading_it(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            base = Settings.from_env(root)
            settings = replace(base, state_dir=root / "state", config_dir=root / "config", db_path=root / "state" / "cayvpn.db", wg_dir=root / "wireguard")
            oversized = root / "oversized.backup"
            with oversized.open("wb") as handle:
                handle.truncate(MAX_ENCRYPTED_BACKUP_BYTES + 1)

            with self.assertRaisesRegex(ValueError, "too large"):
                restore_backup(settings, "long-test-passphrase", oversized)


if __name__ == "__main__":
    unittest.main()
