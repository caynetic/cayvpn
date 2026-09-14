from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class InstallSnapshotTests(unittest.TestCase):
    def command(
        self,
        snapshot: Path,
        install_root: Path,
        active_release: Path,
        state_dir: Path,
        config_dir: Path,
        wireguard_dir: Path,
        snapshot_root: Path,
    ) -> list[str]:
        repository = Path(__file__).resolve().parents[1]
        return [
            sys.executable,
            str(repository / "scripts" / "verify-install-snapshot.py"),
            str(snapshot),
            str(install_root),
            str(active_release),
            str(state_dir),
            str(config_dir),
            str(wireguard_dir),
            str(snapshot_root),
            "wg0",
            "awg0",
            "wg-admin",
        ]

    def test_snapshot_manifest_accepts_exact_private_inventory_then_rejects_tampering(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            snapshot_root = root / "snapshots"
            snapshot = snapshot_root / "install-test"
            state_copy = snapshot / "state"
            state_copy.mkdir(parents=True)
            snapshot.chmod(0o700)
            database = state_copy / "cayvpn.db"
            database.write_bytes(b"verified-owner-state")
            digest = hashlib.sha256(database.read_bytes()).hexdigest()
            install_root = root / "install"
            active_release = install_root / "current"
            state_dir = root / "state"
            config_dir = root / "config"
            wireguard_dir = root / "wireguard"
            manifest = {
                "format": 1,
                "paths": {
                    "install_root": str(install_root),
                    "active_release": str(active_release),
                    "state_dir": str(state_dir),
                    "config_dir": str(config_dir),
                    "wireguard_dir": str(wireguard_dir),
                    "snapshot_root": str(snapshot_root),
                },
                "interfaces": {
                    "user": "wg0",
                    "amnezia": "awg0",
                    "admin": "wg-admin",
                },
                "inventory": {
                    "state": "directory",
                    "state/cayvpn.db": f"file:{digest}",
                },
            }
            (snapshot / "snapshot-manifest.json").write_text(
                json.dumps(manifest, sort_keys=True)
            )
            command = self.command(
                snapshot,
                install_root,
                active_release,
                state_dir,
                config_dir,
                wireguard_dir,
                snapshot_root,
            )

            accepted = subprocess.run(
                command, capture_output=True, text=True, check=False
            )
            self.assertEqual(accepted.returncode, 0, accepted.stderr)

            database.write_bytes(b"tampered-owner-state")
            rejected = subprocess.run(
                command, capture_output=True, text=True, check=False
            )
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("no longer matches", rejected.stderr)


if __name__ == "__main__":
    unittest.main()
