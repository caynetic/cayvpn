import hashlib
import json
import os
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from cayvpn.components import (
    COMPONENT_NAMES,
    ComponentError,
    component_binary,
    ensure_amneziawg,
    ensure_lego,
    sync_release_components,
)
from cayvpn.config import Settings


class ComponentTests(unittest.TestCase):
    def settings(self, root: Path, active_release: Path | None = None) -> Settings:
        return replace(
            Settings.from_env(root),
            config_dir=root / "config",
            wg_dir=root / "wireguard",
            state_dir=root / "state",
            secret_key_path=root / "config" / "agent.key",
            active_release=active_release or root,
            apply_network=True,
        )

    @staticmethod
    def signed_release(
        root: Path,
        version: str,
        overrides: dict[tuple[str, str], bytes] | None = None,
    ) -> dict[tuple[str, str], bytes]:
        overrides = overrides or {}
        contents: dict[tuple[str, str], bytes] = {}
        lock = {
            "schema_version": 1,
            "release_version": version,
            "architectures": {},
        }
        for architecture in ("amd64", "arm64"):
            lock["architectures"][architecture] = {}
            component_dir = root / "components" / architecture
            component_dir.mkdir(parents=True, exist_ok=True)
            for name in COMPONENT_NAMES:
                payload = overrides.get(
                    (architecture, name),
                    f"{version}:{architecture}:{name}".encode(),
                )
                contents[(architecture, name)] = payload
                path = component_dir / name
                path.write_bytes(payload)
                path.chmod(0o755)
                lock["architectures"][architecture][name] = {
                    "path": f"components/{architecture}/{name}",
                    "sha256": hashlib.sha256(payload).hexdigest(),
                }
        (root / "release.json").write_text(
            json.dumps(
                {
                    "version": version,
                    "offline_optional_components": True,
                }
            )
        )
        (root / "components.lock.json").write_text(json.dumps(lock))
        return contents

    @staticmethod
    def architecture() -> str:
        return {"x86_64": "amd64", "aarch64": "arm64"}.get(
            os.uname().machine, os.uname().machine
        )

    def test_amnezia_install_stages_all_three_signed_release_binaries(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            contents = self.signed_release(root, "2.0.1")
            result = ensure_amneziawg(self.settings(root))

            self.assertEqual(result["state"], "installed")
            self.assertEqual(set(result["paths"]), {"awg", "awg_quick", "amneziawg_go"})
            expected_names = {
                "awg": "awg",
                "awg_quick": "awg-quick",
                "amneziawg_go": "amneziawg-go",
            }
            for key, path in result["paths"].items():
                binary = Path(path)
                self.assertEqual(
                    binary.read_bytes(),
                    contents[(self.architecture(), expected_names[key])],
                )
                self.assertTrue(os.access(binary, os.X_OK))

    def test_signed_component_checksum_mismatch_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.signed_release(root, "2.0.1")
            source = root / "components" / self.architecture() / "amneziawg-go"
            source.write_bytes(b"tampered-after-lock-review")

            with self.assertRaises(ComponentError) as error:
                ensure_amneziawg(self.settings(root))
            self.assertEqual(error.exception.code, "component_checksum_failed")

    def test_lego_install_stages_only_the_signed_release_binary(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            contents = self.signed_release(root, "2.0.1")
            result = ensure_lego(self.settings(root))

            binary = Path(result["paths"]["lego"])
            self.assertEqual(
                binary.read_bytes(),
                contents[(self.architecture(), "lego")],
            )
            self.assertTrue(os.access(binary, os.X_OK))

    def test_tampered_installed_binary_is_unavailable_then_repaired_from_signed_release(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            contents = self.signed_release(root, "2.0.1")
            settings = self.settings(root)
            binary = Path(ensure_lego(settings)["paths"]["lego"])
            binary.write_bytes(b"tampered-installed-lego")
            binary.chmod(0o755)

            self.assertIsNone(component_binary(settings, "lego"))
            repaired = Path(ensure_lego(settings)["paths"]["lego"])
            self.assertEqual(
                repaired.read_bytes(),
                contents[(self.architecture(), "lego")],
            )
            self.assertEqual(component_binary(settings, "lego"), str(repaired))

    def test_release_synchronization_rotates_every_native_component(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            releases = root / "releases"
            previous = releases / "2.0.1"
            target = releases / "2.0.2"
            previous.mkdir(parents=True)
            target.mkdir(parents=True)
            previous_contents = self.signed_release(previous, "2.0.1")
            target_contents = self.signed_release(target, "2.0.2")
            active = root / "current"
            active.symlink_to(previous, target_is_directory=True)
            settings = self.settings(root, active)

            sync_release_components(settings)
            architecture = self.architecture()
            for name in COMPONENT_NAMES:
                installed = Path(component_binary(settings, name) or "")
                self.assertEqual(
                    installed.read_bytes(),
                    previous_contents[(architecture, name)],
                )

            sync_release_components(settings, target)
            active.unlink()
            active.symlink_to(target, target_is_directory=True)
            for name in COMPONENT_NAMES:
                installed = Path(component_binary(settings, name) or "")
                self.assertTrue(installed.is_file())
                self.assertEqual(
                    installed.read_bytes(),
                    target_contents[(architecture, name)],
                )

    def test_network_runtime_refuses_components_without_a_signed_lock(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "release.json").write_text(
                json.dumps(
                    {
                        "version": "2.0.1",
                        "offline_optional_components": True,
                    }
                )
            )
            with self.assertRaises(ComponentError) as error:
                ensure_lego(self.settings(root))
            self.assertEqual(error.exception.code, "component_lock_missing")

    def test_component_directories_remain_service_readable_under_private_umask(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.signed_release(root, "2.0.1")
            settings = self.settings(root)
            settings.config_dir.mkdir(mode=0o750)
            settings.config_dir.chmod(0o750)
            private = settings.config_dir / "private"
            private.mkdir(mode=0o700)
            previous_umask = os.umask(0o077)
            try:
                paths = sync_release_components(settings)
                parents = {parent for path in paths.values() for parent in list(Path(path).parents)[:3]}
                for parent in parents:
                    self.assertEqual(parent.stat().st_mode & 0o777, 0o755)
                for parent in parents:
                    parent.chmod(0o700)
                sync_release_components(settings)
                for path in paths.values():
                    for parent in list(Path(path).parents)[:3]:
                        self.assertEqual(parent.stat().st_mode & 0o777, 0o755)
                self.assertEqual(settings.config_dir.stat().st_mode & 0o777, 0o750)
                self.assertEqual(private.stat().st_mode & 0o777, 0o700)
            finally:
                os.umask(previous_umask)

    def test_component_directory_symlink_is_rejected_without_changing_target(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.signed_release(root, "2.0.1")
            settings = self.settings(root)
            settings.config_dir.mkdir()
            private = root / "private"
            private.mkdir(mode=0o700)
            (settings.config_dir / "components").symlink_to(private, target_is_directory=True)
            with self.assertRaises(ComponentError) as error:
                ensure_lego(settings)
            self.assertEqual(error.exception.code, "component_install_unsafe")
            self.assertEqual(private.stat().st_mode & 0o777, 0o700)
            self.assertEqual(list(private.iterdir()), [])

    def test_unreadable_component_is_unavailable(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.signed_release(root, "2.0.1")
            with patch("cayvpn.components._verify_file", side_effect=PermissionError):
                self.assertIsNone(component_binary(self.settings(root), "lego"))


if __name__ == "__main__":
    unittest.main()
