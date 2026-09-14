from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path


COMPONENT_NAMES = (
    "awg",
    "awg-quick",
    "amneziawg-go",
    "hev-socks5-tunnel",
    "lego",
)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class ReleaseArtifactValidatorTests(unittest.TestCase):
    def fixture(self, root: Path) -> tuple[Path, Path, Path, Path]:
        requirements = root / "requirements.lock"
        requirements.write_text("example==1.0\n")
        wheelhouse = root / "wheelhouse"
        for architecture in ("amd64", "arm64"):
            directory = wheelhouse / architecture
            directory.mkdir(parents=True)
            wheel = directory / "example-1.0-py3-none-any.whl"
            with zipfile.ZipFile(wheel, "w") as archive:
                archive.writestr(
                    "example-1.0.dist-info/METADATA",
                    "Metadata-Version: 2.1\nName: example\nVersion: 1.0\n",
                )

        components = root / "components"
        metadata = {
            "schema_version": 1,
            "amneziawg_go": {
                "version": "v1",
                "source": "https://example.invalid/amneziawg-go",
                "commit": "a" * 40,
            },
            "amneziawg_tools": {
                "version": "v1",
                "source": "https://example.invalid/amneziawg-tools",
                "commit": "b" * 40,
            },
            "hev_socks5_tunnel": {
                "version": "v1",
                "source": "https://example.invalid/hev",
                "commit": "c" * 40,
            },
            "lego": {
                "version": "v1",
                "source": "https://example.invalid/lego",
                "commit": "d" * 40,
            },
        }
        ordinary = {
            "BUILD-METADATA.json": json.dumps(metadata, sort_keys=True).encode(),
            "THIRD_PARTY_NOTICES.md": b"reviewed notices\n",
            "licenses/amneziawg-go-LICENSE": b"license\n",
            "licenses/amneziawg-tools-COPYING": b"copying\n",
            "licenses/hev-socks5-tunnel-LICENSE": b"license\n",
            "licenses/lego-LICENSE": b"license\n",
            "source/amneziawg-tools-source.tar.gz": b"reviewed source archive\n",
        }
        for architecture in ("amd64", "arm64"):
            for name in COMPONENT_NAMES:
                ordinary[f"{architecture}/{name}"] = (
                    f"{architecture}:{name}:reviewed".encode()
                )
        for relative, payload in ordinary.items():
            path = components / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
        sums = "".join(
            f"{sha256(components / relative)}  {relative}\n"
            for relative in sorted(ordinary)
        )
        (components / "SHA256SUMS").write_text(sums)

        lock = {
            "schema_version": 1,
            "release_version": "2.0.1",
            "python_version": "3.12",
            "requirements_sha256": sha256(requirements),
            "wheelhouses": {
                architecture: {
                    "files": {
                        wheel.name: sha256(wheel)
                        for wheel in (wheelhouse / architecture).glob("*.whl")
                    }
                }
                for architecture in ("amd64", "arm64")
            },
            "components": {
                "files": {
                    path.relative_to(components).as_posix(): sha256(path)
                    for path in components.rglob("*")
                    if path.is_file()
                },
                "build_metadata": metadata,
            },
        }
        lock_path = root / "2.0.1.json"
        lock_path.write_text(json.dumps(lock, indent=2, sort_keys=True))
        return lock_path, requirements, wheelhouse, components

    def run_validator(
        self,
        lock: Path,
        requirements: Path,
        wheelhouse: Path,
        components: Path,
        output: Path | None = None,
    ) -> subprocess.CompletedProcess[str]:
        root = Path(__file__).resolve().parents[1]
        command = [
            sys.executable,
            str(root / "scripts" / "validate-release-artifacts.py"),
            "--lock",
            str(lock),
            "--requirements",
            str(requirements),
            "--wheelhouse",
            str(wheelhouse),
            "--components",
            str(components),
            "--release-version",
            "2.0.1",
        ]
        if output is not None:
            command.extend(("--write-component-lock", str(output)))
        return subprocess.run(command, capture_output=True, text=True, check=False)

    def test_reviewed_lock_validates_and_writes_runtime_component_lock(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lock, requirements, wheelhouse, components = self.fixture(root)
            output = root / "components.lock.json"

            result = self.run_validator(
                lock, requirements, wheelhouse, components, output
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            runtime = json.loads(output.read_text())
            self.assertEqual(runtime["release_version"], "2.0.1")
            self.assertEqual(
                set(runtime["architectures"]["amd64"]),
                set(COMPONENT_NAMES),
            )
            self.assertEqual(
                runtime["architectures"]["arm64"]["lego"]["path"],
                "components/arm64/lego",
            )

    def test_artifact_repacked_with_new_adjacent_checksums_still_fails_reviewed_lock(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lock, requirements, wheelhouse, components = self.fixture(root)
            wheel = next((wheelhouse / "amd64").glob("*.whl"))
            wheel.write_bytes(b"attacker-repacked-wheel")
            (wheelhouse / "SHA256SUMS").write_text(
                f"{sha256(wheel)}  amd64/{wheel.name}\n"
            )

            result = self.run_validator(
                lock, requirements, wheelhouse, components
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("reviewed SHA-256", result.stderr)

    def test_changed_component_provenance_is_rejected_even_with_rewritten_bundle_checksums(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lock, requirements, wheelhouse, components = self.fixture(root)
            metadata_path = components / "BUILD-METADATA.json"
            metadata = json.loads(metadata_path.read_text())
            metadata["lego"]["commit"] = "e" * 40
            metadata_path.write_text(json.dumps(metadata, sort_keys=True))
            files = [
                path
                for path in components.rglob("*")
                if path.is_file() and path.name != "SHA256SUMS"
            ]
            (components / "SHA256SUMS").write_text(
                "".join(
                    f"{sha256(path)}  {path.relative_to(components).as_posix()}\n"
                    for path in sorted(files)
                )
            )

            result = self.run_validator(
                lock, requirements, wheelhouse, components
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("reviewed SHA-256", result.stderr)

    def replace_fixture_wheel(self, lock, wheelhouse, architecture, filename):
        original = next((wheelhouse / architecture).glob("*.whl"))
        replacement = original.with_name(filename)
        original.rename(replacement)
        document = json.loads(lock.read_text())
        document["wheelhouses"][architecture]["files"] = {filename: sha256(replacement)}
        lock.write_text(json.dumps(document))

    def test_reviewed_hash_cannot_authorize_a_wheel_for_an_incompatible_runtime(self):
        cases = [
            ("arm64", "cp313-cp313-manylinux_2_17_aarch64"),
            ("arm64", "cp313-abi3-manylinux_2_17_aarch64"),
            ("arm64", "cp312-cp312-manylinux_2_99_aarch64"),
            ("arm64", "cp312-cp312-musllinux_1_2_aarch64"),
            ("arm64", "cp312-cp312-macosx_11_0_arm64"),
            ("amd64", "cp312-cp312-win_amd64"),
            ("amd64", "cp311-cp311-manylinux_2_17_x86_64"),
            ("amd64", "cp312-cp312-manylinux_2_17_aarch64"),
            ("amd64", "py2-none-any"),
            ("amd64", "py3-cp313-any"),
            ("amd64", "cp312-cp312-manylinux_2_17_x86_64_invalid"),
        ]
        for architecture, tags in cases:
            with self.subTest(tags=tags), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                lock, requirements, wheelhouse, components = self.fixture(root)
                self.replace_fixture_wheel(lock, wheelhouse, architecture, f"example-1.0-{tags}.whl")
                output = root / "components.lock.json"
                result = self.run_validator(lock, requirements, wheelhouse, components, output)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("not compatible with Ubuntu 24.04 CPython 3.12", result.stderr)
                self.assertFalse(output.exists())

    def test_supported_cpython_stable_abi_and_compressed_tags_remain_accepted(self):
        cases = [
            ("arm64", "cp312-cp312-manylinux_2_39_aarch64"),
            ("arm64", "cp39-abi3-manylinux_2_17_aarch64.manylinux2014_aarch64"),
            ("amd64", "cp37-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64"),
            ("amd64", "cp312-cp312-manylinux2010_x86_64"),
            ("amd64", "py2.py3-none-any"),
        ]
        for architecture, tags in cases:
            with self.subTest(tags=tags), tempfile.TemporaryDirectory() as directory:
                lock, requirements, wheelhouse, components = self.fixture(Path(directory))
                self.replace_fixture_wheel(lock, wheelhouse, architecture, f"example-1.0-{tags}.whl")
                result = self.run_validator(lock, requirements, wheelhouse, components)
                self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
