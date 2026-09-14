"""Exercise the signed bootstrap as a process, with local release transport."""

import hashlib
import io
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tarfile
import tempfile
import unittest


@unittest.skipUnless(sys.platform.startswith("linux"), "The bootstrap uses the supported Linux toolchain")
class BootstrapTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.assets = self.root / "assets"
        self.assets.mkdir()
        source = (Path(__file__).resolve().parents[1] / "bootstrap.sh").read_text()
        self.version = re.search(r'^VERSION="([^"]+)"', source, re.M)[1]
        self.marker = self.root / "installer-version"
        self.os_release = self.root / "os-release"
        self.os_release.write_text('ID=ubuntu\nVERSION_ID="24.04"\nVERSION="24.04.3 LTS (Noble Numbat)"\n')
        key = self.root / "fixture.key"
        public = self.assets / "cayvpn-release.pub"
        subprocess.run(["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(key)], check=True, capture_output=True)
        subprocess.run(["openssl", "pkey", "-in", str(key), "-pubout", "-out", str(public)], check=True, capture_output=True)
        payloads = {
            "install.sh": ('#!/bin/bash\nset -eu\nprintf "%s" "$CAYVPN_RELEASE_VERSION" > ' + shlex.quote(str(self.marker)) + '\n').encode(),
            "requirements.txt": b"# Test fixture\n",
        }
        archive = self.assets / f"cayvpn-{self.version}.tar.gz"
        with tarfile.open(archive, "w:gz") as output:
            for name, contents in payloads.items():
                info = tarfile.TarInfo(f"cayvpn-{self.version}/{name}")
                info.size = len(contents)
                info.mode = 0o755 if name.endswith(".sh") else 0o644
                output.addfile(info, io.BytesIO(contents))
        manifest = self.assets / f"cayvpn-{self.version}.sha256"
        manifest.write_text("".join(f"{hashlib.sha256(contents).hexdigest()}  {name}\n" for name, contents in payloads.items()))
        signature = self.assets / f"{manifest.name}.sig"
        subprocess.run(["openssl", "pkeyutl", "-sign", "-rawin", "-inkey", str(key), "-in", str(manifest), "-out", str(signature)], check=True, capture_output=True)
        self.metadata = {
            "tag_name": f"v{self.version}",
            "html_url": f"https://github.com/caynetic/cayvpn/releases/tag/v{self.version}",
            "draft": False, "prerelease": False, "immutable": True,
            "assets": [{
                "name": path.name, "state": "uploaded", "size": path.stat().st_size,
                "digest": f"sha256:{hashlib.sha256(path.read_bytes()).hexdigest()}",
                "browser_download_url": f"https://github.com/caynetic/cayvpn/releases/download/v{self.version}/{path.name}",
            } for path in (archive, manifest, signature, public)],
        }
        # Only transport, platform identity and the test key are replaced. The
        # shell flow, metadata, signature, inventory and extraction checks run.
        source = source.replace('[[ "${EUID}" -eq 0 ]]', '[[ 0 -eq 0 ]]')
        source = source.replace("/etc/os-release", shlex.quote(str(self.os_release)))
        source = re.sub(r'^PINNED_RELEASE_KEY_SHA256="[^"]+"', f'PINNED_RELEASE_KEY_SHA256="{hashlib.sha256(public.read_bytes()).hexdigest()}"', source, flags=re.M)
        self.script = self.root / "bootstrap.sh"
        self.script.write_text(source)
        binaries = self.root / "bin"
        binaries.mkdir()
        transport = f'''#!{sys.executable}
import pathlib, shutil, sys
args = sys.argv[1:]
url = next(value for value in args if value.startswith("https://"))
name = "release.json" if "/releases/tags/" in url else url.rsplit("/", 1)[1]
shutil.copyfile(pathlib.Path({str(self.assets)!r}) / name, args[args.index("-o") + 1])
'''
        for name, content in {"curl": transport, "dpkg": "#!/bin/sh\nprintf 'amd64\\n'\n", "update-ca-certificates": "#!/bin/sh\nexit 0\n"}.items():
            path = binaries / name
            path.write_text(content)
            path.chmod(0o755)
        self.environment = dict(os.environ, PATH=str(binaries) + os.pathsep + os.environ["PATH"])

    def run_bootstrap(self):
        (self.assets / "release.json").write_text(json.dumps(self.metadata))
        return subprocess.run(["bash", str(self.script)], env=self.environment, capture_output=True, text=True, timeout=30)

    def test_distro_version_cannot_replace_signed_release_version(self):
        result = self.run_bootstrap()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.marker.read_text(), self.version)

    def test_mutable_release_never_runs_installer(self):
        self.metadata["immutable"] = False
        result = self.run_bootstrap()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not published and immutable", result.stderr)
        self.assertFalse(self.marker.exists())

    def test_invalid_signature_never_runs_installer_even_with_matching_transport_digest(self):
        name = f"cayvpn-{self.version}.sha256.sig"
        path = self.assets / name
        path.write_bytes(b"\x00" * 64)
        asset = next(asset for asset in self.metadata["assets"] if asset["name"] == name)
        asset["digest"] = f"sha256:{hashlib.sha256(path.read_bytes()).hexdigest()}"
        result = self.run_bootstrap()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("release signature is invalid", result.stderr)
        self.assertFalse(self.marker.exists())

    def test_unsupported_os_never_runs_installer(self):
        self.os_release.write_text('ID=ubuntu\nVERSION_ID="22.04"\nVERSION="22.04 LTS"\n')
        result = self.run_bootstrap()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("requires Ubuntu 24.04", result.stderr)
        self.assertFalse(self.marker.exists())
