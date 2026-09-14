from __future__ import annotations

import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cayvpn.recovery import protect_file


class RecoveryFileTests(unittest.TestCase):
    def test_encrypted_destination_is_flushed_before_plaintext_is_removed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "plain" / "ca.key"
            destination = root / "protected" / "ca.key.age"
            source.parent.mkdir()
            source.write_bytes(b"private-ca-key")
            events: list[tuple[str, Path]] = []
            original_replace = os.replace
            original_unlink = Path.unlink

            def replace(source_path, destination_path):
                events.append(("replace", Path(destination_path)))
                return original_replace(source_path, destination_path)

            def fsync_directory(path):
                events.append(("fsync-directory", Path(path)))

            def unlink(path, *args, **kwargs):
                events.append(("unlink", Path(path)))
                return original_unlink(path, *args, **kwargs)

            with (
                patch("cayvpn.recovery._age_encrypt", return_value=b"encrypted"),
                patch("cayvpn.recovery.os.replace", side_effect=replace),
                patch("cayvpn.recovery._fsync_directory", side_effect=fsync_directory),
                patch.object(Path, "unlink", autospec=True, side_effect=unlink),
                patch("cayvpn.recovery.os.fsync", wraps=os.fsync) as fsync_file,
            ):
                protect_file(source, destination, "twelve-chars!")

            self.assertFalse(source.exists())
            self.assertEqual(destination.read_bytes(), b"CAYVPN-AGE-1\nencrypted")
            self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o600)
            fsync_file.assert_called()
            self.assertLess(
                events.index(("replace", destination)),
                events.index(("fsync-directory", destination.parent)),
            )
            self.assertLess(
                events.index(("fsync-directory", destination.parent)),
                events.index(("unlink", source)),
            )
            self.assertLess(
                events.index(("unlink", source)),
                events.index(("fsync-directory", source.parent)),
            )

    def test_plaintext_remains_if_encrypted_file_flush_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "ca.key"
            destination = root / "protected" / "ca.key.age"
            source.write_bytes(b"private-ca-key")

            with (
                patch("cayvpn.recovery._age_encrypt", return_value=b"encrypted"),
                patch("cayvpn.recovery.os.fsync", side_effect=OSError("disk failure")),
            ):
                with self.assertRaisesRegex(OSError, "disk failure"):
                    protect_file(source, destination, "twelve-chars!")

            self.assertTrue(source.exists())
            self.assertFalse(destination.exists())
            self.assertEqual(list(destination.parent.glob(".*.new")), [])

    def test_plaintext_remains_if_destination_directory_flush_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "ca.key"
            destination = root / "protected" / "ca.key.age"
            source.write_bytes(b"private-ca-key")

            with (
                patch("cayvpn.recovery._age_encrypt", return_value=b"encrypted"),
                patch(
                    "cayvpn.recovery._fsync_directory",
                    side_effect=OSError("directory flush failure"),
                ),
            ):
                with self.assertRaisesRegex(OSError, "directory flush failure"):
                    protect_file(source, destination, "twelve-chars!")

            self.assertTrue(source.exists())
            self.assertEqual(destination.read_bytes(), b"CAYVPN-AGE-1\nencrypted")


if __name__ == "__main__":
    unittest.main()
