#!/usr/bin/env python3
"""Make generated virtual-environment launchers safe after release staging."""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

MAX_RELOCATABLE_FILE_BYTES = 1024 * 1024


def _normalized_absolute(path: Path, *, must_exist: bool) -> Path:
    if not path.is_absolute():
        raise ValueError("virtual-environment relocation paths must be absolute")
    normalized = Path(os.path.normpath(path))
    if any(character in str(normalized) for character in ("\n", "\r")):
        raise ValueError("virtual-environment relocation paths contain unsafe characters")
    if must_exist:
        # Launchers retain the lexical path passed to venv, which can differ
        # from its resolved spelling on platforms with paths such as /var.
        normalized.resolve(strict=True)
    return normalized


def relocate_virtual_environment(
    venv: Path,
    old_release: Path,
    new_release: Path,
) -> int:
    old_release = _normalized_absolute(old_release, must_exist=True)
    new_release = _normalized_absolute(new_release, must_exist=False)
    venv = _normalized_absolute(venv, must_exist=True)
    if venv != old_release / ".venv":
        raise ValueError("the virtual environment is outside the staged release")
    if old_release == new_release:
        raise ValueError("the staged and final release paths must be different")
    if new_release.exists() or new_release.is_symlink():
        raise ValueError("the final release path already exists")

    bin_dir = venv / "bin"
    if not bin_dir.is_dir() or bin_dir.is_symlink():
        raise ValueError("the virtual environment has no safe bin directory")

    candidates = [venv / "pyvenv.cfg", *sorted(bin_dir.iterdir())]
    old_prefix = os.fsencode(str(old_release))
    new_prefix = os.fsencode(str(new_release))
    changed = 0
    for path in candidates:
        if path.is_symlink() or not path.is_file():
            continue
        file_stat = path.stat()
        if file_stat.st_size > MAX_RELOCATABLE_FILE_BYTES:
            continue
        content = path.read_bytes()
        if old_prefix not in content:
            continue
        if b"\0" in content:
            raise ValueError(f"refusing to rewrite a binary virtual-environment file: {path.name}")
        rewritten = content.replace(old_prefix, new_prefix)
        temporary = path.with_name(f".{path.name}.cayvpn-relocated-{os.getpid()}")
        try:
            with temporary.open("xb") as output:
                output.write(rewritten)
                output.flush()
                os.fsync(output.fileno())
            os.chmod(temporary, stat.S_IMODE(file_stat.st_mode))
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)
        changed += 1

    if changed == 0:
        raise ValueError("the virtual environment contained no staged-path launchers")

    for path in candidates:
        if path.is_symlink() or not path.is_file():
            continue
        if path.stat().st_size <= MAX_RELOCATABLE_FILE_BYTES and old_prefix in path.read_bytes():
            raise ValueError(f"a staged virtual-environment path remains in {path.name}")
    return changed


def main(argv: list[str]) -> int:
    if len(argv) != 4:
        print(
            f"Usage: {Path(argv[0]).name} <venv> <staged-release> <final-release>",
            file=sys.stderr,
        )
        return 2
    try:
        changed = relocate_virtual_environment(
            Path(argv[1]),
            Path(argv[2]),
            Path(argv[3]),
        )
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(f"Relocated {changed} virtual-environment launchers.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
