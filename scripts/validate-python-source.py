#!/usr/bin/env python3
"""Validate packaged Python source without importing it or writing bytecode."""

from __future__ import annotations

import os
import sys
import tokenize
from pathlib import Path


SKIPPED_AT_ANY_DEPTH = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "__pycache__",
}
SKIPPED_ONLY_AT_ROOT = {
    ".venv",
    "venv",
    "wheelhouse",
}
MAXIMUM_PYTHON_SOURCE_BYTES = 8 * 1024 * 1024


def validate(root: Path) -> int:
    root = root.resolve(strict=True)
    if not root.is_dir():
        raise ValueError("the source root is not a directory")

    checked = 0
    for directory, directory_names, file_names in os.walk(
        root, topdown=True, followlinks=False
    ):
        base = Path(directory)
        retained_directories: list[str] = []
        for name in sorted(directory_names):
            if name in SKIPPED_AT_ANY_DEPTH or (
                base == root and name in SKIPPED_ONLY_AT_ROOT
            ):
                continue
            path = base / name
            if path.is_symlink():
                raise ValueError(
                    f"source directory links are not allowed: {path.relative_to(root)}"
                )
            retained_directories.append(name)
        directory_names[:] = retained_directories

        for name in sorted(file_names):
            if not name.endswith(".py"):
                continue
            path = base / name
            relative = path.relative_to(root)
            if path.is_symlink() or not path.is_file():
                raise ValueError(f"unsupported Python source entry: {relative}")
            if path.stat().st_size > MAXIMUM_PYTHON_SOURCE_BYTES:
                raise ValueError(f"Python source file is unexpectedly large: {relative}")
            try:
                with tokenize.open(path) as source_file:
                    source = source_file.read()
                compile(source, str(relative), "exec", dont_inherit=True)
            except (OSError, SyntaxError, UnicodeError, ValueError) as exc:
                raise ValueError(
                    f"Python source validation failed for {relative}: {exc}"
                ) from exc
            checked += 1

    if checked == 0:
        raise ValueError("the release contains no Python source files")
    return checked


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(f"Usage: {Path(argv[0]).name} <source-root>", file=sys.stderr)
        return 2
    try:
        checked = validate(Path(argv[1]))
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(f"Validated {checked} Python source files.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
