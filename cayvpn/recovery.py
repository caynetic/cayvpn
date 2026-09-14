from __future__ import annotations

import argparse
import os
import secrets
from pathlib import Path

from .backup import _age_encrypt


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def protect_file(source: Path, destination: Path, passphrase: str) -> None:
    if len(passphrase) < 12:
        raise ValueError("Recovery passphrase must be at least 12 characters")
    if source.is_symlink() or not source.is_file():
        raise ValueError("Recovery source file is missing or unsafe")
    if destination.is_symlink():
        raise ValueError("Recovery destination is unsafe")
    payload = _age_encrypt(source.read_bytes(), passphrase)
    if payload is None:
        raise RuntimeError("age is required to protect installer recovery material")

    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(
        f".{destination.name}.{os.getpid()}.{secrets.token_hex(6)}.new"
    )
    descriptor = -1
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as output:
            descriptor = -1
            output.write(b"CAYVPN-AGE-1\n" + payload)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, destination)
        _fsync_directory(destination.parent)

        # Remove the plaintext only after the encrypted replacement and its
        # directory entry are durable. Persist that unlink as a separate step.
        source.unlink()
        _fsync_directory(source.parent)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="cayvpn-recovery")
    parser.add_argument("action", choices=["protect-ca-key"])
    parser.add_argument("--source", required=True)
    parser.add_argument("--destination", required=True)
    args = parser.parse_args(argv)
    passphrase = os.environ.get("CAYVPN_RECOVERY_PASSPHRASE", "")
    protect_file(Path(args.source), Path(args.destination), passphrase)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
