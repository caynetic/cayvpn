from __future__ import annotations

import os
import secrets
import uuid
from pathlib import Path

from .config import Settings
from .security import SecretBox


class SecretStoreError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


class RootSecretStore:
    """Root-agent-owned encrypted values stored outside SQLite."""

    def __init__(self, settings: Settings):
        self.settings = settings
        self.key_path = settings.secret_key_path
        self.directory = settings.config_dir / "secrets"
        self.directory.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.directory, 0o700)
        except OSError:
            pass
        if not self.key_path.exists():
            self.key_path.parent.mkdir(parents=True, exist_ok=True)
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            descriptor = os.open(self.key_path, flags, 0o600)
            try:
                os.write(descriptor, secrets.token_urlsafe(48).encode())
            finally:
                os.close(descriptor)
        try:
            os.chmod(self.key_path, 0o600)
        except OSError:
            pass
        key = self.key_path.read_text().strip()
        if not key:
            raise SecretStoreError("secret_key_missing", "The root-agent secret key is empty")
        self.box = SecretBox(key)

    def _path(self, reference: str) -> Path:
        if not reference.startswith("ref::"):
            raise SecretStoreError("invalid_secret_reference", "Invalid secret reference")
        identifier = reference[5:]
        try:
            uuid.UUID(identifier)
        except ValueError as exc:
            raise SecretStoreError("invalid_secret_reference", "Invalid secret reference") from exc
        path = (self.directory / f"{identifier}.secret").resolve()
        if path.parent != self.directory.resolve():
            raise SecretStoreError("invalid_secret_reference", "Invalid secret reference")
        return path

    def store(self, value: str) -> str:
        if not isinstance(value, str) or not value or len(value) > 256 * 1024:
            raise SecretStoreError("invalid_secret", "Secret value is empty or too large")
        reference = f"ref::{uuid.uuid4()}"
        path = self._path(reference)
        temporary = path.with_name(f".{path.name}.new")
        temporary.write_text(self.box.encrypt(value) or "")
        temporary.chmod(0o600)
        os.replace(temporary, path)
        return reference

    def reveal(self, reference: str) -> str:
        path = self._path(reference)
        if not path.is_file():
            raise SecretStoreError("secret_not_found", "Secret reference was not found")
        value = self.box.decrypt(path.read_text().strip())
        if value is None:
            raise SecretStoreError("secret_empty", "Secret reference has no value")
        return value

    def delete(self, reference: str) -> None:
        path = self._path(reference)
        try:
            path.unlink()
        except FileNotFoundError:
            pass
