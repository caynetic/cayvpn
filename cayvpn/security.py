from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import os
import secrets
import time
from urllib.parse import quote
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import bcrypt
from cryptography.fernet import Fernet


ENCRYPTED_PREFIX = "enc::"


def hash_password(value: str) -> str:
    return bcrypt.hashpw(value.encode(), bcrypt.gensalt()).decode()


def verify_password(value: str, hashed: str | None) -> bool:
    if not value or not hashed:
        return False
    try:
        return bcrypt.checkpw(value.encode(), hashed.encode())
    except (ValueError, TypeError):
        return False


class SecretBox:
    """Small envelope-encryption helper for local values and fixtures.

    Production provider and peer material is handled by the root-agent
    ``RootSecretStore``.  The helper remains for explicitly local,
    unprivileged test fixtures and compatibility with locally rendered values.
    """

    def __init__(self, secret: str | None = None):
        raw = (secret or os.environ.get("CAYVPN_DATA_SECRET") or "").strip()
        if not raw:
            raw = secrets.token_urlsafe(32)
        digest = hashlib.sha256(raw.encode()).digest()
        self._fernet = Fernet(base64.urlsafe_b64encode(digest))

    def encrypt(self, value: str | None) -> str | None:
        if value is None:
            return None
        if value.startswith(ENCRYPTED_PREFIX):
            return value
        return ENCRYPTED_PREFIX + self._fernet.encrypt(value.encode()).decode()

    def decrypt(self, value: str | None) -> str | None:
        if value is None:
            return None
        if not value.startswith(ENCRYPTED_PREFIX):
            return value
        token = value[len(ENCRYPTED_PREFIX):].encode()
        return self._fernet.decrypt(token).decode()


def json_safe(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def is_admin_network_address(address: str | None, network: str) -> bool:
    if not address:
        return False
    try:
        return ipaddress.ip_address(address) in ipaddress.ip_network(network, strict=False)
    except ValueError:
        return False


def is_network_address(address: str | None, *networks: str) -> bool:
    if not address:
        return False
    try:
        parsed = ipaddress.ip_address(address)
        return any(parsed in ipaddress.ip_network(network, strict=False) for network in networks)
    except ValueError:
        return False


def generate_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def totp_code(secret: str, at_time: int | None = None, digits: int = 6, period: int = 30) -> str:
    if not 6 <= digits <= 8 or not 15 <= period <= 120:
        raise ValueError("invalid TOTP parameters")
    normalized = "".join(secret.upper().split())
    try:
        padding = "=" * ((8 - len(normalized) % 8) % 8)
        key = base64.b32decode(normalized + padding, casefold=True)
    except (ValueError, TypeError) as exc:
        raise ValueError("invalid TOTP secret") from exc
    if len(key) < 16:
        raise ValueError("invalid TOTP secret")
    counter = int(at_time if at_time is not None else time.time()) // period
    digest = hmac.new(key, counter.to_bytes(8, "big"), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = int.from_bytes(digest[offset:offset + 4], "big") & 0x7FFFFFFF
    return str(value % (10**digits)).zfill(digits)


def verify_totp(secret: str, code: str, at_time: int | None = None, window: int = 1) -> bool:
    supplied = "".join(str(code or "").split())
    if len(supplied) != 6 or not supplied.isdigit() or not 0 <= window <= 2:
        return False
    now = int(at_time if at_time is not None else time.time())
    return any(hmac.compare_digest(supplied, totp_code(secret, now + offset * 30)) for offset in range(-window, window + 1))


def totp_uri(secret: str, account: str = "owner", issuer: str = "CayVPN") -> str:
    normalized = "".join(secret.upper().split())
    # Validate before placing the secret in the one-time provisioning URI.
    totp_code(normalized, 0)
    label = quote(f"{issuer}:{account}", safe="")
    return f"otpauth://totp/{label}?secret={normalized}&issuer={quote(issuer, safe='')}&algorithm=SHA1&digits=6&period=30"
    try:
        return ipaddress.ip_address(address) in ipaddress.ip_network(network, strict=False)
    except ValueError:
        return False


def now_epoch() -> int:
    return int(time.time())


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def token(length: int = 32) -> str:
    return secrets.token_urlsafe(length)


def write_secret_file(path: Path, content: str, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(path, flags, mode)
    try:
        # os.open applies its mode only when creating a new inode. Enforce the
        # requested mode on every rewrite so upgrades both tighten secrets and
        # make intentionally public artifacts readable when policy changes.
        os.fchmod(fd, mode)
        with os.fdopen(fd, "w") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        raise
