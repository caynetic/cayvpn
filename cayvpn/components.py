from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import shutil
import stat
from pathlib import Path

from .config import Settings


class ComponentError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


COMPONENT_NAMES = (
    "awg",
    "awg-quick",
    "amneziawg-go",
    "hev-socks5-tunnel",
    "lego",
)

_COMPONENT_GROUPS = {
    "awg": "amneziawg",
    "awg-quick": "amneziawg",
    "amneziawg-go": "amneziawg",
    "hev-socks5-tunnel": "hev-socks5-tunnel",
    "lego": "lego",
}

_LEGACY_ENVIRONMENT = {
    "awg": ("CAYVPN_AMNEZIA_COMPONENT_DIR", "CAYVPN_AMNEZIAWG_TOOLS_SHA256"),
    "awg-quick": ("CAYVPN_AMNEZIA_COMPONENT_DIR", "CAYVPN_AMNEZIAWG_QUICK_SHA256"),
    "amneziawg-go": ("CAYVPN_AMNEZIA_COMPONENT_DIR", "CAYVPN_AMNEZIAWG_GO_SHA256"),
    "hev-socks5-tunnel": ("CAYVPN_SOCKS5_COMPONENT_DIR", "CAYVPN_SOCKS5_TUNNEL_SHA256"),
    "lego": ("CAYVPN_LEGO_COMPONENT_DIR", "CAYVPN_LEGO_SHA256"),
}


def _architecture() -> str:
    architecture = {"x86_64": "amd64", "aarch64": "arm64"}.get(
        os.uname().machine, os.uname().machine
    )
    if architecture not in {"amd64", "arm64"}:
        raise ComponentError(
            "component_architecture_unsupported",
            "This CayVPN release does not contain native components for the server architecture",
        )
    return architecture


def _valid_sha256(value: object) -> bool:
    return bool(
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdefABCDEF" for character in value)
    )


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _installed_path(settings: Settings, name: str, architecture: str | None = None) -> Path:
    architecture = architecture or _architecture()
    return settings.config_dir / "components" / _COMPONENT_GROUPS[name] / architecture / name


def _release_root(settings: Settings, release_root: Path | None = None) -> Path:
    root = Path(release_root or settings.active_release)
    try:
        return root.resolve(strict=True)
    except OSError as exc:
        raise ComponentError(
            "component_release_missing",
            "The active signed CayVPN release is unavailable",
        ) from exc


def _load_component_lock(
    settings: Settings, release_root: Path | None = None
) -> tuple[Path, dict[str, dict[str, str]]]:
    root = _release_root(settings, release_root)
    release_path = root / "release.json"
    lock_path = root / "components.lock.json"
    if (
        not lock_path.is_file()
        or lock_path.is_symlink()
        or not release_path.is_file()
        or release_path.is_symlink()
    ):
        raise ComponentError(
            "component_lock_missing",
            "The signed CayVPN release is missing its native-component lock",
        )
    try:
        if lock_path.stat().st_size > 128 * 1024:
            raise ValueError("lock is too large")
        document = json.loads(lock_path.read_text(encoding="utf-8"))
        if release_path.stat().st_size > 128 * 1024:
            raise ValueError("release metadata is too large")
        release = json.loads(release_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        raise ComponentError(
            "component_lock_invalid",
            "The signed CayVPN native-component lock is invalid",
        ) from exc
    if (
        not isinstance(document, dict)
        or set(document) != {"schema_version", "release_version", "architectures"}
        or document.get("schema_version") != 1
        or not isinstance(document.get("release_version"), str)
        or not document["release_version"]
        or not isinstance(document.get("architectures"), dict)
        or set(document["architectures"]) != {"amd64", "arm64"}
        or not isinstance(release, dict)
        or release.get("version") != document.get("release_version")
        or release.get("offline_optional_components") is not True
    ):
        raise ComponentError(
            "component_lock_invalid",
            "The signed CayVPN native-component lock has an unsupported format",
        )

    normalized: dict[str, dict[str, str]] = {}
    for architecture in ("amd64", "arm64"):
        entries = document["architectures"].get(architecture)
        if not isinstance(entries, dict) or set(entries) != set(COMPONENT_NAMES):
            raise ComponentError(
                "component_lock_invalid",
                "The signed CayVPN native-component lock has an incomplete inventory",
            )
        normalized[architecture] = {}
        for name in COMPONENT_NAMES:
            entry = entries.get(name)
            expected_path = f"components/{architecture}/{name}"
            if (
                not isinstance(entry, dict)
                or set(entry) != {"path", "sha256"}
                or entry.get("path") != expected_path
                or not _valid_sha256(entry.get("sha256"))
            ):
                raise ComponentError(
                    "component_lock_invalid",
                    "The signed CayVPN native-component lock contains an unsafe entry",
                )
            normalized[architecture][name] = entry["sha256"].lower()
    return root, normalized


def _legacy_spec(settings: Settings, name: str) -> tuple[Path, str] | None:
    # This path exists only for explicit source-tree development. Signed
    # installs never persist CAYVPN_ALLOW_UNVERIFIED_LOCAL and therefore
    # cannot silently fall back to self-supplied component checksums.
    if settings.apply_network and os.environ.get("CAYVPN_ALLOW_UNVERIFIED_LOCAL") != "1":
        return None
    directory_name, checksum_name = _LEGACY_ENVIRONMENT[name]
    directory = os.environ.get(directory_name, "")
    checksum = os.environ.get(checksum_name, "")
    if not directory or not _valid_sha256(checksum):
        return None
    return Path(directory).resolve() / name, checksum.lower()


def _component_spec(
    settings: Settings, name: str, release_root: Path | None = None
) -> tuple[Path, str]:
    if name not in COMPONENT_NAMES:
        raise ComponentError("component_unknown", "The requested native component is not supported")
    try:
        root, lock = _load_component_lock(settings, release_root)
    except ComponentError as exc:
        legacy = _legacy_spec(settings, name) if release_root is None else None
        if legacy is not None:
            return legacy
        raise exc
    architecture = _architecture()
    source = root / "components" / architecture / name
    if source.is_symlink() or not source.is_file():
        raise ComponentError(
            "component_source_missing",
            "A native component listed by the signed CayVPN release is missing",
        )
    return source, lock[architecture][name]


def _verify_file(path: Path, expected_sha256: str, *, installed: bool = False) -> None:
    if path.is_symlink() or not path.is_file():
        code = "component_source_missing" if not installed else "component_install_missing"
        raise ComponentError(code, "The native component file is missing or unsafe")
    if not _valid_sha256(expected_sha256):
        raise ComponentError(
            "component_checksum_missing", "A trusted 64-character component checksum is required"
        )
    if not hmac.compare_digest(_sha256(path), expected_sha256.lower()):
        raise ComponentError(
            "component_checksum_failed",
            "The installed native component does not match the signed CayVPN release",
        )


def _copy_verified(source: Path, destination: Path, expected_sha256: str) -> None:
    _verify_file(source, expected_sha256)
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.is_file() and not destination.is_symlink():
        try:
            _verify_file(destination, expected_sha256, installed=True)
        except ComponentError:
            pass
        else:
            destination.chmod(0o755)
            return

    temporary = destination.with_name(
        f".{destination.name}.{os.getpid()}.{secrets.token_hex(6)}.new"
    )
    descriptor = -1
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o700)
        with os.fdopen(descriptor, "wb", closefd=True) as output, source.open("rb") as input_file:
            descriptor = -1
            shutil.copyfileobj(input_file, output, length=1024 * 1024)
            output.flush()
            os.fsync(output.fileno())
        temporary.chmod(0o755)
        _verify_file(temporary, expected_sha256, installed=True)
        os.replace(temporary, destination)
        directory_fd = os.open(destination.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)


def _prepare_component_directories(settings: Settings, name: str, architecture: str) -> None:
    # These folders contain public release binaries. The installer deliberately
    # uses umask 077 for secrets, but the web service must traverse this subtree.
    # Do not change permissions on the configuration directory or its other data.
    settings.config_dir.mkdir(parents=True, exist_ok=True)
    directory = settings.config_dir
    for part in ("components", _COMPONENT_GROUPS[name], architecture):
        directory = directory / part
        directory.mkdir(exist_ok=True)
        if not stat.S_ISDIR(directory.lstat().st_mode):
            raise ComponentError(
                "component_install_unsafe", "The native component directory is unsafe"
            )
        directory.chmod(0o755)


def _ensure_names(
    settings: Settings, names: tuple[str, ...], release_root: Path | None = None
) -> dict[str, str]:
    if not settings.apply_network and release_root is None:
        try:
            _load_component_lock(settings)
        except ComponentError:
            if not all(_legacy_spec(settings, name) for name in names):
                return {}
    architecture = _architecture()
    paths: dict[str, str] = {}
    for name in names:
        source, expected_sha256 = _component_spec(settings, name, release_root)
        destination = _installed_path(settings, name, architecture)
        _prepare_component_directories(settings, name, architecture)
        _copy_verified(source, destination, expected_sha256)
        paths[name] = str(destination)
    return paths


def validate_release_components(
    settings: Settings, release_root: Path | None = None
) -> dict[str, str]:
    """Verify the complete signed native bundle without installing it."""

    verified: dict[str, str] = {}
    for name in COMPONENT_NAMES:
        source, expected_sha256 = _component_spec(settings, name, release_root)
        _verify_file(source, expected_sha256)
        verified[name] = expected_sha256
    return verified


def sync_release_components(settings: Settings, release_root: Path | None = None) -> dict[str, str]:
    """Atomically synchronize every native helper from a verified release.

    Update activation calls this while services are stopped and after mutable
    state has been snapshotted. A failed copy therefore aborts activation, and
    rollback restores the previous configuration directory and components.
    """

    return _ensure_names(settings, COMPONENT_NAMES, release_root)


def component_binary(settings: Settings, name: str) -> str | None:
    # Standard WireGuard tools remain distribution-managed. Optional native
    # helpers are executable only when they match the currently active signed
    # release (or an explicitly unverified local-development fixture).
    if name not in COMPONENT_NAMES:
        return shutil.which(name)
    try:
        _source, expected_sha256 = _component_spec(settings, name)
        candidate = _installed_path(settings, name)
        _verify_file(candidate, expected_sha256, installed=True)
    except (ComponentError, OSError):
        return None
    if not os.access(candidate, os.X_OK):
        return None
    return str(candidate)


def ensure_amneziawg(settings: Settings) -> dict:
    paths = _ensure_names(settings, ("awg", "awg-quick", "amneziawg-go"))
    if not paths:
        return {"component": "amneziawg", "state": "planned", "paths": {}}
    return {
        "component": "amneziawg",
        "state": "installed",
        "paths": {
            "awg": paths["awg"],
            "awg_quick": paths["awg-quick"],
            "amneziawg_go": paths["amneziawg-go"],
        },
    }


def ensure_socks5_tunnel(settings: Settings) -> dict:
    paths = _ensure_names(settings, ("hev-socks5-tunnel",))
    if not paths:
        return {"component": "socks5", "state": "planned", "paths": {}}
    return {
        "component": "socks5",
        "state": "installed",
        "paths": {"tunnel": paths["hev-socks5-tunnel"]},
    }


def ensure_lego(settings: Settings) -> dict:
    paths = _ensure_names(settings, ("lego",))
    if not paths:
        return {"component": "lego", "state": "planned", "paths": {}}
    return {
        "component": "lego",
        "state": "installed",
        "paths": {"lego": paths["lego"]},
    }
