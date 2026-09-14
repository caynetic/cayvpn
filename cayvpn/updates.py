from __future__ import annotations

import hashlib
import hmac
import fcntl
import ipaddress
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import tarfile
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
from typing import Callable
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from .components import ComponentError, validate_release_components
from .config import Settings


MAX_API_BYTES = 2 * 1024 * 1024
MAX_RELEASE_BYTES = 512 * 1024 * 1024
MAX_ARCHIVE_FILES = 20_000
MAX_RELEASE_NOTES = 8_000
MIN_STAGE_FREE_BYTES = 768 * 1024 * 1024
DEFAULT_RELEASE_HISTORY = 2
DEFAULT_SNAPSHOT_HISTORY = 3
SEMVER = re.compile(
    r"^v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$"
)
SHA256_LINE = re.compile(r"^([0-9a-fA-F]{64})[ \t]+\*?([A-Za-z0-9._/-]+)$")
RELEASE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$")


class UpdateError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class Version:
    major: int
    minor: int
    patch: int
    prerelease: tuple[str, ...] = ()
    build: tuple[str, ...] = ()

    @classmethod
    def parse(cls, value: str) -> "Version":
        match = SEMVER.fullmatch((value or "").strip())
        if not match:
            raise UpdateError("invalid_release", "The release version is not valid semantic versioning.")
        prerelease = tuple((match.group(4) or "").split(".")) if match.group(4) else ()
        for item in prerelease:
            if item.isdigit() and len(item) > 1 and item.startswith("0"):
                raise UpdateError("invalid_release", "The release has an invalid pre-release identifier.")
        build = tuple((match.group(5) or "").split(".")) if match.group(5) else ()
        return cls(int(match.group(1)), int(match.group(2)), int(match.group(3)), prerelease, build)

    def precedence(self) -> tuple:
        if not self.prerelease:
            pre = ((2, ""),)
        else:
            pre = tuple((0, int(item)) if item.isdigit() else (1, item) for item in self.prerelease)
        return self.major, self.minor, self.patch, pre

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Version):
            return NotImplemented
        return self.precedence() < other.precedence()

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Version):
            return False
        return self.precedence() == other.precedence()

    def __le__(self, other: object) -> bool:
        if not isinstance(other, Version):
            return NotImplemented
        return self == other or self < other

    def __str__(self) -> str:
        value = f"{self.major}.{self.minor}.{self.patch}"
        if self.prerelease:
            value += "-" + ".".join(self.prerelease)
        if self.build:
            value += "+" + ".".join(self.build)
        return value


@dataclass(frozen=True)
class ReleaseAsset:
    name: str
    url: str
    size: int
    digest: str | None


@dataclass(frozen=True)
class ReleaseInfo:
    version: str
    tag: str
    title: str
    notes: str
    page_url: str
    published_at: str
    immutable: bool
    assets: dict[str, ReleaseAsset]

    def public_dict(self, current_release: str | None = None) -> dict:
        available = None
        if current_release:
            try:
                available = Version.parse(current_release) < Version.parse(self.version)
            except UpdateError:
                available = current_release != self.version
        return {
            "version": self.version,
            "tag": self.tag,
            "title": self.title,
            "notes": self.notes,
            "page_url": self.page_url,
            "published_at": self.published_at,
            "immutable": self.immutable,
            "available": available,
        }


def _atomic_json(path: Path, payload: dict, mode: int = 0o640) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}-{os.getpid()}-{os.urandom(4).hex()}")
    data = (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode()
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary, mode)
        if os.geteuid() == 0:
            # The root updater and unprivileged worker share status through
            # the service-owned state directory. Preserve that read group.
            os.chown(temporary, -1, path.parent.stat().st_gid)
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if temporary.exists():
            temporary.unlink()


def read_update_state(path: Path) -> dict:
    try:
        value = json.loads(path.read_text())
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError, TypeError):
        return {}


def write_update_state(settings: Settings, state: str, **details) -> dict:
    payload = {
        "schema_version": 1,
        "state": state,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    payload.update({key: value for key, value in details.items() if value is not None})
    _atomic_json(settings.update_state_path, payload)
    return payload


def prune_update_history(
    settings: Settings,
    keep_releases: int = DEFAULT_RELEASE_HISTORY,
    keep_snapshots: int = DEFAULT_SNAPSHOT_HISTORY,
) -> dict:
    """Remove only old, versioned update artifacts while preserving recovery.

    The active release, the explicitly recorded last-good release, a staged
    release, the journal's current snapshot, and the newest history entries
    are always retained. Unknown names, symlinks, incomplete snapshots, and
    paths outside the expected roots are left untouched for SSH inspection.
    Cleanup is deliberately best-effort after a successful update; failure to
    delete old history must never make a working release unhealthy.
    """
    keep_releases = max(0, int(keep_releases))
    keep_snapshots = max(1, int(keep_snapshots))
    removed_releases: list[str] = []
    removed_snapshots: list[str] = []
    warnings: list[str] = []

    release_root = settings.release_dir.resolve()
    active = None
    if settings.active_release.is_symlink():
        try:
            active = settings.active_release.resolve(strict=True)
        except OSError:
            warnings.append("active release could not be resolved")
    last_good = None
    last_good_path = settings.state_dir / "last-good-release"
    if last_good_path.is_file():
        try:
            raw_last_good = Path(last_good_path.read_text().strip())
            if not raw_last_good.is_absolute():
                raw_last_good = release_root / raw_last_good
            last_good = raw_last_good.resolve()
        except OSError:
            warnings.append("last-good release marker could not be read")
    status = read_update_state(settings.update_state_path)
    journal_snapshot = None
    if status.get("state") == "installing" and isinstance(status.get("snapshot"), str):
        try:
            journal_snapshot = Path(status["snapshot"]).resolve()
        except OSError:
            warnings.append("active update snapshot could not be resolved")
    staged = None
    if status.get("state") == "staged" and isinstance(status.get("target_release"), str):
        try:
            target_name = status["target_release"]
            if not RELEASE_NAME.fullmatch(target_name):
                raise ValueError("invalid staged release name")
            staged = (release_root / target_name).resolve()
        except (OSError, ValueError):
            warnings.append("staged release marker was invalid")

    release_candidates: list[tuple[Version, Path]] = []
    if settings.release_dir.is_dir():
        for candidate in settings.release_dir.iterdir():
            if candidate.is_symlink() or not candidate.is_dir():
                continue
            try:
                version = Version.parse(candidate.name)
                resolved_candidate = candidate.resolve(strict=True)
            except UpdateError:
                continue
            except OSError:
                warnings.append(f"could not resolve release {candidate.name}")
                continue
            if release_root not in resolved_candidate.parents:
                continue
            release_candidates.append((version, resolved_candidate))
    release_candidates.sort(key=lambda item: item[0], reverse=True)
    protected_releases = {path for path in (active, last_good, staged) if path is not None}
    keep_release_paths = {candidate for _version, candidate in release_candidates[:keep_releases]}
    keep_release_paths.update(protected_releases)
    for _version, candidate in release_candidates:
        if candidate in keep_release_paths:
            continue
        try:
            shutil.rmtree(candidate)
            removed_releases.append(candidate.name)
        except OSError as exc:
            warnings.append(f"could not remove release {candidate.name}: {exc}")

    def snapshot_candidates(root: Path) -> list[Path]:
        if not root.is_dir():
            return []
        candidates: list[Path] = []
        for item in root.iterdir():
            if not item.is_dir() or item.is_symlink() or not (item / "manifest.json").is_file():
                continue
            try:
                item.stat()
            except OSError:
                warnings.append(f"could not inspect snapshot {item.name}")
                continue
            candidates.append(item.resolve())
        return sorted(candidates, key=lambda item: item.stat().st_mtime, reverse=True)

    for root in (settings.state_dir / "upgrade-snapshots", settings.state_dir / "rollback-snapshots"):
        candidates = snapshot_candidates(root)
        keep = set(candidates[:keep_snapshots])
        if journal_snapshot is not None:
            keep.add(journal_snapshot)
        for candidate in candidates:
            if candidate in keep:
                continue
            try:
                shutil.rmtree(candidate)
                removed_snapshots.append(str(candidate))
            except OSError as exc:
                warnings.append(f"could not remove snapshot {candidate.name}: {exc}")

    return {
        "removed_releases": removed_releases,
        "removed_snapshots": removed_snapshots,
        "warnings": warnings,
        "keep_releases": keep_releases,
        "keep_snapshots": keep_snapshots,
    }


def update_metadata(settings: Settings, **details) -> dict:
    current = read_update_state(settings.update_metadata_path)
    payload = {**current, "schema_version": 1, **details}
    _atomic_json(settings.update_metadata_path, payload, 0o600)
    return payload


def _highest_known_version(settings: Settings, current_release: str | None = None) -> Version | None:
    metadata = read_update_state(settings.update_metadata_path)
    values = [current_release]
    values.extend(metadata.get(key) for key in ("highest_seen_release", "highest_staged_release", "highest_installed_release"))
    parsed = []
    for value in values:
        if not isinstance(value, str) or not value:
            continue
        try:
            parsed.append(Version.parse(value))
        except UpdateError:
            continue
    return max(parsed) if parsed else None


@contextmanager
def update_lock(settings: Settings):
    settings.state_dir.mkdir(parents=True, exist_ok=True)
    lock_path = settings.state_dir / "update.lock"
    with lock_path.open("a+") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise UpdateError("update_busy", "Another CayVPN update or rollback is already running.") from exc
        yield


def _safe_repository(value: str) -> tuple[str, str]:
    parts = (value or "").split("/")
    if len(parts) != 2 or any(not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", item) for item in parts):
        raise UpdateError("invalid_repository", "The configured update repository is invalid.")
    return parts[0], parts[1]


def _is_public_address(value: str) -> bool:
    address = ipaddress.ip_address(value.split("%", 1)[0])
    return bool(address.is_global)


def _validate_https_url(url: str, allowed_hosts: set[str]) -> None:
    parsed = urlsplit(url)
    host = (parsed.hostname or "").lower().rstrip(".")
    if parsed.scheme != "https" or not host or parsed.username or parsed.password or parsed.port not in {None, 443}:
        raise UpdateError("unsafe_update_url", "The update service returned an unsafe download address.")
    if host not in allowed_hosts and not host.endswith(".githubusercontent.com"):
        raise UpdateError("unsafe_update_url", "The update service returned an unapproved download host.")
    try:
        addresses = {item[4][0] for item in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)}
    except OSError as exc:
        raise UpdateError("update_network_error", "The update host could not be resolved.") from exc
    if not addresses or any(not _is_public_address(address) for address in addresses):
        raise UpdateError("unsafe_update_url", "The update host resolved to a protected network address.")


class _SafeRedirects(HTTPRedirectHandler):
    def __init__(self, allowed_hosts: set[str]):
        self.allowed_hosts = allowed_hosts
        self.redirects = 0
        super().__init__()

    def redirect_request(self, request, fp, code, msg, headers, newurl):
        self.redirects += 1
        if self.redirects > 5:
            raise UpdateError("too_many_redirects", "The update download redirected too many times.")
        _validate_https_url(newurl, self.allowed_hosts)
        return super().redirect_request(request, fp, code, msg, headers, newurl)


class HttpFetcher:
    def __init__(self, user_agent: str = "CayVPN/2"):
        self.allowed_hosts = {
            "api.github.com",
            "github.com",
            "objects.githubusercontent.com",
            "release-assets.githubusercontent.com",
            "githubusercontent.com",
        }
        self.user_agent = user_agent

    def _open(self, url: str, accept: str, timeout: int):
        _validate_https_url(url, self.allowed_hosts)
        redirects = _SafeRedirects(self.allowed_hosts)
        opener = build_opener(ProxyHandler({}), redirects)
        request = Request(
            url,
            headers={
                "Accept": accept,
                "User-Agent": self.user_agent,
                "X-GitHub-Api-Version": "2026-03-10",
            },
        )
        try:
            return opener.open(request, timeout=timeout)
        except UpdateError:
            raise
        except HTTPError as exc:
            if exc.code == 404:
                raise UpdateError("release_not_found", "No matching CayVPN release was found.") from exc
            if exc.code == 403:
                raise UpdateError("update_rate_limited", "The update service temporarily refused the request. Try again later.") from exc
            raise UpdateError("update_http_error", f"The update service returned HTTP {exc.code}.") from exc
        except (URLError, TimeoutError, OSError) as exc:
            raise UpdateError("update_network_error", "CayVPN could not reach the update service.") from exc

    @staticmethod
    def _content_length(headers, error_code: str, message: str) -> int | None:
        raw = headers.get("Content-Length")
        if raw is None:
            return None
        try:
            value = int(raw)
        except (TypeError, ValueError) as exc:
            raise UpdateError(error_code, message) from exc
        if value < 0:
            raise UpdateError(error_code, message)
        return value

    def json(self, url: str, max_bytes: int = MAX_API_BYTES) -> dict:
        with self._open(url, "application/vnd.github+json", 15) as response:
            length = self._content_length(response.headers, "invalid_update_response", "The update service returned invalid length metadata.")
            if length is not None and length > max_bytes:
                raise UpdateError("update_response_too_large", "The update service response was unexpectedly large.")
            data = response.read(max_bytes + 1)
        if len(data) > max_bytes:
            raise UpdateError("update_response_too_large", "The update service response was unexpectedly large.")
        try:
            value = json.loads(data)
        except (TypeError, ValueError) as exc:
            raise UpdateError("invalid_update_response", "The update service returned invalid metadata.") from exc
        if not isinstance(value, dict):
            raise UpdateError("invalid_update_response", "The update service returned invalid metadata.")
        return value

    def download(self, url: str, destination: Path, max_bytes: int, expected_size: int | None = None) -> str:
        digest = hashlib.sha256()
        written = 0
        with self._open(url, "application/octet-stream", 30) as response, destination.open("xb") as output:
            length = self._content_length(response.headers, "release_length_mismatch", "The release asset had invalid length metadata.")
            if length is not None and length > max_bytes:
                raise UpdateError("release_too_large", "The release asset exceeded CayVPN's download limit.")
            while True:
                chunk = response.read(min(1024 * 1024, max_bytes - written + 1))
                if not chunk:
                    break
                written += len(chunk)
                if written > max_bytes:
                    raise UpdateError("release_too_large", "The release asset exceeded CayVPN's download limit.")
                output.write(chunk)
                digest.update(chunk)
            output.flush()
            os.fsync(output.fileno())
        if expected_size is not None and written != expected_size:
            raise UpdateError("release_length_mismatch", "The release asset size did not match its published metadata.")
        return digest.hexdigest()


class ReleaseRepository:
    def __init__(self, settings: Settings, fetcher: HttpFetcher | None = None):
        self.settings = settings
        self.fetcher = fetcher or HttpFetcher()
        owner, repository = _safe_repository(settings.update_repository)
        self.owner = owner
        self.repository = repository
        self.api_base = f"https://api.github.com/repos/{owner}/{repository}/releases"
        self.page_base = f"https://github.com/{owner}/{repository}/releases"

    def latest(self) -> ReleaseInfo:
        return self._parse(self.fetcher.json(f"{self.api_base}/latest"))

    def release(self, version: str) -> ReleaseInfo:
        clean = str(Version.parse(version))
        return self._parse(self.fetcher.json(f"{self.api_base}/tags/{quote('v' + clean, safe='')}"), expected_version=clean)

    def _parse(self, payload: dict, expected_version: str | None = None) -> ReleaseInfo:
        if payload.get("draft") is not False or payload.get("prerelease") is not False:
            raise UpdateError("unsupported_release_channel", "Only published stable CayVPN releases may be installed.")
        if payload.get("immutable") is not True:
            raise UpdateError("mutable_release", "This release is not immutable on GitHub and cannot be installed safely.")
        tag = str(payload.get("tag_name") or "")
        parsed_version = Version.parse(tag)
        if parsed_version.prerelease or parsed_version.build:
            raise UpdateError("unsupported_release_channel", "Only plain X.Y.Z CayVPN stable releases may be installed.")
        version = str(parsed_version)
        if expected_version and version != expected_version:
            raise UpdateError("release_mismatch", "The update service returned a different release than requested.")
        if tag != f"v{version}":
            raise UpdateError("invalid_release", "Stable CayVPN release tags must use the form vX.Y.Z.")
        page_url = str(payload.get("html_url") or "")
        if page_url != f"{self.page_base}/tag/{tag}":
            raise UpdateError("invalid_update_response", "The update service returned an unexpected release page.")
        published_at = str(payload.get("published_at") or "")
        try:
            published = datetime.fromisoformat(published_at.replace("Z", "+00:00"))
        except ValueError as exc:
            raise UpdateError("invalid_update_response", "The release publication time is invalid.") from exc
        if published.tzinfo is None or published > datetime.now(timezone.utc) + timedelta(minutes=5):
            raise UpdateError("invalid_update_response", "The release publication time is invalid.")

        expected_names = {
            f"cayvpn-{version}.tar.gz",
            f"cayvpn-{version}.sha256",
            f"cayvpn-{version}.sha256.sig",
            "cayvpn-release.pub",
        }
        assets: dict[str, ReleaseAsset] = {}
        raw_assets = payload.get("assets")
        if not isinstance(raw_assets, list) or len(raw_assets) > 100:
            raise UpdateError("invalid_update_response", "The release asset list is invalid.")
        for raw in raw_assets:
            if not isinstance(raw, dict):
                continue
            name = str(raw.get("name") or "")
            if name not in expected_names:
                continue
            if name in assets or raw.get("state") != "uploaded":
                raise UpdateError("invalid_update_response", "The release contains a duplicate or incomplete required asset.")
            size = raw.get("size")
            if not isinstance(size, int) or size <= 0 or size > MAX_RELEASE_BYTES:
                raise UpdateError("release_too_large", "A required release asset has an invalid size.")
            url = str(raw.get("browser_download_url") or "")
            expected_url = f"{self.page_base}/download/{tag}/{name}"
            if url != expected_url:
                raise UpdateError("invalid_update_response", "A required release asset has an unexpected address.")
            digest = raw.get("digest")
            if digest is not None and not re.fullmatch(r"sha256:[0-9a-fA-F]{64}", str(digest)):
                raise UpdateError("invalid_update_response", "A required release asset has an invalid digest.")
            assets[name] = ReleaseAsset(name, url, size, str(digest).split(":", 1)[1].lower() if digest else None)
        if set(assets) != expected_names:
            raise UpdateError("release_assets_missing", "The release is missing one or more signed CayVPN assets.")
        title = " ".join(str(payload.get("name") or tag).split())[:160]
        notes = str(payload.get("body") or "").replace("\x00", "")[:MAX_RELEASE_NOTES]
        return ReleaseInfo(version, tag, title, notes, page_url, published_at, True, assets)


def _safe_manifest_path(value: str) -> PurePosixPath:
    path = PurePosixPath(value)
    raw_parts = value.split("/")
    if not value or value.startswith("/") or path.is_absolute() or any(part in {"", ".", ".."} for part in raw_parts):
        raise UpdateError("unsafe_release", "The signed release manifest contains an unsafe path.")
    return path


def parse_manifest(data: bytes) -> dict[str, str]:
    try:
        lines = data.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise UpdateError("invalid_release_manifest", "The signed release manifest is not valid UTF-8.") from exc
    result: dict[str, str] = {}
    for line in lines:
        match = SHA256_LINE.fullmatch(line)
        if not match:
            raise UpdateError("invalid_release_manifest", "The signed release manifest contains an invalid entry.")
        name = str(_safe_manifest_path(match.group(2)))
        if name in result:
            raise UpdateError("invalid_release_manifest", "The signed release manifest contains a duplicate entry.")
        result[name] = match.group(1).lower()
    if not result or len(result) > MAX_ARCHIVE_FILES:
        raise UpdateError("invalid_release_manifest", "The signed release manifest has an invalid number of files.")
    return result


def _trusted_key(settings: Settings) -> bytes:
    path = settings.release_trust_key
    try:
        stat = path.stat()
        data = path.read_bytes()
    except OSError as exc:
        raise UpdateError("release_trust_missing", "The CayVPN release trust key is missing. Restore it from the encrypted recovery backup over SSH.") from exc
    if not path.is_file() or stat.st_mode & 0o022:
        raise UpdateError("release_trust_permissions", "The CayVPN release trust key has unsafe permissions.")
    if os.geteuid() == 0 and stat.st_uid != 0:
        raise UpdateError("release_trust_owner", "The CayVPN release trust key is not owned by root.")
    try:
        key = load_pem_public_key(data)
        if not isinstance(key, Ed25519PublicKey):
            raise TypeError("not Ed25519")
    except (TypeError, ValueError) as exc:
        raise UpdateError("release_trust_invalid", "The CayVPN release trust key is invalid.") from exc
    return data


def _verify_signature(settings: Settings, public_key_path: Path, manifest_path: Path, signature_path: Path) -> dict[str, str]:
    trusted = _trusted_key(settings)
    supplied = public_key_path.read_bytes()
    if not hmac.compare_digest(hashlib.sha256(supplied).digest(), hashlib.sha256(trusted).digest()) or supplied != trusted:
        raise UpdateError("release_key_mismatch", "The release was signed by a different key than this VPS trusts.")
    try:
        key = load_pem_public_key(trusted)
        key.verify(signature_path.read_bytes(), manifest_path.read_bytes())
    except (OSError, ValueError, TypeError, InvalidSignature) as exc:
        raise UpdateError("release_signature_invalid", "The CayVPN release signature is invalid.") from exc
    return parse_manifest(manifest_path.read_bytes())


def _archive_inventory(archive: tarfile.TarFile, version: str) -> tuple[str, dict[str, tarfile.TarInfo]]:
    root = f"cayvpn-{version}"
    files: dict[str, tarfile.TarInfo] = {}
    total = 0
    members = archive.getmembers()
    if len(members) > MAX_ARCHIVE_FILES * 2:
        raise UpdateError("unsafe_release", "The release archive contains too many entries.")
    for member in members:
        path = PurePosixPath(member.name)
        raw_parts = member.name.rstrip("/").split("/")
        if path.is_absolute() or not path.parts or path.parts[0] != root or any(part in {"", ".", ".."} for part in raw_parts):
            raise UpdateError("unsafe_release", "The release archive contains an unsafe path.")
        if not (member.isdir() or member.isfile()):
            raise UpdateError("unsafe_release", "The release archive contains links or unsupported file types.")
        if member.isfile():
            relative = str(PurePosixPath(*path.parts[1:]))
            _safe_manifest_path(relative)
            if relative in files:
                raise UpdateError("unsafe_release", "The release archive contains a duplicate file.")
            total += member.size
            if member.size < 0 or total > MAX_RELEASE_BYTES:
                raise UpdateError("release_too_large", "The expanded release exceeded CayVPN's size limit.")
            files[relative] = member
    return root, files


def _extract_verified_archive(archive_path: Path, destination: Path, version: str, manifest: dict[str, str]) -> Path:
    destination.mkdir(parents=True, exist_ok=False)
    with tarfile.open(archive_path, "r:gz") as archive:
        root_name, files = _archive_inventory(archive, version)
        if set(files) != set(manifest):
            raise UpdateError("release_inventory_mismatch", "The release archive did not match its signed file inventory.")
        release_root = destination / root_name
        release_root.mkdir(mode=0o755)
        for name in sorted(files):
            member = files[name]
            target = release_root.joinpath(*PurePosixPath(name).parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            source = archive.extractfile(member)
            if source is None:
                raise UpdateError("unsafe_release", "A release file could not be read.")
            digest = hashlib.sha256()
            with target.open("xb") as output:
                while True:
                    chunk = source.read(1024 * 1024)
                    if not chunk:
                        break
                    output.write(chunk)
                    digest.update(chunk)
            if not hmac.compare_digest(digest.hexdigest(), manifest[name]):
                raise UpdateError("release_checksum_mismatch", f"The signed checksum failed for {name}.")
            os.chmod(target, 0o755 if member.mode & 0o111 else 0o644)
    return release_root


def _architecture() -> str:
    machine = platform.machine().lower()
    if machine in {"x86_64", "amd64"}:
        return "amd64"
    if machine in {"aarch64", "arm64"}:
        return "arm64"
    raise UpdateError("unsupported_architecture", "CayVPN updates support only x86_64 and ARM64.")


def _operating_system() -> str:
    try:
        values = {}
        for line in Path("/etc/os-release").read_text().splitlines():
            key, separator, raw = line.partition("=")
            if separator and re.fullmatch(r"[A-Z0-9_]+", key):
                values[key] = raw.strip().strip('"\'')
    except OSError:
        values = {}
    if values.get("ID") == "ubuntu" and values.get("VERSION_ID") == "24.04":
        return "ubuntu-24.04"
    return f"{values.get('ID', platform.system().lower())}-{values.get('VERSION_ID', platform.release())}"


def _release_metadata(path: Path, version: str, current_release: str | None = None) -> dict:
    try:
        metadata = json.loads((path / "release.json").read_text())
    except (OSError, ValueError, TypeError) as exc:
        raise UpdateError("release_metadata_invalid", "The release is missing valid compatibility metadata.") from exc
    required = {"schema_version", "version", "channel", "supported_os", "supported_architectures", "minimum_cayvpn_version", "offline_dependencies", "offline_optional_components"}
    optional = {"summary", "migration_notes", "component_changes", "compatibility_notes", "expected_interruption_seconds", "requires_reboot", "security_fixes"}
    if not isinstance(metadata, dict) or not required.issubset(metadata) or set(metadata) - required - optional or metadata.get("schema_version") != 1 or metadata.get("version") != version:
        raise UpdateError("release_metadata_invalid", "The release compatibility metadata does not match the requested version.")
    supported_os = metadata.get("supported_os")
    supported_architectures = metadata.get("supported_architectures")
    if (
        metadata.get("channel") != "stable"
        or metadata.get("offline_dependencies") is not True
        or metadata.get("offline_optional_components") is not True
        or not isinstance(supported_os, list)
        or not all(isinstance(item, str) for item in supported_os)
        or not isinstance(supported_architectures, list)
        or not all(isinstance(item, str) for item in supported_architectures)
    ):
        raise UpdateError("release_metadata_invalid", "The release compatibility metadata is invalid.")
    if _operating_system() not in supported_os or _architecture() not in supported_architectures:
        raise UpdateError("release_incompatible", "This release does not support this VPS operating system or architecture.")
    minimum = metadata.get("minimum_cayvpn_version")
    if not isinstance(minimum, str):
        raise UpdateError("release_metadata_invalid", "The release has invalid compatibility version metadata.")
    try:
        minimum_version = Version.parse(minimum)
    except UpdateError as exc:
        raise UpdateError("release_metadata_invalid", "The release has invalid compatibility version metadata.") from exc
    if current_release:
        try:
            current_version = Version.parse(current_release)
        except UpdateError as exc:
            raise UpdateError("release_metadata_invalid", "The release has invalid compatibility version metadata.") from exc
        if current_version < minimum_version:
            raise UpdateError("bridge_release_required", f"Install CayVPN {minimum} or newer before this release.")
    summary = metadata.get("summary", "")
    migration_notes = metadata.get("migration_notes", "")
    component_changes = metadata.get("component_changes", [])
    compatibility_notes = metadata.get("compatibility_notes", [])
    interruption = metadata.get("expected_interruption_seconds", 0)
    if (
        not isinstance(summary, str)
        or len(summary) > 500
        or not isinstance(migration_notes, str)
        or len(migration_notes) > 2_000
        or not isinstance(component_changes, list)
        or len(component_changes) > 20
        or not all(isinstance(item, str) and len(item) <= 240 for item in component_changes)
        or not isinstance(compatibility_notes, list)
        or len(compatibility_notes) > 20
        or not all(isinstance(item, str) and len(item) <= 240 for item in compatibility_notes)
        or not isinstance(interruption, int)
        or isinstance(interruption, bool)
        or interruption < 0
        or interruption > 3_600
        or not isinstance(metadata.get("requires_reboot", False), bool)
        or not isinstance(metadata.get("security_fixes", False), bool)
    ):
        raise UpdateError("release_metadata_invalid", "The release impact metadata is invalid.")
    return metadata


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while True:
            chunk = source.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def verify_installed_release(
    settings: Settings,
    release_path: Path,
    current_release: str | None = None,
    expected_version: str | None = None,
) -> dict:
    manifest_path = release_path / "release.manifest"
    signature_path = release_path / "release.signature"
    public_key_path = release_path / "release.pub"
    if not all(path.is_file() for path in (manifest_path, signature_path, public_key_path)):
        if os.environ.get("CAYVPN_ALLOW_UNVERIFIED_LOCAL") == "1":
            return {"version": release_path.name, "local_unverified": True}
        raise UpdateError("release_metadata_missing", "The staged release is missing signed verification metadata.")
    manifest = _verify_signature(settings, public_key_path, manifest_path, signature_path)
    observed = set()
    generated = {"release.manifest", "release.signature", "release.pub"}
    for candidate in release_path.rglob("*"):
        relative = candidate.relative_to(release_path)
        if not relative.parts:
            continue
        if relative.parts[0] == ".venv" or candidate.name == "__pycache__" or "__pycache__" in relative.parts:
            continue
        name = relative.as_posix()
        if name in generated:
            continue
        if candidate.is_symlink() or (not candidate.is_dir() and not candidate.is_file()):
            raise UpdateError("release_inventory_mismatch", "The staged release contains an unsupported unsigned entry.")
        if candidate.is_file():
            observed.add(name)
    if observed != set(manifest):
        raise UpdateError("release_inventory_mismatch", "The staged release contains missing or unsigned source files.")
    for name, expected in manifest.items():
        target = release_path.joinpath(*_safe_manifest_path(name).parts)
        if not target.is_file() or target.is_symlink():
            raise UpdateError("release_inventory_mismatch", "The staged release is missing a signed file.")
        digest = _file_sha256(target)
        if not hmac.compare_digest(digest, expected):
            raise UpdateError("release_checksum_mismatch", f"The signed checksum failed for {name}.")
    metadata = _release_metadata(release_path, expected_version or release_path.name, current_release)
    return metadata


def _harden_release_tree(release_root: Path) -> None:
    for directory, child_directories, files in os.walk(release_root, topdown=True, followlinks=False):
        current = Path(directory)
        if current.is_symlink():
            continue
        os.chmod(current, 0o755)
        for child in child_directories:
            path = current / child
            if not path.is_symlink():
                os.chmod(path, 0o755)
        for name in files:
            path = current / name
            if path.is_symlink():
                continue
            mode = path.stat().st_mode
            os.chmod(path, 0o755 if mode & 0o111 else 0o644)


class UpdateManager:
    def __init__(
        self,
        settings: Settings,
        repository: ReleaseRepository | None = None,
        command_runner: Callable[..., subprocess.CompletedProcess] | None = None,
    ):
        self.settings = settings
        self.repository = repository or ReleaseRepository(settings)
        self.command_runner = command_runner or subprocess.run

    def status(self) -> dict:
        return read_update_state(self.settings.update_state_path) or {"schema_version": 1, "state": "idle"}

    def check(self, current_release: str) -> dict:
        write_update_state(self.settings, "checking", current_release=current_release)
        try:
            release = self.repository.latest()
            highest = _highest_known_version(self.settings, current_release)
            offered = Version.parse(release.version)
            if highest is not None and offered < highest:
                raise UpdateError("release_rollback_detected", "The update service offered an older release than this VPS has already trusted.")
            result = release.public_dict(current_release)
            state = "available" if result["available"] else "current"
            update_metadata(
                self.settings,
                highest_seen_release=str(max(highest, offered)) if highest is not None else str(offered),
                last_successful_check_at=datetime.now(timezone.utc).isoformat(),
            )
            return write_update_state(self.settings, state, current_release=current_release, release=result)
        except UpdateError as exc:
            write_update_state(self.settings, "check_failed", current_release=current_release, error_code=exc.code, error_message=str(exc))
            raise

    def stage(self, version: str, current_release: str) -> dict:
        requested = str(Version.parse(version))
        if Version.parse(requested) <= Version.parse(current_release):
            raise UpdateError("update_not_newer", "Only a newer CayVPN release can be staged from the panel.")
        highest = _highest_known_version(self.settings, current_release)
        if highest is not None and Version.parse(requested) < highest:
            raise UpdateError("release_rollback_detected", "CayVPN refused a release older than one this VPS has already trusted.")
        write_update_state(self.settings, "staging", current_release=current_release, target_release=requested)
        download_root = self.settings.state_dir / "update-downloads"
        staging_parent = self.settings.release_dir.parent
        download_root.mkdir(parents=True, exist_ok=True)
        staging_parent.mkdir(parents=True, exist_ok=True)
        download_dir = Path(tempfile.mkdtemp(prefix=f"cayvpn-{requested}-", dir=download_root))
        extraction_workspace = Path(tempfile.mkdtemp(prefix=f".release-{requested}-", dir=staging_parent))
        extraction_dir = extraction_workspace / "unpacked"
        target = self.settings.release_dir / requested
        try:
            release = self.repository.release(requested)
            if target.is_symlink():
                raise UpdateError("unsafe_release", "The staged release destination is an unsafe symbolic link.")
            if target.exists():
                metadata = verify_installed_release(self.settings, target, current_release, requested)
                update_metadata(self.settings, highest_staged_release=requested, verified_at=datetime.now(timezone.utc).isoformat())
                return write_update_state(self.settings, "staged", current_release=current_release, target_release=requested, release=release.public_dict(current_release), release_metadata=metadata, already_staged=True)
            required = sum(asset.size for asset in release.assets.values())
            free = shutil.disk_usage(staging_parent).free
            if free < max(MIN_STAGE_FREE_BYTES, required * 3):
                raise UpdateError("insufficient_disk_space", "The VPS does not have enough free disk space to stage this update and preserve rollback data.")
            paths: dict[str, Path] = {}
            for name, asset in release.assets.items():
                destination = download_dir / name
                observed = self.repository.fetcher.download(asset.url, destination, min(MAX_RELEASE_BYTES, asset.size + 1), asset.size)
                if asset.digest and not hmac.compare_digest(observed, asset.digest):
                    raise UpdateError("release_checksum_mismatch", f"GitHub's digest failed for {name}.")
                paths[name] = destination
            archive_name = f"cayvpn-{requested}.tar.gz"
            manifest_name = f"cayvpn-{requested}.sha256"
            signature_name = f"{manifest_name}.sig"
            manifest = _verify_signature(self.settings, paths["cayvpn-release.pub"], paths[manifest_name], paths[signature_name])
            release_root = _extract_verified_archive(paths[archive_name], extraction_dir, requested, manifest)
            metadata = _release_metadata(release_root, requested, current_release)
            architecture = _architecture()
            wheelhouse = release_root / "wheelhouse" / architecture
            if metadata.get("offline_dependencies") is not True or not wheelhouse.is_dir() or not any(wheelhouse.glob("*.whl")):
                raise UpdateError("offline_dependencies_missing", "The release does not contain its signed offline dependency bundle.")
            try:
                validate_release_components(self.settings, release_root)
            except ComponentError as exc:
                raise UpdateError(
                    "offline_components_invalid", str(exc)
                ) from exc
            venv = release_root / ".venv"
            runtime_environment = os.environ.copy()
            runtime_environment["PYTHONDONTWRITEBYTECODE"] = "1"
            trusted_python = self.settings.active_release / ".venv" / "bin" / "python"
            trusted_validator = self.settings.active_release / "scripts" / "validate-python-source.py"
            commands = (
                ([str(trusted_python), str(trusted_validator), str(release_root)], 60),
                ([str(trusted_python), "-m", "venv", str(venv)], 120),
                ([str(venv / "bin" / "python"), "-m", "pip", "install", "--disable-pip-version-check", "--no-index", "--no-deps", "--find-links", str(wheelhouse), "-r", str(release_root / "requirements.lock")], 600),
                ([str(venv / "bin" / "python"), "-c", "import cayvpn, flask, sqlalchemy; print(cayvpn.__version__)"], 60),
                ([str(venv / "bin" / "python"), str(release_root / "scripts" / "relocate-venv.py"), str(venv), str(release_root), str(target)], 60),
            )
            for argv, timeout in commands:
                result = self.command_runner(argv, capture_output=True, text=True, timeout=timeout, check=False, cwd=release_root, env=runtime_environment)
                if result.returncode != 0:
                    message = (result.stderr or result.stdout or "The release runtime could not be prepared.")[-600:]
                    raise UpdateError("release_runtime_failed", message)
            shutil.copy2(paths[manifest_name], release_root / "release.manifest")
            shutil.copy2(paths[signature_name], release_root / "release.signature")
            shutil.copy2(paths["cayvpn-release.pub"], release_root / "release.pub")
            verify_installed_release(self.settings, release_root, current_release, requested)
            _harden_release_tree(release_root)
            self.settings.release_dir.mkdir(parents=True, exist_ok=True)
            os.replace(release_root, target)
            update_metadata(self.settings, highest_staged_release=requested, verified_at=datetime.now(timezone.utc).isoformat())
            return write_update_state(self.settings, "staged", current_release=current_release, target_release=requested, release=release.public_dict(current_release), release_metadata=metadata)
        except UpdateError as exc:
            write_update_state(self.settings, "stage_failed", current_release=current_release, target_release=requested, error_code=exc.code, error_message=str(exc))
            raise
        except (OSError, tarfile.TarError, subprocess.SubprocessError) as exc:
            error = UpdateError("update_stage_error", "The update could not be staged safely. No active release was changed.")
            write_update_state(self.settings, "stage_failed", current_release=current_release, target_release=requested, error_code=error.code, error_message=str(error))
            raise error from exc
        finally:
            shutil.rmtree(download_dir, ignore_errors=True)
            shutil.rmtree(extraction_workspace, ignore_errors=True)
