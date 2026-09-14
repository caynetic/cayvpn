from __future__ import annotations

import hashlib
import errno
import grp
import json
import os
import pwd
import pty
import select
import signal
import shutil
import sqlite3
import stat
import tarfile
import termios
import time
import tempfile
import uuid
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .config import Settings
from .db import Database
from .models import BackupRecord


MAX_ENCRYPTED_BACKUP_BYTES = 128 * 1024 * 1024
AGE_PROMPT_TIMEOUT_SECONDS = 60
AGE_OPERATION_TIMEOUT_SECONDS = 240


def _key(passphrase: str, salt: bytes) -> bytes:
    return Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(passphrase.encode())


def _age_encrypt(plaintext: bytes, passphrase: str) -> bytes | None:
    age = shutil.which("age")
    if not age:
        return None
    with tempfile.TemporaryDirectory(prefix="cayvpn-age-") as temp:
        source = Path(temp) / "state.tar"
        output = Path(temp) / "backup.age"
        source.write_bytes(plaintext)
        source.chmod(0o600)
        _run_age(age, ["--encrypt", "--passphrase", "--output", str(output), str(source)], passphrase, confirmations=2)
        return output.read_bytes()


def _age_decrypt(payload: bytes, passphrase: str) -> bytes:
    age = shutil.which("age")
    if not age:
        raise RuntimeError("age is required to restore this backup on the current node")
    with tempfile.TemporaryDirectory(prefix="cayvpn-age-restore-") as temp:
        source = Path(temp) / "backup.age"
        output = Path(temp) / "state.tar"
        source.write_bytes(payload)
        # age auto-detects passphrase-encrypted input while decrypting. Its
        # --passphrase flag is encryption-only and combining it with
        # --decrypt is rejected by the Ubuntu 24.04 age package.
        _run_age(age, ["--decrypt", "--output", str(output), str(source)], passphrase, confirmations=1)
        return output.read_bytes()


def _run_age(binary: str, arguments: list[str], passphrase: str, confirmations: int) -> None:
    """Run age with a controlling tty so the passphrase never enters argv."""
    child_pid, descriptor = pty.fork()
    if child_pid == 0:
        os.execv(binary, [binary, *arguments])
    prompts = 0
    status = 1
    prompt_buffer = b""
    reaped = False
    deadline = time.monotonic() + AGE_OPERATION_TIMEOUT_SECONDS
    try:
        while True:
            remaining = max(0.0, deadline - time.monotonic())
            if remaining <= 0:
                raise RuntimeError("age operation timed out")
            # Scrypt can take longer than a terminal prompt on a busy 1 GiB
            # node. Once private input is complete, allow the remaining
            # bounded operation window rather than killing active encryption
            # after 60 seconds of intentionally silent processing.
            timeout = remaining if prompts >= confirmations else min(remaining, AGE_PROMPT_TIMEOUT_SECONDS)
            readable, _, _ = select.select([descriptor], [], [], timeout)
            if not readable:
                raise RuntimeError("age operation timed out")
            try:
                chunk = os.read(descriptor, 4096)
            except OSError as exc:
                if exc.errno == errno.EIO:
                    break
                raise
            if not chunk:
                break
            # Terminal reads may split a prompt at any byte boundary. Keep a
            # small rolling buffer until the complete prompt is recognized.
            prompt_buffer = (prompt_buffer + chunk.lower())[-4096:]
            if (b"passphrase" in prompt_buffer or b"password" in prompt_buffer) and prompt_buffer.rstrip().endswith(b":"):
                if prompts < confirmations:
                    _wait_for_secret_input(descriptor)
                    os.write(descriptor, passphrase.encode() + b"\n")
                    prompts += 1
                prompt_buffer = b""
        _, status = os.waitpid(child_pid, 0)
        reaped = True
    finally:
        try:
            os.close(descriptor)
        except OSError:
            pass
        if not reaped:
            try:
                os.kill(child_pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                os.waitpid(child_pid, 0)
            except ChildProcessError:
                pass
    if status != 0 or prompts < confirmations:
        raise RuntimeError("age encryption or decryption failed")


def _wait_for_secret_input(descriptor: int) -> None:
    # age prints its prompt before ReadPassword disables terminal echo. Input
    # sent in that gap can be echoed as another prompt or flushed by the tty.
    # Observe the terminal state instead of assuming the prompt means ready.
    deadline = time.monotonic() + 5
    while termios.tcgetattr(descriptor)[3] & termios.ECHO:
        if time.monotonic() >= deadline:
            raise RuntimeError("age did not prepare its private passphrase input")
        time.sleep(0.005)


def _snapshot_database(source_path: Path, destination: Path) -> bool:
    """Copy committed SQLite state, including pages still resident in WAL."""
    if not source_path.is_file():
        return False
    source = sqlite3.connect(f"{source_path.resolve().as_uri()}?mode=ro", uri=True)
    target = sqlite3.connect(destination)
    try:
        source.backup(target)
    finally:
        target.close()
        source.close()
    destination.chmod(0o600)
    if os.geteuid() == 0:
        source_stat = source_path.stat(follow_symlinks=False)
        os.chown(destination, source_stat.st_uid, source_stat.st_gid, follow_symlinks=False)
    return True


def _allowed_archive_owners() -> tuple[set[int], set[int], set[str], set[str]]:
    """Return the only identities an installed CayVPN backup may restore.

    Production backups contain root-owned security material and files owned by
    the unprivileged ``cayvpn`` service account. Development tests run as the
    current user, so that identity is also accepted without broadening a root
    restore to arbitrary archive-controlled numeric owners.
    """
    user_ids = {0, os.geteuid()}
    group_ids = {0, os.getegid()}
    user_names = {"", "root"}
    group_names = {"", "root", "wheel"}
    try:
        current_user = pwd.getpwuid(os.geteuid())
        user_names.add(current_user.pw_name)
        group_ids.add(current_user.pw_gid)
    except KeyError:
        pass
    try:
        current_group = grp.getgrgid(os.getegid())
        group_names.add(current_group.gr_name)
    except KeyError:
        pass
    try:
        service_user = pwd.getpwnam("cayvpn")
        user_ids.add(service_user.pw_uid)
        group_ids.add(service_user.pw_gid)
        user_names.add(service_user.pw_name)
    except KeyError:
        pass
    try:
        service_group = grp.getgrnam("cayvpn")
        group_ids.add(service_group.gr_gid)
        group_names.add(service_group.gr_name)
    except KeyError:
        pass
    return user_ids, group_ids, user_names, group_names


def _validate_archive_member(
    member: tarfile.TarInfo,
    allowed_user_ids: set[int],
    allowed_group_ids: set[int],
    allowed_user_names: set[str],
    allowed_group_names: set[str],
) -> None:
    member_path = Path(member.name)
    if (
        member_path.is_absolute()
        or ".." in member_path.parts
        or member.issym()
        or member.islnk()
        or not (member.isfile() or member.isdir())
        or member.size > 512 * 1024 * 1024
    ):
        raise ValueError("Backup contains an unsafe archive member")
    if member.mode & 0o7000:
        raise ValueError("Backup contains unsafe special permission bits")
    if member.isdir() and member.mode & 0o500 != 0o500:
        raise ValueError("Backup contains an inaccessible directory")
    if member.isfile() and member.mode & 0o400 != 0o400:
        raise ValueError("Backup contains an unreadable file")
    if member.uid not in allowed_user_ids:
        raise ValueError("Backup contains an unsupported file owner")
    if member.uname:
        if member.uname not in allowed_user_names:
            raise ValueError("Backup contains an unsupported file owner")
        try:
            resolved_user_id = pwd.getpwnam(member.uname).pw_uid
        except KeyError as exc:
            raise ValueError("Backup contains an unknown file owner") from exc
        if resolved_user_id != member.uid:
            raise ValueError("Backup contains inconsistent file owner metadata")
    if member.gid not in allowed_group_ids:
        raise ValueError("Backup contains an unsupported file group")
    if member.gname:
        if member.gname not in allowed_group_names:
            raise ValueError("Backup contains an unsupported file group")
        try:
            resolved_group_id = grp.getgrnam(member.gname).gr_gid
        except KeyError as exc:
            raise ValueError("Backup contains an unknown file group") from exc
        if resolved_group_id != member.gid:
            raise ValueError("Backup contains inconsistent file group metadata")


def _apply_restored_metadata(source: Path, destination: Path) -> None:
    source_stat = source.stat(follow_symlinks=False)
    os.chmod(destination, stat.S_IMODE(source_stat.st_mode), follow_symlinks=False)
    if os.geteuid() == 0:
        os.chown(destination, source_stat.st_uid, source_stat.st_gid, follow_symlinks=False)


def _restore_file(source: Path, destination: Path) -> None:
    """Replace one file atomically while preserving its validated metadata."""
    if destination.parent.is_symlink():
        raise ValueError("Backup restore target contains an unsafe directory link")
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.restore-{uuid.uuid4().hex[:10]}")
    try:
        with source.open("rb") as input_file, temporary.open("xb") as output_file:
            shutil.copyfileobj(input_file, output_file, length=1024 * 1024)
            output_file.flush()
            os.fsync(output_file.fileno())
        _apply_restored_metadata(source, temporary)
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)


def _remove_sqlite_sidecars(database_path: Path) -> None:
    """Discard journals from the replaced database after its users stop.

    Backups and recovery snapshots contain a complete SQLite database. Reusing
    newer WAL pages can silently overwrite the restored records on first open.
    """
    for suffix in ("-journal", "-wal", "-shm"):
        sidecar = database_path.with_name(database_path.name + suffix)
        if not (sidecar.exists() or sidecar.is_symlink()):
            continue
        if sidecar.is_dir() and not sidecar.is_symlink():
            raise RuntimeError("an unsafe SQLite sidecar blocked state restoration")
        sidecar.unlink()


def _restore_directory(source: Path, destination: Path) -> None:
    """Replace a restored tree exactly, without retaining stale live files."""
    if destination.is_symlink():
        raise ValueError("Backup restore target contains an unsafe directory link")
    if destination.exists() and not destination.is_dir():
        raise ValueError("Backup restore target is not a directory")
    if destination.parent.is_symlink():
        raise ValueError("Backup restore target contains an unsafe directory link")
    destination.parent.mkdir(parents=True, exist_ok=True)
    identifier = uuid.uuid4().hex[:10]
    staged = destination.with_name(f".{destination.name}.restore-new-{identifier}")
    previous = destination.with_name(f".{destination.name}.restore-old-{identifier}")
    previous_moved = False
    try:
        shutil.copytree(source, staged, symlinks=False)
        sources = [source, *source.rglob("*")]
        for item in sorted(sources, key=lambda path: len(path.parts), reverse=True):
            target = staged if item == source else staged / item.relative_to(source)
            _apply_restored_metadata(item, target)
            if target.is_file():
                with target.open("rb") as handle:
                    os.fsync(handle.fileno())
        if destination.exists():
            os.replace(destination, previous)
            previous_moved = True
        try:
            os.replace(staged, destination)
        except Exception:
            if previous_moved and not destination.exists():
                os.replace(previous, destination)
                previous_moved = False
            raise
        if previous_moved:
            shutil.rmtree(previous)
            previous_moved = False
        directory = os.open(destination.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if staged.exists():
            shutil.rmtree(staged)


def create_backup(settings: Settings, db: Database, passphrase: str, destination: Path | None = None) -> Path:
    if len(passphrase) < 12:
        raise ValueError("Backup passphrase must be at least 12 characters")
    destination = destination or settings.state_dir / "backups"
    destination.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="cayvpn-backup-") as temp:
        archive = Path(temp) / "state.tar"
        database_snapshot = Path(temp) / settings.db_path.name
        metadata = Path(temp) / "cayvpn-backup-metadata.json"
        metadata.write_text(json.dumps({"format": 1, "public_endpoint": settings.public_endpoint, "server_ip": settings.server_ip, "release": os.environ.get("CAYVPN_RELEASE_VERSION", "unknown")}, sort_keys=True))
        metadata.chmod(0o600)
        database_present = _snapshot_database(settings.db_path, database_snapshot)
        with tarfile.open(archive, "w") as tar:
            if database_present:
                tar.add(database_snapshot, arcname=settings.db_path.name)
            for path in (settings.wg_dir, settings.config_dir):
                if path.exists():
                    tar.add(path, arcname=path.name, recursive=True)
            for path, arcname in (
                (settings.state_dir / "recovery", "recovery"),
                (settings.state_dir / "admin-initial.conf", "admin-initial.conf"),
                (settings.state_dir / "admin-initial.pub", "admin-initial.pub"),
            ):
                if path.exists():
                    tar.add(path, arcname=arcname, recursive=True)
            tar.add(metadata, arcname="cayvpn-backup-metadata.json")
        plaintext = archive.read_bytes()
    output = destination / f"cayvpn-{hashlib.sha256(plaintext).hexdigest()[:16]}.backup"
    age_payload = _age_encrypt(plaintext, passphrase)
    if age_payload is not None:
        encrypted = b"CAYVPN-AGE-1\n" + age_payload
    else:
        # Development fallback for macOS/test environments without the system
        # age binary. Production installs include age and therefore never use
        # this format.
        salt = os.urandom(16)
        nonce = os.urandom(12)
        ciphertext = AESGCM(_key(passphrase, salt)).encrypt(nonce, plaintext, b"cayvpn-backup-v1")
        encrypted = b"CAYVPN-BACKUP-1\n" + salt + nonce + ciphertext
    temporary = output.with_name(f".{output.name}.new")
    temporary.write_bytes(encrypted)
    os.chmod(temporary, 0o600)
    os.replace(temporary, output)
    os.chmod(output, 0o600)
    digest = hashlib.sha256(output.read_bytes()).hexdigest()
    with db.session() as session:
        session.add(BackupRecord(path=str(output), sha256=digest, includes_secrets=True))
    return output


def _read_encrypted_backup(source: Path) -> bytes:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(source, flags)
    except OSError as exc:
        raise ValueError("Backup must be a readable regular file, not a link") from exc
    try:
        observed = os.fstat(descriptor)
        if not stat.S_ISREG(observed.st_mode) or not 1 <= observed.st_size <= MAX_ENCRYPTED_BACKUP_BYTES:
            raise ValueError("Backup file is empty, unsupported, or too large")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            data = bytearray()
            while block := handle.read(1024 * 1024):
                data.extend(block)
                if len(data) > MAX_ENCRYPTED_BACKUP_BYTES:
                    raise ValueError("Backup file is too large")
        return bytes(data)
    finally:
        os.close(descriptor)


def restore_backup(settings: Settings, passphrase: str, source: Path) -> None:
    data = _read_encrypted_backup(source)
    age_prefix = b"CAYVPN-AGE-1\n"
    fallback_prefix = b"CAYVPN-BACKUP-1\n"
    if data.startswith(age_prefix):
        plaintext = _age_decrypt(data[len(age_prefix):], passphrase)
    elif data.startswith(fallback_prefix) and len(data) >= len(fallback_prefix) + 28:
        offset = len(fallback_prefix)
        plaintext = AESGCM(_key(passphrase, data[offset:offset + 16])).decrypt(data[offset + 16:offset + 28], data[offset + 28:], b"cayvpn-backup-v1")
    else:
        raise ValueError("Invalid CayVPN backup")
    with tempfile.TemporaryDirectory(prefix="cayvpn-restore-") as temp:
        archive = Path(temp) / "state.tar"
        archive.write_bytes(plaintext)
        allowed_user_ids, allowed_group_ids, allowed_user_names, allowed_group_names = _allowed_archive_owners()
        with tarfile.open(archive, "r") as tar:
            members = tar.getmembers()
            seen: set[str] = set()
            for member in members:
                canonical_name = str(Path(member.name))
                if canonical_name in seen:
                    raise ValueError("Backup contains duplicate archive members")
                seen.add(canonical_name)
                _validate_archive_member(
                    member,
                    allowed_user_ids,
                    allowed_group_ids,
                    allowed_user_names,
                    allowed_group_names,
                )
            for member in members:
                # All paths, types, owners, groups, sizes, and special mode bits
                # were checked above. Be explicit so Python's changing default
                # extraction filter cannot silently alter restore metadata.
                tar.extract(
                    member,
                    temp,
                    filter="fully_trusted",
                    numeric_owner=True,
                )
        config_sources = [candidate for candidate in (Path(temp) / "cayvpn", Path(temp) / "config") if candidate.exists()]
        if len(config_sources) > 1:
            raise ValueError("Backup contains more than one CayVPN configuration tree")
        restore_items = [
            (Path(temp) / "cayvpn.db", settings.db_path),
            (Path(temp) / "wireguard", settings.wg_dir),
            (Path(temp) / "recovery", settings.state_dir / "recovery"),
            (Path(temp) / "admin-initial.conf", settings.state_dir / "admin-initial.conf"),
            (Path(temp) / "admin-initial.pub", settings.state_dir / "admin-initial.pub"),
        ]
        if config_sources:
            restore_items.insert(2, (config_sources[0], settings.config_dir))
        for source_path, destination in restore_items:
            if source_path.is_file():
                if destination == settings.db_path:
                    _remove_sqlite_sidecars(destination)
                _restore_file(source_path, destination)
            elif source_path.is_dir():
                _restore_directory(source_path, destination)
        metadata_path = Path(temp) / "cayvpn-backup-metadata.json"
        metadata = {}
        if metadata_path.is_file():
            try:
                metadata = json.loads(metadata_path.read_text())
            except (OSError, ValueError):
                metadata = {}
        previous_endpoint = settings.public_endpoint
        restored_endpoint = str(metadata.get("public_endpoint", "")) or None
        report = {
            "previous_public_endpoint": previous_endpoint,
            "backup_public_endpoint": restored_endpoint,
            "endpoint_refresh_required": bool(restored_endpoint and restored_endpoint != previous_endpoint),
        }
        settings.state_dir.mkdir(parents=True, exist_ok=True)
        report_path = settings.state_dir / "restore-report.json"
        report_path.write_text(json.dumps(report, indent=2, sort_keys=True))
        report_path.chmod(0o600)
