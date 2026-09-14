from __future__ import annotations

import argparse
import getpass
import hashlib
import ipaddress
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import time
import tempfile
import uuid
from contextlib import closing, contextmanager
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import desc, select

from .backup import _remove_sqlite_sidecars, create_backup, restore_backup
from .capacity import calculate_capacity, detect_resources, transfer_forecast
from .components import COMPONENT_NAMES, component_binary, sync_release_components
from .config import Settings
from .db import Database
from .models import AdminDevice, CapacitySnapshot, Client, EgressProfile, ManagedNode
from .operations import OperationService
from .protocol import AgentClient, AgentRequest
from .remote_admin import RemoteAdminError, RemoteAdminManager
from .security import hash_password, now_epoch
from .updates import UpdateError, Version, prune_update_history, update_lock, update_metadata, verify_installed_release, write_update_state


PERSISTENT_SERVICE_UNITS = (
    "cayvpn-agent",
    "cayvpn-worker",
    "cayvpn-web",
    "cayvpn-remote-admin-renew.timer",
    "nginx",
)


@contextmanager
def _db(settings: Settings):
    with Database(settings) as database:
        database.initialize_defaults(settings)
        yield database


def cmd_status(settings: Settings) -> int:
    with _db(settings) as db:
        with db.session() as session:
            node = session.get(ManagedNode, 1)
            capacity = session.scalar(select(CapacitySnapshot).order_by(desc(CapacitySnapshot.observed_at)))
            profiles = session.scalars(select(EgressProfile).where(EgressProfile.enabled.is_(True))).all()
    print(json.dumps({"node": {"install_state": node.install_state, "release": node.release, "desired_generation": node.desired_generation, "observed_generation": node.observed_generation}, "capacity": {"safe_active_clients": capacity.safe_active_clients, "max_stored_configs": capacity.max_stored_configs, "max_egress_profiles": capacity.max_egress_profiles, "confidence": capacity.confidence} if capacity else None, "egress": [{"id": profile.id, "driver": profile.driver, "health_state": profile.health_state} for profile in profiles]}, indent=2))
    return 0


def cmd_verify(settings: Settings, *, _agent_verified: bool = False, _emit: bool = True) -> int:
    checks = {
        "state_dir": settings.state_dir.exists(),
        "database": settings.db_path.exists(),
        "wireguard_dir": settings.wg_dir.exists(),
        "active_release": settings.active_release.exists(),
        "agent_socket": settings.agent_socket.exists(),
    }
    try:
        active_release = _active_release_path(settings)
        checks["release_integrity"] = True
        checks["verified_release"] = active_release.name
    except (OSError, RuntimeError, UpdateError, ValueError) as exc:
        checks["release_integrity"] = False
        checks["release_error"] = str(exc)[:240]
    response = None
    for _attempt in range(0 if _agent_verified else (20 if settings.apply_network else 1)):
        if settings.agent_socket.exists():
            request = AgentRequest(uuid.uuid4().hex, "system.snapshot", desired_generation=0, payload={})
            response = AgentClient(settings.agent_socket).execute(request)
            if response.status == "succeeded":
                break
        if settings.apply_network:
            time.sleep(0.5)
    checks["agent"] = _agent_verified or bool(response and response.status == "succeeded")
    if response is not None and response.status != "succeeded":
        checks["agent_error"] = response.error_code or response.error_message
    if settings.apply_network:
        checks["native_components"] = all(
            component_binary(settings, name) for name in COMPONENT_NAMES
        )
        services = {unit: _service_state(unit) for unit in PERSISTENT_SERVICE_UNITS}
        checks["services"] = services
        checks["services_active"] = all(state == "active" for state in services.values())
        checks["wireguard"] = all(
            _command_succeeded(["wg", "show", interface], timeout=5)
            for interface in (settings.user_interface, settings.admin_interface)
        )
        checks["firewall"] = _command_succeeded(["nft", "list", "table", "inet", "cayvpn"], timeout=5)
        try:
            with closing(
                sqlite3.connect(
                    f"file:{settings.db_path.resolve()}?mode=ro", uri=True
                )
            ) as connection:
                row = connection.execute(
                    "SELECT value FROM settings WHERE key = ?",
                    ("remote_admin_enabled",),
                ).fetchone()
            expected_remote_admin = bool(row and row[0] == "1")
            remote_admin = RemoteAdminManager(
                settings, _MaintenanceRunner()
            ).verify_state(expected_remote_admin)
            checks["remote_admin"] = remote_admin
            checks["remote_admin_consistent"] = remote_admin["healthy"]
        except (OSError, RuntimeError, RemoteAdminError, sqlite3.Error, ValueError) as exc:
            checks["remote_admin"] = {"healthy": False, "error": str(exc)[:240]}
            checks["remote_admin_consistent"] = False
        try:
            admin_ip = str(ipaddress.ip_interface(settings.admin_address).ip)
            panel = _run_fixed(
                [
                    "curl",
                    "--silent",
                    "--show-error",
                    "--cacert",
                    str(settings.trust_cert_path),
                    "--resolve",
                    f"{settings.admin_hostname}:{settings.admin_https_port}:{admin_ip}",
                    "--output",
                    "/dev/null",
                    "--write-out",
                    "%{http_code}",
                    f"https://{settings.admin_hostname}:{settings.admin_https_port}/",
                ],
                timeout=10,
            )
            checks["private_panel"] = panel.returncode == 0 and panel.stdout.strip() in {"200", "302", "403"}
        except (OSError, subprocess.SubprocessError, ValueError):
            checks["private_panel"] = False
    if _emit:
        print(json.dumps(checks, indent=2))
    required = ["state_dir", "database", "wireguard_dir", "active_release", "release_integrity", "agent"]
    if settings.apply_network:
        required.extend(
            (
                "native_components",
                "services_active",
                "wireguard",
                "firewall",
                "remote_admin_consistent",
                "private_panel",
            )
        )
    return 0 if all(checks.get(key, False) for key in required) else 1


def cmd_refresh(settings: Settings) -> int:
    with _db(settings) as db:
        with db.session() as session:
            profiles = session.scalars(select(EgressProfile).where(EgressProfile.enabled.is_(True))).all()
            active_clients = session.query(Client).filter(Client.enabled.is_(True)).count()
            active_driver_processes = sum(1 for profile in profiles if profile.driver != "direct_ip")
        resources = detect_resources(active_clients=active_clients, active_driver_processes=active_driver_processes)
        with db.session() as session:
            node = session.get(ManagedNode, 1)
            if node is not None:
                node.architecture = resources.architecture
            estimate = calculate_capacity(resources, [profile.driver for profile in profiles] or ["direct_ip"])
            used_gb, forecast_gb = transfer_forecast(resources.traffic_bytes)
            session.add(CapacitySnapshot(architecture=resources.architecture, vcpus=resources.vcpus, memory_mb=resources.memory_mb, load_1m=resources.load_1m, active_clients=resources.active_clients, active_driver_processes=resources.active_driver_processes, disk_free_mb=resources.disk_free_mb, transfer_used_gb=used_gb, transfer_forecast_gb=forecast_gb, safe_active_clients=estimate.safe_active_clients, max_stored_configs=estimate.max_stored_configs, max_egress_profiles=estimate.max_egress_profiles, estimated_mbps=estimate.estimated_mbps, limiting_factor=estimate.limiting_factor, confidence=estimate.confidence, over_capacity=estimate.over_capacity))
    print("Capacity refreshed")
    return 0


def cmd_remote_admin(settings: Settings, action: str) -> int:
    if action != "renew":
        print("Only remote-admin renewal is supported from SSH.", file=sys.stderr)
        return 1
    with _db(settings) as db:
        if db.get_setting("remote_admin_enabled", "0") != "1":
            print("Remote administration is disabled; no certificate renewal is needed.")
            return 0
        operations = OperationService(db, AgentClient(settings.agent_socket))
        _operation, response = operations.run(
            "remote_admin.renew", {}, actor="certificate-renewal"
        )
    if response.status != "succeeded":
        print(
            f"Remote administration certificate renewal failed safely: {(response.error_message or response.error_code or 'unknown error')[:400]}",
            file=sys.stderr,
        )
        return 1
    print("Remote administration certificate checked and HTTPS reloaded.")
    return 0


def _run_fixed(argv: list[str], timeout: int = 30) -> subprocess.CompletedProcess:
    if not argv or any(not isinstance(item, str) or "\x00" in item for item in argv):
        raise ValueError("invalid maintenance command")
    return subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)


class _MaintenanceRunner:
    """Adapter for fixed maintenance commands used by read-only verifiers."""

    @staticmethod
    def run(argv: list[str], timeout: int = 10) -> subprocess.CompletedProcess:
        return _run_fixed(argv, timeout=timeout)


def _command_succeeded(argv: list[str], timeout: int = 30) -> bool:
    try:
        return _run_fixed(argv, timeout=timeout).returncode == 0
    except (OSError, subprocess.SubprocessError, ValueError):
        return False


def _service_state(unit: str) -> str:
    try:
        result = _run_fixed(["systemctl", "is-active", unit], timeout=5)
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    return (result.stdout or result.stderr or "unknown").strip()[:40]


def cmd_repair(settings: Settings) -> int:
    with _db(settings) as db:
        request = AgentRequest(uuid.uuid4().hex, "system.snapshot", desired_generation=0, payload={})
        response = AgentClient(settings.agent_socket).execute(request) if settings.agent_socket.exists() else None
        services = {unit: _service_state(unit) for unit in PERSISTENT_SERVICE_UNITS}
        output = {"agent": response.to_dict() if response else {"status": "unavailable"}, "services": services}
        if response and response.status == "succeeded":
            with db.session() as session:
                node = session.get(ManagedNode, 1)
                node.observed_generation = max(node.observed_generation, response.observed_generation or 0)
    print(json.dumps(output, indent=2))
    return 0 if response and response.status == "succeeded" else 1


def cmd_backup(settings: Settings) -> int:
    passphrase = getpass.getpass("Backup passphrase: ")
    with _db(settings) as db:
        output = create_backup(settings, db, passphrase)
    print(output)
    return 0


def _restore_extra_items(settings: Settings) -> tuple[tuple[str, Path], ...]:
    return (
        ("recovery", settings.state_dir / "recovery"),
        ("admin-initial.conf", settings.state_dir / "admin-initial.conf"),
        ("admin-initial.pub", settings.state_dir / "admin-initial.pub"),
    )


def _snapshot_restore_extras(settings: Settings, snapshot: Path) -> None:
    root = snapshot / "restore-extras"
    root.mkdir(parents=True, exist_ok=True)
    root.chmod(0o700)
    manifest: dict[str, bool] = {}
    for name, source in _restore_extra_items(settings):
        present = source.exists() or source.is_symlink()
        manifest[name] = present
        if not present:
            continue
        destination = root / name
        if source.is_dir() and not source.is_symlink():
            shutil.copytree(source, destination, symlinks=True)
        else:
            shutil.copy2(source, destination, follow_symlinks=False)
        _copy_path_ownership(source, destination)
    temporary = root / ".manifest.json.new"
    temporary.write_text(json.dumps(manifest, sort_keys=True))
    os.replace(temporary, root / "manifest.json")


def _restore_restore_extras(settings: Settings, snapshot: Path) -> None:
    root = snapshot / "restore-extras"
    manifest_path = root / "manifest.json"
    try:
        manifest = json.loads(manifest_path.read_text())
    except (OSError, TypeError, ValueError) as exc:
        raise RuntimeError("the pre-restore extra-state snapshot is invalid") from exc
    expected = {name for name, _path in _restore_extra_items(settings)}
    if not isinstance(manifest, dict) or set(manifest) != expected or any(not isinstance(value, bool) for value in manifest.values()):
        raise RuntimeError("the pre-restore extra-state snapshot is invalid")
    for name, destination in _restore_extra_items(settings):
        source = root / name
        if manifest[name] and not (source.exists() or source.is_symlink()):
            raise RuntimeError("the pre-restore extra-state snapshot is incomplete")
        _remove_exact_path(destination)
        if not manifest[name]:
            continue
        destination.parent.mkdir(parents=True, exist_ok=True)
        if source.is_dir() and not source.is_symlink():
            shutil.copytree(source, destination, symlinks=True)
        else:
            shutil.copy2(source, destination, follow_symlinks=False)
        _copy_path_ownership(source, destination)


def _validate_restore_backup(settings: Settings, passphrase: str, source: Path) -> None:
    with tempfile.TemporaryDirectory(prefix="cayvpn-restore-validation-") as directory:
        root = Path(directory)
        validation = replace(
            settings,
            state_dir=root / "state",
            config_dir=root / "config",
            db_path=root / "state" / "cayvpn.db",
            wg_dir=root / "wireguard",
        )
        restore_backup(validation, passphrase, source)
        if not validation.db_path.is_file():
            raise RuntimeError("the encrypted backup does not contain a CayVPN database")
        try:
            with closing(sqlite3.connect(f"file:{validation.db_path.resolve()}?mode=ro", uri=True)) as database:
                if database.execute("PRAGMA quick_check").fetchone() != ("ok",):
                    raise RuntimeError("the encrypted backup database did not pass its integrity check")
        except sqlite3.Error as exc:
            raise RuntimeError("the encrypted backup database is unreadable") from exc


def _cmd_restore(settings: Settings, source: Path) -> int:
    active_release = _active_release_path(settings)
    passphrase = getpass.getpass("Backup passphrase: ")
    _validate_restore_backup(settings, passphrase, source)
    snapshot = settings.state_dir / "restore-snapshots" / f"{int(time.time())}-{uuid.uuid4().hex[:10]}"
    snapshot.mkdir(parents=True, exist_ok=False)
    snapshot.chmod(0o700)
    _snapshot_state_paths(settings, snapshot)
    _snapshot_restore_extras(settings, snapshot)
    stop_attempted = False
    state_mutated = False
    try:
        stop_attempted = True
        _stop_units_for_upgrade()
        state_mutated = True
        restore_backup(settings, passphrase, source)
        _run_release_migrations(active_release, settings)
        reconciliation_request = _request_runtime_reconciliation(settings)
        _restart_units()
        _wait_for_runtime_reconciliation(settings, reconciliation_request)
        if cmd_verify(settings) != 0:
            raise RuntimeError("post-restore verification failed")
    except Exception as exc:
        rolled_back = not state_mutated
        if state_mutated:
            try:
                _stop_units_for_upgrade()
                _restore_state_paths(settings, snapshot)
                _restore_restore_extras(settings, snapshot)
                reconciliation_request = _request_runtime_reconciliation(settings)
                _restart_units()
                _wait_for_runtime_reconciliation(settings, reconciliation_request)
                if cmd_verify(settings) != 0:
                    raise RuntimeError("pre-restore state verification failed")
                rolled_back = True
            except Exception:
                rolled_back = False
        elif stop_attempted:
            try:
                reconciliation_request = _request_runtime_reconciliation(settings)
                _restart_units()
                _wait_for_runtime_reconciliation(settings, reconciliation_request)
                if cmd_verify(settings) != 0:
                    raise RuntimeError("pre-restore state verification failed")
            except Exception:
                rolled_back = False
        if rolled_back:
            raise RuntimeError(f"restore failed and the previous state was restored: {exc}") from exc
        raise RuntimeError(f"restore failed and automatic recovery also failed; use snapshot {snapshot}: {exc}") from exc
    report = settings.state_dir / "restore-report.json"
    if report.exists():
        print(report.read_text())
    print(f"Backup restored, migrated, reconciled, and verified. Pre-restore recovery snapshot: {snapshot}")
    return 0


def cmd_restore(settings: Settings, source: str, confirm: bool = False) -> int:
    if not confirm:
        print("Restore pauses CayVPN and replaces its managed state. Re-run with --confirm after checking the backup path.", file=sys.stderr)
        return 2
    try:
        with update_lock(settings):
            return _cmd_restore(settings, Path(source))
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"Restore stopped safely: {str(exc)[:600]}", file=sys.stderr)
        return 1


def cmd_recovery(settings: Settings, approve: bool) -> int:
    if approve:
        code = getpass.getpass("One-time recovery code: ")
        if len(code) < 12:
            print("Recovery code rejected", file=sys.stderr)
            return 1
        with _db(settings) as db:
            db.set_setting("recovery_approval_hash", hash_password(code))
            db.set_setting("recovery_approval_until", str(now_epoch() + 300))
        print("One-time high-risk approval recorded for five minutes.")
        return 0
    print("Use cayvpnctl recovery approve to record a recovery approval.")
    return 0


def _safe_release_name(value: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,79}", value or "") or value in {".", ".."}:
        raise ValueError("invalid release identifier")
    return value


def _release_path(settings: Settings, release: str) -> Path:
    name = _safe_release_name(release)
    path = (settings.release_dir / name).resolve()
    if settings.release_dir.resolve() not in path.parents:
        raise ValueError("release path escapes the release directory")
    if not path.is_dir() or not (path / "requirements.txt").exists():
        raise ValueError("release is not installed")
    return path


def _verify_release_bundle(settings: Settings, release_path: Path, current_release: str | None = None) -> None:
    """Verify the release metadata before an owner-approved switch."""
    try:
        verify_installed_release(settings, release_path, current_release, release_path.name)
    except UpdateError as exc:
        raise RuntimeError(str(exc)) from exc


def _active_release_path(settings: Settings) -> Path:
    """Resolve and verify the release currently trusted by systemd."""
    if not settings.active_release.is_symlink():
        raise RuntimeError("the active CayVPN release link is missing or unsafe")
    try:
        resolved = settings.active_release.resolve(strict=True)
        active = _release_path(settings, resolved.name)
    except (OSError, ValueError) as exc:
        raise RuntimeError("the active CayVPN release could not be resolved safely") from exc
    if resolved != active:
        raise RuntimeError("the active CayVPN release is outside the versioned release directory")
    _verify_release_bundle(settings, active)
    return active


def _atomic_active_link(settings: Settings, release_path: Path) -> None:
    settings.active_release.parent.mkdir(parents=True, exist_ok=True)
    temporary = settings.active_release.with_name(f".{settings.active_release.name}-{uuid.uuid4().hex[:10]}")
    temporary.symlink_to(release_path, target_is_directory=True)
    os.replace(temporary, settings.active_release)


def _run_release_migrations(release_path: Path, settings: Settings) -> None:
    python = release_path / ".venv" / "bin" / "python"
    if not python.is_file():
        raise RuntimeError("release does not contain its Python migration runner")
    environment = os.environ.copy()
    environment["CAYVPN_DB_PATH"] = str(settings.db_path)
    # Console scripts embed an absolute shebang from the staging directory and
    # stop working after that directory becomes the versioned release. Invoke
    # Alembic through the moved environment's Python instead, and resolve its
    # relative migration directory from the release root.
    result = subprocess.run(
        [str(python), "-m", "alembic", "-c", str(release_path / "alembic.ini"), "upgrade", "head"],
        capture_output=True,
        text=True,
        timeout=120,
        env=environment,
        cwd=release_path,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError((result.stderr or result.stdout or "schema migration failed")[-600:])


def _restart_units() -> None:
    result = _run_fixed(["systemctl", "restart", "cayvpn-agent", "cayvpn-worker", "cayvpn-web", "nginx"], timeout=60)
    if result.returncode != 0:
        raise RuntimeError((result.stderr or result.stdout or "services did not restart")[-600:])
    result = _run_fixed(
        ["systemctl", "start", "cayvpn-remote-admin-renew.timer"], timeout=30
    )
    if result.returncode != 0:
        raise RuntimeError(
            (result.stderr or result.stdout or "certificate renewal timer did not restart")[-600:]
        )


def _copy_path_ownership(source: Path, destination: Path) -> None:
    """Mirror ownership after shutil has copied content and modes.

    ``copy2`` and ``copytree`` intentionally do not copy uid/gid. CayVPN runs
    upgrade and recovery snapshots as root, so omitting this step silently
    turns the service database and group-readable files into root-only state.
    """
    if os.geteuid() != 0:
        return
    source_stat = source.lstat()
    os.chown(destination, source_stat.st_uid, source_stat.st_gid, follow_symlinks=False)
    if source.is_dir() and not source.is_symlink():
        for child in source.iterdir():
            _copy_path_ownership(child, destination / child.name)


def _snapshot_state_paths(settings: Settings, snapshot: Path) -> None:
    """Copy only CayVPN-owned mutable state for an atomic release rollback."""
    snapshot.mkdir(parents=True, exist_ok=True)
    manifest = {}
    for name, source in (("database", settings.db_path), ("wireguard", settings.wg_dir), ("config", settings.config_dir)):
        present = source.exists() or source.is_symlink()
        manifest[name] = present
        if not present:
            continue
        destination = snapshot / name
        if name == "database" and source.is_file():
            destination.parent.mkdir(parents=True, exist_ok=True)
            with closing(sqlite3.connect(f"file:{source.resolve()}?mode=ro", uri=True)) as source_db, closing(sqlite3.connect(str(destination))) as target_db:
                source_db.backup(target_db)
                if target_db.execute("PRAGMA quick_check").fetchone() != ("ok",):
                    raise RuntimeError("the SQLite rollback snapshot did not pass its integrity check")
            shutil.copystat(source, destination, follow_symlinks=False)
        elif source.is_dir() and not source.is_symlink():
            shutil.copytree(source, destination, symlinks=True)
        else:
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination, follow_symlinks=False)
        _copy_path_ownership(source, destination)
    temporary = snapshot / ".manifest.json.new"
    temporary.write_text(json.dumps(manifest, sort_keys=True))
    os.replace(temporary, snapshot / "manifest.json")


def _restore_state_paths(settings: Settings, snapshot: Path) -> None:
    manifest_path = snapshot / "manifest.json"
    if not manifest_path.is_file() or snapshot.is_symlink():
        raise RuntimeError("the rollback snapshot is incomplete")
    try:
        manifest = json.loads(manifest_path.read_text())
    except (OSError, ValueError, TypeError) as exc:
        raise RuntimeError("the rollback snapshot manifest is invalid") from exc
    expected_items = {"database", "wireguard", "config"}
    if not isinstance(manifest, dict) or set(manifest) != expected_items or any(not isinstance(value, bool) for value in manifest.values()):
        raise RuntimeError("the rollback snapshot manifest is invalid")
    sources = {name: snapshot / name for name in expected_items}
    if any(manifest[name] and not (sources[name].exists() or sources[name].is_symlink()) for name in expected_items):
        raise RuntimeError("the rollback snapshot is missing a required item")
    if manifest["database"]:
        try:
            with closing(sqlite3.connect(f"file:{sources['database'].resolve()}?mode=ro", uri=True)) as database:
                if database.execute("PRAGMA quick_check").fetchone() != ("ok",):
                    raise RuntimeError("the rollback database snapshot is damaged")
        except sqlite3.Error as exc:
            raise RuntimeError("the rollback database snapshot is damaged") from exc
    for name, destination in (("database", settings.db_path), ("wireguard", settings.wg_dir), ("config", settings.config_dir)):
        source = snapshot / name
        if name == "database":
            _remove_sqlite_sidecars(destination)
        preserve_directory = bool(
            manifest[name] and source.is_dir() and not source.is_symlink()
            and destination.is_dir() and not destination.is_symlink()
        )
        if destination.exists() or destination.is_symlink():
            if preserve_directory:
                # systemd exposes these exact directories as writable mounts.
                # Replacing their contents is permitted; removing the mount
                # itself requires writes to the protected /etc parent.
                for child in destination.iterdir():
                    if child.is_dir() and not child.is_symlink():
                        shutil.rmtree(child)
                    else:
                        child.unlink()
            elif destination.is_dir() and not destination.is_symlink():
                shutil.rmtree(destination)
            else:
                destination.unlink()
        if not manifest.get(name) or not source.exists():
            continue
        destination.parent.mkdir(parents=True, exist_ok=True)
        if source.is_dir() and not source.is_symlink():
            shutil.copytree(source, destination, symlinks=True, dirs_exist_ok=preserve_directory)
        else:
            shutil.copy2(source, destination, follow_symlinks=False)
        _copy_path_ownership(source, destination)
        if name == "database":
            try:
                with closing(sqlite3.connect(f"file:{destination.resolve()}?mode=ro", uri=True)) as database:
                    if database.execute("PRAGMA quick_check").fetchone() != ("ok",):
                        raise RuntimeError("the restored rollback database is damaged")
            except sqlite3.Error as exc:
                raise RuntimeError("the restored rollback database is damaged") from exc


def _matching_upgrade_snapshot(settings: Settings, previous_release: Path, target_release: Path | None = None) -> Path | None:
    root = settings.state_dir / "upgrade-snapshots"
    if not root.is_dir():
        return None
    for candidate in sorted((item for item in root.iterdir() if item.is_dir()), key=lambda item: item.name, reverse=True):
        marker = candidate / "previous-release"
        target_marker = candidate / "target-release"
        if not marker.is_file() or Path(marker.read_text().strip()).resolve() != previous_release.resolve():
            continue
        if target_release is not None and (not target_marker.is_file() or Path(target_marker.read_text().strip()).resolve() != target_release.resolve()):
            continue
        if (candidate / "manifest.json").is_file():
            return candidate
    return None


def _stop_units_for_upgrade() -> None:
    # Stop both the scheduler and a possibly running renewal job before the
    # agent or active release changes.  Otherwise a short-lived-certificate
    # renewal could execute code through the symlink while an update switches
    # that symlink underneath it.
    result = _run_fixed(
        [
            "systemctl",
            "stop",
            "cayvpn-remote-admin-renew.timer",
            "cayvpn-remote-admin-renew.service",
            "cayvpn-web",
            "cayvpn-worker",
            "cayvpn-agent",
        ],
        timeout=60,
    )
    if result.returncode != 0:
        raise RuntimeError((result.stderr or result.stdout or "CayVPN services could not be paused safely")[-600:])


def _request_runtime_reconciliation(settings: Settings) -> str:
    request_id = uuid.uuid4().hex
    with _db(settings) as database:
        database.set_setting("runtime_reconciliation_request", request_id)
        database.set_setting("runtime_reconciliation_completed", "")
    return request_id


def _wait_for_runtime_reconciliation(settings: Settings, request_id: str, timeout: float = 180.0) -> None:
    with _db(settings) as database:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if database.get_setting("runtime_reconciliation_completed", "") == request_id:
                return
            time.sleep(0.5)
    raise RuntimeError("the restarted worker did not reconcile client routes and DNS before the update deadline")


def cmd_upgrade(settings: Settings, release: str | None, confirm: bool) -> int:
    if not confirm:
        print("Upgrade is owner-approved only. Re-run with --confirm after reviewing the signed release.", file=sys.stderr)
        return 2
    with update_lock(settings):
        return _cmd_upgrade(settings, release)


def _cmd_upgrade(settings: Settings, release: str | None) -> int:
    previous = _active_release_path(settings)
    candidates = []
    if settings.release_dir.exists():
        for path in settings.release_dir.iterdir():
            if not path.is_dir() or path.is_symlink():
                continue
            try:
                version = Version.parse(path.name)
            except UpdateError:
                continue
            candidates.append((version, path))
        candidates.sort(key=lambda item: item[0])
    if release is None:
        candidates = [item for item in candidates if item[1].resolve() != previous]
        if not candidates:
            raise ValueError("no alternate installed release is available")
        release = candidates[-1][1].name
    target = _release_path(settings, release)
    if target == previous:
        raise ValueError("the requested release is already active")
    snapshot = settings.state_dir / "upgrade-snapshots" / f"{int(time.time())}-{uuid.uuid4().hex[:10]}"
    snapshot.mkdir(parents=True, exist_ok=True)
    (snapshot / "previous-release").write_text(str(previous) + "\n")
    (snapshot / "target-release").write_text(str(target) + "\n")
    write_update_state(
        settings,
        "installing",
        phase="preparing",
        current_release=previous.name,
        target_release=target.name,
        previous_release=str(previous),
        snapshot=str(snapshot),
    )
    state_mutated = False
    stop_attempted = False
    try:
        _verify_release_bundle(settings, target, previous.name)
        write_update_state(settings, "installing", phase="release_verified", current_release=previous.name, target_release=target.name, previous_release=str(previous), snapshot=str(snapshot))
        _snapshot_state_paths(settings, snapshot)
        write_update_state(settings, "installing", phase="snapshot_ready", current_release=previous.name, target_release=target.name, previous_release=str(previous), snapshot=str(snapshot))
        stop_attempted = True
        _stop_units_for_upgrade()
        write_update_state(settings, "installing", phase="services_stopped", current_release=previous.name, target_release=target.name, previous_release=str(previous), snapshot=str(snapshot))
        state_mutated = True
        write_update_state(settings, "installing", phase="migrating", current_release=previous.name, target_release=target.name, previous_release=str(previous), snapshot=str(snapshot))
        _run_release_migrations(target, settings)
        write_update_state(settings, "installing", phase="migrated", current_release=previous.name, target_release=target.name, previous_release=str(previous), snapshot=str(snapshot))
        sync_release_components(settings, target)
        write_update_state(settings, "installing", phase="components_synchronized", current_release=previous.name, target_release=target.name, previous_release=str(previous), snapshot=str(snapshot))
        reconciliation_request = _request_runtime_reconciliation(settings)
        _atomic_active_link(settings, target)
        write_update_state(settings, "installing", phase="switched", current_release=previous.name, target_release=target.name, previous_release=str(previous), snapshot=str(snapshot))
        _restart_units()
        write_update_state(settings, "installing", phase="services_restarted", current_release=previous.name, target_release=target.name, previous_release=str(previous), snapshot=str(snapshot))
        _wait_for_runtime_reconciliation(settings, reconciliation_request)
        write_update_state(settings, "installing", phase="runtime_reconciled", current_release=previous.name, target_release=target.name, previous_release=str(previous), snapshot=str(snapshot))
        if cmd_verify(settings) != 0:
            raise RuntimeError("post-upgrade verification failed")
    except Exception as exc:
        rolled_back = not state_mutated
        if state_mutated:
            try:
                _stop_units_for_upgrade()
                _restore_state_paths(settings, snapshot)
                _atomic_active_link(settings, previous)
                rollback_reconciliation = _request_runtime_reconciliation(settings)
                _restart_units()
                _wait_for_runtime_reconciliation(settings, rollback_reconciliation)
                if cmd_verify(settings) != 0:
                    raise RuntimeError("restored release verification failed")
                rolled_back = True
            except Exception:
                rolled_back = False
        elif stop_attempted:
            try:
                rollback_reconciliation = _request_runtime_reconciliation(settings)
                _restart_units()
                _wait_for_runtime_reconciliation(settings, rollback_reconciliation)
                if cmd_verify(settings) != 0:
                    raise RuntimeError("restarted release verification failed")
            except Exception:
                rolled_back = False
        write_update_state(
            settings,
            "install_failed",
            phase="rolled_back" if rolled_back else "recovery_required",
            current_release=previous.name,
            target_release=target.name,
            previous_release=str(previous),
            snapshot=str(snapshot),
            rolled_back=rolled_back,
            error_code="upgrade_failed",
            error_message="The update failed its installation or health checks.",
        )
        raise
    # Keep the release we can safely return to, not the newly active one.
    # This makes rollback deterministic even when several versions remain.
    (settings.state_dir / "last-good-release").write_text(str(previous) + "\n")
    update_metadata(settings, highest_installed_release=target.name, installed_at=datetime.now(timezone.utc).isoformat())
    with _db(settings) as database:
        with database.session() as session:
            node = session.get(ManagedNode, 1)
            node.release = target.name
    retention = prune_update_history(settings)
    write_update_state(settings, "installed", current_release=target.name, target_release=target.name, previous_release=str(previous), snapshot=str(snapshot), rolled_back=False, retention=retention)
    print(f"Upgraded to {target.name}")
    return 0


def cmd_rollback(settings: Settings, confirm: bool) -> int:
    if not confirm:
        print("Rollback is owner-approved only. Re-run with --confirm after checking status.", file=sys.stderr)
        return 2
    with update_lock(settings):
        return _cmd_rollback(settings)


def _cmd_rollback(settings: Settings) -> int:
    marker = settings.state_dir / "last-good-release"
    candidates = []
    if marker.exists():
        candidates.append(Path(marker.read_text().strip()))
    versioned_candidates = []
    if settings.release_dir.exists():
        for path in settings.release_dir.iterdir():
            if not path.is_dir() or path.is_symlink():
                continue
            try:
                versioned_candidates.append((Version.parse(path.name), path))
            except UpdateError:
                continue
    candidates.extend(path for _version, path in sorted(versioned_candidates, key=lambda item: item[0], reverse=True))
    current = _active_release_path(settings)
    target = None
    for candidate in candidates:
        try:
            canonical = _release_path(settings, candidate.name)
        except (OSError, ValueError):
            continue
        if candidate.resolve() != canonical or canonical == current:
            continue
        target = canonical
        break
    if target is None:
        raise ValueError("no previous release is available")
    restore_snapshot = _matching_upgrade_snapshot(settings, target, current)
    if restore_snapshot is None:
        raise RuntimeError("the matching pre-upgrade snapshot is unavailable; rollback was not started")
    _verify_release_bundle(settings, target, current.name)
    snapshot = settings.state_dir / "rollback-snapshots" / f"{int(time.time())}-{uuid.uuid4().hex[:10]}"
    _snapshot_state_paths(settings, snapshot)
    write_update_state(settings, "installing", phase="rollback_snapshot_ready", current_release=current.name, target_release=target.name, previous_release=str(current), snapshot=str(snapshot), rollback=True)
    stop_attempted = False
    state_mutated = False
    try:
        stop_attempted = True
        _stop_units_for_upgrade()
        state_mutated = True
        write_update_state(settings, "installing", phase="rollback_restoring", current_release=current.name, target_release=target.name, previous_release=str(current), snapshot=str(snapshot), rollback=True)
        _restore_state_paths(settings, restore_snapshot)
        reconciliation_request = _request_runtime_reconciliation(settings)
        _atomic_active_link(settings, target)
        _restart_units()
        _wait_for_runtime_reconciliation(settings, reconciliation_request)
        if cmd_verify(settings) != 0:
            raise RuntimeError("rollback verification failed")
    except Exception as exc:
        reverted = not state_mutated
        if state_mutated:
            try:
                _stop_units_for_upgrade()
                _restore_state_paths(settings, snapshot)
                _atomic_active_link(settings, current)
                recovery_request = _request_runtime_reconciliation(settings)
                _restart_units()
                _wait_for_runtime_reconciliation(settings, recovery_request)
                if cmd_verify(settings) != 0:
                    raise RuntimeError("pre-rollback release verification failed")
                reverted = True
            except Exception:
                reverted = False
        elif stop_attempted:
            try:
                recovery_request = _request_runtime_reconciliation(settings)
                _restart_units()
                _wait_for_runtime_reconciliation(settings, recovery_request)
                if cmd_verify(settings) != 0:
                    raise RuntimeError("pre-rollback release verification failed")
                reverted = True
            except Exception:
                reverted = False
        write_update_state(
            settings,
            "rollback_failed",
            phase="previous_release_restored" if reverted else "recovery_required",
            current_release=current.name,
            target_release=target.name,
            previous_release=str(current),
            snapshot=str(snapshot),
            rolled_back=False,
            error_code="rollback_failed",
            error_message=(
                "The rollback failed, but CayVPN restored and verified the release that was active before it began."
                if reverted
                else "The rollback failed and CayVPN could not verify restoration. Use cayvpnctl repair over SSH."
            ),
        )
        if not reverted:
            raise RuntimeError(
                "rollback failed and the previously active release could not be verified"
            ) from exc
        raise
    with _db(settings) as database:
        with database.session() as session:
            node = session.get(ManagedNode, 1)
            node.release = target.name
    (settings.state_dir / "last-good-release").write_text(str(current) + "\n")
    retention = prune_update_history(settings)
    write_update_state(settings, "rolled_back", current_release=target.name, target_release=target.name, previous_release=str(current), snapshot=str(snapshot), rolled_back=True, retention=retention)
    print(f"Rolled back to {target.name}")
    return 0


def cmd_diagnostics(settings: Settings) -> int:
    with _db(settings) as db:
        with db.session() as session:
            node = session.get(ManagedNode, 1)
            capacity = session.scalar(select(CapacitySnapshot).order_by(desc(CapacitySnapshot.observed_at)))
            profiles = session.scalars(select(EgressProfile).where(EgressProfile.enabled.is_(True))).all()
    payload = {
        "node": {"install_state": node.install_state, "release": node.release, "desired_generation": node.desired_generation, "observed_generation": node.observed_generation},
        "capacity": {"architecture": capacity.architecture, "vcpus": capacity.vcpus, "memory_mb": capacity.memory_mb, "safe_active_clients": capacity.safe_active_clients, "confidence": capacity.confidence} if capacity else None,
        "egress": [{"id": profile.id, "driver": profile.driver, "health_state": profile.health_state, "capabilities": profile.capabilities} for profile in profiles],
        "services": {unit: _service_state(unit) for unit in PERSISTENT_SERVICE_UNITS},
    }
    print(json.dumps(payload, indent=2))
    return 0


def cmd_admin_device(settings: Settings, action: str, device_id: int | None) -> int:
    with _db(settings) as db:
        if action == "list":
            with db.session() as session:
                devices = session.scalars(select(AdminDevice).order_by(AdminDevice.id)).all()
            print(json.dumps([{"id": item.id, "name": item.name, "address": item.address, "enabled": item.enabled} for item in devices], indent=2))
            return 0
        if not device_id:
            print("A device id is required for revoke.", file=sys.stderr)
            return 2
        with db.session() as session:
            device = session.get(AdminDevice, device_id)
            if device is None:
                raise ValueError("admin device not found")
            secret_ref = device.private_key_enc
            peers = [{"public_key": item.public_key, "allowed_ips": item.address} for item in session.scalars(select(AdminDevice).where(AdminDevice.enabled.is_(True), AdminDevice.id != device_id)).all()]
        request = AgentRequest(uuid.uuid4().hex, "admin.reconcile", payload={"interface": settings.admin_interface, "listen_port": settings.admin_port, "address_cidr": settings.admin_address, "peers": peers})
        response = AgentClient(settings.agent_socket).execute(request)
        if response.status == "succeeded":
            with db.session() as session:
                device = session.get(AdminDevice, device_id)
                if device is not None:
                    device.enabled = False
                    device.revoked_at = datetime.now(timezone.utc)
            if secret_ref and secret_ref.startswith("ref::"):
                AgentClient(settings.agent_socket).execute(AgentRequest(uuid.uuid4().hex, "secret.delete", payload={"secret_ref": secret_ref}))
    print(json.dumps(response.to_dict(), indent=2))
    return 0 if response.status == "succeeded" else 1


UNINSTALL_BACKUP_ROOT = Path("/var/backups/cayvpn")
_INSTALL_SNAPSHOT_PATTERN = re.compile(r"install-[0-9]{8}T[0-9]{6}Z-[0-9]+")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _snapshot_inventory(root: Path) -> dict[str, str]:
    inventory: dict[str, str] = {}
    for directory, directory_names, file_names in os.walk(root, topdown=True, followlinks=False):
        base = Path(directory)
        for name in list(directory_names):
            path = base / name
            relative = path.relative_to(root).as_posix()
            if path.is_symlink():
                inventory[relative] = f"symlink:{os.readlink(path)}"
                directory_names.remove(name)
            else:
                inventory[relative] = "directory"
        for name in file_names:
            path = base / name
            relative = path.relative_to(root).as_posix()
            if relative in {"snapshot-manifest.json", ".snapshot-manifest.json.new"}:
                continue
            if path.is_symlink():
                inventory[relative] = f"symlink:{os.readlink(path)}"
            elif path.is_file():
                inventory[relative] = f"file:{_sha256_file(path)}"
            else:
                raise RuntimeError(f"the install snapshot contains an unsupported entry: {relative}")
    return dict(sorted(inventory.items()))


def _normalized_uninstall_paths(settings: Settings, backup_root: Path) -> dict[str, Path]:
    paths = {
        "install_root": settings.release_dir.parent,
        "active_release": settings.active_release,
        "state_dir": settings.state_dir,
        "config_dir": settings.config_dir,
        "wireguard_dir": settings.wg_dir,
        "snapshot_root": backup_root,
    }
    protected = {Path("/"), Path("/etc"), Path("/opt"), Path("/usr"), Path("/var"), Path("/var/lib"), Path("/var/backups")}
    normalized: dict[str, Path] = {}
    for name, path in paths.items():
        if not path.is_absolute() or "\x00" in str(path):
            raise RuntimeError("CayVPN uninstall paths are invalid")
        if name == "active_release":
            # The installed active path is intentionally a symlink switched
            # atomically between versioned release directories. Validate its
            # lexical parent here, then validate the symlink target below.
            resolved_parent = path.parent.resolve(strict=False)
            if resolved_parent != path.parent or path in protected or len(path.parts) < 3:
                raise RuntimeError("the CayVPN active release path is unsafe")
            normalized[name] = path
            continue
        resolved = path.resolve(strict=False)
        if resolved != path or resolved in protected or len(resolved.parts) < 3:
            raise RuntimeError(f"the CayVPN {name.replace('_', ' ')} path is unsafe")
        normalized[name] = resolved
    install_root = normalized["install_root"]
    if settings.release_dir != install_root / "releases" or normalized["active_release"] != install_root / "current":
        raise RuntimeError("the CayVPN versioned installation layout is invalid")
    active_release = normalized["active_release"]
    release_root = settings.release_dir.resolve(strict=False)
    try:
        active_target = active_release.resolve(strict=True)
    except OSError as exc:
        raise RuntimeError("the active CayVPN release link is missing or unsafe") from exc
    if (
        not active_release.is_symlink()
        or release_root != settings.release_dir
        or not release_root.is_dir()
        or not active_target.is_dir()
        or active_target.parent != release_root
    ):
        raise RuntimeError("the active CayVPN release link is missing or unsafe")
    persistent = [normalized[name] for name in ("state_dir", "config_dir", "wireguard_dir", "snapshot_root")]
    if any(install_root == path or install_root in path.parents or path in install_root.parents for path in persistent):
        raise RuntimeError("the CayVPN installation path overlaps persistent or recovery state")
    database = settings.db_path.resolve(strict=False)
    if database == normalized["state_dir"] or normalized["state_dir"] not in database.parents:
        raise RuntimeError("the CayVPN database is outside its persistent state directory")
    return normalized


def _validated_install_snapshot(settings: Settings, backup_root: Path = UNINSTALL_BACKUP_ROOT) -> Path:
    paths = _normalized_uninstall_paths(settings, backup_root)
    pointer = settings.state_dir / "last-install-snapshot"
    if pointer.is_symlink() or not pointer.is_file():
        raise RuntimeError("the verified pre-install snapshot pointer is missing")
    raw_snapshot = pointer.read_text().strip()
    if not raw_snapshot or "\n" in raw_snapshot or "\r" in raw_snapshot or "\x00" in raw_snapshot:
        raise RuntimeError("the pre-install snapshot pointer is invalid")
    supplied = Path(raw_snapshot)
    root = paths["snapshot_root"]
    if root.is_symlink() or not root.is_dir():
        raise RuntimeError("the protected install snapshot directory is missing or unsafe")
    if not supplied.is_absolute() or supplied.parent.resolve(strict=False) != root or not _INSTALL_SNAPSHOT_PATTERN.fullmatch(supplied.name):
        raise RuntimeError("the pre-install snapshot is outside the protected snapshot directory")
    snapshot = supplied.resolve(strict=True)
    if snapshot != root / supplied.name or snapshot.is_symlink() or not snapshot.is_dir():
        raise RuntimeError("the pre-install snapshot directory is unsafe")
    manifest_path = snapshot / "snapshot-manifest.json"
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise RuntimeError("the pre-install snapshot manifest is missing")
    try:
        manifest = json.loads(manifest_path.read_text())
    except (OSError, ValueError, TypeError) as exc:
        raise RuntimeError("the pre-install snapshot manifest is invalid") from exc
    expected_keys = {"format", "paths", "interfaces", "inventory"}
    expected_paths = {name: str(path) for name, path in paths.items()}
    expected_interfaces = {"user": settings.user_interface, "amnezia": settings.amnezia_interface, "admin": settings.admin_interface}
    if (
        not isinstance(manifest, dict)
        or set(manifest) != expected_keys
        or manifest.get("format") != 1
        or manifest.get("paths") != expected_paths
        or manifest.get("interfaces") != expected_interfaces
        or not isinstance(manifest.get("inventory"), dict)
        or any(not isinstance(key, str) or not isinstance(value, str) for key, value in manifest["inventory"].items())
    ):
        raise RuntimeError("the pre-install snapshot manifest does not match this installation")
    if _snapshot_inventory(snapshot) != manifest["inventory"]:
        raise RuntimeError("the pre-install snapshot failed its integrity check")
    if not (snapshot / "service-state.txt").is_file():
        raise RuntimeError("the pre-install service state is missing")
    _parsed_service_states(settings, snapshot)
    if (snapshot / "install-root-present").exists():
        raise RuntimeError("uninstall cannot safely remove an installation path that existed before CayVPN")
    return snapshot


def _remove_exact_path(path: Path) -> None:
    if path.is_symlink() or path.is_file():
        path.unlink()
    elif path.is_dir():
        shutil.rmtree(path)
    elif path.exists():
        raise RuntimeError(f"refusing to remove unsupported path type: {path}")


def _restore_snapshot_item(source: Path, destination: Path) -> None:
    _remove_exact_path(destination)
    if not (source.exists() or source.is_symlink()):
        return
    destination.parent.mkdir(parents=True, exist_ok=True)
    if source.is_symlink():
        destination.symlink_to(os.readlink(source), target_is_directory=source.is_dir())
    elif source.is_dir():
        shutil.copytree(source, destination, symlinks=True)
    elif source.is_file():
        shutil.copy2(source, destination, follow_symlinks=False)
    else:
        raise RuntimeError(f"the install snapshot contains an unsupported item: {source.name}")


def _preserve_uninstall_backup(source: Path, backup_root: Path = UNINSTALL_BACKUP_ROOT) -> Path:
    if source.is_symlink() or not source.is_file():
        raise RuntimeError("the encrypted uninstall backup was not created safely")
    if backup_root.is_symlink():
        raise RuntimeError("the uninstall backup directory is unsafe")
    backup_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    backup_root.chmod(0o700)
    digest = _sha256_file(source)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    destination = backup_root / f"cayvpn-uninstall-{timestamp}-{digest[:16]}-{uuid.uuid4().hex[:8]}.backup"
    temporary = backup_root / f".{destination.name}.new"
    try:
        with source.open("rb") as input_file, temporary.open("xb") as output_file:
            shutil.copyfileobj(input_file, output_file, length=1024 * 1024)
            output_file.flush()
            os.fsync(output_file.fileno())
        temporary.chmod(0o600)
        os.replace(temporary, destination)
        destination.chmod(0o600)
    finally:
        if temporary.exists():
            temporary.unlink()
    if _sha256_file(destination) != digest:
        _remove_exact_path(destination)
        raise RuntimeError("the preserved uninstall backup failed verification")
    return destination


def _run_required(argv: list[str], timeout: int = 60) -> None:
    result = _run_fixed(argv, timeout=timeout)
    if result.returncode != 0:
        message = (result.stderr or result.stdout or f"{argv[0]} failed").strip()[-600:]
        raise RuntimeError(message)


def _deactivate_all_egress(settings: Settings, database: Database) -> None:
    with database.session() as session:
        profile_ids = sorted(session.scalars(select(EgressProfile.id)).all())
    client = AgentClient(settings.agent_socket)
    failures = []
    for profile_id in profile_ids:
        response = client.execute(AgentRequest(uuid.uuid4().hex, "egress.deactivate", payload={"profile_id": profile_id, "remove_namespace": True}))
        if response.status != "succeeded":
            failures.append(f"{profile_id}:{response.error_code or response.status}")
    if failures:
        raise RuntimeError("the root agent could not remove every egress runtime (" + ", ".join(failures) + ")")


def _recorded_service_units(settings: Settings) -> tuple[str, ...]:
    return (
        "cayvpn-update-recovery.service",
        "cayvpn-agent.service",
        "cayvpn-worker.service",
        "cayvpn-web.service",
        "cayvpn-remote-admin-renew.service",
        "cayvpn-remote-admin-renew.timer",
        f"wg-quick@{settings.user_interface}.service",
        f"wg-quick@{settings.admin_interface}.service",
        "dnsmasq.service",
        "nftables.service",
        "nginx.service",
        "unattended-upgrades.service",
    )


_LEGACY_MISSING_SERVICE_UNITS = frozenset({
    "cayvpn-remote-admin-renew.service",
    "cayvpn-remote-admin-renew.timer",
})
_OPTIONAL_LEGACY_SERVICE_UNITS = frozenset({"AdGuardHome.service"})


def _parsed_service_states(settings: Settings, snapshot: Path) -> dict[str, tuple[str, str]]:
    allowed = set(_recorded_service_units(settings)) | set(_OPTIONAL_LEGACY_SERVICE_UNITS)
    records: dict[str, tuple[str, str]] = {}
    for line in (snapshot / "service-state.txt").read_text().splitlines():
        fields = line.split()
        if len(fields) != 3 or not fields[1].startswith("enabled=") or not fields[2].startswith("active="):
            raise RuntimeError("the pre-install service state is invalid")
        unit, enabled, active = fields[0], fields[1][8:], fields[2][7:]
        if unit not in allowed or unit in records:
            raise RuntimeError("the pre-install service state contains an unexpected unit")
        records[unit] = (enabled, active)
    missing = set(_recorded_service_units(settings)) - set(records)
    if not missing.issubset(_LEGACY_MISSING_SERVICE_UNITS):
        raise RuntimeError("the pre-install service state is incomplete")
    # Install snapshots made before private remote access was added cannot
    # mention these CayVPN-owned units. They did not exist before installation,
    # so their exact historical state is safely equivalent to not-found.
    for unit in missing:
        records[unit] = ("not-found", "inactive")
    return records


def _restore_service_states(settings: Settings, snapshot: Path) -> None:
    records = _parsed_service_states(settings, snapshot)
    units = list(_recorded_service_units(settings))
    units.extend(sorted(_OPTIONAL_LEGACY_SERVICE_UNITS & set(records)))
    for unit in units:
        enabled, active = records[unit]
        allow_missing = enabled == "not-found"
        if enabled in {"enabled", "enabled-runtime", "linked", "linked-runtime", "alias"}:
            _run_required(["systemctl", "enable", unit])
        elif enabled in {"masked", "masked-runtime"}:
            _run_required(["systemctl", "mask", unit])
        elif enabled == "disabled":
            _run_required(["systemctl", "disable", unit])
        elif enabled == "not-found":
            # A package installed by CayVPN may have added and enabled this
            # service. Keep it from starting after uninstall, even though the
            # package itself is retained. Removed CayVPN units may be absent.
            result = _run_fixed(["systemctl", "disable", unit], timeout=60)
            if result.returncode != 0:
                loaded = _run_fixed(["systemctl", "show", "--property=LoadState", "--value", unit])
                if loaded.stdout.strip() != "not-found":
                    raise RuntimeError((result.stderr or result.stdout or f"could not disable {unit}").strip()[-600:])
        elif enabled not in {"static", "indirect", "generated", "transient", "not-found", ""}:
            raise RuntimeError(f"the pre-install enabled state for {unit} is unsupported")
        if active in {"active", "activating", "reloading"}:
            _run_required(["systemctl", "restart", unit])
        elif active in {"inactive", "failed", "deactivating", "unknown", ""}:
            result = _run_fixed(["systemctl", "stop", unit], timeout=60)
            if result.returncode != 0 and not allow_missing:
                raise RuntimeError((result.stderr or result.stdout or f"could not stop {unit}").strip()[-600:])
        else:
            raise RuntimeError(f"the pre-install active state for {unit} is unsupported")


def _restore_install_snapshot(settings: Settings, snapshot: Path, backup_root: Path = UNINSTALL_BACKUP_ROOT) -> None:
    install_root = _normalized_uninstall_paths(settings, backup_root)["install_root"]
    service_records = _parsed_service_states(settings, snapshot)
    restore_items = (
        ("wireguard", settings.wg_dir),
        ("cayvpn", settings.config_dir),
        ("state", settings.state_dir),
        ("nftables.conf", Path("/etc/nftables.conf")),
        ("99-cayvpn-forwarding.conf", Path("/etc/sysctl.d/99-cayvpn-forwarding.conf")),
        ("external/cayvpn-admin.conf", Path("/etc/dnsmasq.d/cayvpn-admin.conf")),
        ("external/nginx-cayvpn", Path("/etc/nginx/sites-available/cayvpn")),
        ("external/nginx-enabled-cayvpn", Path("/etc/nginx/sites-enabled/cayvpn")),
        ("external/nginx-enabled-cayvpn-remote", Path("/etc/nginx/sites-enabled/cayvpn-remote")),
        ("external/nginx-enabled-default", Path("/etc/nginx/sites-enabled/default")),
        ("external/nginx-cayvpn-dropin", Path("/etc/systemd/system/nginx.service.d/10-cayvpn-admin.conf")),
        ("external/cayvpnctl", Path("/usr/local/bin/cayvpnctl")),
        ("external/52-cayvpn-security-updates", Path("/etc/apt/apt.conf.d/52-cayvpn-security-updates")),
        ("cayvpn-update-recovery.service", Path("/etc/systemd/system/cayvpn-update-recovery.service")),
        ("cayvpn-agent.service", Path("/etc/systemd/system/cayvpn-agent.service")),
        ("cayvpn-worker.service", Path("/etc/systemd/system/cayvpn-worker.service")),
        ("cayvpn-web.service", Path("/etc/systemd/system/cayvpn-web.service")),
        ("cayvpn-remote-admin-renew.service", Path("/etc/systemd/system/cayvpn-remote-admin-renew.service")),
        ("cayvpn-remote-admin-renew.timer", Path("/etc/systemd/system/cayvpn-remote-admin-renew.timer")),
    )
    for source_name, destination in restore_items:
        _restore_snapshot_item(snapshot / source_name, destination)
    # Install snapshots from older CayVPN builds included AdGuard Home. Restore
    # it only when that independently validated legacy record is present. A
    # current snapshot deliberately omits it so uninstall cannot remove an
    # owner-managed AdGuard installation added after CayVPN was installed.
    if "AdGuardHome.service" in service_records:
        _restore_snapshot_item(snapshot / "external/AdGuardHome", Path("/opt/AdGuardHome"))
        _restore_snapshot_item(
            snapshot / "AdGuardHome.service",
            Path("/etc/systemd/system/AdGuardHome.service"),
        )
    os.chdir("/")
    _remove_exact_path(install_root)
    _remove_exact_path(Path("/run/cayvpn"))
    _run_required(["systemctl", "daemon-reload"])
    if shutil.which("nft"):
        _run_required(["nft", "flush", "ruleset"])
        live_rules = snapshot / "nftables-live.conf"
        if live_rules.is_file() and live_rules.stat().st_size:
            _run_required(["nft", "-f", str(live_rules)])
        elif not live_rules.exists() and Path("/etc/nftables.conf").is_file():
            _run_required(["nft", "-f", "/etc/nftables.conf"])
    _run_required(["sysctl", "--system"], timeout=120)
    _restore_service_states(settings, snapshot)
    if not (snapshot / "cayvpn-user-present").exists():
        result = _run_fixed(["userdel", "cayvpn"], timeout=30)
        if result.returncode != 0 and _command_succeeded(["getent", "passwd", "cayvpn"]):
            raise RuntimeError((result.stderr or result.stdout or "the CayVPN system user could not be removed").strip()[-600:])
    if not (snapshot / "cayvpn-group-present").exists():
        result = _run_fixed(["groupdel", "cayvpn"], timeout=30)
        if result.returncode != 0 and _command_succeeded(["getent", "group", "cayvpn"]):
            raise RuntimeError((result.stderr or result.stdout or "the CayVPN system group could not be removed").strip()[-600:])


def _restart_interrupted_uninstall(settings: Settings) -> None:
    _run_fixed(["systemctl", "start", "cayvpn-agent", f"wg-quick@{settings.user_interface}", f"wg-quick@{settings.admin_interface}", "cayvpn-worker", "cayvpn-web", "cayvpn-remote-admin-renew.timer", "nginx"], timeout=90)


def cmd_uninstall(settings: Settings, confirm: bool) -> int:
    if not confirm:
        print("Uninstall is SSH-only and destructive. Re-run with --confirm to create the encrypted backup and remove CayVPN services.", file=sys.stderr)
        return 2
    if os.geteuid() != 0:
        print("Run cayvpnctl uninstall as root over SSH.", file=sys.stderr)
        return 2
    try:
        snapshot = _validated_install_snapshot(settings)
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"Uninstall refused before changing the VPS: {exc}", file=sys.stderr)
        return 1
    passphrase = getpass.getpass("Backup passphrase (required before uninstall): ")
    if len(passphrase) < 12:
        print("Backup passphrase must be at least 12 characters.", file=sys.stderr)
        return 1
    database = None
    preserved = None
    services_paused = False
    restore_started = False
    try:
        database = Database(settings)
        output = create_backup(settings, database, passphrase)
        preserved = _preserve_uninstall_backup(output)
        # Keep update recovery active until the root agent has removed every
        # Location runtime. The agent Requires that oneshot unit, so stopping
        # it here would also stop the agent before cleanup can run.
        _run_required(["systemctl", "stop", "cayvpn-remote-admin-renew.timer", "cayvpn-web", "cayvpn-worker", "nginx"], timeout=60)
        services_paused = True
        _deactivate_all_egress(settings, database)
        _run_required([
            "systemctl", "disable", "--now",
            "cayvpn-remote-admin-renew.timer", "cayvpn-web", "cayvpn-worker", "cayvpn-agent", "cayvpn-update-recovery",
            f"wg-quick@{settings.user_interface}", f"wg-quick@{settings.admin_interface}",
        ], timeout=90)
        if _command_succeeded(["ip", "link", "show", settings.amnezia_interface], timeout=10):
            _run_required(["ip", "link", "delete", settings.amnezia_interface], timeout=30)
        database.engine.dispose()
        database = None
        restore_started = True
        _restore_install_snapshot(settings, snapshot)
    except (OSError, RuntimeError, subprocess.SubprocessError, ValueError) as exc:
        if database is not None:
            database.engine.dispose()
        if services_paused and not restore_started:
            _restart_interrupted_uninstall(settings)
        suffix = f" The encrypted recovery backup remains at {preserved}." if preserved else ""
        print(f"Uninstall stopped: {exc}.{suffix}", file=sys.stderr)
        return 1
    print(f"CayVPN was removed and the pre-install VPS state was restored. Encrypted recovery backup: {preserved}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="cayvpnctl", description="CayVPN node management and recovery")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("status", "verify", "repair", "diagnostics"):
        sub.add_parser(name)
    upgrade = sub.add_parser("upgrade")
    upgrade.add_argument("--release")
    upgrade.add_argument("--confirm", action="store_true")
    rollback = sub.add_parser("rollback")
    rollback.add_argument("--confirm", action="store_true")
    uninstall = sub.add_parser("uninstall")
    uninstall.add_argument("--confirm", action="store_true")
    sub.add_parser("capacity")
    sub.add_parser("backup")
    restore = sub.add_parser("restore")
    restore.add_argument("source")
    restore.add_argument("--confirm", action="store_true")
    recovery = sub.add_parser("recovery")
    recovery.add_argument("action", choices=["approve"])
    admin_device = sub.add_parser("admin-device")
    admin_device.add_argument("action", choices=["list", "revoke"], nargs="?", default="list")
    admin_device.add_argument("device_id", type=int, nargs="?")
    remote_admin = sub.add_parser("remote-admin")
    remote_admin.add_argument("action", choices=["renew"])
    provision = sub.add_parser("provision")
    provision.add_argument("--admin-public-key", required=True)
    provision.add_argument("--admin-address", default="10.255.0.2/32")
    args = parser.parse_args(argv)
    settings = Settings.from_env()
    if args.command == "status":
        return cmd_status(settings)
    if args.command == "verify":
        return cmd_verify(settings)
    if args.command == "capacity":
        return cmd_refresh(settings)
    if args.command == "backup":
        return cmd_backup(settings)
    if args.command == "restore":
        return cmd_restore(settings, args.source, args.confirm)
    if args.command == "recovery":
        return cmd_recovery(settings, args.action == "approve")
    if args.command == "repair":
        return cmd_repair(settings)
    if args.command == "upgrade":
        try:
            return cmd_upgrade(settings, args.release, args.confirm)
        except (OSError, RuntimeError, UpdateError, ValueError) as exc:
            print(f"Upgrade stopped safely: {str(exc)[:600]}", file=sys.stderr)
            return 1
    if args.command == "rollback":
        try:
            return cmd_rollback(settings, args.confirm)
        except (OSError, RuntimeError, UpdateError, ValueError) as exc:
            print(f"Rollback stopped safely: {str(exc)[:600]}", file=sys.stderr)
            return 1
    if args.command == "diagnostics":
        return cmd_diagnostics(settings)
    if args.command == "uninstall":
        return cmd_uninstall(settings, args.confirm)
    if args.command == "admin-device":
        return cmd_admin_device(settings, args.action, args.device_id)
    if args.command == "remote-admin":
        return cmd_remote_admin(settings, args.action)
    if args.command == "provision":
        from .bootstrap import bootstrap
        bootstrap(settings, args.admin_public_key, args.admin_address)
        print("CayVPN node marked verified")
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
