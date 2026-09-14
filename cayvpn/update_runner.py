from __future__ import annotations

import argparse
import json
import logging
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

from .cli import _active_release_path, _atomic_active_link, _request_runtime_reconciliation, _restore_state_paths, cmd_upgrade
from .config import Settings
from .db import Database
from .models import ManagedNode, Operation
from .updates import UpdateManager, Version, read_update_state, update_lock, verify_installed_release, write_update_state


logger = logging.getLogger(__name__)


def _complete_operation(settings: Settings, operation_id: str | None, desired_generation: int, status: str, result: dict, error: str | None = None) -> None:
    if not operation_id:
        return
    with Database(settings) as database:
        database.initialize_defaults(settings)
        with database.session() as session:
            operation = session.get(Operation, operation_id)
            if operation is None:
                return
            operation.status = status
            operation.observed_generation = desired_generation if status == "succeeded" else operation.observed_generation
            operation.result_json = json.dumps(result, sort_keys=True)
            operation.error_code = None if status == "succeeded" else "upgrade_failed"
            operation.error_message = error
            operation.completed_at = datetime.now(timezone.utc)
            node = session.get(ManagedNode, 1)
            if node is not None and status == "succeeded":
                node.observed_generation = max(node.observed_generation, desired_generation)


def apply_update(settings: Settings, release: str, operation_id: str | None, desired_generation: int) -> int:
    if operation_id:
        with Database(settings) as database:
            database.initialize_defaults(settings)
            with database.session() as session:
                operation = session.get(Operation, operation_id)
                if operation is not None:
                    operation.status = "running"
    try:
        result = cmd_upgrade(settings, release, True)
    except Exception:
        logger.exception("CayVPN update %s failed", release)
        _complete_operation(
            settings,
            operation_id,
            desired_generation,
            "failed",
            {"release": release, "rolled_back": read_update_state(settings.update_state_path).get("rolled_back", False)},
            "The update failed and CayVPN attempted to restore the previous verified release.",
        )
        return 1
    _complete_operation(settings, operation_id, desired_generation, "succeeded", {"release": release, "verified": True})
    return result


def stage_update(settings: Settings, release: str, operation_id: str | None, desired_generation: int) -> int:
    with update_lock(settings):
        if operation_id:
            with Database(settings) as database:
                database.initialize_defaults(settings)
                with database.session() as session:
                    operation = session.get(Operation, operation_id)
                    if operation is not None:
                        operation.status = "running"
        try:
            current = str(Version.parse(_active_release_path(settings).name))
            result = UpdateManager(settings).stage(release, current)
        except Exception:
            logger.exception("CayVPN update %s could not be staged", release)
            state = read_update_state(settings.update_state_path)
            _complete_operation(
                settings,
                operation_id,
                desired_generation,
                "failed",
                {"release": release, "state": state.get("state", "stage_failed")},
                "The update could not be downloaded and verified. No active release was changed.",
            )
            return 1
        _complete_operation(settings, operation_id, desired_generation, "succeeded", {"release": release, "state": "staged", "verified": True})
        return 0


def _contained(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except (OSError, ValueError):
        return False


def recover_interrupted_update(settings: Settings) -> int:
    with update_lock(settings):
        state = read_update_state(settings.update_state_path)
        if state.get("state") in {"stage_queued", "staging"}:
            for parent, prefix in ((settings.state_dir / "update-downloads", "cayvpn-"), (settings.release_dir.parent, ".release-")):
                if not parent.is_dir():
                    continue
                for candidate in parent.iterdir():
                    if candidate.name.startswith(prefix) and candidate.is_dir() and not candidate.is_symlink():
                        shutil.rmtree(candidate, ignore_errors=True)
            write_update_state(settings, "stage_failed", target_release=state.get("target_release"), error_code="power_interruption", error_message="The VPS restarted while downloading the update. The active release was never changed; check again when ready.")
            return 0
        if state.get("state") == "install_queued":
            write_update_state(settings, "install_interrupted", phase="no_active_change", target_release=state.get("target_release"), rolled_back=False, error_code="power_interruption", error_message="The VPS restarted before installation began. The previously active release was unchanged.")
            return 0
        recovery_retry = state.get("state") == "install_failed" and state.get("phase") == "recovery_required"
        if state.get("state") != "installing" and not recovery_retry:
            return 0
        previous_value = state.get("previous_release")
        snapshot_value = state.get("snapshot")
        target_release = str(state.get("target_release") or "unknown")
        phase = str(state.get("phase") or "unknown")
        if phase in {"preparing", "release_verified", "snapshot_ready", "services_stopped"}:
            write_update_state(settings, "install_interrupted", phase="no_active_change", target_release=target_release, rolled_back=False, error_code="power_interruption", error_message="The VPS restarted before the update changed active state. The previously active release was unchanged.")
            return 0
        previous = Path(previous_value) if isinstance(previous_value, str) else None
        snapshot = Path(snapshot_value) if isinstance(snapshot_value, str) else None
        # Explicit SSH rollback journals snapshot the release that was active
        # before the downgrade in their own tree. Recover that snapshot if the
        # downgrade is interrupted, retaining the same containment boundary.
        snapshot_root = settings.state_dir / (
            "rollback-snapshots" if state.get("rollback") is True else "upgrade-snapshots"
        )
        if (
            previous is None
            or snapshot is None
            or not _contained(previous, settings.release_dir)
            or not _contained(snapshot, snapshot_root)
            or not previous.is_dir()
            or previous.is_symlink()
            or not (previous / "release.manifest").is_file()
            or not snapshot.is_dir()
            or snapshot.is_symlink()
            or not (snapshot / "manifest.json").is_file()
        ):
            write_update_state(settings, "install_failed", phase="recovery_required", target_release=target_release, previous_release=previous_value, snapshot=snapshot_value, rollback=state.get("rollback") is True, rolled_back=False, error_code="invalid_recovery_journal", error_message="The interrupted update journal could not be recovered automatically. Restore the protected recovery journal over SSH before restarting CayVPN.")
            return 1
        try:
            verify_installed_release(settings, previous, expected_version=previous.name)
            _restore_state_paths(settings, snapshot)
            _atomic_active_link(settings, previous)
            reconciliation_request = _request_runtime_reconciliation(settings)
        except Exception:
            logger.exception("Interrupted CayVPN update recovery failed")
            write_update_state(settings, "install_failed", phase="recovery_required", target_release=target_release, previous_release=str(previous), snapshot=str(snapshot), rollback=state.get("rollback") is True, rolled_back=False, error_code="automatic_recovery_failed", error_message="Automatic recovery failed. Correct the reported recovery error over SSH and restart cayvpn-update-recovery before changing VPN routes.")
            return 1
        write_update_state(
            settings,
            "install_interrupted",
            phase="rollback_restored_pending_reconciliation",
            current_release=previous.name,
            target_release=target_release,
            previous_release=str(previous),
            snapshot=str(snapshot),
            reconciliation_request=reconciliation_request,
            rolled_back=False,
            error_code="power_interruption",
            error_message=(
                "The VPS restarted during the update. CayVPN restored the previous signed release "
                "and will mark recovery complete only after routes and services verify."
            ),
        )
        return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="cayvpn-update-runner")
    subcommands = parser.add_subparsers(dest="command", required=True)
    for command in ("stage", "apply"):
        command_parser = subcommands.add_parser(command)
        command_parser.add_argument("--release", required=True)
        command_parser.add_argument("--operation-id")
        command_parser.add_argument("--desired-generation", type=int, default=0)
    subcommands.add_parser("recover")
    args = parser.parse_args(argv)
    settings = Settings.from_env()
    if args.command == "stage":
        return stage_update(settings, args.release, args.operation_id, args.desired_generation)
    if args.command == "apply":
        return apply_update(settings, args.release, args.operation_id, args.desired_generation)
    return recover_interrupted_update(settings)


if __name__ == "__main__":
    sys.exit(main())
