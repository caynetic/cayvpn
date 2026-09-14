from __future__ import annotations

import json
import logging
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sqlalchemy import select

from .capacity import calculate_capacity, detect_resources, transfer_forecast
from .config import Settings
from .db import Database
from .dual_stack import family_capabilities, merge_capability_observation, normalize_capabilities
from .health import ordered_healthy_profile_ids, record_probe
from .models import CapacitySnapshot, Client, EgressPool, EgressProfile, ManagedNode, Operation, RouteBinding, WizardDraft
from .operations import OperationService, effective_profile_capabilities, profile_supports_required_ipv6
from .protocol import AgentClient, AgentRequest, AgentResponse
from .updates import read_update_state, write_update_state


PENDING_ROUTE_GRACE_SECONDS = AgentClient.timeout_for("route.switch") + 15
STALE_OPERATION_EXTRA_GRACE_SECONDS = 15
HEALTH_PROBE_INTERVAL_SECONDS = 30
MAINTENANCE_REFRESH_INTERVAL_SECONDS = 3600


def refresh(settings: Settings, db: Database) -> None:
    with db.session() as session:
        profiles = session.scalars(select(EgressProfile).where(EgressProfile.enabled.is_(True))).all()
        drivers = [profile.driver for profile in profiles] or ["direct_ip"]
        active_clients = session.query(Client).filter(Client.enabled.is_(True)).count()
        active_driver_processes = sum(1 for profile in profiles if profile.driver != "direct_ip")
    resources = detect_resources(active_clients=active_clients, active_driver_processes=active_driver_processes)
    with db.session() as session:
        node = session.get(ManagedNode, 1)
        if node is not None:
            node.architecture = resources.architecture
        transfer = db.get_setting("transfer_allowance_gb")
        advertised = db.get_setting("advertised_mbps")
        estimate = calculate_capacity(resources, drivers, int(transfer) if transfer and transfer.isdigit() else None, int(advertised) if advertised and advertised.isdigit() else None)
        used_gb, forecast_gb = transfer_forecast(resources.traffic_bytes)
        override_active = db.get_setting("capacity_override_active", "0") == "1"
        session.add(CapacitySnapshot(architecture=resources.architecture, vcpus=resources.vcpus, memory_mb=resources.memory_mb, disk_free_mb=resources.disk_free_mb, load_1m=resources.load_1m, active_clients=resources.active_clients, active_driver_processes=resources.active_driver_processes, interface_speed_mbps=resources.interface_speed_mbps, transfer_allowance_gb=int(transfer) if transfer and transfer.isdigit() else None, transfer_used_gb=used_gb, transfer_forecast_gb=forecast_gb, safe_active_clients=estimate.safe_active_clients, max_stored_configs=estimate.max_stored_configs, max_egress_profiles=estimate.max_egress_profiles, estimated_mbps=estimate.estimated_mbps, limiting_factor=estimate.limiting_factor, confidence=estimate.confidence, over_capacity=estimate.over_capacity, override_active=override_active, override_reason=db.get_setting("capacity_override_reason", "") if override_active else None))


def probe_egresses(settings: Settings, db: Database) -> None:
    """Refresh exit health and perform only owner-approved pool failover.

    A queued response means the agent is unavailable, so the worker leaves the
    previous state unchanged.  It never treats an unavailable probe as a
    healthy direct-IP fallback.
    """
    agent = AgentClient(settings.agent_socket)
    operations = OperationService(db, agent)
    with db.session() as session:
        profiles = session.scalars(select(EgressProfile).where(EgressProfile.enabled.is_(True))).all()
        snapshot = [
            (
                profile.id,
                profile.driver,
                profile.config,
                profile.secret_enc,
                profile.health_state,
                profile.consecutive_failures,
                profile.consecutive_successes,
                profile.ipv6_health_state,
                profile.ipv6_consecutive_failures,
                profile.ipv6_consecutive_successes,
            )
            for profile in profiles
        ]
    for profile_id, driver, config, secret_ref, state, failures, successes, ipv6_state, ipv6_failures, ipv6_successes in snapshot:
        payload = {"profile_id": profile_id, "driver": driver, "config": config}
        if secret_ref and secret_ref.startswith("ref::"):
            payload["secret_ref"] = secret_ref
        _operation, response = operations.run("egress.probe", payload, actor="worker")
        if response.status != "succeeded":
            continue
        result = response.result or {}
        missing_runtime_reasons = {
            "provider_namespace_missing",
            "provider_interface_missing",
            "socks_namespace_missing",
            "socks_runtime_unavailable",
        }
        if (
            driver in {"provider_tunnel", "socks5"}
            and str(result.get("reason") or "") in missing_runtime_reasons
        ):
            _recovery_operation, recovery = operations.run(
                "egress.activate",
                payload,
                actor="worker-runtime-recovery",
            )
            if recovery.status == "queued":
                continue
            if recovery.status == "succeeded":
                recovered = recovery.result or {}
                result = {
                    **recovered,
                    "health_state": (
                        "healthy" if recovered.get("verified") else "unhealthy"
                    ),
                }
            else:
                result = {
                    **result,
                    "health_state": "unhealthy",
                    "verified": False,
                    "reason": str(recovery.error_code or "runtime_recovery_failed"),
                }
        reported_state = str(result.get("health_state", "pending"))
        if reported_state == "pending":
            continue
        if reported_state == "blocked":
            with db.session() as session:
                profile = session.get(EgressProfile, profile_id)
                if profile is None:
                    continue
                profile.health_state = "blocked"
                profile.consecutive_failures = 0
                profile.consecutive_successes = 0
                profile.last_failure_reason = str(result.get("reason") or "runtime capability is unavailable")[:240]
                profile.last_check_at = datetime.now(timezone.utc)
                profile.ipv6_health_state = "blocked"
                profile.ipv6_consecutive_failures = 0
                profile.ipv6_consecutive_successes = 0
                profile.ipv6_last_failure_reason = str(result.get("ipv6_reason") or result.get("reason") or "runtime capability is unavailable")[:240]
                profile.ipv6_last_check_at = datetime.now(timezone.utc)
                profile.capabilities_json = json.dumps(normalize_capabilities({}), sort_keys=True)
                profile.observed_exit_ip = None
                profile.observed_exit_ipv6 = None
            _failover_bound_clients(settings, db, operations, profile_id)
            continue
        observed_families = result.get("families") if isinstance(result.get("families"), dict) else {}
        ipv4_observation = family_capabilities({"families": {"ipv4": observed_families.get("ipv4", result)}}, "ipv4")
        ipv6_observation = family_capabilities({"families": {"ipv6": observed_families.get("ipv6", {})}}, "ipv6")
        success = reported_state in {"healthy", "active"} and bool(result.get("verified", True)) and ipv4_observation["tcp"] and ipv4_observation["dns"] and bool(result.get("observed_exit_ipv4") or result.get("observed_exit_ip"))
        transition = record_probe(state, failures, successes, success, result.get("reason"))
        reported_ipv6_state = str(result.get("ipv6_health_state", "unavailable"))
        ipv6_configured = reported_ipv6_state != "unavailable"
        ipv6_success = bool(ipv6_configured and ipv6_observation["tcp"] and ipv6_observation["dns"] and result.get("observed_exit_ipv6"))
        ipv6_transition = record_probe(ipv6_state, ipv6_failures, ipv6_successes, ipv6_success, result.get("ipv6_reason")) if ipv6_configured else None
        with db.session() as session:
            profile = session.get(EgressProfile, profile_id)
            if profile is None:
                continue
            profile.health_state = transition.state
            profile.consecutive_failures = transition.failures
            profile.consecutive_successes = transition.successes
            profile.last_failure_reason = transition.reason
            profile.last_check_at = datetime.now(timezone.utc)
            current_capabilities = normalize_capabilities(profile.capabilities_storage)
            if success:
                current_capabilities = merge_capability_observation(current_capabilities, {"families": {"ipv4": ipv4_observation}})
                profile.observed_exit_ip = str(result.get("observed_exit_ipv4") or result.get("observed_exit_ip"))[:64]
            elif transition.state in {"unhealthy", "blocked"}:
                current_capabilities["ipv4"] = {"tcp": False, "udp": False, "dns": False}
                profile.observed_exit_ip = None
            if ipv6_transition is None:
                profile.ipv6_health_state = "unavailable"
                profile.ipv6_consecutive_failures = 0
                profile.ipv6_consecutive_successes = 0
                profile.ipv6_last_failure_reason = str(result.get("ipv6_reason") or "ipv6_not_configured")[:240]
                profile.ipv6_last_check_at = datetime.now(timezone.utc)
                current_capabilities["ipv6"] = {"tcp": False, "udp": False, "dns": False}
                profile.observed_exit_ipv6 = None
            else:
                profile.ipv6_health_state = ipv6_transition.state
                profile.ipv6_consecutive_failures = ipv6_transition.failures
                profile.ipv6_consecutive_successes = ipv6_transition.successes
                profile.ipv6_last_failure_reason = ipv6_transition.reason
                profile.ipv6_last_check_at = datetime.now(timezone.utc)
                if ipv6_success:
                    current_capabilities = merge_capability_observation(current_capabilities, {"families": {"ipv6": ipv6_observation}})
                    profile.observed_exit_ipv6 = str(result["observed_exit_ipv6"])[:64]
                elif ipv6_transition.state in {"unhealthy", "blocked"}:
                    current_capabilities["ipv6"] = {"tcp": False, "udp": False, "dns": False}
                    profile.observed_exit_ipv6 = None
            profile.capabilities_json = json.dumps(current_capabilities, sort_keys=True)
        if transition.changed and transition.state == "unhealthy":
            _failover_bound_clients(settings, db, operations, profile_id)
        if ipv6_transition and ipv6_transition.changed:
            if ipv6_transition.state == "unhealthy":
                _handle_ipv6_failure(settings, db, operations, profile_id)
            elif ipv6_transition.state == "healthy":
                _restore_smart_ipv6(settings, db, operations, profile_id)


def _ipv6_profile_payload(profile: EgressProfile) -> dict:
    return {
        "profile_id": profile.id,
        "driver": profile.driver,
        "config": profile.config,
        "capabilities": effective_profile_capabilities(profile),
        "health_state": profile.health_state,
        "ipv6_health_state": profile.ipv6_health_state,
    }


def _reconcile_one_client_ipv6(settings: Settings, db: Database, operations: OperationService, client_id: int, profile_id: int) -> None:
    with db.session() as session:
        client = session.get(Client, client_id)
        profile = session.get(EgressProfile, profile_id)
        if client is None or profile is None or not client.enabled or not client.ipv6_address:
            return
        ingress_interface = settings.amnezia_interface if client.ingress_protocol == "amneziawg" else settings.user_interface
        payload = {
            "client_id": client.id,
            "client_address": f"{client.address}/32",
            "client_ipv6_address": f"{client.ipv6_address}/128",
            "ipv6_policy": client.ipv6_policy,
            "ingress_interface": ingress_interface,
            "profile_id": profile.id,
            "dns_mode": client.dns_mode,
            "profile": _ipv6_profile_payload(profile),
        }
    operation, response = operations.run("route.ipv6_reconcile", payload, actor="worker-ipv6")
    with db.session() as session:
        binding = session.scalar(select(RouteBinding).where(RouteBinding.client_id == client_id))
        if binding is None:
            return
        binding.desired_generation = operation.desired_generation
        binding.observed_generation = response.observed_generation or 0
        if response.status == "succeeded":
            binding.last_error = None if response.result.get("ipv6_state") == "active" else "IPv6 is protected by an explicit block; IPv4 remains active."
        else:
            binding.last_error = response.error_message or "IPv6 reconciliation failed; its route remains blocked."


def _block_required_client(settings: Settings, db: Database, operations: OperationService, client_id: int, profile_id: int, reason: str) -> None:
    with db.session() as session:
        client = session.get(Client, client_id)
        if client is None:
            return
        ingress_interface = settings.amnezia_interface if client.ingress_protocol == "amneziawg" else settings.user_interface
        payload = {
            "client_id": client.id,
            "client_address": f"{client.address}/32",
            "client_ipv6_address": f"{client.ipv6_address}/128" if client.ipv6_address else None,
            "ingress_interface": ingress_interface,
            "profile_id": profile_id,
        }
    operation, response = operations.run("route.fail_closed", payload, actor="worker-ipv6")
    with db.session() as session:
        binding = session.scalar(select(RouteBinding).where(RouteBinding.client_id == client_id))
        if binding:
            binding.state = "blocked"
            binding.last_error = reason
            binding.desired_generation = operation.desired_generation
            binding.observed_generation = response.observed_generation or 0


def _handle_ipv6_failure(settings: Settings, db: Database, operations: OperationService, profile_id: int) -> None:
    """Block only IPv6 for Smart clients; fully fail over Required clients."""
    with db.session() as session:
        bindings = session.scalars(select(RouteBinding).where(RouteBinding.egress_profile_id == profile_id)).all()
        clients = {client.id: client for client in session.scalars(select(Client).where(Client.enabled.is_(True))).all()}
        profiles = {profile.id: profile for profile in session.scalars(select(EgressProfile).where(EgressProfile.enabled.is_(True))).all()}
        pools = {pool.id: pool for pool in session.scalars(select(EgressPool).where(EgressPool.enabled.is_(True))).all()}
        smart_ids: list[int] = []
        required: list[tuple[int, int | None]] = []
        for binding in bindings:
            client = clients.get(binding.client_id)
            if client is None:
                continue
            if client.ipv6_policy != "required":
                smart_ids.append(client.id)
                continue
            pool = pools.get(binding.pool_id) if binding.pool_id else None
            candidate = None
            if pool is not None:
                try:
                    ordered = [int(item) for item in json.loads(pool.profile_ids_json or "[]")]
                except (TypeError, ValueError, json.JSONDecodeError):
                    ordered = []
                candidate = next(
                    (
                        item
                        for item in ordered
                        if item != profile_id
                        and item in profiles
                        and profiles[item].health_state in {"healthy", "active"}
                        and profile_supports_required_ipv6(profiles[item])
                    ),
                    None,
                )
            required.append((client.id, pool.id if pool is not None and candidate else None))
    for client_id in smart_ids:
        _reconcile_one_client_ipv6(settings, db, operations, client_id, profile_id)
    for client_id, pool_id in required:
        if pool_id:
            try:
                operations.route_switch(client_id, pool_id=pool_id, actor="worker-ipv6-failover")
                continue
            except (ValueError, RuntimeError):
                pass
        _block_required_client(settings, db, operations, client_id, profile_id, "Required IPv6 is unavailable and no verified dual-stack backup is ready.")


def _restore_smart_ipv6(settings: Settings, db: Database, operations: OperationService, profile_id: int) -> None:
    with db.session() as session:
        bindings = session.scalars(select(RouteBinding).where(RouteBinding.egress_profile_id == profile_id)).all()
        clients = {client.id: client for client in session.scalars(select(Client).where(Client.enabled.is_(True))).all()}
        work = [(client.id, client.ipv6_policy) for binding in bindings if (client := clients.get(binding.client_id)) is not None]
    for client_id, policy in work:
        if policy == "required":
            try:
                operations.route_switch(client_id, profile_id=profile_id, actor="worker-ipv6-recovery")
            except (ValueError, RuntimeError):
                continue
        else:
            _reconcile_one_client_ipv6(settings, db, operations, client_id, profile_id)


def _failover_bound_clients(settings: Settings, db: Database, operations: OperationService, failed_profile_id: int) -> None:
    with db.session() as session:
        bindings = session.scalars(select(RouteBinding).where(RouteBinding.egress_profile_id == failed_profile_id)).all()
        profiles = {profile.id: profile for profile in session.scalars(select(EgressProfile).where(EgressProfile.enabled.is_(True))).all()}
        pools = {pool.id: pool for pool in session.scalars(select(EgressPool).where(EgressPool.enabled.is_(True))).all()}
        clients = {client.id: client for client in session.scalars(select(Client).where(Client.enabled.is_(True))).all()}
        work: list[tuple[int, int | None, int | None, str]] = []
        for binding in bindings:
            client = clients.get(binding.client_id)
            if client is None:
                continue
            pool = pools.get(binding.pool_id) if binding.pool_id else None
            if pool is None:
                work.append((client.id, None, failed_profile_id, "no approved failover pool"))
                continue
            try:
                ordered_ids = [int(item) for item in json.loads(pool.profile_ids_json or "[]")]
            except (TypeError, ValueError, json.JSONDecodeError):
                ordered_ids = []
            candidates = ordered_healthy_profile_ids(ordered_ids, profiles, excluded=failed_profile_id)
            if client.ipv6_policy == "required":
                candidates = [candidate_id for candidate_id in candidates if profile_supports_required_ipv6(profiles[candidate_id])]
            if candidates:
                work.append((client.id, pool.id, candidates[0], "approved pool failover"))
            else:
                work.append((client.id, None, failed_profile_id, "no healthy approved exit"))
    for client_id, pool_id, target_id, reason in work:
        if reason == "approved pool failover":
            try:
                operations.route_switch(client_id, pool_id=pool_id, actor="worker-failover")
            except (ValueError, RuntimeError):
                continue
        else:
            with db.session() as session:
                client = session.get(Client, client_id)
                if client is None:
                    continue
            ingress_interface = settings.amnezia_interface if client.ingress_protocol == "amneziawg" else settings.user_interface
            operation, response = operations.run(
                "route.fail_closed",
                {
                    "client_id": client_id,
                    "client_address": f"{client.address}/32",
                    "client_ipv6_address": f"{client.ipv6_address}/128" if client.ipv6_address else None,
                    "ingress_interface": ingress_interface,
                    "profile_id": target_id,
                },
                actor="worker-failover",
            )
            with db.session() as session:
                binding = session.scalar(select(RouteBinding).where(RouteBinding.client_id == client_id))
                if binding:
                    binding.state = "blocked"
                    binding.last_error = reason
                    binding.desired_generation = operation.desired_generation
                    binding.observed_generation = response.observed_generation or 0


def _finish_lost_route_operation(session, generation: int, reconciliation: Operation, active: bool) -> None:
    if generation < 1:
        return
    stale = session.scalar(
        select(Operation).where(
            Operation.action == "route.switch",
            Operation.status == "queued",
            Operation.desired_generation == generation,
        )
    )
    if stale is None:
        return
    stale.status = "succeeded" if active else "failed"
    stale.observed_generation = reconciliation.observed_generation
    stale.result_json = json.dumps(
        {
            "original_response_lost": True,
            "reconciled_by": reconciliation.id,
            "reconciled_state": "active" if active else "blocked",
        },
        sort_keys=True,
    )
    stale.error_code = None if active else "route_reconcile_failed"
    stale.error_message = None if active else "The timed-out route could not be verified and remains blocked."
    stale.completed_at = datetime.now(timezone.utc)


def reconcile_runtime(
    settings: Settings,
    db: Database,
    pending_only: bool = False,
    agent: AgentClient | None = None,
) -> tuple[Operation | None, AgentResponse | None]:
    """Restore desired peers and approved routes after restart or timeout.

    Full reconciliation follows worker or agent startup. Pending-only
    reconciliation completes a previously authorized route whose response was
    lost, without resetting unrelated active client connections.
    """
    agent = agent or AgentClient(settings.agent_socket)
    operations = OperationService(db, agent)
    pending_generations: dict[int, int] = {}
    with db.session() as session:
        clients = session.scalars(select(Client).where(Client.enabled.is_(True))).all()
        bindings = {binding.client_id: binding for binding in session.scalars(select(RouteBinding)).all() if binding.client_id}
        profiles = {profile.id: profile for profile in session.scalars(select(EgressProfile).where(EgressProfile.enabled.is_(True))).all()}
        routes = []
        for client in clients:
            binding = bindings.get(client.id)
            if pending_only and (binding is None or binding.state != "pending"):
                continue
            if binding is not None and binding.state == "pending":
                pending_generations[client.id] = binding.desired_generation
            client_route = {
                "client_id": client.id,
                "client_address": f"{client.address}/32",
                "client_ipv6_address": f"{client.ipv6_address}/128" if client.ipv6_address else None,
                "ipv6_policy": client.ipv6_policy,
                "dns_mode": client.dns_mode,
            }
            if binding is None or not binding.egress_profile_id:
                ingress_interface = settings.amnezia_interface if client.ingress_protocol == "amneziawg" else settings.user_interface
                routes.append({**client_route, "ingress_interface": ingress_interface, "profile_id": 1, "profile": {"profile_id": 1, "driver": "direct_ip", "config": {"address": settings.server_ip}, "capabilities": {"families": {"ipv4": {"tcp": True, "udp": True, "dns": True}, "ipv6": {"tcp": False, "udp": False, "dns": False}}}, "health_state": "blocked", "ipv6_health_state": "blocked"}})
                continue
            profile = profiles.get(binding.egress_profile_id)
            if profile is None:
                ingress_interface = settings.amnezia_interface if client.ingress_protocol == "amneziawg" else settings.user_interface
                routes.append({**client_route, "ingress_interface": ingress_interface, "profile_id": binding.egress_profile_id, "profile": {"profile_id": binding.egress_profile_id, "driver": "direct_ip", "config": {"address": settings.server_ip}, "capabilities": {"families": {"ipv4": {"tcp": False, "udp": False, "dns": False}, "ipv6": {"tcp": False, "udp": False, "dns": False}}}, "health_state": "blocked", "ipv6_health_state": "blocked"}})
                continue
            ingress_interface = settings.amnezia_interface if client.ingress_protocol == "amneziawg" else settings.user_interface
            routes.append({**client_route, "ingress_interface": ingress_interface, "profile_id": profile.id, "profile": {"profile_id": profile.id, "driver": profile.driver, "config": profile.config, "capabilities": effective_profile_capabilities(profile), "secret_ref": profile.secret_enc if profile.secret_enc and profile.secret_enc.startswith("ref::") else None, "health_state": profile.health_state, "ipv6_health_state": profile.ipv6_health_state}})
    if not routes:
        return None, None
    operation, response = operations.run("runtime.reconcile", {"routes": routes}, actor="worker-reconcile")
    result = response.result or {}
    applied_clients = {int(item) for item in result.get("applied_clients", []) if str(item).isdigit()}
    blocked_clients = {int(item) for item in result.get("blocked_clients", []) if str(item).isdigit()}
    with db.session() as session:
        for client_id in applied_clients:
            binding = session.scalar(select(RouteBinding).where(RouteBinding.client_id == client_id))
            if binding:
                binding.state = "active"
                binding.last_error = None
                binding.desired_generation = operation.desired_generation
                binding.observed_generation = response.observed_generation or 0
                _finish_lost_route_operation(session, pending_generations.get(client_id, 0), operation, True)
        for client_id in blocked_clients:
            binding = session.scalar(select(RouteBinding).where(RouteBinding.client_id == client_id))
            if binding:
                binding.state = "blocked"
                binding.last_error = response.error_message or "runtime reconciliation did not verify this route"
                binding.desired_generation = operation.desired_generation
                binding.observed_generation = response.observed_generation or 0
                _finish_lost_route_operation(session, pending_generations.get(client_id, 0), operation, False)
    return operation, response


def _agent_socket_signature(path: Path) -> tuple[int, int] | None:
    try:
        observed = path.stat()
    except OSError:
        return None
    return observed.st_ino, observed.st_mtime_ns


def _pending_routes(db: Database, now: datetime | None = None) -> bool:
    """Return true only when pending route state is safe to recover.

    A normal provider switch can remain pending for most of the agent action
    timeout. Reconciliation during that window queues stale desired state
    behind the legitimate switch and can overwrite its rollback result. A
    queued matching operation means the caller already lost its response and
    is immediately recoverable; an orphaned running/pending record is only
    recoverable after the action timeout plus a small scheduling margin.
    """
    observed_now = now or datetime.now(timezone.utc)
    cutoff = observed_now - timedelta(seconds=PENDING_ROUTE_GRACE_SECONDS)
    with db.session() as session:
        bindings = session.scalars(select(RouteBinding).where(RouteBinding.state == "pending")).all()
        for binding in bindings:
            queued = session.scalar(
                select(Operation.id).where(
                    Operation.action == "route.switch",
                    Operation.status == "queued",
                    Operation.desired_generation == binding.desired_generation,
                ).limit(1)
            )
            if queued is not None:
                return True
            updated_at = binding.updated_at
            if updated_at is None:
                return True
            if updated_at.tzinfo is None:
                updated_at = updated_at.replace(tzinfo=timezone.utc)
            if updated_at <= cutoff:
                return True
        return False


def close_stale_operations(db: Database, now: datetime | None = None) -> dict[str, int]:
    """Close interrupted history only after later state is verified.

    A process restart can leave an operation in ``running`` before its final
    agent response is persisted. Agent-unavailable responses can likewise
    remain ``queued`` while reconciliation catches up. Neither record should
    look active forever, but an in-flight operation or pending route must not
    be disturbed. The global observed generation gives us a conservative
    boundary: close only old rows that a later verified generation has already
    superseded.
    """

    observed_now = now or datetime.now(timezone.utc)
    closed: dict[str, int] = {}
    with db.session() as session:
        node = session.get(ManagedNode, 1)
        if node is None:
            return closed
        pending_route_generations = {
            binding.desired_generation
            for binding in session.scalars(select(RouteBinding).where(RouteBinding.state == "pending")).all()
        }
        unfinished = session.scalars(select(Operation).where(Operation.status.in_(("queued", "running")))).all()
        for operation in unfinished:
            created_at = operation.created_at
            if created_at is None:
                continue
            if created_at.tzinfo is None:
                created_at = created_at.replace(tzinfo=timezone.utc)
            stale_after = timedelta(seconds=AgentClient.timeout_for(operation.action) + STALE_OPERATION_EXTRA_GRACE_SECONDS)
            if created_at + stale_after > observed_now:
                continue
            if operation.desired_generation > node.observed_generation:
                continue
            if operation.action == "route.switch" and operation.desired_generation in pending_route_generations:
                continue
            previous_status = operation.status
            operation.status = "failed"
            operation.error_code = "operation_superseded"
            operation.error_message = "The operation did not record a final response and was superseded by a verified later generation."
            operation.result_json = json.dumps(
                {
                    "closed_by": "worker-reconcile",
                    "node_observed_generation": node.observed_generation,
                },
                sort_keys=True,
            )
            operation.completed_at = observed_now
            key = f"{previous_status}:{operation.action}"
            closed[key] = closed.get(key, 0) + 1
    return closed


def _close_and_audit_stale_operations(settings: Settings, db: Database) -> None:
    closed = close_stale_operations(db)
    if closed:
        OperationService(db, AgentClient(settings.agent_socket)).audit(
            "worker-reconcile",
            "operation.stale_closed",
            {"closed": closed},
        )


def reconcile_agent_state(settings: Settings, db: Database) -> bool:
    operations = OperationService(db, AgentClient(settings.agent_socket))
    _operation, peers = operations.reconcile_clients(actor="worker-reconcile")
    if peers.status != "succeeded":
        return False
    _operation, runtime = reconcile_runtime(settings, db)
    return runtime is None or (
        runtime.status == "succeeded"
        and (runtime.result or {}).get("verified") is True
    )


def record_reconciliation_completion(
    settings: Settings,
    db: Database,
    expected_request: str | None = None,
) -> bool:
    request_id = db.get_setting("runtime_reconciliation_request", "")
    if not request_id or (expected_request and request_id != expected_request):
        return False
    state = read_update_state(settings.update_state_path)
    if not state and settings.update_state_path.exists():
        # Older root updaters wrote this file with a root-only read group.
        # Read their journal through the existing authenticated root API so
        # an upgrade to this worker can finish without weakening file modes.
        if not settings.apply_network:
            return False
        status = AgentClient(settings.agent_socket).execute(
            AgentRequest(uuid.uuid4().hex, "update.status", payload={})
        )
        if (
            status.status != "succeeded"
            or status.result.get("schema_version") != 1
            or not status.result.get("state")
            or status.result.get("state") == "idle"
        ):
            return False
        state = status.result
    if (
        state.get("state") == "install_interrupted"
        and state.get("phase") == "rollback_restored_pending_reconciliation"
        and state.get("reconciliation_request") == request_id
    ):
        # Boot recovery restored signed files, but only the restarted worker
        # can prove routes and the rest of the running node are healthy.
        if settings.apply_network:
            verified = AgentClient(settings.agent_socket).execute(
                AgentRequest(uuid.uuid4().hex, "system.verify", payload={})
            )
            if verified.status != "succeeded" or verified.result.get("verified") is not True:
                return False
        else:
            from .cli import cmd_verify

            if cmd_verify(settings) != 0:
                return False
        preserved = {
            key: value
            for key, value in state.items()
            if key
            not in {
                "schema_version",
                "state",
                "updated_at",
                "phase",
                "rolled_back",
                "error_message",
            }
        }
        write_update_state(
            settings,
            "install_interrupted",
            **preserved,
            phase="rolled_back_on_boot",
            rolled_back=True,
            error_message=(
                "The VPS restarted during the update, so CayVPN restored and "
                "verified the previous signed release."
            ),
        )
    db.set_setting("runtime_reconciliation_completed", request_id)
    return True


def cleanup_expired_wizard_drafts(settings: Settings, db: Database, now: datetime | None = None) -> int:
    """Remove expired resumable answers and their opaque temporary secrets.

    A draft whose secret cannot be removed is retained so the next worker pass
    can retry.  This favors secret cleanup over prematurely losing the only
    reference to that material.
    """

    observed_now = now or datetime.now(timezone.utc)
    operations = OperationService(db, AgentClient(settings.agent_socket))
    with db.session() as session:
        drafts = session.scalars(select(WizardDraft)).all()
        expired = []
        for draft in drafts:
            expires_at = draft.expires_at
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)
            if expires_at <= observed_now:
                expired.append((draft.id, draft.secret_ref))
    removed = 0
    for draft_id, secret_ref in expired:
        if secret_ref:
            _operation, response = operations.run("secret.delete", {"secret_ref": secret_ref}, actor="wizard-expiry")
            if response.status != "succeeded":
                continue
        with db.session() as session:
            draft = session.get(WizardDraft, draft_id)
            if draft is not None:
                session.delete(draft)
                removed += 1
    return removed


def run_worker() -> None:
    logging.basicConfig(level="INFO", format="%(asctime)s %(levelname)s %(name)s %(message)s")
    settings = Settings.from_env()
    db = Database(settings)
    db.initialize_defaults(settings)
    last_agent_signature = None
    reconciled_request: str | None = None
    try:
        cleanup_expired_wizard_drafts(settings, db)
        if reconcile_agent_state(settings, db):
            last_agent_signature = _agent_socket_signature(settings.agent_socket)
            reconciled_request = db.get_setting("runtime_reconciliation_request", "") or None
            if record_reconciliation_completion(settings, db, reconciled_request):
                reconciled_request = None
        _close_and_audit_stale_operations(settings, db)
    except Exception:
        logging.getLogger(__name__).exception("worker startup reconciliation failed")
    next_refresh = 0.0
    next_health_probe = 0.0
    while True:
        try:
            current_signature = _agent_socket_signature(settings.agent_socket)
            if current_signature is not None and current_signature != last_agent_signature:
                if reconcile_agent_state(settings, db):
                    last_agent_signature = current_signature
                    reconciled_request = db.get_setting("runtime_reconciliation_request", "") or None
                    if record_reconciliation_completion(settings, db, reconciled_request):
                        reconciled_request = None
            elif current_signature is not None and _pending_routes(db):
                reconcile_runtime(settings, db, pending_only=True)
            _close_and_audit_stale_operations(settings, db)
            if reconciled_request and record_reconciliation_completion(
                settings, db, reconciled_request
            ):
                reconciled_request = None
            now = time.monotonic()
            if now >= next_refresh:
                cleanup_expired_wizard_drafts(settings, db)
                refresh(settings, db)
                next_refresh = now + MAINTENANCE_REFRESH_INTERVAL_SECONDS
            if now >= next_health_probe:
                probe_egresses(settings, db)
                next_health_probe = now + HEALTH_PROBE_INTERVAL_SECONDS
        except Exception:
            logging.getLogger(__name__).exception("worker refresh failed")
        time.sleep(5)


if __name__ == "__main__":
    run_worker()
