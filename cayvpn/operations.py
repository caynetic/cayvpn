from __future__ import annotations

import hashlib
import json
import logging
import uuid
from datetime import datetime, timezone

from sqlalchemy import desc, select, update

from .db import Database
from .dns_service import blocklist_available
from .dual_stack import capabilities_for_api, ipv6_usable, normalize_capabilities
from .models import AuditEvent, Client, EgressPool, EgressProfile, ManagedNode, Operation, RouteBinding
from .protocol import AgentClient, AgentRequest, AgentResponse


logger = logging.getLogger(__name__)


def effective_profile_capabilities(profile: EgressProfile) -> dict:
    capabilities = normalize_capabilities(profile.capabilities_storage)
    if profile.ipv6_health_state not in {"healthy", "active"}:
        capabilities["ipv6"] = {"tcp": False, "udp": False, "dns": False}
    return capabilities_for_api(capabilities)


def profile_supports_required_ipv6(profile: EgressProfile) -> bool:
    return profile.ipv6_health_state in {"healthy", "active"} and ipv6_usable(profile.capabilities)


def _redact(value):
    if isinstance(value, dict):
        return {
            key: (
                "[redacted]"
                if key.lower()
                in {
                    "password",
                    "passphrase",
                    "secret",
                    "secret_ref",
                    "private_key",
                    "private_key_ref",
                    "config",
                    "config_text",
                    "client_config",
                    "value",
                    "recovery_code",
                    "code",
                    "provisioning_uri",
                    "token",
                }
                else _redact(child)
            )
            for key, child in value.items()
        }
    if isinstance(value, list):
        return [_redact(child) for child in value]
    return value


class OperationService:
    def __init__(self, db: Database, agent: AgentClient):
        self.db = db
        self.agent = agent

    def _generation(self) -> int:
        with self.db.session() as session:
            generation = session.execute(
                update(ManagedNode)
                .where(ManagedNode.id == 1)
                .values(desired_generation=ManagedNode.desired_generation + 1)
                .returning(ManagedNode.desired_generation)
            ).scalar_one_or_none()
            if generation is None:
                raise RuntimeError("the managed CayVPN node is missing")
            return int(generation)

    def audit(self, actor: str, action: str, details: dict) -> None:
        with self.db.session() as session:
            previous = session.scalar(select(AuditEvent).order_by(desc(AuditEvent.id)))
            previous_hash = previous.event_hash if previous else ""
            payload = json.dumps({"actor": actor, "action": action, "details": _redact(details), "previous": previous_hash}, sort_keys=True, default=str)
            event_hash = hashlib.sha256(payload.encode()).hexdigest()
            session.add(AuditEvent(actor=actor, action=action, details_json=json.dumps(_redact(details), sort_keys=True), previous_hash=previous_hash or None, event_hash=event_hash))

    def run(self, action: str, payload: dict, actor: str = "owner", node_id: int = 1) -> tuple[Operation, AgentResponse]:
        operation_id = uuid.uuid4().hex
        generation = self._generation()
        request = AgentRequest(operation_id, action, node_id=node_id, desired_generation=generation, payload=payload)
        with self.db.session() as session:
            # A persisted running state distinguishes a request that is still
            # legitimately using its action timeout from one whose caller
            # lost contact with the agent. The worker may reconcile queued
            # work, but must never race an in-flight network mutation.
            operation = Operation(id=operation_id, action=action, status="running", desired_generation=generation, request_json=json.dumps(_redact(payload), sort_keys=True))
            session.add(operation)
        response = self.agent.execute(request)
        with self.db.session() as session:
            operation = session.get(Operation, operation_id)
            # A background update runner can finish before systemd-run returns
            # to the agent. Preserve that terminal result instead of racing it
            # back to the agent's initial "queued" acknowledgement.
            if operation.status not in {"succeeded", "failed"}:
                operation.status = response.status
                operation.observed_generation = response.observed_generation
                operation.result_json = json.dumps(_redact(response.result), sort_keys=True)
                operation.error_code = response.error_code
                operation.error_message = response.error_message
                if response.status in {"succeeded", "failed"}:
                    operation.completed_at = datetime.now(timezone.utc)
            node = session.get(ManagedNode, node_id)
            if node is not None and response.observed_generation is not None:
                node.observed_generation = max(node.observed_generation, response.observed_generation)
        self.audit(actor, action, payload)
        return operation, response

    def reconcile_clients(self, actor: str = "system") -> tuple[Operation, AgentResponse]:
        with self.db.session() as session:
            peers = session.scalars(select(Client).where(Client.enabled.is_(True))).all()
            grouped = {
                "wireguard": (self.db.settings.user_interface, [peer for peer in peers if peer.ingress_protocol == "wireguard"]),
                "amneziawg": (self.db.settings.amnezia_interface, [peer for peer in peers if peer.ingress_protocol == "amneziawg"]),
            }
        last_operation = None
        last_response = None
        for protocol, (interface, protocol_peers) in grouped.items():
            payload = {
                "interface": interface,
                "protocol": protocol,
                "peers": [
                    {
                        "public_key": peer.public_key,
                        "allowed_ips": ", ".join(
                            item for item in (f"{peer.address}/32", f"{peer.ipv6_address}/128" if peer.ipv6_address else "") if item
                        ),
                        "persistent_keepalive": 25,
                    }
                    for peer in protocol_peers
                ],
            }
            last_operation, last_response = self.run("wireguard.reconcile", payload, actor=actor)
            if last_response.status != "succeeded":
                return last_operation, last_response
        if last_operation is None or last_response is None:
            payload = {"interface": self.db.settings.user_interface, "protocol": "wireguard", "peers": []}
            return self.run("wireguard.reconcile", payload, actor=actor)
        return last_operation, last_response

    def update_client_settings(self, client_id: int, dns_mode: str, ipv6_policy: str, settings_revision: str, actor: str = "owner") -> tuple[Operation | None, AgentResponse]:
        if not isinstance(dns_mode, str) or not isinstance(ipv6_policy, str) or dns_mode not in {"standard", "ad_blocking"} or ipv6_policy not in {"auto", "required"}:
            raise ValueError("Choose a valid web protection and IPv6 setting")
        if not isinstance(settings_revision, str) or not settings_revision:
            raise ValueError("Reload the connection settings before saving")
        return self.route_switch(client_id, actor=actor, client_settings={
            "dns_mode": dns_mode, "ipv6_policy": ipv6_policy, "settings_revision": settings_revision,
        })

    def route_switch(self, client_id: int, profile_id: int | None = None, pool_id: int | None = None, actor: str = "owner", *, client_settings: dict | None = None) -> tuple[Operation | None, AgentResponse]:
        if client_settings is None and bool(profile_id) == bool(pool_id):
            raise ValueError("Choose exactly one exit or failover pool")
        with self.db.session() as session:
            # Claim the desired route and settings in one SQLite transaction.
            # Another owner request must not overwrite an in-flight change.
            session.connection().exec_driver_sql("BEGIN IMMEDIATE")
            client = session.get(Client, client_id)
            if client is None or not client.enabled:
                raise ValueError("The client is not available")
            if client_settings is None and client.route_mode == "fixed":
                if client.fixed_egress_id and profile_id != client.fixed_egress_id:
                    raise ValueError("This client is pinned to its fixed exit")
                if client.pool_id and pool_id != client.pool_id:
                    raise ValueError("This client is pinned to its fixed failover pool")
            binding = session.scalar(select(RouteBinding).where(RouteBinding.client_id == client_id))
            if binding is not None and binding.state == "pending" and (binding.egress_profile_id or binding.desired_generation):
                raise ValueError("This connection is still being checked. Wait for that change to finish before saving again")
            previous_settings = {"dns_mode": client.dns_mode, "ipv6_policy": client.ipv6_policy}
            if client_settings is not None:
                if client.updated_at.isoformat() != client_settings["settings_revision"]:
                    raise ValueError("This connection changed since you opened it. Reload the settings and try again")
                if all(client_settings[key] == value for key, value in previous_settings.items()):
                    return None, AgentResponse("unchanged", "succeeded", result={"unchanged": True, "verified": True})
                if client_settings["dns_mode"] == "ad_blocking" and not blocklist_available(self.db.settings.config_dir / "adblock"):
                    raise ValueError("Ad and tracker blocking is not available on this server yet")
                if binding is None or not binding.egress_profile_id:
                    raise ValueError("Choose a ready Location for this connection before editing its protection")
                # Keep the currently selected backup, rather than triggering
                # a failback by selecting the first member of its pool again.
                profile_id, pool_id = binding.egress_profile_id, binding.pool_id
                client.dns_mode = client_settings["dns_mode"]
                client.ipv6_policy = client_settings["ipv6_policy"]
                if client.dns_mode != previous_settings["dns_mode"]:
                    client.generated_config_version += 1
            if binding is None:
                binding = RouteBinding(client_id=client_id, mode="switchable")
                session.add(binding)
            previous_profile_id = binding.egress_profile_id
            target = None
            if profile_id:
                target = session.get(EgressProfile, profile_id)
                if target is None or not target.enabled:
                    raise ValueError("The selected exit is not available")
            else:
                pool = session.get(EgressPool, pool_id)
                if pool is None or not pool.enabled:
                    raise ValueError("The selected failover pool is not available")
                try:
                    ordered_ids = [int(item) for item in json.loads(pool.profile_ids_json or "[]")]
                except (TypeError, ValueError, json.JSONDecodeError) as exc:
                    raise ValueError("The selected failover pool is invalid") from exc
                for candidate_id in ordered_ids:
                    candidate = session.get(EgressProfile, candidate_id)
                    if (
                        candidate
                        and candidate.enabled
                        and candidate.health_state in {"healthy", "active"}
                        and (client.ipv6_policy != "required" or profile_supports_required_ipv6(candidate))
                    ):
                        target = candidate
                        break
                if target is None:
                    raise ValueError("The selected failover pool has no healthy approved exit")
                profile_id = target.id
            if target.health_state not in {"healthy", "active"}:
                raise ValueError("Verify the selected exit before assigning a client")
            if client.ipv6_policy == "required" and not profile_supports_required_ipv6(target):
                raise ValueError("This client requires IPv6. Choose an exit that has passed both IPv4 and IPv6 checks")
            if client.ipv6_policy == "required" and not client.ipv6_address:
                raise ValueError("This connection needs an IPv6 address before Require IPv6 can be enabled")
            previous_pool_id = binding.pool_id
            previous_profile = session.get(EgressProfile, previous_profile_id) if previous_profile_id else None
            ingress_interface = self.db.settings.amnezia_interface if client.ingress_protocol == "amneziawg" else self.db.settings.user_interface
            binding.egress_profile_id = profile_id
            binding.pool_id = pool_id
            binding.state = "pending"
            payload = {
                "client_id": client_id,
                "client_address": f"{client.address}/32",
                "client_ipv6_address": f"{client.ipv6_address}/128" if client.ipv6_address else None,
                "ipv6_policy": client.ipv6_policy,
                "ingress_interface": ingress_interface,
                "target_profile_id": profile_id,
                "target_pool_id": pool_id,
                "previous_profile_id": previous_profile_id,
                "previous_pool_id": previous_pool_id,
                "dns_mode": client.dns_mode,
                "previous_dns_mode": previous_settings["dns_mode"],
                "previous_ipv6_policy": previous_settings["ipv6_policy"],
                "settings_change": client_settings is not None,
                "target_profile": {
                    "profile_id": target.id,
                    "driver": target.driver,
                    "config": target.config,
                    "capabilities": effective_profile_capabilities(target),
                    "health_state": target.health_state,
                    "ipv6_health_state": target.ipv6_health_state,
                },
            }
            if target.secret_enc and target.secret_enc.startswith("ref::"):
                payload["target_profile"]["secret_ref"] = target.secret_enc
            if previous_profile is not None:
                payload["previous_profile"] = {
                    "profile_id": previous_profile.id,
                    "driver": previous_profile.driver,
                    "config": previous_profile.config,
                    "capabilities": effective_profile_capabilities(previous_profile),
                    "health_state": previous_profile.health_state,
                    "ipv6_health_state": previous_profile.ipv6_health_state,
                }
                if previous_profile.secret_enc and previous_profile.secret_enc.startswith("ref::"):
                    payload["previous_profile"]["secret_ref"] = previous_profile.secret_enc
        operation, response = self.run("route.switch", payload, actor=actor)
        with self.db.session() as session:
            binding = session.scalar(select(RouteBinding).where(RouteBinding.client_id == client_id))
            if response.status == "succeeded" and response.result.get("verified"):
                binding.state = "active"
            elif response.status == "failed" and response.error_code == "route_switch_failed":
                if client_settings is not None:
                    client = session.get(Client, client_id)
                    if client.dns_mode != previous_settings["dns_mode"]:
                        # An owner may have downloaded the pending profile.
                        # Give the restored configuration a fresh revision too.
                        client.generated_config_version += 1
                    client.dns_mode = previous_settings["dns_mode"]
                    client.ipv6_policy = previous_settings["ipv6_policy"]
                restored_profile_id = response.result.get("restored_profile_id")
                if restored_profile_id:
                    binding.egress_profile_id = int(restored_profile_id)
                    binding.pool_id = previous_pool_id
                    binding.state = "active" if response.result.get("restored_verified") else "blocked"
                else:
                    binding.egress_profile_id = previous_profile_id if client_settings is not None else None
                    binding.pool_id = previous_pool_id if client_settings is not None else None
                    binding.state = "blocked"
            else:
                binding.state = "pending"
            binding.desired_generation = operation.desired_generation
            binding.observed_generation = response.observed_generation or 0
            binding.last_error = response.error_message
        return operation, response
