from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import logging
import os
import grp
import re
import secrets
import shutil
import socket
import stat
import struct
import subprocess
import time
from pathlib import Path
from typing import Callable

from .capacity import as_dict, calculate_capacity, detect_resources
from .backup import create_backup
from .components import ComponentError, component_binary, ensure_amneziawg, ensure_socks5_tunnel
from .config import Settings, admin_dns_search_domain
from .drivers import DriverValidationError, parse_provider_wireguard, parse_socks5, probe_socks5_capabilities, validate_driver
from .dual_stack import capabilities_for_api, family_capabilities, ipv6_usable, normalize_capabilities
from .network import NetworkOperationError, NetworkRouteManager
from .protocol import AgentRequest, AgentResponse
from .remote_admin import RemoteAdminError, RemoteAdminManager
from .security import generate_totp_secret, totp_uri, verify_totp, write_secret_file
from .secret_store import RootSecretStore, SecretStoreError
from .updates import UpdateError, UpdateManager, Version, verify_installed_release, write_update_state


logger = logging.getLogger(__name__)


AMNEZIA_PARAMETER_LABELS = {
    "jc": "Jc",
    "jmin": "Jmin",
    "jmax": "Jmax",
    "s1": "S1",
    "s2": "S2",
    "h1": "H1",
    "h2": "H2",
    "h3": "H3",
    "h4": "H4",
}


class RestrictedRunner:
    """Run only fixed argv operations selected by the agent implementation."""

    def run(self, argv: list[str], timeout: int = 10) -> subprocess.CompletedProcess:
        if not argv or any("\x00" in item for item in argv):
            raise ValueError("invalid system operation")
        return subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)

    def spawn(self, argv: list[str], timeout: int = 10):
        if not argv or any(not isinstance(item, str) or "\x00" in item for item in argv):
            raise ValueError("invalid system operation")
        # Long-lived namespace keepers and runtime children use fixed argv.
        # stdout/stderr are discarded so provider credentials can never enter
        # the agent journal.
        return subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, close_fds=True)


class NodeExecutor:
    def __init__(self, settings: Settings, runner: RestrictedRunner | None = None):
        self.settings = settings
        self.runner = runner or RestrictedRunner()
        self.routes = NetworkRouteManager(settings, self.runner)
        self.remote_admin = RemoteAdminManager(settings, self.runner)
        self.secrets = RootSecretStore(settings)
        self.observed_generation = 0

    def execute(self, request: AgentRequest) -> AgentResponse:
        try:
            if request.action in {"update.stage", "update.apply"}:
                handler = self.update_stage if request.action == "update.stage" else self.update_apply
                result = handler(request.payload, request.operation_id, request.desired_generation)
                return AgentResponse(request.operation_id, "queued", self.observed_generation, result=result)
            handler = {
                "system.snapshot": self.system_snapshot,
                "system.verify": self.system_verify,
                "runtime.reconcile": self.runtime_reconcile,
                "wireguard.reconcile": self.wireguard_reconcile,
                "wireguard.remove_peer": self.wireguard_remove_peer,
                "egress.validate": self.egress_validate,
                "egress.activate": self.egress_activate,
                "egress.deactivate": self.egress_deactivate,
                "egress.probe": self.egress_probe,
                "route.switch": self.route_switch,
                "route.ipv6_reconcile": self.route_ipv6_reconcile,
                "route.fail_closed": self.route_fail_closed,
                "route.remove": self.route_remove,
                "firewall.reconcile": self.firewall_reconcile,
                "admin.reconcile": self.admin_reconcile,
                "component.install": self.component_install,
                "remote_admin.configure": self.remote_admin_configure,
                "remote_admin.renew": self.remote_admin_renew,
                "secret.store": self.secret_store,
                "secret.delete": self.secret_delete,
                "totp.create": self.totp_create,
                "totp.uri": self.totp_uri,
                "totp.verify": self.totp_verify,
                "config.render_client": self.config_render_client,
                "config.render_admin": self.config_render_admin,
                "backup.create": self.backup_create,
                "update.check": self.update_check,
                "update.status": self.update_status,
                "update.discard": self.update_discard,
            }[request.action]
            result = handler(request.payload)
            self.observed_generation = max(self.observed_generation, request.desired_generation)
            return AgentResponse(request.operation_id, "succeeded", self.observed_generation, result=result or {})
        except DriverValidationError as exc:
            return AgentResponse(request.operation_id, "failed", self.observed_generation, error_code="validation_error", error_message=str(exc))
        except NetworkOperationError as exc:
            return AgentResponse(request.operation_id, "failed", self.observed_generation, result=getattr(exc, "result", {}) or {}, error_code=exc.code, error_message=str(exc))
        except ComponentError as exc:
            return AgentResponse(request.operation_id, "failed", self.observed_generation, error_code=exc.code, error_message=str(exc))
        except RemoteAdminError as exc:
            return AgentResponse(request.operation_id, "failed", self.observed_generation, error_code=exc.code, error_message=str(exc))
        except SecretStoreError as exc:
            return AgentResponse(request.operation_id, "failed", self.observed_generation, error_code=exc.code, error_message=str(exc))
        except UpdateError as exc:
            return AgentResponse(request.operation_id, "failed", self.observed_generation, error_code=exc.code, error_message=str(exc))
        except ValueError as exc:
            return AgentResponse(request.operation_id, "failed", self.observed_generation, error_code="validation_error", error_message=str(exc))
        except Exception as exc:  # the caller receives a typed redacted error
            logger.exception("Agent operation %s failed", request.action)
            return AgentResponse(request.operation_id, "failed", self.observed_generation, error_code="agent_error", error_message=str(exc))

    @staticmethod
    def _wireguard_key(value: object, label: str = "WireGuard key") -> str:
        key = str(value or "")
        try:
            decoded = base64.b64decode(key.encode(), validate=True)
        except (ValueError, TypeError):
            decoded = b""
        if len(decoded) != 32:
            raise ValueError(f"invalid {label}")
        return key

    def system_verify(self, payload: dict) -> dict:
        if payload:
            raise ValueError("system verification accepts no parameters")
        from .cli import cmd_verify

        # The authenticated request is already executing in the root agent;
        # connecting back to its serial socket would deadlock this operation.
        return {"verified": cmd_verify(self.settings, _agent_verified=True, _emit=False) == 0}

    def system_snapshot(self, _payload: dict) -> dict:
        resources = detect_resources()
        return as_dict(resources, calculate_capacity(resources))

    @staticmethod
    def _effective_profile_capabilities(profile: dict) -> dict:
        capabilities = normalize_capabilities(profile.get("capabilities") or {})
        if str(profile.get("ipv6_health_state", "")) not in {"healthy", "active"}:
            capabilities["ipv6"] = {"tcp": False, "udp": False, "dns": False}
        return capabilities_for_api(capabilities)

    @staticmethod
    def _intersect_capabilities(first: dict, second: dict) -> dict:
        return capabilities_for_api({
            family: {
                field: family_capabilities(first, family)[field] and family_capabilities(second, family)[field]
                for field in ("tcp", "udp", "dns")
            }
            for family in ("ipv4", "ipv6")
        })

    def runtime_reconcile(self, payload: dict) -> dict:
        """Rebuild only the typed runtime state persisted by the web plane.

        This is intentionally a separate action from ordinary route changes:
        the worker calls it after a service restart, while the panel continues
        to use the transactional route-switch path for deliberate changes.
        """
        if set(payload) - {"routes"}:
            raise ValueError("unsupported runtime reconciliation field")
        routes = payload.get("routes", [])
        if not isinstance(routes, list) or len(routes) > 4096:
            raise ValueError("invalid runtime route list")
        applied = 0
        blocked = 0
        failed = 0
        applied_clients: list[int] = []
        blocked_clients: list[int] = []
        expected_blocked_clients: list[int] = []
        failed_clients: list[int] = []
        for item in routes:
            if not isinstance(item, dict) or set(item) - {"client_id", "client_address", "client_ipv6_address", "ipv6_policy", "ingress_interface", "profile_id", "dns_mode", "profile"}:
                raise ValueError("unsupported runtime route field")
            client_address = str(item.get("client_address", ""))
            client_ipv6_address = item.get("client_ipv6_address")
            ipv6_policy = str(item.get("ipv6_policy", "auto"))
            ingress_interface = item.get("ingress_interface")
            profile_id = int(item.get("profile_id", 0))
            if not client_address or profile_id < 1:
                raise ValueError("runtime route is incomplete")
            profile = item.get("profile") or {}
            if not isinstance(profile, dict) or set(profile) - {"profile_id", "driver", "config", "capabilities", "secret_ref", "health_state", "ipv6_health_state"}:
                raise ValueError("unsupported runtime profile field")
            health_state = str(profile.get("health_state", ""))
            if health_state not in {"healthy", "active"}:
                self.routes.fail_closed(client_address, profile_id, ingress_interface, client_ipv6_address)
                blocked += 1
                if item.get("client_id") is not None:
                    client_id = int(item["client_id"])
                    blocked_clients.append(client_id)
                    expected_blocked_clients.append(client_id)
                continue
            try:
                driver = str(profile.get("driver", "direct_ip")).lower()
                config = profile.get("config") or {}
                capabilities = self._effective_profile_capabilities(profile)
                secret_payload = {"secret_ref": profile.get("secret_ref")} if profile.get("secret_ref") else {}
                if driver == "provider_tunnel":
                    secret = self._secret_payload(secret_payload)
                    parsed = parse_provider_wireguard(secret or "")
                    runtime = self.routes.activate_provider(profile_id, parsed)
                    runtime_capabilities = self._intersect_capabilities(capabilities, runtime)
                    self.routes.activate_client_policy(client_address, profile_id, str(item.get("dns_mode", "standard")), ingress_interface, client_ipv6_address, ipv6_policy, runtime_capabilities)
                elif driver == "socks5":
                    component = ensure_socks5_tunnel(self.settings)
                    tunnel = component.get("paths", {}).get("tunnel")
                    if not tunnel:
                        raise NetworkOperationError("component_not_installed", "The pinned SOCKS5 tunnel component is not installed")
                    secret = self._secret_payload(secret_payload)
                    parsed = parse_socks5(str(config.get("endpoint", "")), allow_private=False)
                    capabilities_probe = probe_socks5_capabilities(parsed, secret or parsed.get("password"))
                    if not capabilities_probe.get("tcp"):
                        raise NetworkOperationError("socks_capability_failed", "The SOCKS5 provider did not pass repeated TCP capability checks")
                    ipv6_probe = family_capabilities(capabilities_probe, "ipv6")
                    runtime = self.routes.activate_socks5(profile_id, parsed, secret or parsed.get("password"), tunnel, udp_allowed=bool(capabilities_probe.get("udp")), ipv6_allowed=ipv6_usable(capabilities_probe), ipv6_udp_allowed=ipv6_probe["udp"])
                    runtime_capabilities = self._intersect_capabilities(capabilities, runtime)
                    self.routes.activate_client_policy(client_address, profile_id, str(item.get("dns_mode", "standard")), ingress_interface, client_ipv6_address, ipv6_policy, runtime_capabilities)
                else:
                    self.routes.activate(client_address, profile_id, driver, config, capabilities, str(item.get("dns_mode", "standard")), ingress_interface, client_ipv6_address, ipv6_policy)
                applied += 1
                if item.get("client_id") is not None:
                    applied_clients.append(int(item["client_id"]))
            except Exception:
                try:
                    self.routes.fail_closed(client_address, profile_id, ingress_interface, client_ipv6_address)
                except Exception:
                    pass
                blocked += 1
                failed += 1
                if item.get("client_id") is not None:
                    client_id = int(item["client_id"])
                    blocked_clients.append(client_id)
                    failed_clients.append(client_id)
        return {
            "routes": len(routes),
            "applied": applied,
            "blocked": blocked,
            "failed": failed,
            "applied_clients": applied_clients,
            "blocked_clients": blocked_clients,
            "expected_blocked_clients": expected_blocked_clients,
            "failed_clients": failed_clients,
            "verified": failed == 0,
        }

    def wireguard_reconcile(self, payload: dict) -> dict:
        """Apply only the allowlisted peer state; never accepts hooks."""
        protocol = str(payload.get("protocol", "wireguard")).lower()
        if protocol not in {"wireguard", "amneziawg"}:
            raise ValueError("invalid WireGuard protocol")
        expected_interface = (
            self.settings.amnezia_interface
            if protocol == "amneziawg"
            else self.settings.user_interface
        )
        interface = payload.get("interface", expected_interface)
        if interface != expected_interface:
            raise ValueError("WireGuard interface is not managed by this operation")
        peers = payload.get("peers", [])
        if not isinstance(peers, list) or len(peers) > 4096:
            raise ValueError("invalid peer list")
        for peer in peers:
            if not isinstance(peer, dict) or set(peer) - {"public_key", "allowed_ips", "persistent_keepalive"}:
                raise ValueError("unsupported WireGuard peer field")
            self._wireguard_key(peer.get("public_key"), "peer public key")
            if not peer.get("allowed_ips"):
                raise ValueError("WireGuard peer is incomplete")
            for allowed_ip in str(peer["allowed_ips"]).split(","):
                try:
                    ipaddress.ip_network(allowed_ip.strip(), strict=False)
                except ValueError as exc:
                    raise ValueError("invalid WireGuard allowed IP") from exc
        tool_name = "awg" if protocol == "amneziawg" else "wg"
        tool = component_binary(self.settings, tool_name)
        if self.settings.apply_network and protocol == "amneziawg" and peers:
            # The userspace interface is a child of the restricted agent
            # service and therefore disappears on agent restart. Recreate it
            # from the pinned, checksum-verified component before restoring
            # persisted peers; otherwise every reboot leaves AWG clients
            # present in the database but unable to reconnect.
            component = ensure_amneziawg(self.settings)
            paths = component.get("paths", {})
            tool = paths.get("awg")
            quick = paths.get("awg_quick")
            userspace = paths.get("amneziawg_go")
            if not tool or not quick or not userspace:
                raise NetworkOperationError("component_not_installed", "The pinned AmneziaWG userspace component is incomplete")
            self._ensure_amnezia_interface(tool, quick, userspace)
        if self.settings.apply_network and not tool:
            if peers:
                raise NetworkOperationError("component_not_installed", f"The {protocol} userspace component is not installed")
            return {"interface": interface, "protocol": protocol, "peer_count": 0, "applied": False, "state": "not_installed"}
        if self.settings.apply_network and tool:
            current = self.runner.run([tool, "show", interface, "peers"], timeout=10)
            if current.returncode != 0 and protocol == "amneziawg" and not peers:
                # AmneziaWG is installed on demand. Before the first Amnezia
                # client exists there is deliberately no awg0 interface or
                # config to save. Confirm the link itself is absent so an
                # unrelated tool failure cannot be mistaken for a harmless
                # empty reconciliation.
                link = self.runner.run([self.routes.ip, "link", "show", interface], timeout=10)
                link_error = (link.stderr or link.stdout or "").lower()
                if link.returncode != 0 and any(marker in link_error for marker in ("does not exist", "no such device", "not found")):
                    return {
                        "interface": interface,
                        "protocol": protocol,
                        "peer_count": 0,
                        "applied": False,
                        "state": "not_configured",
                    }
            if current.returncode != 0:
                raise RuntimeError(current.stderr.strip() or current.stdout.strip() or "WireGuard interface state could not be read")
            if protocol == "wireguard" and interface == self.settings.user_interface:
                address_result = self.runner.run([self.routes.ip, "-6", "address", "replace", self.settings.user_address_v6, "dev", interface], timeout=10)
                if address_result.returncode != 0:
                    raise RuntimeError(address_result.stderr.strip() or "The standard WireGuard IPv6 address could not be applied")
            if current.returncode == 0:
                desired_keys = {str(peer["public_key"]) for peer in peers}
                for old_key in [line.strip() for line in (current.stdout or "").splitlines() if line.strip() and line.strip() not in desired_keys]:
                    removed = self.runner.run([tool, "set", interface, "peer", old_key, "remove"], timeout=10)
                    if removed.returncode != 0:
                        raise RuntimeError(removed.stderr.strip() or "WireGuard rejected stale peer removal")
            for peer in peers:
                argv = [tool, "set", interface, "peer", peer["public_key"], "allowed-ips", peer["allowed_ips"]]
                keepalive = peer.get("persistent_keepalive")
                if keepalive:
                    argv.extend(["persistent-keepalive", str(int(keepalive))])
                result = self.runner.run(argv)
                if result.returncode != 0:
                    raise RuntimeError(result.stderr.strip() or "WireGuard rejected peer update")
            quick = component_binary(self.settings, "awg-quick") if protocol == "amneziawg" else shutil.which("wg-quick")
            if protocol == "amneziawg" and quick:
                userspace = component_binary(self.settings, "amneziawg-go")
                if not userspace:
                    raise NetworkOperationError("component_not_installed", "The pinned AmneziaWG userspace engine is not installed")
                config_path = self.settings.wg_dir / f"{interface}.conf"
                saved = self.runner.run(self._amnezia_quick_argv(tool, quick, userspace, "save", config_path), timeout=20)
                if saved.returncode != 0:
                    raise RuntimeError(saved.stderr.strip() or "WireGuard state could not be persisted")
            elif quick:
                saved = self.runner.run([quick, "save", interface], timeout=20)
                if saved.returncode != 0:
                    raise RuntimeError(saved.stderr.strip() or "WireGuard state could not be persisted")
        return {"interface": interface, "protocol": protocol, "peer_count": len(peers), "applied": bool(self.settings.apply_network and tool)}

    def wireguard_remove_peer(self, payload: dict) -> dict:
        protocol = str(payload.get("protocol", "wireguard")).lower()
        if protocol not in {"wireguard", "amneziawg"}:
            raise ValueError("invalid WireGuard protocol")
        expected_interface = (
            self.settings.amnezia_interface
            if protocol == "amneziawg"
            else self.settings.user_interface
        )
        interface = payload.get("interface", expected_interface)
        if interface != expected_interface:
            raise ValueError("WireGuard interface is not managed by this operation")
        public_key = payload.get("public_key")
        self._wireguard_key(public_key, "peer public key")
        applied = False
        tool = component_binary(self.settings, "awg") if protocol == "amneziawg" else shutil.which("wg")
        if self.settings.apply_network and not tool:
            raise NetworkOperationError("component_not_installed", f"The {protocol} userspace component is not installed")
        if self.settings.apply_network and tool:
            result = self.runner.run([tool, "set", interface, "peer", public_key, "remove"])
            if result.returncode != 0:
                raise RuntimeError(result.stderr.strip() or "WireGuard rejected peer removal")
            quick = component_binary(self.settings, "awg-quick") if protocol == "amneziawg" else shutil.which("wg-quick")
            if protocol == "amneziawg" and quick:
                userspace = component_binary(self.settings, "amneziawg-go")
                if not userspace:
                    raise NetworkOperationError("component_not_installed", "The pinned AmneziaWG userspace engine is not installed")
                config_path = self.settings.wg_dir / f"{interface}.conf"
                saved = self.runner.run(self._amnezia_quick_argv(tool, quick, userspace, "save", config_path), timeout=20)
                if saved.returncode != 0:
                    raise RuntimeError(saved.stderr.strip() or "WireGuard state could not be persisted")
            elif quick:
                saved = self.runner.run([quick, "save", interface], timeout=20)
                if saved.returncode != 0:
                    raise RuntimeError(saved.stderr.strip() or "WireGuard state could not be persisted")
            applied = True
        return {"interface": interface, "removed": public_key[:8], "applied": applied}

    def egress_validate(self, payload: dict) -> dict:
        config = dict(payload.get("config") or {})
        secret = payload.get("secret")
        if payload.get("secret_ref"):
            secret = self.secrets.reveal(str(payload["secret_ref"]))
        if payload.get("driver") == "provider_tunnel" and secret:
            config["config_text"] = secret
        result = validate_driver(
            payload.get("driver", ""),
            config,
            secret,
            allow_private=bool(payload.get("allow_private", False)),
        )
        capabilities = result.capabilities
        warnings = list(result.warnings)
        if result.driver == "socks5" and payload.get("live_checks"):
            parsed = parse_socks5(str(config.get("endpoint", "")), allow_private=bool(payload.get("allow_private", False)))
            capabilities = probe_socks5_capabilities(parsed, secret or parsed.get("password"))
            if not capabilities.get("tcp") or not capabilities.get("dns"):
                warnings.append("The proxy did not pass repeated IPv4 TCP and DNS checks, so it cannot be saved as a usable exit yet.")
        return {"driver": result.driver, "valid": result.valid, "capabilities": capabilities, "redacted_config": result.redacted_config, "warnings": warnings}

    def egress_activate(self, payload: dict) -> dict:
        validated = self.egress_validate(payload)
        if not validated["valid"]:
            raise ValueError("egress is not a full usable exit")
        driver = validated["driver"]
        if not self.settings.apply_network:
            return {**validated, "state": "planned", "fail_closed": True, "verified": False}
        if driver == "provider_tunnel":
            secret = self._secret_payload(payload)
            parsed = parse_provider_wireguard(secret or "")
            if parsed["protocol"] == "amneziawg":
                component = ensure_amneziawg(self.settings)
                awg = component.get("paths", {}).get("awg")
                if not awg:
                    raise NetworkOperationError("component_not_installed", "The AmneziaWG provider component is not installed")
            runtime = self.routes.activate_provider(payload.get("profile_id") or 1, parsed)
            return {**validated, **runtime, "state": "active", "fail_closed": True, "verified": bool(runtime.get("verified"))}
        if driver == "socks5":
            component = ensure_socks5_tunnel(self.settings)
            tunnel = component.get("paths", {}).get("tunnel")
            if not tunnel:
                raise NetworkOperationError("component_not_installed", "The pinned SOCKS5 tunnel component is not installed")
            secret = self._secret_payload(payload)
            parsed = parse_socks5(str((payload.get("config") or {}).get("endpoint", "")), allow_private=False)
            capabilities = probe_socks5_capabilities(parsed, secret or parsed.get("password"))
            if not capabilities.get("tcp") or not capabilities.get("dns"):
                raise NetworkOperationError("socks_capability_failed", "The SOCKS5 provider did not pass repeated IPv4 TCP and DNS checks")
            ipv6_capabilities = family_capabilities(capabilities, "ipv6")
            runtime = self.routes.activate_socks5(
                payload.get("profile_id") or 1,
                parsed,
                secret or parsed.get("password"),
                tunnel,
                udp_allowed=bool(capabilities.get("udp")),
                ipv6_allowed=ipv6_usable(capabilities),
                ipv6_udp_allowed=ipv6_capabilities["udp"],
            )
            observed = self._intersect_capabilities(capabilities, runtime)
            return {**validated, **runtime, **observed, "state": "active", "fail_closed": True, "verified": bool(runtime.get("verified"))}
        if driver in {"direct_ip", "additional_ip"}:
            runtime = self.routes.probe_direct(payload.get("profile_id") or 1, driver, payload.get("config") or {})
            return {
                **validated,
                **runtime,
                "state": "active" if runtime.get("verified") else "pending",
                "fail_closed": True,
                "verified": bool(runtime.get("verified")),
            }
        return {**validated, "state": "active", "fail_closed": True, "verified": False}

    def _secret_payload(self, payload: dict) -> str | None:
        if payload.get("secret_ref"):
            return self.secrets.reveal(str(payload["secret_ref"]))
        secret = payload.get("secret")
        return str(secret) if secret else None

    def egress_deactivate(self, payload: dict) -> dict:
        if set(payload) - {"profile_id", "remove_namespace"}:
            raise ValueError("unsupported egress deactivation field")
        profile_id = payload.get("profile_id")
        runtime = self.routes.deactivate_runtime(profile_id, remove_namespace=bool(payload.get("remove_namespace", False))) if profile_id else {"state": "inactive", "applied": False}
        return {"profile_id": profile_id, **runtime, "fail_closed": True}

    def egress_probe(self, payload: dict) -> dict:
        driver = str(payload.get("driver", "")).lower()
        if self.settings.apply_network:
            if driver == "provider_tunnel":
                secret = self._secret_payload(payload)
                parsed = parse_provider_wireguard(secret or "")
                if parsed["protocol"] == "amneziawg" and not component_binary(self.settings, "awg"):
                    return {"profile_id": payload.get("profile_id"), "health_state": "blocked", "reason": "component_not_installed", "tcp": False, "udp": False, "dns": False, "ipv6": False}
                return self.routes.probe_provider(payload.get("profile_id") or 1, parsed)
            if driver == "socks5":
                tunnel = component_binary(self.settings, "hev-socks5-tunnel")
                if not tunnel:
                    return {"profile_id": payload.get("profile_id"), "health_state": "blocked", "reason": "component_not_installed", "tcp": False, "udp": False, "dns": False, "ipv6": False}
                secret = self._secret_payload(payload)
                parsed = parse_socks5(str((payload.get("config") or {}).get("endpoint", "")), allow_private=False)
                capabilities = probe_socks5_capabilities(parsed, secret or parsed.get("password"))
                if not capabilities.get("tcp") or not capabilities.get("dns"):
                    return {"profile_id": payload.get("profile_id"), "health_state": "unhealthy", "verified": False, "reason": "socks_capability_failed", **capabilities}
                runtime = self.routes.probe_socks5(payload.get("profile_id") or 1, tunnel)
                observed = self._intersect_capabilities(capabilities, runtime)
                return {**runtime, **observed, **{key: value for key, value in capabilities.items() if key.endswith("_checks")}}
            if driver in {"direct_ip", "additional_ip"}:
                return self.routes.probe_direct(payload.get("profile_id") or 1, driver, payload.get("config") or {})
        return {"profile_id": payload.get("profile_id"), "health_state": "pending", "tcp": False, "udp": False, "dns": False, "ipv6": False}

    def route_switch(self, payload: dict) -> dict:
        target = payload.get("target_profile_id") or payload.get("target_pool_id")
        if not target:
            raise ValueError("route target is required")
        client_address = payload.get("client_address")
        client_ipv6_address = payload.get("client_ipv6_address")
        ipv6_policy = str(payload.get("ipv6_policy", "auto"))
        if not client_address:
            raise NetworkOperationError("client_address_required", "The client address is required for an isolated route switch")
        target_profile = payload.get("target_profile") or {}
        target_profile_id = payload.get("target_profile_id") or 1
        previous = payload.get("previous_profile_id")
        previous_profile = payload.get("previous_profile") or {}
        ingress_interface = payload.get("ingress_interface")

        def apply_profile(profile_id: int, profile: dict, *, restoring: bool = False) -> dict:
            dns_mode = str(payload.get("previous_dns_mode" if restoring else "dns_mode", payload.get("dns_mode", "standard")))
            policy_ipv6 = str(payload.get("previous_ipv6_policy", ipv6_policy)) if restoring else ipv6_policy
            driver = str(profile.get("driver", "direct_ip")).lower()
            config = profile.get("config") or {}
            capabilities = self._effective_profile_capabilities(profile)
            secret_payload = {"secret_ref": profile.get("secret_ref")} if profile.get("secret_ref") else {}
            if driver == "provider_tunnel":
                secret = self._secret_payload(secret_payload)
                parsed = parse_provider_wireguard(secret or "")
                runtime = self.routes.activate_provider(profile_id, parsed)
                active_capabilities = self._intersect_capabilities(capabilities, runtime)
                policy = self.routes.activate_client_policy(client_address, profile_id, dns_mode, ingress_interface, client_ipv6_address, policy_ipv6, active_capabilities)
                return {**runtime, **policy, "client_address": client_address}
            if driver == "socks5":
                component = ensure_socks5_tunnel(self.settings)
                tunnel = component.get("paths", {}).get("tunnel")
                if not tunnel:
                    raise NetworkOperationError("component_not_installed", "The pinned SOCKS5 tunnel component is not installed")
                secret = self._secret_payload(secret_payload)
                parsed = parse_socks5(str(config.get("endpoint", "")), allow_private=False)
                socks_capabilities = probe_socks5_capabilities(parsed, secret or parsed.get("password"))
                if not socks_capabilities.get("tcp") or not socks_capabilities.get("dns"):
                    raise NetworkOperationError("socks_capability_failed", "The SOCKS5 provider did not pass repeated TCP capability checks")
                socks_ipv6 = family_capabilities(socks_capabilities, "ipv6")
                runtime = self.routes.activate_socks5(
                    profile_id,
                    parsed,
                    secret or parsed.get("password"),
                    tunnel,
                    udp_allowed=bool(socks_capabilities.get("udp")),
                    ipv6_allowed=ipv6_usable(socks_capabilities),
                    ipv6_udp_allowed=socks_ipv6["udp"],
                )
                active_capabilities = self._intersect_capabilities(capabilities, self._intersect_capabilities(socks_capabilities, runtime))
                policy = self.routes.activate_client_policy(client_address, profile_id, dns_mode, ingress_interface, client_ipv6_address, policy_ipv6, active_capabilities)
                return {**socks_capabilities, **runtime, **policy, "client_address": client_address}
            return self.routes.activate(client_address, profile_id, driver, config, capabilities, dns_mode, ingress_interface, client_ipv6_address, policy_ipv6)

        try:
            # The old route is blocked first. If the new exit cannot be
            # applied, the client remains on a prohibit route until the old
            # healthy route is restored or the owner selects another exit.
            if previous and previous != target_profile_id:
                self.routes.deactivate(client_address, previous, ingress_interface, client_ipv6_address)
            self.routes.fail_closed(client_address, target_profile_id, ingress_interface, client_ipv6_address)
            applied = apply_profile(target_profile_id, target_profile)
            if payload.get("settings_change") and not applied.get("verified"):
                raise NetworkOperationError("settings_unverified", "The connection settings could not be verified")
            return {"client_id": payload.get("client_id"), "target": target, **applied}
        except Exception as exc:
            reason_code = getattr(exc, "code", type(exc).__name__)
            restored_profile_id = None
            restored_verified = False
            try:
                # Runtime processes are shared by every client on an egress;
                # route-switch cleanup must never tear down a healthy profile
                # that other clients still use.
                self.routes.deactivate(client_address, target_profile_id, ingress_interface, client_ipv6_address)
            except Exception:
                # The final fail-closed call below is the safety boundary if
                # cleanup itself cannot complete.
                pass
            if previous and previous_profile and str(previous_profile.get("health_state", "")) in {"healthy", "active"}:
                try:
                    previous_id = int(previous_profile.get("profile_id") or previous)
                    self.routes.fail_closed(client_address, previous_id, ingress_interface, client_ipv6_address)
                    restored = apply_profile(previous_id, previous_profile, restoring=True)
                    restored_profile_id = previous_id
                    restored_verified = bool(restored.get("verified"))
                except Exception:
                    restored_profile_id = None
                    restored_verified = False
            if not restored_verified:
                try:
                    self.routes.fail_closed(client_address, target_profile_id, ingress_interface, client_ipv6_address)
                except Exception:
                    pass
            if restored_profile_id:
                raise NetworkOperationError(
                    "route_switch_failed",
                    "The selected exit failed verification; the previous healthy route was restored.",
                    {"restored_profile_id": restored_profile_id, "restored_verified": restored_verified, "failure_code": str(reason_code)},
                ) from exc
            raise NetworkOperationError(
                "route_switch_failed",
                "The selected exit failed verification; client traffic remains blocked.",
                {"restored_profile_id": None, "restored_verified": False, "failure_code": str(reason_code)},
            ) from exc

    def route_ipv6_reconcile(self, payload: dict) -> dict:
        allowed = {"client_id", "client_address", "client_ipv6_address", "ingress_interface", "profile_id", "dns_mode", "ipv6_policy", "profile"}
        if set(payload) - allowed:
            raise ValueError("unsupported IPv6 reconciliation field")
        profile = payload.get("profile") or {}
        if not isinstance(profile, dict) or set(profile) - {"profile_id", "driver", "config", "capabilities", "health_state", "ipv6_health_state"}:
            raise ValueError("unsupported IPv6 profile field")
        capabilities = self._effective_profile_capabilities(profile)
        result = self.routes.reconcile_client_ipv6(
            payload.get("client_address"),
            payload.get("client_ipv6_address"),
            payload.get("profile_id") or profile.get("profile_id") or 1,
            str(profile.get("driver", "direct_ip")),
            profile.get("config") or {},
            capabilities,
            str(payload.get("ipv6_policy", "auto")),
            str(payload.get("dns_mode", "standard")),
            payload.get("ingress_interface"),
        )
        return {"client_id": payload.get("client_id"), **result}

    def route_fail_closed(self, payload: dict) -> dict:
        client_address = payload.get("client_address")
        profile_id = payload.get("profile_id") or 1
        if not client_address:
            raise NetworkOperationError("client_address_required", "The client address is required to block a route")
        result = self.routes.fail_closed(client_address, profile_id, payload.get("ingress_interface"), payload.get("client_ipv6_address"))
        return {"client_id": payload.get("client_id"), **result, "state": "blocked", "verified": bool(result.get("applied"))}

    def route_remove(self, payload: dict) -> dict:
        client_address = payload.get("client_address")
        profile_id = payload.get("profile_id") or 1
        if not client_address:
            raise NetworkOperationError("client_address_required", "The client address is required to remove a route")
        result = self.routes.deactivate(client_address, profile_id, payload.get("ingress_interface"), payload.get("client_ipv6_address"))
        return {"client_id": payload.get("client_id"), **result, "removed": True, "verified": bool(result.get("fail_closed"))}

    def firewall_reconcile(self, payload: dict) -> dict:
        # nftables rules are generated from typed state by the production
        # installer.  This operation intentionally refuses raw rulesets.
        if set(payload) - {"admin_network", "user_port", "admin_port", "allow_ssh", "egress_interfaces"}:
            raise ValueError("unsupported firewall field")
        return {"state": "planned", "default_policy": "drop", "raw_rules_accepted": False}

    def admin_reconcile(self, payload: dict) -> dict:
        if set(payload) - {"interface", "listen_port", "address_cidr", "peers"}:
            raise ValueError("unsupported admin field")
        interface = payload.get("interface", self.settings.admin_interface)
        if interface != self.settings.admin_interface:
            raise ValueError("admin reconciliation may only target the configured admin interface")
        listen_port = int(payload.get("listen_port", self.settings.admin_port))
        if not 1 <= listen_port <= 65535:
            raise ValueError("invalid admin listen port")
        address_cidr = str(payload.get("address_cidr", self.settings.admin_address))
        peers = payload.get("peers", [])
        if not isinstance(peers, list) or len(peers) > 128:
            raise ValueError("invalid admin peer list")
        seen: set[str] = set()
        for peer in peers:
            if not isinstance(peer, dict) or set(peer) - {"public_key", "allowed_ips"}:
                raise ValueError("unsupported admin peer field")
            public_key = str(peer.get("public_key", ""))
            allowed_ips = str(peer.get("allowed_ips", ""))
            self._wireguard_key(public_key, "admin peer public key")
            if public_key in seen:
                raise ValueError("invalid or duplicate admin peer key")
            seen.add(public_key)
            if not allowed_ips.endswith("/32"):
                raise ValueError("admin peers must use /32 addresses")
            try:
                address = ipaddress.ip_interface(allowed_ips)
                if address.ip not in ipaddress.ip_network(self.settings.admin_network, strict=False):
                    raise ValueError
            except ValueError as exc:
                raise ValueError("admin peer address is outside the admin network") from exc
        applied = False
        if self.settings.apply_network and shutil.which("wg"):
            current = self.runner.run([shutil.which("wg"), "show", interface, "peers"], timeout=10)
            if current.returncode == 0:
                desired = seen
                for old_key in [line.strip() for line in (current.stdout or "").splitlines() if line.strip()]:
                    if old_key not in desired:
                        removed = self.runner.run([shutil.which("wg"), "set", interface, "peer", old_key, "remove"], timeout=10)
                        if removed.returncode != 0:
                            raise RuntimeError(removed.stderr.strip() or "admin peer removal failed")
            for peer in peers:
                result = self.runner.run([shutil.which("wg"), "set", interface, "peer", peer["public_key"], "allowed-ips", peer["allowed_ips"]], timeout=10)
                if result.returncode != 0:
                    raise RuntimeError(result.stderr.strip() or "admin peer update failed")
            if shutil.which("wg-quick"):
                saved = self.runner.run([shutil.which("wg-quick"), "save", interface], timeout=20)
                if saved.returncode != 0:
                    raise RuntimeError(saved.stderr.strip() or "admin WireGuard state could not be persisted")
            applied = True
        return {"interface": interface, "listen_port": listen_port, "address_cidr": address_cidr, "peer_count": len(peers), "state": "applied" if applied else "planned"}

    def component_install(self, payload: dict) -> dict:
        if set(payload) - {"component"}:
            raise ValueError("unsupported component field")
        component = str(payload.get("component", "")).lower()
        if component not in {"amneziawg", "socks5"}:
            raise ValueError("unsupported component")
        result = ensure_amneziawg(self.settings) if component == "amneziawg" else ensure_socks5_tunnel(self.settings)
        if component == "amneziawg" and result.get("state") == "installed" and self.settings.apply_network:
            self._ensure_amnezia_interface(result["paths"]["awg"], result["paths"]["awg_quick"], result["paths"]["amneziawg_go"])
        return result

    def remote_admin_configure(self, payload: dict) -> dict:
        if set(payload) != {"enabled"} or type(payload.get("enabled")) is not bool:
            raise ValueError("remote administration requires one enabled boolean")
        return self.remote_admin.configure(payload["enabled"])

    def remote_admin_renew(self, payload: dict) -> dict:
        if payload:
            raise ValueError("remote administration renewal does not accept fields")
        return self.remote_admin.renew()

    @staticmethod
    def _new_amnezia_parameters() -> dict[str, str]:
        headers: list[int] = []
        while len(headers) < 4:
            candidate = secrets.randbelow(2**32 - 1) + 1
            if candidate not in headers:
                headers.append(candidate)
        return {
            "Jc": "4",
            "Jmin": "64",
            "Jmax": "128",
            "S1": "32",
            "S2": "32",
            "H1": str(headers[0]),
            "H2": str(headers[1]),
            "H3": str(headers[2]),
            "H4": str(headers[3]),
        }

    @staticmethod
    def _read_amnezia_parameters(config_path: Path) -> dict[str, str]:
        if not config_path.is_file():
            raise RuntimeError("The AmneziaWG server configuration is missing")
        section = ""
        values: dict[str, str] = {}
        forbidden = {"preup", "postup", "predown", "postdown"}
        for raw_line in config_path.read_text().splitlines():
            line = raw_line.split("#", 1)[0].strip()
            if not line:
                continue
            if line.startswith("[") and line.endswith("]"):
                section = line[1:-1].strip().lower()
                continue
            if section != "interface" or "=" not in line:
                continue
            key, value = (part.strip() for part in line.split("=", 1))
            lowered = key.lower()
            if lowered in forbidden:
                raise RuntimeError("AmneziaWG interface hooks are not allowed")
            if lowered in AMNEZIA_PARAMETER_LABELS:
                if lowered in values or not value or "\r" in value or "\n" in value:
                    raise RuntimeError("The AmneziaWG server parameters are invalid")
                values[lowered] = value
        if set(values) != set(AMNEZIA_PARAMETER_LABELS):
            raise RuntimeError("The AmneziaWG server parameters are incomplete")
        try:
            jc = int(values["jc"])
            jmin = int(values["jmin"])
            jmax = int(values["jmax"])
            s1 = int(values["s1"])
            s2 = int(values["s2"])
            headers = [int(values[f"h{number}"]) for number in range(1, 5)]
        except ValueError as exc:
            raise RuntimeError("The AmneziaWG server parameters are invalid") from exc
        if not 0 <= jc <= 12 or not 64 <= jmin <= jmax <= 1024 or not 0 <= s1 <= 64 or not 0 <= s2 <= 64:
            raise RuntimeError("The AmneziaWG server parameters are outside supported ranges")
        if any(not 1 <= header <= 2**32 - 1 for header in headers) or len(set(headers)) != 4:
            raise RuntimeError("The AmneziaWG header values must be unique and nonzero")
        return {label: values[key] for key, label in AMNEZIA_PARAMETER_LABELS.items()}

    @staticmethod
    def _amnezia_quick_argv(awg: str, quick: str, userspace: str, action: str, config_path: Path) -> list[str]:
        if action not in {"up", "down", "save", "strip"}:
            raise ValueError("unsupported AmneziaWG quick action")
        env_binary = shutil.which("env") or "/usr/bin/env"
        component_path = str(Path(awg).resolve().parent)
        trusted_path = f"{component_path}:/usr/sbin:/usr/bin:/sbin:/bin"
        return [
            env_binary,
            f"PATH={trusted_path}",
            f"WG_QUICK_USERSPACE_IMPLEMENTATION={str(Path(userspace).resolve())}",
            str(Path(quick).resolve()),
            action,
            str(config_path.resolve()),
        ]

    def _ensure_amnezia_interface(self, awg: str, quick: str, userspace: str) -> None:
        key_path = self.settings.wg_dir / "awg-server.key"
        public_path = self.settings.wg_dir / "awg-server.pub"
        config_path = self.settings.wg_dir / f"{self.settings.amnezia_interface}.conf"
        if not key_path.exists():
            generated = self.runner.run([awg, "genkey"], timeout=10)
            private_key = (generated.stdout or "").strip()
            if generated.returncode != 0 or not private_key:
                raise RuntimeError("AmneziaWG server key generation failed")
            write_secret_file(key_path, private_key)
        if not public_path.exists():
            # The Amnezia tools accept the private key through stdin only; the
            # root agent never places it in argv.
            generated = subprocess.run([awg, "pubkey"], input=key_path.read_text(), capture_output=True, text=True, timeout=10, check=False)
            public_key = (generated.stdout or "").strip()
            if generated.returncode != 0 or not public_key:
                raise RuntimeError("AmneziaWG server public key generation failed")
            write_secret_file(public_path, public_key, mode=0o644)
        # Public keys are embedded in exported client configurations. Older
        # pre-release builds created this file as root-only, so repair its
        # mode idempotently whenever the component is reconciled.
        public_path.chmod(0o644)
        if not config_path.exists():
            parameters = self._new_amnezia_parameters()
            write_secret_file(config_path, "\n".join([
                "[Interface]",
                f"Address = {self.settings.amnezia_address}, {self.settings.amnezia_address_v6}",
                f"ListenPort = {self.settings.amnezia_port}",
                f"PrivateKey = {key_path.read_text().strip()}",
                *(f"{key} = {value}" for key, value in parameters.items()),
                "SaveConfig = false",
                "",
            ]))
        else:
            existing_config = config_path.read_text()
            lines = existing_config.splitlines()
            section = ""
            address_lines: list[int] = []
            addresses: list[str] = []
            for index, line in enumerate(lines):
                content = line.split("#", 1)[0].strip()
                if content.startswith("[") and content.endswith("]"):
                    section = content[1:-1].strip().lower()
                elif section == "interface" and "=" in content:
                    key, value = (part.strip() for part in content.split("=", 1))
                    if key.lower() == "address":
                        address_lines.append(index)
                        for item in value.split(","):
                            address = str(ipaddress.ip_interface(item.strip()))
                            if address not in addresses:
                                addresses.append(address)
            if not address_lines:
                raise RuntimeError("The AmneziaWG server configuration has no interface address")
            ipv6_address = str(ipaddress.ip_interface(self.settings.amnezia_address_v6))
            if ipv6_address not in addresses:
                addresses.append(ipv6_address)
            # The installer can use separate Address lines. Read all of them
            # and repair duplicates left by older first-line-only checks.
            updated_lines = [f"Address = {', '.join(addresses)}" if index == address_lines[0] else line
                             for index, line in enumerate(lines) if index == address_lines[0] or index not in address_lines]
            if updated_lines != lines:
                write_secret_file(config_path, "\n".join(updated_lines) + "\n")
        self._read_amnezia_parameters(config_path)
        link = self.runner.run([self.routes.ip, "link", "show", self.settings.amnezia_interface], timeout=10)
        if link.returncode != 0:
            started = self.runner.run(self._amnezia_quick_argv(awg, quick, userspace, "up", config_path), timeout=30)
            if started.returncode != 0:
                raise RuntimeError(started.stderr.strip() or "AmneziaWG interface could not start")

    def secret_store(self, payload: dict) -> dict:
        if set(payload) - {"value", "label"}:
            raise ValueError("unsupported secret field")
        reference = self.secrets.store(payload.get("value"))
        return {"secret_ref": reference, "label": str(payload.get("label", "secret"))[:80]}

    def secret_delete(self, payload: dict) -> dict:
        if set(payload) - {"secret_ref"}:
            raise ValueError("unsupported secret field")
        reference = str(payload.get("secret_ref", ""))
        self.secrets.delete(reference)
        return {"secret_ref": reference, "state": "deleted"}

    @staticmethod
    def _totp_identity(payload: dict) -> tuple[str, str]:
        account = str(payload.get("account", "owner"))
        issuer = str(payload.get("issuer", "CayVPN"))
        if not account or len(account) > 120 or any(ord(character) < 32 for character in account):
            raise ValueError("invalid TOTP account")
        if not issuer or len(issuer) > 80 or any(ord(character) < 32 for character in issuer):
            raise ValueError("invalid TOTP issuer")
        return account, issuer

    def totp_create(self, payload: dict) -> dict:
        if set(payload) - {"account", "issuer"}:
            raise ValueError("unsupported TOTP creation field")
        account, issuer = self._totp_identity(payload)
        secret = generate_totp_secret()
        reference = self.secrets.store(secret)
        return {"secret_ref": reference, "provisioning_uri": totp_uri(secret, account, issuer)}

    def totp_uri(self, payload: dict) -> dict:
        if set(payload) - {"secret_ref", "account", "issuer"}:
            raise ValueError("unsupported TOTP provisioning field")
        account, issuer = self._totp_identity(payload)
        reference = str(payload.get("secret_ref", ""))
        return {"provisioning_uri": totp_uri(self.secrets.reveal(reference), account, issuer)}

    def totp_verify(self, payload: dict) -> dict:
        if set(payload) - {"secret_ref", "code"}:
            raise ValueError("unsupported TOTP verification field")
        reference = str(payload.get("secret_ref", ""))
        code = str(payload.get("code", ""))
        return {"verified": verify_totp(self.secrets.reveal(reference), code)}

    @staticmethod
    def _config_endpoint(value: object) -> str:
        endpoint = str(value or "")
        if not endpoint or len(endpoint) > 253 or not re.fullmatch(r"[A-Za-z0-9:.\[\]-]+:[0-9]{1,5}", endpoint):
            raise ValueError("invalid configuration endpoint")
        try:
            port = int(endpoint.rsplit(":", 1)[1])
        except (IndexError, ValueError) as exc:
            raise ValueError("invalid configuration endpoint") from exc
        if not 1 <= port <= 65535:
            raise ValueError("invalid configuration endpoint port")
        return endpoint

    def config_render_client(self, payload: dict) -> dict:
        allowed = {"secret_ref", "address", "server_public_key", "endpoint", "dns", "protocol", "allowed_ips", "persistent_keepalive", "ipv6_policy"}
        if set(payload) - allowed:
            raise ValueError("unsupported client config field")
        private_key = self.secrets.reveal(str(payload.get("secret_ref", "")))
        self._wireguard_key(payload.get("server_public_key"), "server public key")
        address = str(payload.get("address", ""))
        addresses = []
        for item in address.split(","):
            try:
                addresses.append(ipaddress.ip_interface(item.strip()))
            except ValueError as exc:
                raise ValueError("invalid client configuration address") from exc
        if not 1 <= len(addresses) <= 2 or len({item.version for item in addresses}) != len(addresses):
            raise ValueError("client configuration must have one address per family")
        if not any(item.version == 4 and item.network.prefixlen == 32 for item in addresses):
            raise ValueError("client configuration requires an IPv4 /32 address")
        if any(item.version == 6 and item.network.prefixlen != 128 for item in addresses):
            raise ValueError("client IPv6 configuration addresses must use /128")
        endpoint = self._config_endpoint(payload.get("endpoint"))
        protocol = str(payload.get("protocol", "wireguard")).lower()
        if protocol not in {"wireguard", "amneziawg"}:
            raise ValueError("unsupported client config protocol")
        allowed_ips = str(payload.get("allowed_ips", "0.0.0.0/0, ::/0"))
        try:
            allowed_networks = [ipaddress.ip_network(item.strip(), strict=False) for item in allowed_ips.split(",")]
        except ValueError as exc:
            raise ValueError("invalid client AllowedIPs") from exc
        required_networks = {ipaddress.IPv4Network("0.0.0.0/0"), ipaddress.IPv6Network("::/0")}
        if len(allowed_networks) != 2 or set(allowed_networks) != required_networks:
            raise ValueError("client configuration requires the IPv4 and IPv6 full-tunnel routes")
        allowed_ips = "0.0.0.0/0, ::/0"
        dns = str(payload.get("dns", ""))
        dns_addresses = []
        for item in dns.split(","):
            try:
                dns_addresses.append(ipaddress.ip_address(item.strip()))
            except ValueError as exc:
                raise ValueError("invalid client DNS address") from exc
        if not 1 <= len(dns_addresses) <= 2 or len({item.version for item in dns_addresses}) != len(dns_addresses):
            raise ValueError("client DNS must have at most one address per family")
        ipv6_policy = str(payload.get("ipv6_policy", "auto"))
        if ipv6_policy not in {"auto", "required"}:
            raise ValueError("invalid client IPv6 policy")
        keepalive = int(payload.get("persistent_keepalive", 25))
        if not 0 <= keepalive <= 65535:
            raise ValueError("invalid keepalive")
        rendered_dns = ", ".join(
            [*(str(address) for address in dns_addresses), admin_dns_search_domain(self.settings.admin_hostname)]
        )
        interface_lines = [
            "# Managed by CayVPN. This is a full-tunnel configuration.",
            f"# Ingress protocol: {protocol}",
            f"# IPv6 protection: {'required' if ipv6_policy == 'required' else 'smart'}",
            "[Interface]",
            f"PrivateKey = {private_key}",
            f"Address = {address}",
            f"DNS = {rendered_dns}",
        ]
        if protocol == "amneziawg":
            parameters = self._read_amnezia_parameters(self.settings.wg_dir / f"{self.settings.amnezia_interface}.conf")
            interface_lines.extend(f"{key} = {value}" for key, value in parameters.items())
        config = "\n".join([
            *interface_lines,
            "",
            "[Peer]",
            f"PublicKey = {payload['server_public_key']}",
            f"Endpoint = {endpoint}",
            f"AllowedIPs = {allowed_ips}",
            f"PersistentKeepalive = {keepalive}",
            "",
        ])
        return {"config": config, "protocol": protocol}

    def config_render_admin(self, payload: dict) -> dict:
        allowed = {"secret_ref", "address", "server_public_key", "endpoint", "dns", "allowed_ips"}
        if set(payload) - allowed:
            raise ValueError("unsupported admin config field")
        private_key = self.secrets.reveal(str(payload.get("secret_ref", "")))
        self._wireguard_key(payload.get("server_public_key"), "admin server public key")
        address = str(payload.get("address", ""))
        interface = ipaddress.ip_interface(address)
        if interface.version != 4 or interface.network.prefixlen != 32:
            raise ValueError("invalid admin address")
        endpoint = self._config_endpoint(payload.get("endpoint"))
        admin_ip = str(ipaddress.ip_interface(self.settings.admin_address).ip)
        dns = str(payload.get("dns", admin_ip))
        dns_address = ipaddress.ip_address(dns)
        allowed_ips = str(payload.get("allowed_ips", f"{admin_ip}/32"))
        for item in allowed_ips.split(","):
            ipaddress.ip_network(item.strip(), strict=False)
        config = "\n".join([
            "# CayVPN private admin tunnel. Keep this file secret.",
            "[Interface]",
            f"PrivateKey = {private_key}",
            f"Address = {address}",
            f"DNS = {dns_address}, {admin_dns_search_domain(self.settings.admin_hostname)}",
            "",
            "[Peer]",
            f"PublicKey = {payload['server_public_key']}",
            f"Endpoint = {endpoint}",
            f"AllowedIPs = {allowed_ips}",
            "PersistentKeepalive = 25",
            "",
        ])
        return {"config": config, "protocol": "wireguard"}

    def backup_create(self, payload: dict) -> dict:
        if set(payload) - {"passphrase"}:
            raise ValueError("unsupported backup field")
        passphrase = str(payload.get("passphrase", ""))
        if not 12 <= len(passphrase) <= 512:
            raise ValueError("Backup passphrase must be at least 12 characters")
        from .db import Database

        with Database(self.settings) as database:
            database.initialize_defaults(self.settings)
            output = create_backup(self.settings, database, passphrase)
        return {"path": str(output), "sha256": hashlib.sha256(output.read_bytes()).hexdigest(), "state": "created"}

    def _current_release(self) -> str:
        try:
            active = self.settings.active_release.resolve()
            if active != self.settings.active_release and active.parent.resolve() == self.settings.release_dir.resolve():
                return str(Version.parse(active.name))
        except (OSError, UpdateError):
            pass
        return str(Version.parse(os.environ.get("CAYVPN_RELEASE_VERSION", "2.0.0-dev")))

    def update_check(self, _payload: dict) -> dict:
        manager = UpdateManager(self.settings)
        state = manager.status().get("state")
        if state in {"stage_queued", "staging", "install_queued", "installing"}:
            raise UpdateError("update_busy", "Another CayVPN update task is already running.")
        if state == "staged":
            raise UpdateError("staged_update_pending", "Install or remove the verified download before checking for another update.")
        return manager.check(self._current_release())

    def _start_update_runner(self, command: str, release: str, operation_id: str, desired_generation: int) -> str:
        if command not in {"stage", "apply"}:
            raise ValueError("unsupported update runner action")
        unit = f"cayvpn-update-{command}-{operation_id[:18]}"
        runner = self.settings.active_release / ".venv" / "bin" / "python"
        argv = [
            "/usr/bin/systemd-run",
            f"--unit={unit}",
            "--collect",
            "--property=Type=exec",
            "--property=TimeoutStartSec=30min",
            "--property=UMask=0077",
            "--property=Environment=PYTHONDONTWRITEBYTECODE=1",
            "--property=NoNewPrivileges=true",
            "--property=PrivateTmp=true",
            "--property=ProtectHome=true",
            "--property=ProtectSystem=full",
            f"--property=ReadWritePaths={self.settings.state_dir} {self.settings.config_dir} {self.settings.wg_dir} {self.settings.release_dir.parent}",
            str(runner),
            "-m",
            "cayvpn.update_runner",
            command,
            "--release",
            release,
            "--operation-id",
            operation_id,
            "--desired-generation",
            str(desired_generation),
        ]
        result = self.runner.run(argv, timeout=20)
        if result.returncode != 0:
            raise UpdateError("update_runner_failed", "The verified update task could not be started. No active release was changed.")
        return unit

    def update_stage(self, payload: dict, operation_id: str, desired_generation: int) -> dict:
        if set(payload) != {"release"}:
            raise ValueError("unsupported update staging field")
        release = str(Version.parse(str(payload.get("release", ""))))
        current = self._current_release()
        if Version.parse(release) <= Version.parse(current):
            raise UpdateError("update_not_newer", "Only a newer CayVPN release can be staged from the panel.")
        state = UpdateManager(self.settings).status().get("state")
        if state in {"stage_queued", "staging", "install_queued", "installing"}:
            raise UpdateError("update_busy", "Another CayVPN update task is already running.")
        if state == "staged":
            raise UpdateError("staged_update_pending", "Install or remove the verified download before downloading another update.")
        queued = write_update_state(self.settings, "stage_queued", current_release=current, target_release=release, operation_id=operation_id)
        if not self.settings.apply_network:
            queued["simulated"] = True
            return queued
        try:
            queued["unit"] = self._start_update_runner("stage", release, operation_id, desired_generation)
        except UpdateError as exc:
            write_update_state(self.settings, "stage_failed", current_release=current, target_release=release, operation_id=operation_id, error_code=exc.code, error_message=str(exc))
            raise
        return queued

    def update_status(self, _payload: dict) -> dict:
        return UpdateManager(self.settings).status()

    def update_discard(self, payload: dict) -> dict:
        if set(payload) != {"release"}:
            raise ValueError("unsupported update discard field")
        release = str(Version.parse(str(payload.get("release", ""))))
        status = UpdateManager(self.settings).status()
        if status.get("state") != "staged" or status.get("target_release") != release:
            raise UpdateError("release_not_staged", "That verified download is no longer staged.")
        target = (self.settings.release_dir / release).resolve()
        release_root = self.settings.release_dir.resolve()
        if release_root not in target.parents or target.is_symlink() or not target.is_dir():
            raise UpdateError("unsafe_release", "The staged release path is unsafe and was not removed.")
        try:
            if self.settings.active_release.exists() and self.settings.active_release.resolve() == target:
                raise UpdateError("active_release", "The active CayVPN release cannot be discarded.")
            shutil.rmtree(target)
        except UpdateError:
            raise
        except OSError as exc:
            raise UpdateError("discard_failed", "The verified download could not be removed safely.") from exc
        return write_update_state(self.settings, "discarded", current_release=self._current_release(), target_release=release)

    def update_apply(self, payload: dict, operation_id: str, desired_generation: int) -> dict:
        if set(payload) != {"release"}:
            raise ValueError("unsupported update installation field")
        release = str(Version.parse(str(payload.get("release", ""))))
        current = self._current_release()
        if Version.parse(release) <= Version.parse(current):
            raise UpdateError("update_not_newer", "Only a newer staged release can be installed from the panel.")
        target = (self.settings.release_dir / release).resolve()
        if self.settings.release_dir.resolve() not in target.parents or not target.is_dir():
            raise UpdateError("release_not_staged", "Download and verify this release before installing it.")
        verify_installed_release(self.settings, target, current, release)
        status = UpdateManager(self.settings).status()
        if status.get("state") != "staged" or status.get("target_release") != release:
            raise UpdateError("release_not_staged", "Download and verify this release before installing it.")
        queued = write_update_state(self.settings, "install_queued", current_release=current, target_release=release, operation_id=operation_id)
        if not self.settings.apply_network:
            queued["simulated"] = True
            return queued
        try:
            unit = self._start_update_runner("apply", release, operation_id, desired_generation)
        except UpdateError:
            write_update_state(self.settings, "install_failed", current_release=current, target_release=release, operation_id=operation_id, error_code="update_runner_failed", error_message="The verified update could not be started. No active release was changed.")
            raise
        queued["unit"] = unit
        return queued


class AgentServer:
    def __init__(self, settings: Settings, executor: NodeExecutor | None = None):
        self.settings = settings
        self.executor = executor or NodeExecutor(settings)
        self.socket_path = settings.agent_socket

    @staticmethod
    def _send_response(connection, response: AgentResponse) -> bool:
        try:
            connection.sendall((json.dumps(response.to_dict()) + "\n").encode())
            return True
        except (BrokenPipeError, ConnectionResetError, OSError):
            # The typed operation may finish after a caller disconnects. A
            # lost response must not terminate the root agent and tear down
            # every process-pinned namespace; worker reconciliation resolves
            # the operation's desired generation separately.
            logger.warning("Agent caller disconnected before operation %s was returned", response.operation_id)
            return False

    @staticmethod
    def _peer_credentials(connection) -> tuple[int, int, int]:
        """Return the kernel-reported pid, uid, and gid for a Unix peer."""
        option = getattr(socket, "SO_PEERCRED", None)
        if option is None:
            raise OSError("SO_PEERCRED is unavailable on this platform")
        raw = connection.getsockopt(socket.SOL_SOCKET, option, struct.calcsize("3i"))
        return struct.unpack("3i", raw)

    @classmethod
    def _peer_authorized(cls, connection) -> bool:
        try:
            # Linux struct ucred is ordered pid, uid, gid. Treating it as
            # uid, gid, pid rejects legitimate root and service callers while
            # comparing the process id to the service group.
            pid, uid, gid = cls._peer_credentials(connection)
            expected_gid = grp.getgrnam("cayvpn").gr_gid
        except (KeyError, OSError, struct.error):
            return False
        # The socket is already mode 0660, but checking the credentials at
        # accept time prevents a replaced socket or an unexpected local group
        # member from reaching typed root operations. The service group is the
        # deliberate web/worker boundary; it cannot grant arbitrary commands
        # because AgentRequest still validates the action and payload.
        return pid > 0 and (uid == 0 or gid == expected_gid)

    def serve_forever(self) -> None:
        self.socket_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            existing = self.socket_path.lstat()
            if not stat.S_ISSOCK(existing.st_mode):
                raise RuntimeError("CayVPN agent socket path is not a socket")
            self.socket_path.unlink()
        except FileNotFoundError:
            pass
        try:
            os.chmod(self.socket_path.parent, 0o750)
            os.chown(self.socket_path.parent, 0, grp.getgrnam("cayvpn").gr_gid)
        except (KeyError, PermissionError):
            logger.warning("Could not harden the CayVPN agent socket directory")
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(str(self.socket_path))
        os.chmod(self.socket_path, 0o660)
        try:
            os.chown(self.socket_path, 0, grp.getgrnam("cayvpn").gr_gid)
        except (KeyError, PermissionError):
            logger.warning("Could not assign cayvpn group to agent socket")
        server.listen(16)
        logger.info("CayVPN agent listening on %s", self.socket_path)
        try:
            while True:
                connection, _ = server.accept()
                with connection:
                    if not self._peer_authorized(connection):
                        logger.warning("Rejected an unauthorized CayVPN agent socket caller")
                        self._send_response(connection, AgentResponse("unknown", "failed", error_code="agent_peer_not_authorized", error_message="The local CayVPN caller is not authorized."))
                        continue
                    data = b""
                    while b"\n" not in data and len(data) < 2 * 1024 * 1024:
                        chunk = connection.recv(65536)
                        if not chunk:
                            break
                        data += chunk
                    request = {}
                    try:
                        request = json.loads(data.split(b"\n", 1)[0].decode())
                        agent_request = AgentRequest(
                            operation_id=request["operation_id"],
                            action=request["action"],
                            node_id=request.get("node_id", 1),
                            desired_generation=request.get("desired_generation", 0),
                            payload=request.get("payload") or {},
                            protocol_version=request.get("protocol_version", 1),
                        )
                        response = self.executor.execute(agent_request)
                    except Exception as exc:
                        response = AgentResponse(str(request.get("operation_id", "unknown")) if isinstance(request, dict) else "unknown", "failed", error_code="invalid_request", error_message=str(exc))
                    self._send_response(connection, response)
        finally:
            server.close()


def run_agent() -> None:
    logging.basicConfig(level=os.environ.get("CAYVPN_LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(name)s %(message)s")
    AgentServer(Settings.from_env()).serve_forever()
