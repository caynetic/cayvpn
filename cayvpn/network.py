from __future__ import annotations

import hashlib
import ipaddress
import json
import shutil
import socket
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from .config import Settings
from .components import component_binary
from .dual_stack import family_capabilities, ipv6_usable
from .security import write_secret_file


class NetworkOperationError(RuntimeError):
    """An operation could not be applied safely by the root agent."""

    def __init__(self, code: str, message: str, result: dict | None = None):
        super().__init__(message)
        self.code = code
        self.result = result or {}


@dataclass(frozen=True)
class NamespacePlan:
    name: str
    host_interface: str
    namespace_interface: str
    host_address: str
    namespace_address: str
    host_address_v6: str
    namespace_address_v6: str


class NetworkRouteManager:
    """Apply the small, typed network surface needed by the root agent.

    The manager deliberately accepts structured values rather than a route
    string.  Direct and additional-IP exits use a private veth namespace and
    one policy table per client.  The namespace gives us a safe place to add
    driver-specific processes later without changing the panel contract.
    """

    def __init__(self, settings: Settings, runner):
        self.settings = settings
        self.runner = runner
        self.ip = shutil.which("ip") or "ip"
        self.nft = shutil.which("nft") or "nft"
        self.conntrack = shutil.which("conntrack")
        self.unshare = shutil.which("unshare") or "unshare"
        self.nsenter = shutil.which("nsenter") or "nsenter"
        self.sleep = shutil.which("sleep") or "sleep"
        self.sysctl = shutil.which("sysctl") or "sysctl"
        self.namespace_processes: dict[str, object] = {}
        self.runtime_processes: dict[int, object] = {}
        self.runtime_udp_modes: dict[int, bool] = {}
        self.runtime_udp_v6_modes: dict[int, bool] = {}
        self.runtime_ipv6_modes: dict[int, bool] = {}
        self.dns_processes: dict[tuple[int, str], object] = {}
        self.client_dns_address = settings.client_dns_address
        self.client_adblock_dns_address = settings.client_adblock_dns_address
        self.client_dns_address_v6 = settings.client_dns_address_v6
        self.client_adblock_dns_address_v6 = settings.client_adblock_dns_address_v6

    @staticmethod
    def _profile_number(value: object) -> int:
        try:
            number = int(value)
        except (TypeError, ValueError) as exc:
            raise NetworkOperationError("invalid_profile", "An egress profile id is required") from exc
        if number < 1 or number > 999999:
            raise NetworkOperationError("invalid_profile", "The egress profile id is out of range")
        return number

    def _names(self, profile_id: object) -> NamespacePlan:
        number = self._profile_number(profile_id)
        digest = hashlib.sha256(str(number).encode()).hexdigest()[:6]
        # Linux interface names are limited to 15 characters.
        name = f"cv-eg-{digest}"[:15]
        host = f"cvh{digest}"[:15]
        peer = f"cvn{digest}"[:15]
        transport_v4 = ipaddress.IPv4Network(
            self.settings.egress_network_v4, strict=True
        )
        pair_base_v4 = number * 4
        if pair_base_v4 + 2 >= transport_v4.num_addresses:
            raise NetworkOperationError(
                "invalid_profile",
                "The Location id exceeds the configured IPv4 transport network",
            )
        host_v4 = transport_v4.network_address + pair_base_v4 + 1
        namespace_v4 = host_v4 + 1
        transport = ipaddress.IPv6Network(self.settings.egress_network_v6, strict=False)
        pair_base = number * 2
        host_v6 = transport.network_address + pair_base
        namespace_v6 = host_v6 + 1
        return NamespacePlan(
            name=name,
            host_interface=host,
            namespace_interface=peer,
            host_address=f"{host_v4}/30",
            namespace_address=f"{namespace_v4}/30",
            host_address_v6=f"{host_v6}/127",
            namespace_address_v6=f"{namespace_v6}/127",
        )

    def _run(self, argv: list[str], timeout: int = 15, allow_existing: bool = False):
        if not argv or any(not isinstance(item, str) or "\x00" in item for item in argv):
            raise NetworkOperationError("invalid_network_operation", "Invalid network operation")
        result = self.runner.run(argv, timeout=timeout)
        if result.returncode != 0:
            detail = (result.stderr or result.stdout or "network command failed").strip()
            normalized = detail.lower()
            if allow_existing and any(
                marker in normalized
                for marker in ("file exists", "already exists", "address already assigned")
            ):
                return result
            raise NetworkOperationError("network_command_failed", detail[:240])
        return result

    def _namespace_process(self, name: str):
        process = self.namespace_processes.get(name)
        if process is None:
            return None
        if getattr(process, "poll", lambda: 1)() is not None:
            self.namespace_processes.pop(name, None)
            return None
        pid = getattr(process, "pid", None)
        if not isinstance(pid, int) or pid < 2:
            self.namespace_processes.pop(name, None)
            return None
        return process

    def _namespace_argv(self, plan: NamespacePlan | str, argv: list[str]) -> list[str]:
        name = plan.name if isinstance(plan, NamespacePlan) else plan
        process = self._namespace_process(name)
        if process is None:
            raise NetworkOperationError("namespace_unavailable", "The isolated egress namespace is unavailable")
        return [self.nsenter, "--target", str(process.pid), "--net", "--", *argv]

    def _run_namespace(self, plan: NamespacePlan, argv: list[str], timeout: int = 15, allow_existing: bool = False):
        return self._run(self._namespace_argv(plan, argv), timeout=timeout, allow_existing=allow_existing)

    @staticmethod
    def _route_uses(result: object, interface: str, gateway: str | None = None) -> bool:
        """Require a kernel route observation to use the exact typed path."""
        if getattr(result, "returncode", 1) != 0:
            return False
        output = str(getattr(result, "stdout", "") or "")
        lowered = output.lower()
        if any(word in lowered for word in ("prohibit", "unreachable", "blackhole")):
            return False
        tokens = output.split()
        try:
            observed_interface = tokens[tokens.index("dev") + 1]
        except (ValueError, IndexError):
            return False
        if observed_interface != interface:
            return False
        if gateway is not None:
            try:
                observed_gateway = tokens[tokens.index("via") + 1]
            except (ValueError, IndexError):
                return False
            if observed_gateway != gateway:
                return False
        return True

    def _stop_namespace(self, name: str) -> None:
        process = self.namespace_processes.pop(name, None)
        if process is None or getattr(process, "poll", lambda: 0)() is not None:
            return
        process.terminate()
        try:
            process.wait(timeout=2)
        except Exception:
            process.kill()
            try:
                process.wait(timeout=2)
            except Exception:
                pass

    def _start_namespace(self, plan: NamespacePlan):
        spawn = getattr(self.runner, "spawn", None)
        if spawn is None:
            raise NetworkOperationError("namespace_runtime_unavailable", "The root runner cannot create isolated network namespaces")
        process = spawn([self.unshare, "--net", "--", self.sleep, "infinity"], timeout=10)
        self.namespace_processes[plan.name] = process
        for _ in range(30):
            if getattr(process, "poll", lambda: 1)() is not None:
                break
            try:
                probe_argv = self._namespace_argv(plan, [self.ip, "link", "show", "lo"])
            except NetworkOperationError:
                break
            probe = self.runner.run(probe_argv, timeout=5)
            if probe.returncode == 0:
                return process
            time.sleep(0.05)
        self._stop_namespace(plan.name)
        raise NetworkOperationError("namespace_runtime_failed", "The isolated egress namespace did not start")

    def _namespace_exists(self, name: str) -> bool:
        process = self._namespace_process(name)
        if process is None:
            return False
        probe = self.runner.run(self._namespace_argv(name, [self.ip, "link", "show", "lo"]), timeout=10)
        if probe.returncode == 0:
            return True
        self._stop_namespace(name)
        return False

    def ensure_namespace(self, profile_id: object) -> NamespacePlan:
        plan = self._names(profile_id)
        if not self._namespace_exists(plan.name):
            stale_link = self.runner.run([self.ip, "link", "delete", plan.host_interface], timeout=10)
            if stale_link.returncode != 0:
                detail = (stale_link.stderr or stale_link.stdout or "").lower()
                if not any(marker in detail for marker in ("no such", "not found", "does not exist", "cannot find")):
                    raise NetworkOperationError("stale_namespace_link_remove_failed", "A stale egress namespace interface could not be removed")
            process = self._start_namespace(plan)
            try:
                self._run([self.ip, "link", "add", plan.host_interface, "type", "veth", "peer", "name", plan.namespace_interface])
                self._run([self.ip, "link", "set", plan.namespace_interface, "netns", str(process.pid)])
                self._run([self.ip, "addr", "add", plan.host_address, "dev", plan.host_interface], allow_existing=True)
                self._run([self.ip, "-6", "addr", "add", plan.host_address_v6, "dev", plan.host_interface], allow_existing=True)
                self._run([self.ip, "link", "set", plan.host_interface, "up"])
                self._run_namespace(plan, [self.ip, "addr", "add", plan.namespace_address, "dev", plan.namespace_interface], allow_existing=True)
                self._run_namespace(plan, [self.ip, "-6", "addr", "add", plan.namespace_address_v6, "dev", plan.namespace_interface], allow_existing=True)
                self._run_namespace(plan, [self.ip, "link", "set", "lo", "up"])
                self._run_namespace(plan, [self.ip, "link", "set", plan.namespace_interface, "up"])
                host_ip = str(ipaddress.ip_interface(plan.host_address).ip)
                self._run_namespace(plan, [self.ip, "route", "replace", "default", "via", host_ip, "dev", plan.namespace_interface])
                host_ip_v6 = str(ipaddress.ip_interface(plan.host_address_v6).ip)
                self._run_namespace(plan, [self.ip, "-6", "route", "replace", "default", "via", host_ip_v6, "dev", plan.namespace_interface])
            except Exception:
                self._stop_namespace(plan.name)
                raise
        self._ensure_namespace_forwarding(plan)
        self._ensure_namespace_source_nat(plan)
        namespace_ip = str(ipaddress.ip_interface(plan.namespace_address).ip)
        self._ensure_source_nat_default(namespace_ip, self.settings.server_ip)
        if self.settings.server_ipv6:
            self._ensure_source_nat_default(
                str(ipaddress.ip_interface(plan.namespace_address_v6).ip),
                self.settings.server_ipv6,
            )
        return plan

    def _ensure_namespace_forwarding(self, plan: NamespacePlan) -> None:
        """Enable both address families inside the isolated egress namespace.

        Network namespaces inherit IPv4 forwarding on Ubuntu, but a newly
        created namespace starts with IPv6 forwarding disabled. Direct-exit
        traffic crosses the namespace and returns through its veth, so both
        families must be explicitly enabled there as well as on the host.
        """
        for setting in ("net.ipv4.ip_forward", "net.ipv6.conf.all.forwarding"):
            observed = self.runner.run(self._namespace_argv(plan, [self.sysctl, "-n", setting]), timeout=10)
            if observed.returncode == 0 and (observed.stdout or "").strip() == "1":
                continue
            self._run_namespace(plan, [self.sysctl, "-w", f"{setting}=1"], timeout=10)

    def _ensure_namespace_source_nat(self, plan: NamespacePlan) -> None:
        """Give a returning namespace packet a fresh host conntrack tuple.

        A client packet first traverses the host policy table, crosses the
        profile veth, and then returns through that same veth for a direct or
        provider-endpoint route. Without this namespace-level translation the
        second host pass reuses the first conntrack entry and skips public
        source NAT. Masquerading to the generated namespace address creates a
        distinct tuple; the host map then selects the profile's explicit
        public source address.
        """
        prefix = self._namespace_argv(plan, [self.nft])
        observed = self.runner.run([*prefix, "list", "chain", "ip", "cayvpn", "postrouting"], timeout=10)
        expected = f'oifname "{plan.namespace_interface}" masquerade'
        if observed.returncode != 0 or expected not in (observed.stdout or ""):
            removed = self.runner.run([*prefix, "delete", "table", "ip", "cayvpn"], timeout=10)
            if removed.returncode != 0:
                detail = (removed.stderr or removed.stdout or "").lower()
                if not any(marker in detail for marker in ("no such", "not found", "does not exist", "cannot find")):
                    raise NetworkOperationError("namespace_nat_reconcile_failed", "The egress namespace NAT table could not be reconciled")
            self._run([*prefix, "add", "table", "ip", "cayvpn"])
            self._run([
                *prefix,
                "add",
                "chain",
                "ip",
                "cayvpn",
                "postrouting",
                "{",
                "type",
                "nat",
                "hook",
                "postrouting",
                "priority",
                "srcnat",
                ";",
                "policy",
                "accept",
                ";",
                "}",
            ])
            self._run([*prefix, "add", "rule", "ip", "cayvpn", "postrouting", "oifname", plan.namespace_interface, "masquerade"])
        self._ensure_namespace_source_nat_v6(plan)

    def _ensure_namespace_source_nat_v6(self, plan: NamespacePlan) -> None:
        prefix = self._namespace_argv(plan, [self.nft])
        observed = self.runner.run([*prefix, "list", "chain", "ip6", "cayvpn", "postrouting"], timeout=10)
        expected = f'oifname "{plan.namespace_interface}" masquerade'
        if observed.returncode == 0 and expected in (observed.stdout or ""):
            return
        removed = self.runner.run([*prefix, "delete", "table", "ip6", "cayvpn"], timeout=10)
        if removed.returncode != 0:
            detail = (removed.stderr or removed.stdout or "").lower()
            if not any(marker in detail for marker in ("no such", "not found", "does not exist", "cannot find")):
                raise NetworkOperationError("namespace_nat_reconcile_failed", "The IPv6 egress namespace NAT table could not be reconciled")
        self._run([*prefix, "add", "table", "ip6", "cayvpn"])
        self._run([
            *prefix, "add", "chain", "ip6", "cayvpn", "postrouting", "{", "type", "nat", "hook", "postrouting", "priority", "srcnat", ";", "policy", "accept", ";", "}",
        ])
        self._run([*prefix, "add", "rule", "ip6", "cayvpn", "postrouting", "oifname", plan.namespace_interface, "masquerade"])

    def _ensure_namespace_egress_nat(self, plan: NamespacePlan, interface: str) -> None:
        """Translate managed client addresses to a provider tunnel address."""
        prefix = self._namespace_argv(plan, [self.nft])
        observed = self.runner.run([*prefix, "list", "chain", "ip", "cayvpn", "postrouting"], timeout=10)
        expected = f'oifname "{interface}" masquerade'
        if observed.returncode != 0:
            self._ensure_namespace_source_nat(plan)
        if expected not in (observed.stdout or ""):
            self._run([*prefix, "add", "rule", "ip", "cayvpn", "postrouting", "oifname", interface, "masquerade"])
        prefix_v6 = self._namespace_argv(plan, [self.nft])
        observed_v6 = self.runner.run([*prefix_v6, "list", "chain", "ip6", "cayvpn", "postrouting"], timeout=10)
        expected_v6 = f'oifname "{interface}" masquerade'
        if observed_v6.returncode != 0:
            self._ensure_namespace_source_nat_v6(plan)
            observed_v6 = self.runner.run([*prefix_v6, "list", "chain", "ip6", "cayvpn", "postrouting"], timeout=10)
        if expected_v6 not in (observed_v6.stdout or ""):
            self._run([*prefix_v6, "add", "rule", "ip6", "cayvpn", "postrouting", "oifname", interface, "masquerade"])

    def _ensure_client_return_routes(self, plan: NamespacePlan) -> None:
        """Keep tunnel replies from following the egress default route again."""
        host_ip = str(ipaddress.ip_interface(plan.host_address).ip)
        for configured in (self.settings.user_network, self.settings.amnezia_network, self.settings.user_network_v6, self.settings.amnezia_network_v6):
            try:
                network = ipaddress.ip_network(str(configured), strict=False)
            except ValueError as exc:
                raise NetworkOperationError("invalid_ingress_network", "A configured client network is invalid") from exc
            host_route = str(ipaddress.ip_interface(plan.host_address_v6).ip) if network.version == 6 else host_ip
            self._run_namespace(
                plan,
                [self.ip, "-6" if network.version == 6 else "-4", "route", "replace", str(network), "via", host_route, "dev", plan.namespace_interface],
            )

    @staticmethod
    def _client_address(value: object) -> tuple[str, int]:
        try:
            interface = ipaddress.ip_interface(str(value))
        except ValueError as exc:
            raise NetworkOperationError("invalid_client_address", "The client address is invalid") from exc
        if interface.version != 4 or interface.network.prefixlen != 32:
            raise NetworkOperationError("invalid_client_address", "Only IPv4 /32 client addresses are supported by this route manager")
        return str(interface.ip), interface.network.prefixlen

    def _client_ipv6_address(self, value: object | None) -> tuple[str, int] | None:
        if value in (None, ""):
            return None
        try:
            interface = ipaddress.ip_interface(str(value))
        except ValueError as exc:
            raise NetworkOperationError("invalid_client_address", "The client IPv6 address is invalid") from exc
        if interface.version != 6 or interface.network.prefixlen != 128:
            raise NetworkOperationError("invalid_client_address", "Client IPv6 addresses must use a /128 prefix")
        managed_networks = (
            ipaddress.IPv6Network(self.settings.user_network_v6, strict=True),
            ipaddress.IPv6Network(self.settings.amnezia_network_v6, strict=True),
        )
        if not any(interface.ip in network for network in managed_networks):
            raise NetworkOperationError("invalid_client_address", "The client IPv6 address must be a private CayVPN address")
        return str(interface.ip), interface.network.prefixlen

    @staticmethod
    def _table(profile_id: object, client_address: object | None = None) -> tuple[int, int]:
        if client_address is not None:
            try:
                address = ipaddress.ip_address(str(client_address).split("/", 1)[0])
            except ValueError as exc:
                raise NetworkOperationError("invalid_client_address", "The client address is invalid") from exc
            if address.version != 4:
                raise NetworkOperationError("invalid_client_address", "Only IPv4 client addresses are supported by this route manager")
            # Linux route-table identifiers are unsigned 32-bit values.  The
            # client IPv4 address is globally unique across the configured
            # ingress networks, so clients cannot flush one another's table.
            table = 100000 + int(address)
            return table, 10000
        number = NetworkRouteManager._profile_number(profile_id)
        # Keep the egress table away from distribution-managed tables and put
        # source rules ahead of Linux's main/default rules (32766/32767).
        # Rules with the same priority remain distinct because the source
        # selector differs per client; switching removes the old table rule.
        return 20000 + number, 10000

    def _ingress_interface(self, value: object | None) -> str:
        interface = str(value or self.settings.user_interface).strip()
        allowed = {self.settings.user_interface, self.settings.amnezia_interface}
        if interface not in allowed:
            raise NetworkOperationError("invalid_ingress_interface", "The client ingress interface is invalid")
        return interface

    def _validate_ipv6_ingress(self, ipv6: tuple[str, int] | None, ingress_interface: str) -> None:
        if ipv6 is None:
            return
        expected = self.settings.amnezia_network_v6 if ingress_interface == self.settings.amnezia_interface else self.settings.user_network_v6
        if ipaddress.IPv6Address(ipv6[0]) not in ipaddress.IPv6Network(expected, strict=True):
            raise NetworkOperationError(
                "invalid_client_address",
                "The client IPv6 address does not belong to its connection type",
            )

    def _matching_policy_rules(self, address: str, table: int, priority: int, ingress_interface: str | None, family: int = 4) -> int:
        result = self.runner.run([self.ip, "-o", f"-{family}", "rule", "show"], timeout=10)
        if result.returncode != 0:
            raise NetworkOperationError("route_rule_read_failed", "Existing client route rules could not be inspected")
        matches = 0
        sources = {address, f"{address}/{'128' if family == 6 else '32'}"}
        for line in (result.stdout or "").splitlines():
            tokens = line.split()
            if not tokens or tokens[0].rstrip(":") != str(priority):
                continue
            try:
                source = tokens[tokens.index("from") + 1]
                table_keyword = "lookup" if "lookup" in tokens else "table"
                observed_table = tokens[tokens.index(table_keyword) + 1]
            except (ValueError, IndexError):
                continue
            if source not in sources or observed_table != str(table):
                continue
            observed_iif = None
            if "iif" in tokens:
                try:
                    observed_iif = tokens[tokens.index("iif") + 1]
                except IndexError:
                    continue
            if observed_iif == ingress_interface:
                matches += 1
        return matches

    def _delete_policy_rule(self, address: str, table: int, priority: int, ingress_interface: str | None, family: int = 4) -> None:
        argv = [self.ip, f"-{family}", "rule", "delete", "from", f"{address}/{'128' if family == 6 else '32'}"]
        if ingress_interface:
            argv.extend(["iif", ingress_interface])
        argv.extend(["table", str(table), "priority", str(priority)])
        result = self.runner.run(argv, timeout=10)
        if result.returncode != 0:
            detail = (result.stderr or result.stdout or "").lower()
            if not any(marker in detail for marker in ("no such file", "cannot find", "not found", "no rule")):
                raise NetworkOperationError("route_rule_remove_failed", "The previous client route rule could not be removed")

    def _ensure_policy_rule(self, address: str, table: int, priority: int, ingress_interface: object | None = None, family: int = 4) -> str:
        interface = self._ingress_interface(ingress_interface)
        scoped_count = self._matching_policy_rules(address, table, priority, interface, family)
        legacy_count = self._matching_policy_rules(address, table, priority, None, family)
        if scoped_count == 1 and legacy_count == 0:
            return interface
        for _ in range(scoped_count):
            self._delete_policy_rule(address, table, priority, interface, family)
        # CayVPN pre-release builds used a source-only rule.  Remove it during
        # reconciliation because return traffic would otherwise be sent back
        # into the egress namespace and loop.
        for _ in range(legacy_count):
            self._delete_policy_rule(address, table, priority, None, family)
        self._run(
            [self.ip, f"-{family}", "rule", "add", "from", f"{address}/{'128' if family == 6 else '32'}", "iif", interface, "table", str(table), "priority", str(priority)]
        )
        return interface

    def _remove_policy_rule(self, address: str, table: int, priority: int, ingress_interface: object | None = None, family: int = 4) -> None:
        interface = self._ingress_interface(ingress_interface)
        for _ in range(self._matching_policy_rules(address, table, priority, interface, family)):
            self._delete_policy_rule(address, table, priority, interface, family)
        for _ in range(self._matching_policy_rules(address, table, priority, None, family)):
            self._delete_policy_rule(address, table, priority, None, family)

    def _flush_table(self, table: int, family: int = 4) -> None:
        result = self.runner.run([self.ip, f"-{family}", "route", "flush", "table", str(table)], timeout=15)
        if result.returncode == 0:
            return
        detail = (result.stderr or result.stdout or "network command failed").strip()
        normalized = detail.lower()
        # iproute2 reports a missing policy table as an error even though an
        # empty table is exactly the desired result. This is expected for a
        # client's first fail-closed transition and must not prevent CayVPN
        # from installing the prohibit default route immediately afterward.
        if "fib table does not exist" in normalized or "routing table does not exist" in normalized:
            return
        raise NetworkOperationError("network_command_failed", detail[:240])

    def fail_closed(self, client_address: object, profile_id: object, ingress_interface: object | None = None, client_ipv6_address: object | None = None) -> dict:
        address, _ = self._client_address(client_address)
        ipv6 = self._client_ipv6_address(client_ipv6_address)
        table, priority = self._table(profile_id, address)
        interface = self._ingress_interface(ingress_interface)
        self._validate_ipv6_ingress(ipv6, interface)
        if not self.settings.apply_network:
            return {"state": "planned", "fail_closed": True, "applied": False, "table": table, "ingress_interface": interface, "ipv6_state": "blocked" if ipv6 else "not_configured"}
        self._ensure_policy_rule(address, table, priority, interface)
        self._flush_table(table)
        self._run([self.ip, "-4", "route", "add", "prohibit", "default", "table", str(table)])
        if ipv6:
            self._ensure_policy_rule(ipv6[0], table, priority, interface, family=6)
            self._flush_table(table, family=6)
            self._run([self.ip, "-6", "route", "add", "prohibit", "default", "table", str(table)])
        self._flush_connection_state(address, ipv6[0] if ipv6 else None)
        return {"state": "blocked", "fail_closed": True, "applied": True, "table": table, "ingress_interface": interface, "ipv6_state": "blocked" if ipv6 else "not_configured"}

    def _flush_connection_state(self, address: str, ipv6_address: str | None = None) -> None:
        if self.conntrack:
            result = self.runner.run([self.conntrack, "-D", "-s", address], timeout=15)
            # conntrack returns non-zero when there are no matching entries;
            # that is a successful cleanup outcome for this operation.
            if result.returncode not in (0, 1):
                raise NetworkOperationError("connection_reset_failed", "Existing client connections could not be cleared")
            if ipv6_address:
                result_v6 = self.runner.run([self.conntrack, "-D", "-f", "ipv6", "-s", ipv6_address], timeout=15)
                if result_v6.returncode not in (0, 1):
                    raise NetworkOperationError("connection_reset_failed", "Existing client IPv6 connections could not be cleared")

    def _flush_ipv6_connection_state(self, ipv6_address: str) -> None:
        if not self.conntrack:
            return
        result = self.runner.run([self.conntrack, "-D", "-f", "ipv6", "-s", ipv6_address], timeout=15)
        if result.returncode not in (0, 1):
            raise NetworkOperationError("connection_reset_failed", "Existing client IPv6 connections could not be cleared")

    def _set_source_nat(self, source_address: str, exit_address: str) -> bool:
        """Bind one typed namespace source to an explicit public address.

        The map is declared by the installer.  A source map is used instead
        of a generated shell rule so activation can replace one exact profile
        mapping without accepting arbitrary nftables syntax.
        """
        try:
            source = ipaddress.ip_address(source_address)
            exit_ip = ipaddress.ip_address(exit_address)
        except ValueError as exc:
            raise NetworkOperationError("invalid_source_nat", "The source NAT addresses are invalid") from exc
        if source.version != exit_ip.version:
            raise NetworkOperationError("unsupported_source_nat", "Source NAT addresses must use the same address family")
        map_name = "cayvpn_snat_v6" if source.version == 6 else "cayvpn_snat_v4"
        observed = self.runner.run(
            [self.nft, "get", "element", "inet", "cayvpn", map_name, "{", str(source), "}"],
            timeout=10,
        )
        expected = f"{source} : {exit_ip}"
        if observed.returncode == 0 and expected in " ".join((observed.stdout or "").split()):
            return False
        if observed.returncode != 0:
            detail = (observed.stderr or observed.stdout or "").lower()
            if not any(marker in detail for marker in ("no such", "not found", "does not exist", "cannot find")):
                raise NetworkOperationError("source_nat_read_failed", "The current source NAT mapping could not be inspected")
            self._run([self.nft, "add", "element", "inet", "cayvpn", map_name, "{", str(source), ":", str(exit_ip), "}"])
            return True

        # nftables applies one -f input as a transaction. Replacing an
        # existing profile mapping this way cannot expose a delete/add gap
        # that might otherwise select a different public address.
        digest = hashlib.sha256(str(source).encode()).hexdigest()[:12]
        batch_path = self.settings.config_dir / "runtime" / f"snat-{digest}.nft"
        write_secret_file(
            batch_path,
            "\n".join([
                f"delete element inet cayvpn {map_name} {{ {source} }}",
                f"add element inet cayvpn {map_name} {{ {source} : {exit_ip} }}",
                "",
            ]),
        )
        try:
            self._run([self.nft, "-f", str(batch_path)])
        finally:
            batch_path.unlink(missing_ok=True)
        return True

    def _ensure_source_nat_default(self, source_address: str, exit_address: str) -> None:
        """Install a namespace default without replacing an explicit exit.

        Namespace setup is re-entered by DNS and runtime reconciliation.  An
        additional-IP activation may already have bound this namespace source
        to its provider address, so setup must preserve any existing mapping
        instead of silently restoring the VPS address.
        """
        try:
            source = ipaddress.ip_address(source_address)
            exit_ip = ipaddress.ip_address(exit_address)
        except ValueError as exc:
            raise NetworkOperationError("invalid_source_nat", "The source NAT addresses are invalid") from exc
        if source.version != exit_ip.version:
            raise NetworkOperationError("unsupported_source_nat", "Source NAT addresses must use the same address family")
        map_name = "cayvpn_snat_v6" if source.version == 6 else "cayvpn_snat_v4"
        observed = self.runner.run(
            [self.nft, "get", "element", "inet", "cayvpn", map_name, "{", str(source), "}"],
            timeout=10,
        )
        if observed.returncode == 0:
            return
        detail = (observed.stderr or observed.stdout or "").lower()
        if not any(marker in detail for marker in ("no such", "not found", "does not exist", "cannot find")):
            raise NetworkOperationError("source_nat_read_failed", "The current source NAT mapping could not be inspected")
        self._run([self.nft, "add", "element", "inet", "cayvpn", map_name, "{", str(source), ":", str(exit_ip), "}"])

    def _remove_source_nat(self, client_address: str) -> None:
        try:
            client = ipaddress.ip_address(client_address)
        except ValueError as exc:
            raise NetworkOperationError("invalid_source_nat", "The source NAT address is invalid") from exc
        map_name = "cayvpn_snat_v6" if client.version == 6 else "cayvpn_snat_v4"
        result = self.runner.run([self.nft, "delete", "element", "inet", "cayvpn", map_name, "{", str(client), "}"], timeout=10)
        if result.returncode != 0:
            detail = (result.stderr or result.stdout or "").lower()
            if not any(marker in detail for marker in ("no such", "not found", "does not exist", "cannot find")):
                raise NetworkOperationError("source_nat_remove_failed", "The previous additional-IP source mapping could not be removed")

    @staticmethod
    def _stop_process(process: object) -> None:
        if getattr(process, "poll", lambda: 0)() is not None:
            return
        process.terminate()
        try:
            process.wait(timeout=2)
        except Exception:
            process.kill()
            try:
                process.wait(timeout=2)
            except Exception:
                pass

    def _dns_resolver_ready(self, plan: NamespacePlan, dns_address: str, dns_address_v6: str, process: object) -> bool:
        probe_argvs = [
            self._namespace_argv(
                plan,
                [sys.executable, "-m", "cayvpn.dns_probe", "--address", address, "--timeout", "2"],
            )
            for address in (dns_address, dns_address_v6)
        ]
        # A cold provider interface may need a handshake before its first DoH
        # request succeeds. Spread retries across that startup window instead
        # of consuming every attempt in a few hundred milliseconds and
        # leaving the first client blocked while a later client succeeds.
        for attempt in range(10):
            if getattr(process, "poll", lambda: 1)() is not None:
                return False
            try:
                probes = [self.runner.run(probe_argv, timeout=4) for probe_argv in probe_argvs]
            except (OSError, subprocess.SubprocessError):
                probes = []
            if len(probes) == 2 and all(probe.returncode == 0 for probe in probes):
                return True
            if attempt < 9:
                time.sleep(0.5)
        return False

    def _ensure_dns_resolver(self, profile_id: object, dns_mode: str) -> dict:
        if dns_mode not in {"standard", "ad_blocking"}:
            raise NetworkOperationError("invalid_dns_mode", "The DNS mode is invalid")
        dns_address = self.client_adblock_dns_address if dns_mode == "ad_blocking" else self.client_dns_address
        dns_address_v6 = self.client_adblock_dns_address_v6 if dns_mode == "ad_blocking" else self.client_dns_address_v6
        try:
            parsed_dns_address = ipaddress.ip_address(dns_address)
        except ValueError as exc:
            raise NetworkOperationError("invalid_dns_address", "The stable client DNS address is invalid") from exc
        if parsed_dns_address.version != 4 or parsed_dns_address.is_loopback or parsed_dns_address.is_multicast or parsed_dns_address.is_unspecified:
            raise NetworkOperationError("invalid_dns_address", "The stable client DNS address must be a non-loopback IPv4 address")
        try:
            parsed_dns_address_v6 = ipaddress.IPv6Address(dns_address_v6)
        except ValueError as exc:
            raise NetworkOperationError("invalid_dns_address", "The stable client IPv6 DNS address is invalid") from exc
        if not parsed_dns_address_v6.is_private or parsed_dns_address_v6.is_loopback or parsed_dns_address_v6.is_link_local or parsed_dns_address_v6.is_multicast or parsed_dns_address_v6.is_unspecified:
            raise NetworkOperationError("invalid_dns_address", "The stable client IPv6 DNS address must be a private CayVPN address")
        number = self._profile_number(profile_id)
        if not self.settings.apply_network:
            return {"dns": dns_address, "dns_ipv6": dns_address_v6, "dns_state": "planned", "dns_applied": False}
        plan = self.ensure_namespace(number)
        self._run_namespace(plan, [self.ip, "addr", "add", f"{dns_address}/32", "dev", "lo"], allow_existing=True)
        self._run_namespace(plan, [self.ip, "-6", "addr", "add", f"{dns_address_v6}/128", "dev", "lo"], allow_existing=True)
        process_key = (number, dns_mode)
        process = self.dns_processes.get(process_key)
        if process is not None and getattr(process, "poll", lambda: 0)() is None:
            if self._dns_resolver_ready(plan, dns_address, dns_address_v6, process):
                return {"dns": dns_address, "dns_ipv6": dns_address_v6, "dns_state": "active", "dns_applied": True, "dns_verified": True}
            self.dns_processes.pop(process_key, None)
            self._stop_process(process)
            raise NetworkOperationError("dns_probe_failed", "The isolated DNS resolver did not pass its egress probe")
        spawn = getattr(self.runner, "spawn", None)
        if spawn is None:
            # Test and diagnostic runners may intentionally model only the
            # route manager.  They receive a planned DNS state; the real root
            # runner always exposes spawn and therefore never reports this as
            # an active resolver.
            return {"dns": dns_address, "dns_ipv6": dns_address_v6, "dns_state": "planned", "dns_applied": False}
        blocklist = self.settings.config_dir / "adblock"
        if dns_mode == "ad_blocking":
            from .dns_service import blocklist_available

            if not blocklist_available(blocklist):
                raise NetworkOperationError(
                    "ad_blocking_unavailable",
                    "Ad and tracker blocking is unavailable because this CayVPN server has no verified blocklist",
                )
        argv = self._namespace_argv(
            plan,
            [
                sys.executable,
                "-m",
                "cayvpn.dns_service",
                "--address",
                dns_address,
                "--address-v6",
                dns_address_v6,
                "--port",
                "53",
                "--mode",
                dns_mode,
                "--host-record",
                f"{self.settings.admin_hostname}={ipaddress.ip_interface(self.settings.admin_address).ip}",
            ],
        )
        if dns_mode == "ad_blocking":
            argv.extend(["--blocklist", str(blocklist)])
        process = spawn(argv, timeout=10)
        self.dns_processes[process_key] = process
        if not self._dns_resolver_ready(plan, dns_address, dns_address_v6, process):
            self.dns_processes.pop(process_key, None)
            self._stop_process(process)
            raise NetworkOperationError("dns_runtime_failed", "The isolated DNS resolver did not start and answer through its egress")
        return {"dns": dns_address, "dns_ipv6": dns_address_v6, "dns_state": "active", "dns_applied": True, "dns_verified": True}

    def _add_dns_route(self, plan: NamespacePlan, table: int, dns_address: str, dns_address_v6: str | None = None) -> None:
        namespace_ip = str(ipaddress.ip_interface(plan.namespace_address).ip)
        self._run([self.ip, "-4", "route", "replace", f"{dns_address}/32", "via", namespace_ip, "dev", plan.host_interface, "table", str(table)])
        if dns_address_v6:
            namespace_ip_v6 = str(ipaddress.ip_interface(plan.namespace_address_v6).ip)
            self._run([self.ip, "-6", "route", "replace", f"{dns_address_v6}/128", "via", namespace_ip_v6, "dev", plan.host_interface, "table", str(table)])

    def activate_client_policy(
        self,
        client_address: object,
        profile_id: object,
        dns_mode: str = "standard",
        ingress_interface: object | None = None,
        client_ipv6_address: object | None = None,
        ipv6_policy: str = "auto",
        capabilities: dict | None = None,
    ) -> dict:
        address, _ = self._client_address(client_address)
        ipv6 = self._client_ipv6_address(client_ipv6_address)
        interface = self._ingress_interface(ingress_interface)
        self._validate_ipv6_ingress(ipv6, interface)
        if dns_mode not in {"standard", "ad_blocking"}:
            raise NetworkOperationError("invalid_dns_mode", "The DNS mode is invalid")
        if ipv6_policy not in {"auto", "required"}:
            raise NetworkOperationError("invalid_ipv6_policy", "The client IPv6 preference is invalid")
        ipv6_available = bool(ipv6 and ipv6_usable(capabilities or {}))
        if ipv6_policy == "required" and not ipv6_available:
            self.fail_closed(client_address, profile_id, interface, client_ipv6_address)
            raise NetworkOperationError("ipv6_required_unavailable", "This client requires IPv6, but the selected exit has not passed IPv6 checks")
        if not self.settings.apply_network:
            dns_address = self.client_adblock_dns_address if dns_mode == "ad_blocking" else self.client_dns_address
            dns_address_v6 = self.client_adblock_dns_address_v6 if dns_mode == "ad_blocking" else self.client_dns_address_v6
            return {"state": "planned", "fail_closed": True, "applied": False, "verified": False, "dns": dns_address, "dns_ipv6": dns_address_v6, "ipv6_state": "planned" if ipv6_available else "blocked"}
        plan = self.ensure_namespace(profile_id)
        table, priority = self._table(profile_id, address)
        self._ensure_policy_rule(address, table, priority, interface)
        self._flush_table(table)
        if ipv6:
            self._ensure_policy_rule(ipv6[0], table, priority, interface, family=6)
            self._flush_table(table, family=6)
        namespace_ip = str(ipaddress.ip_interface(plan.namespace_address).ip)
        namespace_ip_v6 = str(ipaddress.ip_interface(plan.namespace_address_v6).ip)
        try:
            self._run([self.ip, "-4", "route", "replace", "default", "via", namespace_ip, "dev", plan.host_interface, "table", str(table)])
            dns = self._ensure_dns_resolver(profile_id, dns_mode)
            self._add_dns_route(plan, table, str(dns["dns"]), str(dns["dns_ipv6"]) if ipv6 else None)
            if ipv6:
                if ipv6_available:
                    self._run([self.ip, "-6", "route", "replace", "default", "via", namespace_ip_v6, "dev", plan.host_interface, "table", str(table)])
                else:
                    self._run([self.ip, "-6", "route", "add", "prohibit", "default", "table", str(table)])
            self._flush_connection_state(address, ipv6[0] if ipv6 else None)
            probe = self.runner.run([self.ip, "-4", "route", "get", "1.1.1.1", "from", address, "iif", interface], timeout=10)
            if not self._route_uses(probe, plan.host_interface, namespace_ip):
                raise NetworkOperationError("route_probe_failed", "The new route did not pass the local kernel probe")
            if ipv6_available:
                probe_v6 = self.runner.run([self.ip, "-6", "route", "get", "2606:4700:4700::1111", "from", ipv6[0], "iif", interface], timeout=10)
                if not self._route_uses(probe_v6, plan.host_interface, namespace_ip_v6):
                    raise NetworkOperationError("ipv6_route_probe_failed", "The new IPv6 route did not pass the local kernel probe")
        except Exception:
            self.fail_closed(f"{address}/32", profile_id, interface, f"{ipv6[0]}/128" if ipv6 else None)
            raise
        return {"state": "active", "fail_closed": True, "applied": True, "verified": True, "namespace": plan.name, "table": table, "ingress_interface": interface, **dns, "ipv6_state": "active" if ipv6_available else "blocked", "connections_reset": True}

    def reconcile_client_ipv6(
        self,
        client_address: object,
        client_ipv6_address: object,
        profile_id: object,
        driver: str,
        config: dict,
        capabilities: dict,
        ipv6_policy: str = "auto",
        dns_mode: str = "standard",
        ingress_interface: object | None = None,
    ) -> dict:
        """Change only one client's IPv6 route after a family health transition.

        Smart mode must not reset or replace the client's working IPv4 route.
        Required mode may block both families when no verified dual-stack exit
        is available; the worker normally attempts an approved failover first.
        """
        address, _ = self._client_address(client_address)
        ipv6 = self._client_ipv6_address(client_ipv6_address)
        if ipv6 is None:
            raise NetworkOperationError("client_ipv6_required", "The client has no managed IPv6 address")
        if ipv6_policy not in {"auto", "required"}:
            raise NetworkOperationError("invalid_ipv6_policy", "The client IPv6 preference is invalid")
        interface = self._ingress_interface(ingress_interface)
        self._validate_ipv6_ingress(ipv6, interface)
        available = ipv6_usable(capabilities)
        table, priority = self._table(profile_id, address)
        if not self.settings.apply_network:
            return {"state": "planned", "applied": False, "verified": False, "ipv4_untouched": True, "ipv6_state": "planned" if available else "blocked"}
        if ipv6_policy == "required" and not available:
            result = self.fail_closed(client_address, profile_id, interface, client_ipv6_address)
            return {**result, "state": "blocked", "ipv6_state": "blocked", "ipv4_untouched": False, "verified": bool(result.get("applied"))}

        self._ensure_policy_rule(ipv6[0], table, priority, interface, family=6)
        self._flush_table(table, family=6)
        if not available:
            self._run([self.ip, "-6", "route", "add", "prohibit", "default", "table", str(table)])
            # Generated profiles retain their private IPv6 DNS address during
            # Smart-mode failover. Keep that one resolver reachable while the
            # IPv6 internet default remains prohibited; its upstream traffic
            # still uses the selected exit's verified IPv4 path.
            if dns_mode not in {"standard", "ad_blocking"}:
                raise NetworkOperationError("invalid_dns_mode", "The DNS mode is invalid")
            plan = self._names(profile_id)
            if not self._namespace_exists(plan.name):
                raise NetworkOperationError("egress_runtime_unavailable", "The selected exit runtime is unavailable; IPv6 remains blocked")
            dns_v6 = self.client_adblock_dns_address_v6 if dns_mode == "ad_blocking" else self.client_dns_address_v6
            namespace_v6 = str(ipaddress.ip_interface(plan.namespace_address_v6).ip)
            self._run([self.ip, "-6", "route", "replace", f"{dns_v6}/128", "via", namespace_v6, "dev", plan.host_interface, "table", str(table)])
            self._flush_ipv6_connection_state(ipv6[0])
            return {"state": "active", "applied": True, "verified": True, "ipv4_untouched": True, "ipv6_state": "blocked", "table": table}

        driver = str(driver or "").lower()
        source_nat_v6_changed = False
        if driver in {"direct_ip", "additional_ip"}:
            plan = self.ensure_namespace(profile_id)
            public_v6 = str(config.get("ipv6_address") or (self.settings.server_ipv6 if driver == "direct_ip" else "")).strip()
            if not public_v6:
                raise NetworkOperationError("ipv6_exit_address_missing", "The selected exit has no verified public IPv6 address")
            source_nat_v6_changed = self._set_source_nat(str(ipaddress.ip_interface(plan.namespace_address_v6).ip), public_v6)
        elif driver in {"provider_tunnel", "socks5"}:
            plan = self._names(profile_id)
            if not self._namespace_exists(plan.name):
                raise NetworkOperationError("egress_runtime_unavailable", "The selected exit runtime is unavailable; IPv6 remains blocked")
        else:
            raise NetworkOperationError("runtime_driver_unavailable", "The selected exit driver cannot carry IPv6")

        namespace_ip_v6 = str(ipaddress.ip_interface(plan.namespace_address_v6).ip)
        try:
            if source_nat_v6_changed:
                self._flush_ipv6_connection_state(namespace_ip_v6)
            dns = self._ensure_dns_resolver(profile_id, dns_mode)
            self._run([self.ip, "-6", "route", "replace", f"{dns['dns_ipv6']}/128", "via", namespace_ip_v6, "dev", plan.host_interface, "table", str(table)])
            self._run([self.ip, "-6", "route", "replace", "default", "via", namespace_ip_v6, "dev", plan.host_interface, "table", str(table)])
            probe = self.runner.run([self.ip, "-6", "route", "get", "2606:4700:4700::1111", "from", ipv6[0], "iif", interface], timeout=10)
            if not self._route_uses(probe, plan.host_interface, namespace_ip_v6):
                raise NetworkOperationError("ipv6_route_probe_failed", "The IPv6 route did not pass the local kernel probe")
        except Exception:
            self._flush_table(table, family=6)
            self._run([self.ip, "-6", "route", "add", "prohibit", "default", "table", str(table)], allow_existing=True)
            self._flush_ipv6_connection_state(ipv6[0])
            raise
        self._flush_ipv6_connection_state(ipv6[0])
        return {"state": "active", "applied": True, "verified": True, "ipv4_untouched": True, "ipv6_state": "active", "table": table, "dns_ipv6": dns["dns_ipv6"]}

    def _runtime_interface(self, prefix: str, profile_id: object) -> str:
        number = self._profile_number(profile_id)
        digest = hashlib.sha256(str(number).encode()).hexdigest()[:8]
        name = f"{prefix}{digest}"
        if len(name) > 15 or not name.replace("-", "").isalnum():
            raise NetworkOperationError("invalid_runtime_interface", "The generated runtime interface is invalid")
        return name

    @staticmethod
    def _public_endpoint_addresses(host: str, port: int) -> list[str]:
        try:
            addresses = socket.getaddrinfo(host, port, type=socket.SOCK_DGRAM)
        except OSError as exc:
            raise NetworkOperationError("endpoint_resolution_failed", "The provider endpoint could not be resolved") from exc
        result: list[str] = []
        for _, _, _, _, sockaddr in addresses:
            candidate = sockaddr[0]
            try:
                address = ipaddress.ip_address(candidate)
            except ValueError:
                continue
            if address.is_private or address.is_loopback or address.is_link_local or address.is_multicast or address.is_unspecified:
                raise NetworkOperationError("unsafe_endpoint_resolution", "The provider endpoint resolved to a private or local address")
            if candidate not in result:
                result.append(candidate)
        if not result:
            raise NetworkOperationError("endpoint_resolution_failed", "The provider endpoint has no public address")
        return result

    def _supported_endpoint_address(self, host: str, port: int) -> str:
        """Select an endpoint family the VPS can actually originate."""
        addresses = self._public_endpoint_addresses(host, port)
        for candidate in addresses:
            family = ipaddress.ip_address(candidate).version
            if family == 4 or self.settings.server_ipv6:
                return candidate
        raise NetworkOperationError(
            "endpoint_family_unavailable",
            "This endpoint is IPv6-only, but the VPS has no verified public IPv6 address.",
        )

    @staticmethod
    def _provider_setconf(parsed: dict) -> str:
        interface = parsed.get("interface") or {}
        peer = parsed.get("peer") or {}
        fields = {
            "privatekey": interface.get("privatekey"),
            "publickey": peer.get("publickey"),
            "presharedkey": peer.get("presharedkey"),
            "allowedips": peer.get("allowedips"),
            "endpoint": peer.get("endpoint"),
            "persistentkeepalive": peer.get("persistentkeepalive"),
        }
        if not fields["privatekey"] or not fields["publickey"] or not fields["allowedips"] or not fields["endpoint"]:
            raise NetworkOperationError("provider_config_incomplete", "The provider tunnel configuration is incomplete")
        if any("\n" in str(value) or "\r" in str(value) for value in fields.values() if value is not None):
            raise NetworkOperationError("provider_config_invalid", "The provider tunnel contains an invalid line")
        lines = ["[Interface]", f"PrivateKey = {fields['privatekey']}"]
        interface_fields = {
            "listenport": "ListenPort",
            "fwmark": "FwMark",
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
        for key, label in interface_fields.items():
            if interface.get(key) not in (None, ""):
                lines.append(f"{label} = {interface[key]}")
        lines.extend(["", "[Peer]", f"PublicKey = {fields['publickey']}"])
        if fields["presharedkey"]:
            lines.append(f"PresharedKey = {fields['presharedkey']}")
        lines.append(f"AllowedIPs = {fields['allowedips']}")
        lines.append(f"Endpoint = {fields['endpoint']}")
        if fields["persistentkeepalive"]:
            lines.append(f"PersistentKeepalive = {fields['persistentkeepalive']}")
        return "\n".join(lines) + "\n"

    @classmethod
    def _provider_quick_config(cls, parsed: dict) -> str:
        """Render a hook-free config that only creates the AWG interface.

        ``amneziawg-go`` needs the TUN and UAPI descriptors prepared by
        ``awg-quick`` on systems without the Amnezia kernel module.  Keeping
        ``Table = off`` leaves all provider routing under CayVPN's isolated
        namespace manager instead of allowing the imported config to install
        policy rules of its own.
        """
        address = str((parsed.get("interface") or {}).get("address", "")).strip()
        if not address:
            raise NetworkOperationError("provider_config_incomplete", "The provider tunnel has no interface address")
        if "\n" in address or "\r" in address:
            raise NetworkOperationError("provider_config_invalid", "The provider tunnel contains an invalid address")
        lines = cls._provider_setconf(parsed).splitlines()
        try:
            section_break = lines.index("")
        except ValueError as exc:
            raise NetworkOperationError("provider_config_invalid", "The provider tunnel configuration is invalid") from exc
        lines[section_break:section_break] = [f"Address = {address}", "Table = off"]
        return "\n".join(lines) + "\n"

    @staticmethod
    def _amnezia_quick_argv(awg: str, quick: str, userspace: str, action: str, config_path: Path) -> list[str]:
        if action not in {"up", "down"}:
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

    def _provider_connectivity_observation(self, plan: NamespacePlan) -> dict:
        probe_argv = self._namespace_argv(
            plan,
            [sys.executable, "-m", "cayvpn.egress_probe", "--timeout", "3", "--json"],
        )
        for attempt in range(2):
            try:
                # The probe keeps its strict three-second timeout for each
                # network operation. Allow enough process time for the full
                # IPv4/IPv6, DNS, identity, and UDP sequence to complete.
                probe = self.runner.run(probe_argv, timeout=20)
            except (OSError, subprocess.SubprocessError):
                probe = None
            if probe is not None and probe.returncode == 0:
                try:
                    details = json.loads(probe.stdout or "")
                except (TypeError, ValueError, json.JSONDecodeError):
                    details = {}
                if isinstance(details, dict):
                    families = details.get("families") if isinstance(details.get("families"), dict) else {}
                    ipv4_details = families.get("ipv4") if isinstance(families.get("ipv4"), dict) else details
                    ipv6_details = families.get("ipv6") if isinstance(families.get("ipv6"), dict) else {}

                    def public_observation(value: object, family: int) -> str | None:
                        try:
                            address = ipaddress.ip_address(str(value or ""))
                        except ValueError:
                            return None
                        if address.version != family or not address.is_global:
                            return None
                        return str(address)

                    observed_v4 = public_observation(details.get("observed_exit_ipv4") or details.get("observed_exit_ip"), 4)
                    observed_v6 = public_observation(details.get("observed_exit_ipv6"), 6)
                    v4 = {
                        "tcp": bool(ipv4_details.get("tcp") and observed_v4),
                        "udp": bool(ipv4_details.get("udp")),
                        "dns": bool(ipv4_details.get("dns")),
                    }
                    v6 = {
                        "tcp": bool(ipv6_details.get("tcp") and observed_v6),
                        "udp": bool(ipv6_details.get("udp")),
                        "dns": bool(ipv6_details.get("dns")),
                    }
                    if v4["tcp"] and v4["dns"]:
                        return {
                            "connectivity": True,
                            **v4,
                            "ipv6": v6["tcp"] and v6["dns"],
                            "observed_exit_ip": observed_v4,
                            "observed_exit_ipv4": observed_v4,
                            "observed_exit_ipv6": observed_v6,
                            "families": {"ipv4": v4, "ipv6": v6},
                        }
            if attempt == 0:
                time.sleep(0.5)
        unavailable = {"tcp": False, "udp": False, "dns": False}
        return {"connectivity": False, **unavailable, "ipv6": False, "observed_exit_ip": None, "observed_exit_ipv4": None, "observed_exit_ipv6": None, "families": {"ipv4": dict(unavailable), "ipv6": dict(unavailable)}}

    def activate_provider(self, profile_id: object, parsed: dict) -> dict:
        """Bring up a sanitized provider WireGuard tunnel in its namespace.

        The endpoint route is installed before the provider default route, so
        the tunnel handshake cannot recurse through itself.  Imported hooks,
        unmanaged route directives, and provider shell commands never reach
        this method; ``parse_provider_wireguard`` has already removed them.
        """
        if not self.settings.apply_network:
            return {"state": "planned", "applied": False, "verified": False, "driver": "provider_tunnel"}
        interface = self._runtime_interface("cvw", profile_id)
        endpoint = str((parsed.get("peer") or {}).get("endpoint", ""))
        try:
            host, port_text = endpoint.rsplit(":", 1)
            host = host.strip("[]")
            port = int(port_text)
        except (ValueError, IndexError) as exc:
            raise NetworkOperationError("provider_endpoint_invalid", "The provider endpoint is invalid") from exc
        endpoint_ip = self._supported_endpoint_address(host, port)
        plan = self.ensure_namespace(profile_id)
        runtime_peer = dict(parsed.get("peer") or {})
        runtime_peer["endpoint"] = f"[{endpoint_ip}]:{port}" if ipaddress.ip_address(endpoint_ip).version == 6 else f"{endpoint_ip}:{port}"
        runtime_parsed = dict(parsed)
        runtime_parsed["peer"] = runtime_peer
        endpoint_family = ipaddress.ip_address(endpoint_ip).version
        host_ip = str(ipaddress.ip_interface(plan.host_address_v6 if endpoint_family == 6 else plan.host_address).ip)
        self._run_namespace(plan, [self.ip, f"-{endpoint_family}", "route", "replace", f"{endpoint_ip}/{'128' if endpoint_family == 6 else '32'}", "via", host_ip, "dev", plan.namespace_interface])
        is_amnezia = parsed.get("protocol") == "amneziawg"
        tool = component_binary(self.settings, "awg") if is_amnezia else shutil.which("wg")
        if not tool:
            raise NetworkOperationError("component_not_installed", "The provider tunnel userspace component is not installed")
        runtime_dir = self.settings.config_dir / "runtime"
        runtime_dir.mkdir(parents=True, exist_ok=True)
        config_path = runtime_dir / f"provider-{self._profile_number(profile_id)}.conf"
        quick_path: Path | None = None
        if is_amnezia:
            userspace = component_binary(self.settings, "amneziawg-go")
            quick = component_binary(self.settings, "awg-quick")
            if not userspace or not quick:
                raise NetworkOperationError("component_not_installed", "The pinned AmneziaWG userspace engine is not installed")
        connectivity: dict = {}
        provider_ipv6_verified = False
        try:
            if is_amnezia:
                link = self.runner.run(self._namespace_argv(plan, [self.ip, "link", "show", interface]), timeout=10)
                if link.returncode != 0:
                    quick_path = runtime_dir / f"{interface}.conf"
                    write_secret_file(quick_path, self._provider_quick_config(runtime_parsed))
                    self._run_namespace(plan, self._amnezia_quick_argv(tool, quick, userspace, "up", quick_path), timeout=30)
                    for _ in range(20):
                        link = self.runner.run(self._namespace_argv(plan, [self.ip, "link", "show", interface]), timeout=10)
                        if link.returncode == 0:
                            break
                        time.sleep(0.1)
                    else:
                        raise NetworkOperationError("provider_interface_missing", "The AmneziaWG userspace interface did not start")
            else:
                self._run_namespace(plan, [self.ip, "link", "add", interface, "type", "wireguard"], allow_existing=True)
            write_secret_file(config_path, self._provider_setconf(runtime_parsed))
            self._run_namespace(plan, [tool, "setconf", interface, str(config_path)], timeout=20)
            addresses = list((parsed.get("interface") or {}).get("address", "").split(","))
            if not addresses:
                raise NetworkOperationError("provider_config_incomplete", "The provider tunnel has no interface address")
            for address in addresses:
                self._run_namespace(plan, [self.ip, "addr", "add", address.strip(), "dev", interface], allow_existing=True)
            self._run_namespace(plan, [self.ip, "link", "set", interface, "up"])
            self._ensure_namespace_egress_nat(plan, interface)
            self._ensure_client_return_routes(plan)
            self._run_namespace(plan, [self.ip, "route", "replace", "default", "dev", interface])
            if parsed.get("full_tunnel_ipv6"):
                self._run_namespace(plan, [self.ip, "-6", "route", "replace", "default", "dev", interface])
            else:
                self._run_namespace(plan, [self.ip, "-6", "route", "replace", "prohibit", "default"])
            probe = self.runner.run(self._namespace_argv(plan, [self.ip, "-4", "route", "get", "1.1.1.1"]), timeout=10)
            if not self._route_uses(probe, interface):
                raise NetworkOperationError("provider_route_probe_failed", "The provider namespace did not pass its route probe")
            ipv6_route_healthy = False
            if parsed.get("full_tunnel_ipv6"):
                probe_v6 = self.runner.run(self._namespace_argv(plan, [self.ip, "-6", "route", "get", "2606:4700:4700::1111"]), timeout=10)
                ipv6_route_healthy = self._route_uses(probe_v6, interface)
                if not ipv6_route_healthy:
                    # Preserve the working IPv4 exit while making a bad IPv6
                    # provider route explicit and non-leaking for Smart mode.
                    self._run_namespace(plan, [self.ip, "-6", "route", "replace", "prohibit", "default"])
            connectivity = self._provider_connectivity_observation(plan)
            if not connectivity.get("connectivity"):
                raise NetworkOperationError("provider_connectivity_probe_failed", "The provider tunnel did not pass its encrypted connectivity probe")
            if parsed.get("full_tunnel_ipv6"):
                observed_ipv6 = family_capabilities(
                    {"families": connectivity.get("families") or {}},
                    "ipv6",
                )
                provider_ipv6_verified = bool(
                    ipv6_route_healthy
                    and observed_ipv6["tcp"]
                    and observed_ipv6["dns"]
                    and connectivity.get("observed_exit_ipv6")
                )
                if not provider_ipv6_verified:
                    # A syntactically valid IPv6 default is not enough. If
                    # the live family checks or public-address verification
                    # fail, Smart mode must leave IPv4 working while replacing
                    # the provider route with an explicit fail-closed route.
                    self._run_namespace(
                        plan,
                        [self.ip, "-6", "route", "replace", "prohibit", "default"],
                    )
        except Exception:
            self.runner.run(self._namespace_argv(plan, [self.ip, "link", "delete", interface]), timeout=10)
            raise
        finally:
            try:
                config_path.unlink()
            except FileNotFoundError:
                pass
            if quick_path is not None:
                try:
                    quick_path.unlink()
                except FileNotFoundError:
                    pass
        observed_families = connectivity.get("families") or {}
        ipv4 = family_capabilities({"families": observed_families}, "ipv4")
        configured_v6 = bool(parsed.get("full_tunnel_ipv6"))
        ipv6 = family_capabilities({"families": observed_families}, "ipv6") if configured_v6 and ipv6_route_healthy else {"tcp": False, "udp": False, "dns": False}
        ipv6_verified = provider_ipv6_verified
        return {"state": "active", "applied": True, "verified": True, "namespace": plan.name, "interface": interface, "driver": "provider_tunnel", "endpoint_route": endpoint_ip, "observed_exit_ip": connectivity.get("observed_exit_ip"), "observed_exit_ipv4": connectivity.get("observed_exit_ipv4"), "observed_exit_ipv6": connectivity.get("observed_exit_ipv6") if ipv6_verified else None, **ipv4, "ipv6": ipv6_verified, "ipv6_health_state": "healthy" if ipv6_verified else ("unhealthy" if configured_v6 else "unavailable"), "ipv6_reason": None if ipv6_verified else ("provider_ipv6_check_failed" if configured_v6 else "provider_ipv6_not_configured"), "families": {"ipv4": ipv4, "ipv6": ipv6}}

    def probe_provider(self, profile_id: object, parsed: dict) -> dict:
        if not self.settings.apply_network:
            return {"profile_id": profile_id, "health_state": "pending", "verified": False, "tcp": False, "udp": False, "dns": False, "ipv6": False}
        plan = self._names(profile_id)
        interface = self._runtime_interface("cvw", profile_id)
        if not self._namespace_exists(plan.name):
            return {"profile_id": profile_id, "health_state": "unhealthy", "verified": False, "reason": "provider_namespace_missing", "tcp": False, "udp": False, "dns": False, "ipv6": False}
        link = self.runner.run(self._namespace_argv(plan, [self.ip, "link", "show", interface]), timeout=10)
        if link.returncode != 0:
            return {"profile_id": profile_id, "health_state": "unhealthy", "verified": False, "reason": "provider_interface_missing", "tcp": False, "udp": False, "dns": False, "ipv6": False}
        route = self.runner.run(self._namespace_argv(plan, [self.ip, "-4", "route", "get", "1.1.1.1"]), timeout=10)
        route_healthy = self._route_uses(route, interface)
        configured_v6 = bool(parsed.get("full_tunnel_ipv6"))
        ipv6_route_healthy = False
        if configured_v6:
            route_v6 = self.runner.run(self._namespace_argv(plan, [self.ip, "-6", "route", "get", "2606:4700:4700::1111"]), timeout=10)
            ipv6_route_healthy = self._route_uses(route_v6, interface)
        connectivity = self._provider_connectivity_observation(plan) if route_healthy else {"connectivity": False}
        healthy = route_healthy and bool(connectivity.get("connectivity"))
        reason = None if healthy else ("provider_connectivity_failed" if route_healthy else "provider_route_failed")
        observed_families = connectivity.get("families") or {}
        ipv4 = family_capabilities({"families": observed_families}, "ipv4") if healthy else {"tcp": False, "udp": False, "dns": False}
        ipv6 = family_capabilities({"families": observed_families}, "ipv6") if healthy and configured_v6 and ipv6_route_healthy else {"tcp": False, "udp": False, "dns": False}
        ipv6_active = ipv6["tcp"] and ipv6["dns"] and bool(connectivity.get("observed_exit_ipv6"))
        return {"profile_id": profile_id, "health_state": "healthy" if healthy else "unhealthy", "ipv6_health_state": "healthy" if ipv6_active else ("unhealthy" if configured_v6 else "unavailable"), "verified": healthy, **ipv4, "ipv6": ipv6_active, "families": {"ipv4": ipv4, "ipv6": ipv6}, "observed_exit_ip": connectivity.get("observed_exit_ip"), "observed_exit_ipv4": connectivity.get("observed_exit_ipv4"), "observed_exit_ipv6": connectivity.get("observed_exit_ipv6") if ipv6_active else None, "reason": reason, "ipv6_reason": None if ipv6_active else ("provider_ipv6_check_failed" if configured_v6 else "provider_ipv6_not_configured")}

    def probe_direct(self, profile_id: object, driver: str, config: dict) -> dict:
        if not self.settings.apply_network:
            return {"profile_id": profile_id, "health_state": "pending", "verified": False, "tcp": False, "udp": False, "dns": False, "ipv6": False}
        address = str(config.get("address", "")).strip()
        try:
            parsed_address = ipaddress.ip_address(address)
        except ValueError:
            return {"profile_id": profile_id, "health_state": "unhealthy", "verified": False, "reason": "invalid_exit_address", "tcp": False, "udp": False, "dns": False, "ipv6": False}
        if parsed_address.version != 4:
            return {"profile_id": profile_id, "health_state": "blocked", "verified": False, "reason": "ipv6_runtime_unavailable", "tcp": False, "udp": False, "dns": False, "ipv6": False}
        if driver == "additional_ip":
            interface = str(config.get("interface", "")).strip()
            argv = [self.ip, "-4", "addr", "show"]
            if interface:
                argv.extend(["dev", interface])
            observed = self.runner.run(argv, timeout=10)
            if observed.returncode != 0 or address not in (observed.stdout or ""):
                return {"profile_id": profile_id, "health_state": "unhealthy", "verified": False, "reason": "additional_ip_not_observed", "tcp": False, "udp": False, "dns": False, "ipv6": False}
        route = self.runner.run([self.ip, "-4", "route", "get", "1.1.1.1", "from", address], timeout=10)
        output = (route.stdout or "").lower()
        healthy = route.returncode == 0 and not any(word in output for word in ("prohibit", "unreachable", "blackhole"))
        observed_source = None
        fields = (route.stdout or "").split()
        if "src" in fields:
            index = fields.index("src")
            if index + 1 < len(fields):
                observed_source = fields[index + 1]
        elif "from" in fields:
            # When an explicit source is supplied, iproute2 on Ubuntu 24.04
            # echoes it as ``from ADDRESS`` and omits the otherwise automatic
            # ``src ADDRESS`` field. Both forms describe the kernel-selected
            # source for this typed route probe.
            index = fields.index("from")
            if index + 1 < len(fields):
                observed_source = fields[index + 1]
        expected_interface = str(config.get("interface", "")).strip() if driver == "additional_ip" else self.settings.out_interface
        expected_gateway = str(config.get("gateway", "")).strip() if driver == "additional_ip" else ""
        route_path_verified = not expected_interface or self._route_uses(route, expected_interface, expected_gateway or None)
        route_verified = healthy and observed_source == address and route_path_verified
        configured_v6 = str(config.get("ipv6_address") or (self.settings.server_ipv6 if driver == "direct_ip" else "")).strip()
        parsed_v6: ipaddress.IPv6Address | None = None
        ipv6_route_verified = False
        ipv6_reason = "ipv6_not_configured"
        if configured_v6:
            try:
                parsed_v6 = ipaddress.IPv6Address(configured_v6)
                if not parsed_v6.is_global:
                    raise ValueError
            except ValueError:
                ipv6_reason = "invalid_ipv6_exit_address"
                parsed_v6 = None
            if parsed_v6 is not None:
                if driver == "additional_ip":
                    interface = str(config.get("interface", "")).strip()
                    observed_v6_address = self.runner.run([self.ip, "-6", "addr", "show", "dev", interface], timeout=10)
                    if observed_v6_address.returncode != 0 or str(parsed_v6) not in (observed_v6_address.stdout or ""):
                        ipv6_reason = "additional_ipv6_not_observed"
                        parsed_v6 = None
                if parsed_v6 is not None:
                    route_v6 = self.runner.run([self.ip, "-6", "route", "get", "2606:4700:4700::1111", "from", str(parsed_v6)], timeout=10)
                    fields_v6 = (route_v6.stdout or "").split()
                    observed_source_v6 = None
                    for marker in ("src", "from"):
                        if marker in fields_v6 and fields_v6.index(marker) + 1 < len(fields_v6):
                            observed_source_v6 = fields_v6[fields_v6.index(marker) + 1]
                            break
                    expected_gateway_v6 = str(config.get("ipv6_gateway", "")).strip() if driver == "additional_ip" else ""
                    ipv6_path_verified = not expected_interface or self._route_uses(route_v6, expected_interface, expected_gateway_v6 or None)
                    ipv6_route_verified = route_v6.returncode == 0 and observed_source_v6 == str(parsed_v6) and ipv6_path_verified and not any(word in (route_v6.stdout or "").lower() for word in ("prohibit", "unreachable", "blackhole"))
                    ipv6_reason = None if ipv6_route_verified else "direct_ipv6_route_probe_failed"

        live_argv = [sys.executable, "-m", "cayvpn.egress_probe", "--timeout", "3", "--json", "--source-v4", address]
        if parsed_v6 is not None and ipv6_route_verified:
            live_argv.extend(["--source-v6", str(parsed_v6)])
        live = self.runner.run(live_argv, timeout=12)
        try:
            details = json.loads(live.stdout or "") if live.returncode == 0 else {}
        except (TypeError, ValueError, json.JSONDecodeError):
            details = {}
        observed_v4 = str(details.get("observed_exit_ipv4") or details.get("observed_exit_ip") or "")
        observed_v6 = str(details.get("observed_exit_ipv6") or "")
        families = details.get("families") if isinstance(details.get("families"), dict) else {}
        live_v4 = family_capabilities({"families": {"ipv4": families.get("ipv4", details)}}, "ipv4")
        live_v6 = family_capabilities({"families": {"ipv6": families.get("ipv6", {})}}, "ipv6")
        try:
            observed_v4 = str(ipaddress.IPv4Address(observed_v4))
        except ValueError:
            observed_v4 = ""
        try:
            observed_v6 = str(ipaddress.IPv6Address(observed_v6))
        except ValueError:
            observed_v6 = ""
        verified = route_verified and observed_v4 == address and live_v4["tcp"] and live_v4["dns"]
        ipv6_verified = bool(
            parsed_v6 is not None
            and ipv6_route_verified
            and observed_v6 == str(parsed_v6)
            and live_v6["tcp"]
            and live_v6["dns"]
        )
        if parsed_v6 is not None and ipv6_route_verified and not ipv6_verified:
            ipv6_reason = "observed_ipv6_mismatch" if observed_v6 and observed_v6 != str(parsed_v6) else "direct_ipv6_live_check_failed"
        ipv4 = live_v4 if verified else {"tcp": bool(live_v4["tcp"]), "udp": bool(live_v4["udp"]), "dns": bool(live_v4["dns"])}
        ipv6 = live_v6 if ipv6_verified else {"tcp": False, "udp": False, "dns": False}
        return {
            "profile_id": profile_id,
            "health_state": "healthy" if verified else "unhealthy",
            "ipv6_health_state": "healthy" if ipv6_verified else ("unhealthy" if configured_v6 else "unavailable"),
            "verified": verified,
            "observed_exit_ip": observed_v4 or observed_source,
            "observed_exit_ipv4": observed_v4 or None,
            "observed_exit_ipv6": observed_v6 if ipv6_verified else None,
            **ipv4,
            "ipv6": ipv6_verified,
            "families": {"ipv4": ipv4, "ipv6": ipv6},
            "reason": None if verified else ("observed_exit_mismatch" if route_verified else ("direct_route_path_mismatch" if healthy and observed_source == address and not route_path_verified else ("observed_source_mismatch" if healthy else "direct_route_probe_failed"))),
            "ipv6_reason": ipv6_reason,
        }

    def _socks_tun_address(self, profile_id: object) -> tuple[str, str]:
        number = self._profile_number(profile_id)
        third = 1 + ((number // 240) % 254)
        fourth = 2 + (number % 240)
        return f"198.18.{third}.{fourth}", f"198.18.{third}.0/24"

    def _socks_tun_ipv6_address(self, profile_id: object) -> str:
        number = self._profile_number(profile_id)
        network = ipaddress.IPv6Network(self.settings.egress_network_v6, strict=True)
        return str(network.network_address + (1 << 63) + number)

    @staticmethod
    def _socks_config(parsed: dict, password: str | None, tun_name: str, tun_address: str, tun_address_v6: str | None = None, udp_mode: str = "udp") -> str:
        if udp_mode not in {"tcp", "udp"}:
            raise NetworkOperationError("invalid_socks_mode", "Invalid SOCKS5 UDP relay mode")
        host = str(parsed.get("host", ""))
        port = int(parsed.get("port", 0))
        username = str(parsed.get("username", ""))
        lines = [
            "tunnel:",
            f"  name: {tun_name}",
            "  mtu: 1500",
            "  multi-queue: false",
            f"  ipv4: {tun_address}",
            f"  ipv6: '{tun_address_v6 or ''}'",
            "  icmp: 'off'",
            "socks5:",
            f"  port: {port}",
            f"  address: {host}",
            f"  udp: '{udp_mode}'",
            "  pipeline: false",
            "  log-level: error",
        ]
        if username:
            lines.append(f"  username: '{username.replace(chr(39), chr(39) * 2)}'")
        if password:
            escaped = password.replace("'", "''")
            lines.append(f"  password: '{escaped}'")
        return "\n".join(lines) + "\n"

    def _configure_socks_udp_guard(self, plan: NamespacePlan, tun_name: str, udp_allowed: bool, ipv6_udp_allowed: bool = False) -> None:
        """Block client UDP explicitly when the provider lacks RFC 1928 relay support.

        hev-socks5-tunnel's ``tcp`` UDP mode is a separate UDP-over-TCP
        extension intended for HevSocks5Server, not a generic TCP-only mode.
        CayVPN therefore keeps the standard relay setting and enforces a
        typed namespace firewall rule before the TUN route becomes active.
        Client DNS remains available because the local resolver uses encrypted
        TCP upstreams and the guard applies only to forwarded TUN traffic.
        """
        table = "cayvpn_socks_guard"
        prefix = self._namespace_argv(plan, [self.nft])
        removed = self.runner.run([*prefix, "delete", "table", "inet", table], timeout=10)
        if removed.returncode != 0:
            detail = (removed.stderr or removed.stdout or "").lower()
            if not any(marker in detail for marker in ("no such", "not found", "does not exist", "cannot find")):
                raise NetworkOperationError("socks_udp_guard_failed", "The SOCKS5 UDP guard could not be reconciled")
        if udp_allowed and ipv6_udp_allowed:
            return
        self._run_namespace(plan, [self.nft, "add", "table", "inet", table])
        self._run_namespace(
            plan,
            [
                self.nft,
                "add",
                "chain",
                "inet",
                table,
                "forward",
                "{",
                "type",
                "filter",
                "hook",
                "forward",
                "priority",
                "filter",
                ";",
                "policy",
                "accept",
                ";",
                "}",
            ],
        )
        if not udp_allowed:
            self._run_namespace(
                plan,
                [self.nft, "add", "rule", "inet", table, "forward", "iifname", plan.namespace_interface, "oifname", tun_name, "meta", "nfproto", "ipv4", "meta", "l4proto", "udp", "drop"],
            )
        if not ipv6_udp_allowed:
            self._run_namespace(
                plan,
                [self.nft, "add", "rule", "inet", table, "forward", "iifname", plan.namespace_interface, "oifname", tun_name, "meta", "nfproto", "ipv6", "meta", "l4proto", "udp", "drop"],
            )

    def activate_socks5(
        self,
        profile_id: object,
        parsed: dict,
        password: str | None,
        binary: str,
        udp_allowed: bool = False,
        ipv6_allowed: bool = False,
        ipv6_udp_allowed: bool = False,
    ) -> dict:
        """Run hev-socks5-tunnel in the profile namespace.

        The generated YAML contains only typed values from the validated
        endpoint and the root-agent secret.  It never accepts post-up or
        pre-down scripts; the upstream component's documented tunnel and
        SOCKS5 fields are the only emitted configuration.
        """
        if not self.settings.apply_network:
            return {"state": "planned", "applied": False, "verified": False, "driver": "socks5"}
        if not binary or "\n" in binary or "\r" in binary:
            raise NetworkOperationError("component_not_installed", "The pinned SOCKS5 tunnel component is not installed")
        connectivity: dict = {}
        plan = self.ensure_namespace(profile_id)
        tun_name = self._runtime_interface("cvt", profile_id)
        tun_address, _tun_network = self._socks_tun_address(profile_id)
        tun_address_v6 = self._socks_tun_ipv6_address(profile_id) if ipv6_allowed else None
        endpoint_ip = self._supported_endpoint_address(str(parsed.get("host", "")), int(parsed.get("port", 0)))
        runtime_parsed = dict(parsed)
        runtime_parsed["host"] = endpoint_ip
        endpoint_family = ipaddress.ip_address(endpoint_ip).version
        host_ip = str(ipaddress.ip_interface(plan.host_address_v6 if endpoint_family == 6 else plan.host_address).ip)
        self._run_namespace(plan, [self.ip, f"-{endpoint_family}", "route", "replace", f"{endpoint_ip}/{'128' if endpoint_family == 6 else '32'}", "via", host_ip, "dev", plan.namespace_interface])
        number = self._profile_number(profile_id)
        old = self.runtime_processes.get(number)
        reuse = (
            old is not None
            and getattr(old, "poll", lambda: 0)() is None
            and self.runtime_udp_modes.get(number) == udp_allowed
            and self.runtime_udp_v6_modes.get(number) == ipv6_udp_allowed
            and self.runtime_ipv6_modes.get(number) == ipv6_allowed
        )
        if not reuse and old is not None and getattr(old, "poll", lambda: 0)() is None:
            old.terminate()
        process = old if reuse else None
        config_path = self.settings.config_dir / "runtime" / f"socks-{number}.yml"
        if not reuse:
            config_path.parent.mkdir(parents=True, exist_ok=True)
            write_secret_file(config_path, self._socks_config(runtime_parsed, password, tun_name, tun_address, tun_address_v6, "udp"))
            spawn = getattr(self.runner, "spawn", None)
            if spawn is None:
                config_path.unlink(missing_ok=True)
                raise NetworkOperationError("runtime_driver_unavailable", "The root runner cannot start isolated tunnel processes")
            process = spawn(self._namespace_argv(plan, [binary, str(config_path)]), timeout=10)
            self.runtime_processes[number] = process
            self.runtime_udp_modes[number] = udp_allowed
            self.runtime_udp_v6_modes[number] = ipv6_udp_allowed
            self.runtime_ipv6_modes[number] = ipv6_allowed
        try:
            ready = False
            for _ in range(30):
                link = self.runner.run(self._namespace_argv(plan, [self.ip, "link", "show", tun_name]), timeout=5)
                if link.returncode == 0:
                    ready = True
                    break
                if process is not None and getattr(process, "poll", lambda: None)() is not None:
                    break
                time.sleep(0.1)
            if not ready:
                if process is not None:
                    process.terminate()
                raise NetworkOperationError("socks_runtime_failed", "The SOCKS5 tunnel did not create its TUN interface")
            # Hold all routed traffic while the UDP policy is replaced. The
            # proxy endpoint keeps its explicit host-veth route, so the
            # tunnel can stay up without creating a direct-egress window.
            self._run_namespace(plan, [self.ip, "route", "replace", "prohibit", "default"])
            self._run_namespace(plan, [self.ip, "-6", "route", "replace", "prohibit", "default"])
            self._configure_socks_udp_guard(plan, tun_name, udp_allowed, ipv6_udp_allowed)
            self._ensure_client_return_routes(plan)
            self._run_namespace(plan, [self.ip, "route", "replace", "default", "dev", tun_name])
            if ipv6_allowed:
                self._run_namespace(plan, [self.ip, "-6", "route", "replace", "default", "dev", tun_name])
            probe = self.runner.run(self._namespace_argv(plan, [self.ip, "-4", "route", "get", "1.1.1.1"]), timeout=10)
            if not self._route_uses(probe, tun_name):
                raise NetworkOperationError("socks_route_probe_failed", "The SOCKS5 namespace did not pass its route probe")
            ipv6_route_healthy = False
            if ipv6_allowed:
                probe_v6 = self.runner.run(self._namespace_argv(plan, [self.ip, "-6", "route", "get", "2606:4700:4700::1111"]), timeout=10)
                ipv6_route_healthy = self._route_uses(probe_v6, tun_name)
                if not ipv6_route_healthy:
                    self._run_namespace(plan, [self.ip, "-6", "route", "replace", "prohibit", "default"])
            connectivity = self._provider_connectivity_observation(plan)
            if not connectivity.get("connectivity"):
                raise NetworkOperationError("socks_connectivity_probe_failed", "The SOCKS5 exit did not pass its encrypted DNS and HTTPS probe")
        except Exception:
            if process is not None:
                self._stop_process(process)
            self.runtime_processes.pop(number, None)
            self.runtime_udp_modes.pop(number, None)
            self.runtime_udp_v6_modes.pop(number, None)
            self.runtime_ipv6_modes.pop(number, None)
            raise
        finally:
            try:
                config_path.unlink()
            except FileNotFoundError:
                pass
        observed = connectivity.get("families") or {}
        live_v4 = family_capabilities({"families": observed}, "ipv4")
        live_v6 = family_capabilities({"families": observed}, "ipv6") if ipv6_allowed and ipv6_route_healthy else {"tcp": False, "udp": False, "dns": False}
        ipv4 = {"tcp": live_v4["tcp"], "udp": live_v4["udp"] and udp_allowed, "dns": live_v4["dns"]}
        ipv6 = {"tcp": live_v6["tcp"], "udp": live_v6["udp"] and ipv6_udp_allowed, "dns": live_v6["dns"]}
        return {"state": "active", "applied": True, "verified": ipv4["tcp"] and ipv4["dns"], "namespace": plan.name, "interface": tun_name, "driver": "socks5", **ipv4, "ipv6": ipv6["tcp"] and ipv6["dns"], "families": {"ipv4": ipv4, "ipv6": ipv6}, "udp_guard": {"ipv4": "allow" if udp_allowed else "drop", "ipv6": "allow" if ipv6_udp_allowed else "drop"}, "observed_exit_ip": connectivity.get("observed_exit_ip"), "observed_exit_ipv4": connectivity.get("observed_exit_ipv4"), "observed_exit_ipv6": connectivity.get("observed_exit_ipv6") if ipv6["tcp"] else None}

    def probe_socks5(self, profile_id: object, binary: str) -> dict:
        if not self.settings.apply_network:
            return {"profile_id": profile_id, "health_state": "pending", "verified": False, "tcp": False, "udp": False, "dns": False, "ipv6": False}
        number = self._profile_number(profile_id)
        plan = self._names(profile_id)
        tun_name = self._runtime_interface("cvt", profile_id)
        if not self._namespace_exists(plan.name):
            return {"profile_id": profile_id, "health_state": "unhealthy", "verified": False, "tcp": False, "udp": False, "dns": False, "ipv6": False, "reason": "socks_namespace_missing"}
        link = self.runner.run(self._namespace_argv(plan, [self.ip, "link", "show", tun_name]), timeout=10)
        # The agent may have restarted while the namespace process survived;
        # the TUN link is the durable observation, while a missing link is a
        # failed runtime probe.
        link_healthy = link.returncode == 0
        udp_active = bool(self.runtime_udp_modes.get(number, False))
        udp_v6_active = bool(self.runtime_udp_v6_modes.get(number, False))
        ipv6_configured = bool(self.runtime_ipv6_modes.get(number, False))
        route_v4 = self.runner.run(self._namespace_argv(plan, [self.ip, "-4", "route", "get", "1.1.1.1"]), timeout=10) if link_healthy else None
        route_v4_healthy = bool(route_v4 is not None and self._route_uses(route_v4, tun_name))
        route_v6_healthy = False
        if link_healthy and ipv6_configured:
            route_v6 = self.runner.run(self._namespace_argv(plan, [self.ip, "-6", "route", "get", "2606:4700:4700::1111"]), timeout=10)
            route_v6_healthy = self._route_uses(route_v6, tun_name)
        connectivity = self._provider_connectivity_observation(plan) if route_v4_healthy else {"connectivity": False}
        connectivity_healthy = route_v4_healthy and bool(connectivity.get("connectivity"))
        reason = None if connectivity_healthy else ("socks_connectivity_failed" if route_v4_healthy else ("socks_route_failed" if link_healthy else "socks_runtime_unavailable"))
        observed = connectivity.get("families") or {}
        live_v4 = family_capabilities({"families": observed}, "ipv4") if connectivity_healthy else {"tcp": False, "udp": False, "dns": False}
        live_v6 = family_capabilities({"families": observed}, "ipv6") if connectivity_healthy and ipv6_configured and route_v6_healthy else {"tcp": False, "udp": False, "dns": False}
        ipv4 = {"tcp": live_v4["tcp"], "udp": live_v4["udp"] and udp_active, "dns": live_v4["dns"]}
        ipv6 = {"tcp": live_v6["tcp"], "udp": live_v6["udp"] and udp_v6_active, "dns": live_v6["dns"]}
        ipv6_healthy = ipv6["tcp"] and ipv6["dns"]
        return {"profile_id": profile_id, "health_state": "healthy" if connectivity_healthy else "unhealthy", "ipv6_health_state": "healthy" if ipv6_healthy else ("unhealthy" if ipv6_configured else "unavailable"), "verified": connectivity_healthy, **ipv4, "udp_active": udp_active, "udp_v6_active": udp_v6_active, "ipv6": ipv6_healthy, "families": {"ipv4": ipv4, "ipv6": ipv6}, "observed_exit_ip": connectivity.get("observed_exit_ip"), "observed_exit_ipv4": connectivity.get("observed_exit_ipv4"), "observed_exit_ipv6": connectivity.get("observed_exit_ipv6") if ipv6_healthy else None, "reason": reason, "ipv6_reason": None if ipv6_healthy else ("socks_ipv6_check_failed" if ipv6_configured else "socks_ipv6_not_enabled")}

    def deactivate_runtime(self, profile_id: object, remove_namespace: bool = False) -> dict:
        number = self._profile_number(profile_id)
        process = self.runtime_processes.pop(number, None)
        self.runtime_udp_modes.pop(number, None)
        self.runtime_udp_v6_modes.pop(number, None)
        self.runtime_ipv6_modes.pop(number, None)
        if process is not None and getattr(process, "poll", lambda: 0)() is None:
            process.terminate()
        for process_key in [key for key in self.dns_processes if key[0] == number]:
            resolver = self.dns_processes.pop(process_key, None)
            if resolver is not None and getattr(resolver, "poll", lambda: 0)() is None:
                resolver.terminate()
        if not self.settings.apply_network:
            return {"profile_id": number, "state": "inactive", "applied": False, "fail_closed": True}
        plan = self._names(number)
        # Deleting the exact generated runtime link is enough to stop the
        # provider tunnel or TUN path; the namespace remains for a later
        # activation and still has a prohibit route for client policy tables.
        if self._namespace_exists(plan.name):
            for interface in (self._runtime_interface("cvw", number), self._runtime_interface("cvt", number)):
                removed = self.runner.run(self._namespace_argv(plan, [self.ip, "link", "delete", interface]), timeout=10)
                if removed.returncode != 0:
                    detail = (removed.stderr or removed.stdout or "").lower()
                    if not any(marker in detail for marker in ("no such", "not found", "does not exist", "cannot find")):
                        raise NetworkOperationError("runtime_link_remove_failed", "The egress runtime link could not be removed")
        if remove_namespace and self._namespace_exists(plan.name):
            self._remove_source_nat(str(ipaddress.ip_interface(plan.namespace_address).ip))
            self._remove_source_nat(str(ipaddress.ip_interface(plan.namespace_address_v6).ip))
            self._stop_namespace(plan.name)
        return {"profile_id": number, "state": "inactive", "applied": True, "fail_closed": True}

    def _validate_additional_route_config(self, config: dict) -> None:
        interface = str(config.get("interface", "")).strip()
        gateway = str(config.get("gateway", "")).strip()
        if interface and (not interface.replace("-", "").replace(".", "").replace(":", "").isalnum() or len(interface) > 15):
            raise NetworkOperationError("invalid_interface", "The egress interface is invalid")
        if gateway:
            try:
                ipaddress.ip_address(gateway)
            except ValueError as exc:
                raise NetworkOperationError("invalid_gateway", "The egress gateway is invalid") from exc

    def activate(
        self,
        client_address: object,
        profile_id: object,
        driver: str,
        config: dict,
        capabilities: dict | None = None,
        dns_mode: str = "standard",
        ingress_interface: object | None = None,
        client_ipv6_address: object | None = None,
        ipv6_policy: str = "auto",
    ) -> dict:
        address, _ = self._client_address(client_address)
        ipv6 = self._client_ipv6_address(client_ipv6_address)
        interface = self._ingress_interface(ingress_interface)
        self._validate_ipv6_ingress(ipv6, interface)
        driver = str(driver or "").lower()
        if ipv6_policy not in {"auto", "required"}:
            raise NetworkOperationError("invalid_ipv6_policy", "The client IPv6 preference is invalid")
        capabilities = capabilities or {}
        ipv6_available = bool(ipv6 and ipv6_usable(capabilities))
        if ipv6_policy == "required" and not ipv6_available:
            self.fail_closed(client_address, profile_id, interface, client_ipv6_address)
            raise NetworkOperationError("ipv6_required_unavailable", "This client requires IPv6, but the selected exit has not passed IPv6 checks")
        if not self.settings.apply_network:
            return {"state": "planned", "fail_closed": True, "applied": False, "verified": False, "driver": driver, "ipv6_state": "planned" if ipv6_available else "blocked"}
        if driver not in {"direct_ip", "additional_ip"}:
            raise NetworkOperationError(
                "runtime_driver_unavailable",
                "This exit is validated but its isolated runtime component is not installed on the node; traffic remains blocked.",
            )
        if driver == "additional_ip":
            self._validate_additional_route_config(config)
        plan = self.ensure_namespace(profile_id)
        table, priority = self._table(profile_id, address)
        self._ensure_policy_rule(address, table, priority, interface)
        self._flush_table(table)
        if ipv6:
            self._ensure_policy_rule(ipv6[0], table, priority, interface, family=6)
            self._flush_table(table, family=6)
        namespace_ip = str(ipaddress.ip_interface(plan.namespace_address).ip)
        namespace_ip_v6 = str(ipaddress.ip_interface(plan.namespace_address_v6).ip)
        source_nat_changed = False
        source_nat_v6_changed = False
        route = [self.ip, "-4", "route", "replace", "default", "via", namespace_ip, "dev", plan.host_interface, "table", str(table)]
        # For a reserved/additional address, keep the intended source as
        # metadata for the namespace route; the provider remains responsible
        # for having attached the address to the node.
        if driver == "additional_ip":
            source = str(config.get("address", "")).strip()
            try:
                parsed = ipaddress.ip_address(source)
            except ValueError as exc:
                raise NetworkOperationError("invalid_address", "The additional IP is invalid") from exc
            if parsed.version != 4:
                raise NetworkOperationError("unsupported_address", "Only IPv4 additional addresses are supported by this runtime")
            route.extend(["src", source])
        try:
            # Replace the namespace-to-public mapping while this client's
            # policy table is still empty. Installing the route first would
            # create a brief window where an additional exit could inherit
            # the VPS direct address from namespace bootstrap.
            source_nat_changed = self._set_source_nat(namespace_ip, str(config.get("address", "")).strip())
            if ipv6_available:
                public_v6 = str(config.get("ipv6_address") or self.settings.server_ipv6).strip()
                if not public_v6:
                    raise NetworkOperationError("ipv6_exit_address_missing", "The exit passed no usable public IPv6 address")
                source_nat_v6_changed = self._set_source_nat(namespace_ip_v6, public_v6)
            dns = self._ensure_dns_resolver(profile_id, dns_mode)
            if source_nat_changed:
                self._flush_connection_state(namespace_ip)
            if source_nat_v6_changed:
                self._flush_ipv6_connection_state(namespace_ip_v6)
            self._run(route)
            self._add_dns_route(plan, table, str(dns["dns"]), str(dns["dns_ipv6"]) if ipv6 else None)
            if ipv6:
                if ipv6_available:
                    self._run([self.ip, "-6", "route", "replace", "default", "via", namespace_ip_v6, "dev", plan.host_interface, "table", str(table)])
                else:
                    self._run([self.ip, "-6", "route", "add", "prohibit", "default", "table", str(table)])
        except Exception:
            self._flush_table(table)
            self._run([self.ip, "-4", "route", "add", "prohibit", "default", "table", str(table)], allow_existing=True)
            if ipv6:
                self._flush_table(table, family=6)
                self._run([self.ip, "-6", "route", "add", "prohibit", "default", "table", str(table)], allow_existing=True)
            raise
        self._flush_connection_state(address, ipv6[0] if ipv6 else None)
        probe = self.runner.run([self.ip, "-4", "route", "get", "1.1.1.1", "from", address, "iif", interface], timeout=10)
        if not self._route_uses(probe, plan.host_interface, namespace_ip):
            self.fail_closed(f"{address}/32", profile_id, interface, f"{ipv6[0]}/128" if ipv6 else None)
            raise NetworkOperationError("route_probe_failed", "The new route did not pass the local kernel probe")
        if ipv6_available:
            probe_v6 = self.runner.run([self.ip, "-6", "route", "get", "2606:4700:4700::1111", "from", ipv6[0], "iif", interface], timeout=10)
            if not self._route_uses(probe_v6, plan.host_interface, namespace_ip_v6):
                self.fail_closed(f"{address}/32", profile_id, interface, f"{ipv6[0]}/128")
                raise NetworkOperationError("ipv6_route_probe_failed", "The new IPv6 route did not pass the local kernel probe")
        return {
            "state": "active",
            "fail_closed": True,
            "applied": True,
            "verified": True,
            "namespace": plan.name,
            "table": table,
            "ingress_interface": interface,
            "driver": driver,
            "ipv6_state": "active" if ipv6_available else "blocked",
            **dns,
            "connections_reset": True,
        }

    def deactivate(self, client_address: object | None, profile_id: object, ingress_interface: object | None = None, client_ipv6_address: object | None = None) -> dict:
        if not client_address:
            return {"state": "inactive", "fail_closed": True, "applied": False}
        interface = self._ingress_interface(ingress_interface)
        result = self.fail_closed(client_address, profile_id, interface, client_ipv6_address)
        if self.settings.apply_network:
            address, _ = self._client_address(client_address)
            table, priority = self._table(profile_id, address)
            self._remove_policy_rule(address, table, priority, interface)
            ipv6 = self._client_ipv6_address(client_ipv6_address)
            self._validate_ipv6_ingress(ipv6, interface)
            if ipv6:
                self._remove_policy_rule(ipv6[0], table, priority, interface, family=6)
        return result | {"state": "inactive"}
