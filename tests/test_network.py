import subprocess
import tempfile
import unittest
import base64
import ipaddress
import json
import os
from pathlib import Path
from unittest.mock import patch

from cayvpn.config import Settings
from cayvpn.drivers import parse_provider_wireguard
from cayvpn.network import NetworkOperationError, NetworkRouteManager


def inner_command(argv):
    """Return the command executed inside a process-pinned namespace."""
    if argv and Path(argv[0]).name == "nsenter" and "--" in argv:
        return argv[argv.index("--") + 1 :]
    return argv


class FakeProcess:
    def __init__(self, pid):
        self.pid = pid
        self.returncode = None

    def poll(self):
        return self.returncode

    def terminate(self):
        self.returncode = -15

    def kill(self):
        self.returncode = -9

    def wait(self, timeout=None):
        if self.returncode is None:
            self.returncode = 0
        return self.returncode


class FakeRunner:
    def __init__(self):
        self.calls = []
        self.policy_rules = []
        self.policy_rules_v6 = []
        self.route_defaults = {}
        self.next_pid = 4200

    def spawn(self, argv, timeout=10):
        self.calls.append((argv, timeout))
        process = FakeProcess(self.next_pid)
        self.next_pid += 1
        return process

    def run(self, argv, timeout=10):
        self.calls.append((argv, timeout))
        command = inner_command(argv)
        if "cayvpn.egress_probe" in command:
            details = {
                "connectivity": True,
                "tcp": True,
                "udp": True,
                "dns": True,
                "observed_exit_ip": "8.8.4.4",
                "observed_exit_ipv4": "8.8.4.4",
                "observed_exit_ipv6": None,
                "families": {
                    "ipv4": {"connectivity": True, "tcp": True, "udp": True, "dns": True},
                    "ipv6": {"connectivity": False, "tcp": False, "udp": False, "dns": False},
                },
            }
            return subprocess.CompletedProcess(argv, 0, json.dumps(details), "")
        if Path(command[0]).name == "nft" and command[1:3] == ["get", "element"]:
            return subprocess.CompletedProcess(argv, 1, "", "Error: No such file or directory")
        if Path(command[0]).name == "ip" and command[1:2] == ["-o"] and command[2] in {"-4", "-6"} and command[3:] == ["rule", "show"]:
            selected_rules = self.policy_rules_v6 if command[2] == "-6" else self.policy_rules
            lines = []
            for rule in selected_rules:
                iif = f" iif {rule['iif']}" if rule["iif"] else ""
                lines.append(f"{rule['priority']}: from {rule['source']}{iif} lookup {rule['table']}")
            return subprocess.CompletedProcess(argv, 0, "\n".join(lines), "")
        if Path(command[0]).name == "ip" and command[1:4] in (["-4", "rule", "add"], ["-4", "rule", "delete"], ["-6", "rule", "add"], ["-6", "rule", "delete"]):
            selected_rules = self.policy_rules_v6 if command[1] == "-6" else self.policy_rules
            source = command[command.index("from") + 1]
            interface = command[command.index("iif") + 1] if "iif" in command else None
            rule = {
                "source": source,
                "iif": interface,
                "table": command[command.index("table") + 1],
                "priority": command[command.index("priority") + 1],
            }
            if command[3] == "add":
                selected_rules.append(rule)
                return subprocess.CompletedProcess(argv, 0, "", "")
            if rule in selected_rules:
                selected_rules.remove(rule)
                return subprocess.CompletedProcess(argv, 0, "", "")
            return subprocess.CompletedProcess(argv, 2, "", "RTNETLINK answers: No such file or directory")
        if Path(command[0]).name == "ip" and "route" in command:
            route_index = command.index("route")
            family = command[1] if len(command) > 1 and command[1] in {"-4", "-6"} else "-4"
            namespace = argv[argv.index("--target") + 1] if "--target" in argv else None
            if route_index + 1 < len(command) and command[route_index + 1] == "flush" and "table" in command:
                self.route_defaults.pop((namespace, family, command[command.index("table") + 1]), None)
                return subprocess.CompletedProcess(argv, 0, "", "")
            if route_index + 1 < len(command) and command[route_index + 1] in {"add", "replace"} and "default" in command:
                table = command[command.index("table") + 1] if "table" in command else "main"
                if "prohibit" in command or "unreachable" in command or "blackhole" in command:
                    self.route_defaults[(namespace, family, table)] = {"blocked": True}
                else:
                    self.route_defaults[(namespace, family, table)] = {
                        "blocked": False,
                        "via": command[command.index("via") + 1] if "via" in command else None,
                        "dev": command[command.index("dev") + 1] if "dev" in command else None,
                    }
                return subprocess.CompletedProcess(argv, 0, "", "")
            if route_index + 1 < len(command) and command[route_index + 1] == "get":
                table = "main"
                if namespace is None and "from" in command and "iif" in command:
                    source = command[command.index("from") + 1]
                    interface = command[command.index("iif") + 1]
                    selected_rules = self.policy_rules_v6 if family == "-6" else self.policy_rules
                    matched = next((rule for rule in selected_rules if rule["source"].split("/", 1)[0] == source and rule["iif"] == interface), None)
                    if matched:
                        table = matched["table"]
                route = self.route_defaults.get((namespace, family, table))
                if route:
                    if route["blocked"]:
                        return subprocess.CompletedProcess(argv, 0, "prohibit default", "")
                    parts = [command[route_index + 2]]
                    if route.get("via"):
                        parts.extend(["via", route["via"]])
                    if route.get("dev"):
                        parts.extend(["dev", route["dev"]])
                    return subprocess.CompletedProcess(argv, 0, " ".join(parts), "")
        if Path(command[0]).name == "ip" and command[1:4] == ["-4", "route", "get"]:
            return subprocess.CompletedProcess(argv, 0, "1.1.1.1 via 169.254.101.1 dev cvhabc123", "")
        return subprocess.CompletedProcess(argv, 0, "", "")


class NetworkTests(unittest.TestCase):
    def settings(self, root: Path) -> Settings:
        base = Settings.from_env(root)
        blocklist = root / "config" / "adblock"
        blocklist.mkdir(parents=True, exist_ok=True)
        (blocklist / "test.txt").write_text("||ads.example^\n")
        return base.__class__(
            **{**base.__dict__, "state_dir": root / "state", "config_dir": root / "config", "wg_dir": root / "wireguard", "apply_network": True}
        )

    def test_location_transport_ipv4_addresses_do_not_repeat_for_supported_ids(self):
        with tempfile.TemporaryDirectory() as directory:
            settings = self.settings(Path(directory))
            manager = NetworkRouteManager(settings, FakeRunner())
            plans = [manager._names(profile_id) for profile_id in (1, 101, 999999)]
            addresses = {
                address.split("/", 1)[0]
                for plan in plans
                for address in (plan.host_address, plan.namespace_address)
            }
            transport = ipaddress.IPv4Network(settings.egress_network_v4)

            self.assertEqual(len(addresses), 6)
            self.assertTrue(
                all(ipaddress.IPv4Address(address) in transport for address in addresses)
            )
            self.assertNotEqual(plans[0].host_address, plans[1].host_address)

    def test_direct_route_isolated_and_verified(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runner = FakeRunner()
            manager = NetworkRouteManager(self.settings(root), runner)
            result = manager.activate("10.8.0.2/32", 1, "direct_ip", {"address": "198.51.100.10"}, {"ipv6": False})
            self.assertTrue(result["verified"])
            self.assertTrue(result["namespace"].startswith("cv-eg-"))
            policy_adds = [call[0] for call in runner.calls if Path(call[0][0]).name == "ip" and call[0][1:5] == ["-4", "rule", "add", "from"]]
            self.assertEqual(len(policy_adds), 1)
            self.assertIn("iif", policy_adds[0])
            self.assertEqual(policy_adds[0][policy_adds[0].index("iif") + 1], "wg0")
            route_probes = [call[0] for call in runner.calls if Path(call[0][0]).name == "ip" and call[0][1:4] == ["-4", "route", "get"]]
            self.assertTrue(route_probes)
            self.assertEqual(route_probes[-1][route_probes[-1].index("iif") + 1], "wg0")
            self.assertTrue(any("prohibit" not in call[0] for call in runner.calls if Path(call[0][0]).name == "ip"))
            plan = manager._names(1)
            namespace_ip = plan.namespace_address.split("/", 1)[0]
            self.assertTrue(any("default" in call[0] and "via" in call[0] and namespace_ip in call[0] for call in runner.calls))
            self.assertTrue(any(Path(inner_command(call[0])[0]).name == "nft" and "masquerade" in inner_command(call[0]) for call in runner.calls))
            source_maps = [call[0] for call in runner.calls if Path(call[0][0]).name == "nft" and "cayvpn_snat_v4" in call[0] and "add" in call[0]]
            self.assertTrue(any(namespace_ip in call and "198.51.100.10" in call for call in source_maps))
            self.assertEqual(manager._table(1)[1], 10000)

    def test_dead_namespace_keeper_is_recreated_without_named_netns_mounts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runner = FakeRunner()
            manager = NetworkRouteManager(self.settings(root), runner)
            plan = manager._names(1)
            dead = runner.spawn([manager.unshare, "--net", "--", manager.sleep, "infinity"])
            dead.terminate()
            manager.namespace_processes[plan.name] = dead
            plan = manager.ensure_namespace(1)
            self.assertEqual(plan.name, "cv-eg-6b86b2")
            calls = [call[0] for call in runner.calls]
            self.assertEqual(manager.namespace_processes[plan.name].poll(), None)
            self.assertIsNot(manager.namespace_processes[plan.name], dead)
            self.assertIn([manager.unshare, "--net", "--", manager.sleep, "infinity"], calls)
            self.assertFalse(any(Path(call[0]).name == "ip" and call[1:2] == ["netns"] for call in calls))
            self.assertTrue(any(Path(call[0]).name == "nsenter" for call in calls))

    def test_unsupported_runtime_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manager = NetworkRouteManager(self.settings(root), FakeRunner())
            with self.assertRaises(NetworkOperationError) as error:
                manager.activate("10.8.0.2/32", 2, "socks5", {"endpoint": "socks5://proxy.example:1080"}, {"tcp": True})
            self.assertEqual(error.exception.code, "runtime_driver_unavailable")

    def test_smart_ipv6_keeps_ipv4_active_and_installs_an_explicit_ipv6_block(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runner = FakeRunner()
            settings = self.settings(root)
            manager = NetworkRouteManager(settings, runner)
            client_v6 = f"{ipaddress.IPv6Network(settings.user_network_v6).network_address + 2}/128"

            result = manager.activate(
                "10.8.0.2/32",
                1,
                "direct_ip",
                {"address": "198.51.100.10"},
                {"families": {"ipv4": {"tcp": True, "udp": True, "dns": True}, "ipv6": {"tcp": False, "udp": False, "dns": False}}},
                client_ipv6_address=client_v6,
                ipv6_policy="auto",
            )

            self.assertTrue(result["verified"])
            self.assertEqual(result["ipv6_state"], "blocked")
            commands = [inner_command(call[0]) for call in runner.calls]
            self.assertTrue(any(command[1:6] == ["-6", "route", "add", "prohibit", "default"] for command in commands if Path(command[0]).name == "ip"))
            self.assertTrue(any(command[1:5] == ["-4", "route", "replace", "default"] for command in commands if Path(command[0]).name == "ip"))

    def test_required_ipv6_blocks_both_families_before_an_unusable_exit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runner = FakeRunner()
            settings = self.settings(root)
            manager = NetworkRouteManager(settings, runner)
            client_v6 = f"{ipaddress.IPv6Network(settings.user_network_v6).network_address + 2}/128"

            with self.assertRaises(NetworkOperationError) as error:
                manager.activate(
                    "10.8.0.2/32",
                    1,
                    "direct_ip",
                    {"address": "198.51.100.10"},
                    {"families": {"ipv4": {"tcp": True, "udp": True, "dns": True}, "ipv6": {"tcp": False, "udp": False, "dns": False}}},
                    client_ipv6_address=client_v6,
                    ipv6_policy="required",
                )

            self.assertEqual(error.exception.code, "ipv6_required_unavailable")
            commands = [inner_command(call[0]) for call in runner.calls]
            self.assertTrue(any(command[1:6] == ["-4", "route", "add", "prohibit", "default"] for command in commands if Path(command[0]).name == "ip"))
            self.assertTrue(any(command[1:6] == ["-6", "route", "add", "prohibit", "default"] for command in commands if Path(command[0]).name == "ip"))

    def test_smart_ipv4_exit_keeps_advertised_ipv6_dns_without_an_ipv6_default(self):
        for activation in ("direct", "isolated"):
            with self.subTest(activation=activation), tempfile.TemporaryDirectory() as directory:
                runner = FakeRunner()
                settings = self.settings(Path(directory))
                manager = NetworkRouteManager(settings, runner)
                client_v6 = f"{ipaddress.IPv6Network(settings.user_network_v6).network_address + 2}/128"
                options = dict(client_ipv6_address=client_v6, ipv6_policy="auto", dns_mode="ad_blocking")
                if activation == "direct":
                    result = manager.activate("10.8.0.2/32", 1, "direct_ip", {"address": "198.51.100.10"}, {}, **options)
                else:
                    result = manager.activate_client_policy("10.8.0.2/32", 1, capabilities={}, **options)
                self.assertEqual(result["ipv6_state"], "blocked")
                commands = [inner_command(call[0]) for call in runner.calls]
                self.assertTrue(any(command[1:5] == ["-6", "route", "replace", f"{settings.client_adblock_dns_address_v6}/128"] for command in commands))
                self.assertTrue(any(command[1:6] == ["-6", "route", "add", "prohibit", "default"] for command in commands))
                self.assertFalse(any(command[1:5] == ["-6", "route", "replace", "default"] and command[-2:] == ["table", str(result["table"])] for command in commands))
                runner.calls.clear()
                result = manager.reconcile_client_ipv6("10.8.0.2/32", client_v6, 1, "direct_ip", {}, {}, dns_mode="ad_blocking")
                self.assertTrue(result["ipv4_untouched"])
                commands = [inner_command(call[0]) for call in runner.calls]
                self.assertTrue(any(command[1:5] == ["-6", "route", "replace", f"{settings.client_adblock_dns_address_v6}/128"] for command in commands))
                self.assertTrue(any(command[1:6] == ["-6", "route", "add", "prohibit", "default"] for command in commands))
                self.assertFalse(any(command[1:2] == ["-4"] for command in commands))

    def test_verified_dual_stack_exit_routes_and_translates_both_families_together(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runner = FakeRunner()
            settings = self.settings(root)
            manager = NetworkRouteManager(settings, runner)
            client_v6 = f"{ipaddress.IPv6Network(settings.user_network_v6).network_address + 2}/128"
            public_v6 = "2001:4860:4860::20"

            result = manager.activate(
                "10.8.0.2/32",
                1,
                "direct_ip",
                {"address": "198.51.100.10", "ipv6_address": public_v6},
                {"families": {"ipv4": {"tcp": True, "udp": True, "dns": True}, "ipv6": {"tcp": True, "udp": True, "dns": True}}},
                client_ipv6_address=client_v6,
                ipv6_policy="auto",
            )

            self.assertTrue(result["verified"])
            self.assertEqual(result["ipv6_state"], "active")
            plan = manager._names(1)
            namespace_v6 = str(ipaddress.IPv6Interface(plan.namespace_address_v6).ip)
            self.assertTrue(any(Path(call[0][0]).name == "nft" and "cayvpn_snat_v6" in call[0] and namespace_v6 in call[0] and public_v6 in call[0] for call in runner.calls))
            commands = [inner_command(call[0]) for call in runner.calls]
            self.assertTrue(any(Path(command[0]).name == "sysctl" and command[1:] == ["-w", "net.ipv6.conf.all.forwarding=1"] for command in commands))
            self.assertTrue(any(command[1:5] == ["-6", "route", "replace", "default"] for command in commands if Path(command[0]).name == "ip"))

    def test_client_ipv6_must_belong_to_the_selected_ingress_network(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            settings = self.settings(root)
            manager = NetworkRouteManager(settings, FakeRunner())
            amnezia_v6 = f"{ipaddress.IPv6Network(settings.amnezia_network_v6).network_address + 2}/128"
            with self.assertRaises(NetworkOperationError) as error:
                manager.fail_closed("10.8.0.2/32", 1, settings.user_interface, amnezia_v6)
            self.assertEqual(error.exception.code, "invalid_client_address")

    def test_policy_probe_rejects_a_route_that_bypasses_the_selected_namespace(self):
        class BypassRunner(FakeRunner):
            def run(self, argv, timeout=10):
                command = inner_command(argv)
                if Path(command[0]).name == "ip" and command[1:4] == ["-4", "route", "get"] and "iif" in command:
                    self.calls.append((argv, timeout))
                    return subprocess.CompletedProcess(argv, 0, "1.1.1.1 via 192.0.2.1 dev eth0", "")
                return super().run(argv, timeout)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manager = NetworkRouteManager(self.settings(root), BypassRunner())
            with self.assertRaises(NetworkOperationError) as error:
                manager.activate("10.8.0.2/32", 1, "direct_ip", {"address": "198.51.100.10"}, {"ipv6": False})
            self.assertEqual(error.exception.code, "route_probe_failed")

    def test_tcp_only_socks_uses_an_explicit_udp_guard_and_verified_exit_ip(self):
        class SocksRunner(FakeRunner):
            def __init__(self):
                super().__init__()
                self.socks_config = ""

            def spawn(self, argv, timeout=10):
                if argv and str(argv[-1]).endswith(".yml"):
                    self.socks_config = Path(argv[-1]).read_text()
                return super().spawn(argv, timeout)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runner = SocksRunner()
            manager = NetworkRouteManager(self.settings(root), runner)
            parsed = {"host": "proxy.example", "port": 1080, "username": "user"}
            with patch.object(NetworkRouteManager, "_public_endpoint_addresses", return_value=["8.8.8.8"]):
                result = manager.activate_socks5(4, parsed, "secret", "/pinned/hev-socks5-tunnel", udp_allowed=False)

            self.assertTrue(result["verified"])
            self.assertFalse(result["udp"])
            self.assertEqual(result["udp_guard"], {"ipv4": "drop", "ipv6": "drop"})
            self.assertEqual(result["observed_exit_ip"], "8.8.4.4")
            self.assertIn("udp: 'udp'", runner.socks_config)
            guard_rules = [inner_command(call[0]) for call in runner.calls if "cayvpn_socks_guard" in inner_command(call[0])]
            self.assertTrue(any("add" in command and "rule" in command and "udp" in command and "drop" in command for command in guard_rules))
            inner_calls = [inner_command(call[0]) for call in runner.calls]
            hold_index = next(index for index, command in enumerate(inner_calls) if command[1:] == ["route", "replace", "prohibit", "default"])
            drop_index = next(index for index, command in enumerate(inner_calls) if "cayvpn_socks_guard" in command and "drop" in command)
            release_index = next(index for index, command in enumerate(inner_calls) if index > drop_index and command[1:] == ["route", "replace", "default", "dev", result["interface"]])
            self.assertLess(hold_index, drop_index)
            self.assertLess(drop_index, release_index)

    def test_udp_capable_socks_removes_the_tcp_only_guard(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runner = FakeRunner()
            manager = NetworkRouteManager(self.settings(root), runner)
            parsed = {"host": "proxy.example", "port": 1080, "username": ""}
            with patch.object(NetworkRouteManager, "_public_endpoint_addresses", return_value=["8.8.8.8"]):
                result = manager.activate_socks5(5, parsed, None, "/pinned/hev-socks5-tunnel", udp_allowed=True)

            self.assertTrue(result["udp"])
            self.assertEqual(result["udp_guard"], {"ipv4": "allow", "ipv6": "drop"})
            guard_rules = [inner_command(call[0]) for call in runner.calls if "cayvpn_socks_guard" in inner_command(call[0])]
            self.assertTrue(any("delete" in command and "table" in command for command in guard_rules))
            self.assertFalse(any("nfproto" in command and "ipv4" in command and "l4proto" in command and "udp" in command and "drop" in command for command in guard_rules))
            self.assertTrue(any("nfproto" in command and "ipv6" in command and "l4proto" in command and "udp" in command and "drop" in command for command in guard_rules))

    def test_deactivate_removes_the_profile_rule_after_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runner = FakeRunner()
            manager = NetworkRouteManager(self.settings(root), runner)
            manager.deactivate("10.8.0.2/32", 3)
            self.assertTrue(any(call[0][1:4] == ["-4", "rule", "delete"] for call in runner.calls))
            self.assertEqual(runner.policy_rules, [])

    def test_policy_rule_is_idempotent_and_scoped_to_amnezia_ingress(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runner = FakeRunner()
            manager = NetworkRouteManager(self.settings(root), runner)
            manager.fail_closed("10.9.0.2/32", 3, "awg0")
            manager.fail_closed("10.9.0.2/32", 3, "awg0")
            self.assertEqual(len(runner.policy_rules), 1)
            self.assertEqual(runner.policy_rules[0]["iif"], "awg0")

    def test_first_fail_closed_route_accepts_an_absent_policy_table(self):
        class MissingTableRunner(FakeRunner):
            def run(self, argv, timeout=10):
                if Path(argv[0]).name == "ip" and argv[1:4] == ["-4", "route", "flush"]:
                    self.calls.append((argv, timeout))
                    return subprocess.CompletedProcess(argv, 2, "", "Error: ipv4: FIB table does not exist.\nFlush terminated")
                return super().run(argv, timeout)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runner = MissingTableRunner()
            manager = NetworkRouteManager(self.settings(root), runner)
            result = manager.fail_closed("10.8.0.2/32", 3, "wg0")
            self.assertEqual(result["state"], "blocked")
            self.assertTrue(any(call[0][1:5] == ["-4", "route", "add", "prohibit"] for call in runner.calls))

    def test_policy_table_flush_still_rejects_unexpected_failures(self):
        class BrokenFlushRunner(FakeRunner):
            def run(self, argv, timeout=10):
                if Path(argv[0]).name == "ip" and argv[1:4] == ["-4", "route", "flush"]:
                    self.calls.append((argv, timeout))
                    return subprocess.CompletedProcess(argv, 2, "", "RTNETLINK answers: Operation not permitted")
                return super().run(argv, timeout)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manager = NetworkRouteManager(self.settings(root), BrokenFlushRunner())
            with self.assertRaises(NetworkOperationError) as error:
                manager.fail_closed("10.8.0.2/32", 3, "wg0")
            self.assertEqual(error.exception.code, "network_command_failed")

    def test_idempotent_address_add_accepts_ubuntu_already_assigned_response(self):
        class AssignedAddressRunner(FakeRunner):
            def run(self, argv, timeout=10):
                self.calls.append((argv, timeout))
                return subprocess.CompletedProcess(argv, 2, "", "Error: ipv4: Address already assigned.")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manager = NetworkRouteManager(self.settings(root), AssignedAddressRunner())
            result = manager._run(
                [manager.ip, "-n", "cv-eg-test", "addr", "add", "10.254.0.53/32", "dev", "lo"],
                allow_existing=True,
            )
            self.assertEqual(result.returncode, 2)

            with self.assertRaises(NetworkOperationError) as error:
                manager._run(
                    [manager.ip, "-n", "cv-eg-test", "addr", "add", "10.254.0.53/32", "dev", "lo"],
                )
            self.assertEqual(error.exception.code, "network_command_failed")

    def test_legacy_source_only_rule_is_replaced_before_activation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runner = FakeRunner()
            manager = NetworkRouteManager(self.settings(root), runner)
            table, priority = manager._table(4, "10.8.0.2")
            runner.policy_rules.append({"source": "10.8.0.2/32", "iif": None, "table": str(table), "priority": str(priority)})
            manager.fail_closed("10.8.0.2/32", 4, "wg0")
            self.assertEqual(len(runner.policy_rules), 1)
            self.assertEqual(runner.policy_rules[0]["iif"], "wg0")

    def test_unknown_ingress_interface_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manager = NetworkRouteManager(self.settings(root), FakeRunner())
            with self.assertRaises(NetworkOperationError) as error:
                manager.fail_closed("10.8.0.2/32", 3, "eth0")
            self.assertEqual(error.exception.code, "invalid_ingress_interface")

    def test_policy_tables_are_per_client_even_when_exit_is_shared(self):
        first = NetworkRouteManager._table(3, "10.8.0.2")
        second = NetworkRouteManager._table(3, "10.8.0.3")
        self.assertNotEqual(first[0], second[0])
        self.assertEqual(first[1], second[1])

    def test_additional_ip_probe_requires_the_address_to_be_observed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manager = NetworkRouteManager(self.settings(root), FakeRunner())
            result = manager.probe_direct(4, "additional_ip", {"address": "198.51.100.20", "interface": "eth0"})
            self.assertEqual(result["health_state"], "unhealthy")
            self.assertEqual(result["reason"], "additional_ip_not_observed")

    def test_dns_modes_use_separate_stable_addresses(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manager = NetworkRouteManager(self.settings(root), FakeRunner())
            standard = manager.activate_client_policy("10.8.0.2/32", 5, "standard")
            filtered = manager.activate_client_policy("10.8.0.3/32", 5, "ad_blocking")
            self.assertNotEqual(standard["dns"], filtered["dns"])
            commands = [inner_command(call[0]) for call in manager.runner.calls]
            dns_command = next(command for command in commands if "cayvpn.dns_service" in command)
            self.assertIn("--host-record", dns_command)
            self.assertIn("admin.cayvpn.home.arpa=10.255.0.1", dns_command)

    def test_ad_blocking_fails_closed_when_no_usable_list_exists(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            settings = self.settings(root)
            (settings.config_dir / "adblock" / "test.txt").write_text("! comments only\n")
            manager = NetworkRouteManager(settings, FakeRunner())
            with self.assertRaises(NetworkOperationError) as error:
                manager.activate_client_policy("10.8.0.3/32", 5, "ad_blocking")
            self.assertEqual(error.exception.code, "ad_blocking_unavailable")

    def test_dns_activation_waits_for_a_real_resolver_response(self):
        class DelayedDnsRunner(FakeRunner):
            def __init__(self):
                super().__init__()
                self.dns_probes = 0

            def run(self, argv, timeout=10):
                command = inner_command(argv)
                if "cayvpn.dns_probe" in command:
                    self.calls.append((argv, timeout))
                    self.dns_probes += 1
                    return subprocess.CompletedProcess(argv, 0 if self.dns_probes >= 3 else 1, "", "")
                return super().run(argv, timeout)

        with tempfile.TemporaryDirectory() as directory, patch("cayvpn.network.time.sleep"):
            root = Path(directory)
            runner = DelayedDnsRunner()
            manager = NetworkRouteManager(self.settings(root), runner)
            result = manager.activate_client_policy("10.8.0.2/32", 5, "standard")
            self.assertEqual(runner.dns_probes, 4)
            self.assertTrue(result["dns_verified"])

    def test_dns_activation_fails_closed_when_the_resolver_never_answers(self):
        class FailedDnsRunner(FakeRunner):
            def __init__(self):
                super().__init__()
                self.dns_probes = 0

            def run(self, argv, timeout=10):
                command = inner_command(argv)
                if "cayvpn.dns_probe" in command:
                    self.calls.append((argv, timeout))
                    self.dns_probes += 1
                    return subprocess.CompletedProcess(argv, 1, "", "")
                return super().run(argv, timeout)

        with tempfile.TemporaryDirectory() as directory, patch("cayvpn.network.time.sleep"):
            root = Path(directory)
            runner = FailedDnsRunner()
            manager = NetworkRouteManager(self.settings(root), runner)
            with self.assertRaises(NetworkOperationError) as error:
                manager.activate_client_policy("10.8.0.2/32", 5, "standard")
            self.assertEqual(error.exception.code, "dns_runtime_failed")
            self.assertEqual(runner.dns_probes, 20)
            self.assertEqual(manager.dns_processes, {})

    def test_dns_activation_requires_the_ipv6_listener_too(self):
        class IPv4OnlyDnsRunner(FakeRunner):
            def run(self, argv, timeout=10):
                command = inner_command(argv)
                if "cayvpn.dns_probe" in command:
                    self.calls.append((argv, timeout))
                    address = command[command.index("--address") + 1]
                    return subprocess.CompletedProcess(argv, 1 if ":" in address else 0, "", "")
                return super().run(argv, timeout)

        with tempfile.TemporaryDirectory() as directory, patch("cayvpn.network.time.sleep"):
            manager = NetworkRouteManager(self.settings(Path(directory)), IPv4OnlyDnsRunner())
            with self.assertRaises(NetworkOperationError) as error:
                manager.activate_client_policy("10.8.0.2/32", 5, "standard")
            self.assertEqual(error.exception.code, "dns_runtime_failed")

    def test_direct_probe_requires_the_observed_source_address(self):
        class SourceRunner(FakeRunner):
            def run(self, argv, timeout=10):
                self.calls.append((argv, timeout))
                if Path(argv[0]).name == "ip" and argv[1:4] == ["-4", "route", "get"]:
                    return subprocess.CompletedProcess(argv, 0, "1.1.1.1 via 169.254.101.1 dev cvhabc123 src 198.51.100.10", "")
                if "cayvpn.egress_probe" in argv:
                    details = {"connectivity": True, "tcp": True, "udp": True, "dns": True, "observed_exit_ip": "198.51.100.10"}
                    return subprocess.CompletedProcess(argv, 0, json.dumps(details), "")
                return subprocess.CompletedProcess(argv, 0, "", "")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manager = NetworkRouteManager(self.settings(root), SourceRunner())
            result = manager.probe_direct(1, "direct_ip", {"address": "198.51.100.10"})
            self.assertTrue(result["verified"])
            self.assertEqual(result["observed_exit_ip"], "198.51.100.10")

    def test_direct_probe_accepts_ubuntu_explicit_from_output(self):
        class ExplicitSourceRunner(FakeRunner):
            def run(self, argv, timeout=10):
                self.calls.append((argv, timeout))
                if Path(argv[0]).name == "ip" and argv[1:4] == ["-4", "route", "get"]:
                    return subprocess.CompletedProcess(
                        argv,
                        0,
                        "1.1.1.1 from 198.51.100.10 via 198.51.100.1 dev eth0 uid 0\n    cache\n",
                        "",
                    )
                if "cayvpn.egress_probe" in argv:
                    details = {"connectivity": True, "tcp": True, "udp": True, "dns": True, "observed_exit_ip": "198.51.100.10"}
                    return subprocess.CompletedProcess(argv, 0, json.dumps(details), "")
                return subprocess.CompletedProcess(argv, 0, "", "")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manager = NetworkRouteManager(self.settings(root), ExplicitSourceRunner())
            result = manager.probe_direct(1, "direct_ip", {"address": "198.51.100.10"})
            self.assertTrue(result["verified"])
            self.assertEqual(result["observed_exit_ip"], "198.51.100.10")

    def test_additional_ip_probe_rejects_a_different_outbound_interface(self):
        class WrongInterfaceRunner(FakeRunner):
            def run(self, argv, timeout=10):
                self.calls.append((argv, timeout))
                if Path(argv[0]).name == "ip" and argv[1:4] == ["-4", "addr", "show"]:
                    return subprocess.CompletedProcess(argv, 0, "inet 198.51.100.20/32 scope global eth0", "")
                if Path(argv[0]).name == "ip" and argv[1:4] == ["-4", "route", "get"]:
                    return subprocess.CompletedProcess(argv, 0, "1.1.1.1 from 198.51.100.20 dev eth1", "")
                if "cayvpn.egress_probe" in argv:
                    details = {"tcp": True, "udp": True, "dns": True, "observed_exit_ip": "198.51.100.20"}
                    return subprocess.CompletedProcess(argv, 0, json.dumps(details), "")
                return subprocess.CompletedProcess(argv, 0, "", "")

        with tempfile.TemporaryDirectory() as directory:
            manager = NetworkRouteManager(self.settings(Path(directory)), WrongInterfaceRunner())
            result = manager.probe_direct(4, "additional_ip", {"address": "198.51.100.20", "interface": "eth0"})
            self.assertFalse(result["verified"])
            self.assertEqual(result["reason"], "direct_route_path_mismatch")

    def test_additional_ip_installs_typed_source_nat_mapping(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runner = FakeRunner()
            manager = NetworkRouteManager(self.settings(root), runner)
            result = manager.activate("10.8.0.2/32", 6, "additional_ip", {"address": "198.51.100.20", "interface": "eth0"}, {"ipv6": False})
            self.assertTrue(result["verified"])
            namespace_ip = manager._names(6).namespace_address.split("/", 1)[0]
            self.assertTrue(any(Path(call[0][0]).name == "nft" and "cayvpn_snat_v4" in call[0] and namespace_ip in call[0] and "198.51.100.20" in call[0] for call in runner.calls))
            self.assertFalse(any(Path(call[0][0]).name == "nft" and "cayvpn_snat_v4" in call[0] and "10.8.0.2" in call[0] and "198.51.100.20" in call[0] for call in runner.calls))

    def test_additional_ip_mapping_survives_dns_namespace_reentry(self):
        class StatefulMapRunner(FakeRunner):
            def __init__(self):
                super().__init__()
                self.source_maps = {}

            def run(self, argv, timeout=10):
                command = inner_command(argv)
                if Path(command[0]).name == "nft" and command[1:3] == ["get", "element"]:
                    self.calls.append((argv, timeout))
                    source = command[-2]
                    target = self.source_maps.get(source)
                    if target:
                        map_name = command[5]
                        output = f"table inet cayvpn {{ map {map_name} {{ elements = {{ {source} : {target} }} }} }}"
                        return subprocess.CompletedProcess(argv, 0, output, "")
                    return subprocess.CompletedProcess(argv, 1, "", "Error: No such file or directory")
                if Path(command[0]).name == "nft" and command[1:3] == ["add", "element"]:
                    self.calls.append((argv, timeout))
                    self.source_maps[command[-4]] = command[-2]
                    return subprocess.CompletedProcess(argv, 0, "", "")
                if Path(command[0]).name == "nft" and command[1:2] == ["-f"]:
                    self.calls.append((argv, timeout))
                    lines = Path(command[2]).read_text().splitlines()
                    for line in lines:
                        fields = line.replace("{", "").replace("}", "").replace(":", "").split()
                        if fields[:2] == ["delete", "element"]:
                            self.source_maps.pop(fields[-1], None)
                        elif fields[:2] == ["add", "element"]:
                            self.source_maps[fields[-2]] = fields[-1]
                    return subprocess.CompletedProcess(argv, 0, "", "")
                return super().run(argv, timeout)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runner = StatefulMapRunner()
            manager = NetworkRouteManager(self.settings(root), runner)
            manager.conntrack = "conntrack"
            result = manager.activate(
                "10.8.0.2/32",
                6,
                "additional_ip",
                {"address": "198.51.100.20", "interface": "eth0"},
                {"ipv6": False},
            )

            namespace_ip = manager._names(6).namespace_address.split("/", 1)[0]
            self.assertTrue(result["verified"])
            self.assertEqual(runner.source_maps[namespace_ip], "198.51.100.20")
            namespace_resets = [
                inner_command(call[0])
                for call in runner.calls
                if Path(inner_command(call[0])[0]).name == "conntrack"
                and inner_command(call[0])[-2:] == ["-s", namespace_ip]
            ]
            self.assertEqual(len(namespace_resets), 1)

    def test_matching_profile_source_nat_mapping_is_not_rewritten(self):
        class MatchingMapRunner(FakeRunner):
            def run(self, argv, timeout=10):
                self.calls.append((argv, timeout))
                if Path(argv[0]).name == "nft" and argv[1:3] == ["get", "element"]:
                    return subprocess.CompletedProcess(
                        argv,
                        0,
                        "table inet cayvpn { map cayvpn_snat_v4 { elements = { 169.254.101.2 : 198.51.100.10 } } }",
                        "",
                    )
                return subprocess.CompletedProcess(argv, 0, "", "")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runner = MatchingMapRunner()
            manager = NetworkRouteManager(self.settings(root), runner)
            manager._set_source_nat("169.254.101.2", "198.51.100.10")
            self.assertFalse(any("add" in call[0][1:] or "delete" in call[0][1:] or "-f" in call[0][1:] for call in runner.calls))

    def test_profile_source_nat_change_uses_one_nft_transaction(self):
        class ExistingMapRunner(FakeRunner):
            def __init__(self):
                super().__init__()
                self.batch = ""

            def run(self, argv, timeout=10):
                self.calls.append((argv, timeout))
                if Path(argv[0]).name == "nft" and argv[1:3] == ["get", "element"]:
                    return subprocess.CompletedProcess(
                        argv,
                        0,
                        "table inet cayvpn { map cayvpn_snat_v4 { elements = { 169.254.101.2 : 198.51.100.10 } } }",
                        "",
                    )
                if Path(argv[0]).name == "nft" and argv[1] == "-f":
                    self.batch = Path(argv[2]).read_text()
                return subprocess.CompletedProcess(argv, 0, "", "")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runner = ExistingMapRunner()
            manager = NetworkRouteManager(self.settings(root), runner)
            manager._set_source_nat("169.254.101.2", "198.51.100.20")
            self.assertIn("delete element inet cayvpn cayvpn_snat_v4 { 169.254.101.2 }", runner.batch)
            self.assertIn("add element inet cayvpn cayvpn_snat_v4 { 169.254.101.2 : 198.51.100.20 }", runner.batch)
            batch_calls = [call[0] for call in runner.calls if Path(call[0][0]).name == "nft" and "-f" in call[0]]
            self.assertEqual(len(batch_calls), 1)
            self.assertFalse(Path(batch_calls[0][2]).exists())

    def test_amnezia_provider_uses_pinned_userspace_interface_not_kernel_wireguard(self):
        class ProviderRunner(FakeRunner):
            def __init__(self, engine: str):
                super().__init__()
                self.engine = engine
                self.engine_started = False
                self.quick_config = ""

            def run(self, argv, timeout=10):
                self.calls.append((argv, timeout))
                command = inner_command(argv)
                quick = next((item for item in argv if Path(item.split("=", 1)[-1]).name == "awg-quick"), None)
                if quick:
                    self.quick_config = Path(argv[-1]).read_text()
                    self.engine_started = True
                    return subprocess.CompletedProcess(argv, 0, "", "")
                if Path(command[0]).name == "ip" and command[-3:] == ["link", "show", "lo"]:
                    return subprocess.CompletedProcess(argv, 0, "", "")
                if Path(command[0]).name == "ip" and "link" in command and "show" in command:
                    return subprocess.CompletedProcess(argv, 0 if self.engine_started else 1, "", "")
                if Path(command[0]).name == "ip" and command[-4:-1] == ["route", "get", "1.1.1.1"]:
                    return subprocess.CompletedProcess(argv, 0, "1.1.1.1 dev tunnel", "")
                return super().run(argv, timeout)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            settings = self.settings(root)
            architecture = {"x86_64": "amd64", "aarch64": "arm64"}.get(os.uname().machine, os.uname().machine)
            component_dir = settings.config_dir / "components" / "amneziawg" / architecture
            component_dir.mkdir(parents=True)
            for name in ("awg", "awg-quick", "amneziawg-go"):
                path = component_dir / name
                path.write_text(name)
                path.chmod(0o755)
            runner = ProviderRunner(str(component_dir / "amneziawg-go"))
            manager = NetworkRouteManager(settings, runner)
            key = base64.b64encode(b"\0" * 32).decode()
            parsed = parse_provider_wireguard(
                f"[Interface]\nPrivateKey = {key}\nAddress = 10.20.0.2/32\nJc = 4\nJmin = 64\nJmax = 128\nS1 = 32\nS2 = 32\nH1 = 101\nH2 = 202\nH3 = 303\nH4 = 404\n\n"
                f"[Peer]\nPublicKey = {key}\nAllowedIPs = 0.0.0.0/0\nEndpoint = vpn.example:51820\n"
            )
            with (
                patch(
                    "cayvpn.network.component_binary",
                    side_effect=lambda _settings, name: str(component_dir / name),
                ),
                patch.object(NetworkRouteManager, "_public_endpoint_addresses", return_value=["198.51.100.20"]),
            ):
                result = manager.activate_provider(7, parsed)

            self.assertTrue(result["verified"])
            quick_calls = [call[0] for call in runner.calls if any(Path(item.split("=", 1)[-1]).name == "awg-quick" for item in call[0])]
            self.assertEqual(len(quick_calls), 1)
            expected_userspace = (component_dir / "amneziawg-go").resolve()
            self.assertTrue(any(item == f"WG_QUICK_USERSPACE_IMPLEMENTATION={expected_userspace}" for item in quick_calls[0]))
            self.assertIn("Address = 10.20.0.2/32", runner.quick_config)
            self.assertIn("Table = off", runner.quick_config)
            self.assertNotIn("DNS =", runner.quick_config)
            self.assertFalse(any("type" in call[0] and "wireguard" in call[0] for call in runner.calls))
            interface = manager._runtime_interface("cvw", 7)
            self.assertTrue(any("oifname" in call[0] and interface in call[0] and "masquerade" in call[0] for call in runner.calls))
            route_calls = [inner_command(call[0]) for call in runner.calls if Path(inner_command(call[0])[0]).name == "ip" and "route" in inner_command(call[0]) and "replace" in inner_command(call[0])]
            self.assertTrue(any(settings.user_network in call for call in route_calls))
            self.assertTrue(any(settings.amnezia_network in call for call in route_calls))
            self.assertTrue(any("cayvpn.egress_probe" in inner_command(call[0]) for call in runner.calls))
            self.assertFalse(any((settings.config_dir / "runtime").glob("*.conf")))

    def test_provider_ipv6_live_failure_replaces_default_with_prohibit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runner = FakeRunner()
            manager = NetworkRouteManager(self.settings(root), runner)
            key = base64.b64encode(b"\0" * 32).decode()
            parsed = parse_provider_wireguard(
                f"[Interface]\nPrivateKey = {key}\nAddress = 10.20.0.2/32, 2001:db8::2/128\n\n"
                f"[Peer]\nPublicKey = {key}\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = vpn.example:51820\n"
            )

            with (
                patch("cayvpn.network.shutil.which", return_value="/usr/bin/wg"),
                patch.object(NetworkRouteManager, "_public_endpoint_addresses", return_value=["198.51.100.20"]),
            ):
                result = manager.activate_provider(7, parsed)

            self.assertTrue(result["verified"])
            self.assertFalse(result["ipv6"])
            plan = manager._names(7)
            process = manager.namespace_processes[plan.name]
            self.assertTrue(runner.route_defaults[(str(process.pid), "-6", "main")]["blocked"])
            self.assertFalse(runner.route_defaults[(str(process.pid), "-4", "main")]["blocked"])
            probe_index = next(
                index
                for index, call in enumerate(runner.calls)
                if "cayvpn.egress_probe" in inner_command(call[0])
            )
            prohibit_index = max(
                index
                for index, call in enumerate(runner.calls)
                if inner_command(call[0])[-5:]
                == ["-6", "route", "replace", "prohibit", "default"]
            )
            self.assertGreater(prohibit_index, probe_index)

    def test_provider_probe_requires_real_namespace_connectivity(self):
        class FailedConnectivityRunner(FakeRunner):
            def run(self, argv, timeout=10):
                command = inner_command(argv)
                if "cayvpn.egress_probe" in command:
                    self.calls.append((argv, timeout))
                    return subprocess.CompletedProcess(argv, 1, "", "")
                return super().run(argv, timeout)

        with tempfile.TemporaryDirectory() as directory, patch("cayvpn.network.time.sleep"):
            root = Path(directory)
            runner = FailedConnectivityRunner()
            manager = NetworkRouteManager(self.settings(root), runner)
            plan = manager.ensure_namespace(3)
            interface = manager._runtime_interface("cvw", 3)
            manager._run_namespace(plan, [manager.ip, "-4", "route", "replace", "default", "dev", interface])

            result = manager.probe_provider(3, {})

            self.assertEqual(result["health_state"], "unhealthy")
            self.assertFalse(result["verified"])
            self.assertEqual(result["reason"], "provider_connectivity_failed")

    def test_provider_connectivity_probe_allows_the_full_family_check_sequence(self):
        with tempfile.TemporaryDirectory() as directory:
            runner = FakeRunner()
            manager = NetworkRouteManager(self.settings(Path(directory)), runner)
            result = manager._provider_connectivity_observation(manager.ensure_namespace(3))

            probe_calls = [
                call
                for call in runner.calls
                if "cayvpn.egress_probe" in inner_command(call[0])
            ]
            self.assertTrue(result["connectivity"])
            self.assertEqual([timeout for _argv, timeout in probe_calls], [20])


if __name__ == "__main__":
    unittest.main()
