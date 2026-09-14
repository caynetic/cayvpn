import base64
import os
import subprocess
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from cayvpn.agent import AgentServer, NodeExecutor
from cayvpn.protocol import AgentResponse
from cayvpn.config import Settings
from cayvpn.security import totp_code
from cayvpn.updates import UpdateError, write_update_state


class AgentRunner:
    def __init__(self):
        self.calls = []

    def run(self, argv, timeout=10):
        self.calls.append((argv, timeout))
        if argv[1:4] == ["link", "show", "awg0"]:
            return subprocess.CompletedProcess(argv, 1, "", "not found")
        return subprocess.CompletedProcess(argv, 0, "", "")


class AgentTests(unittest.TestCase):
    def test_agent_socket_accepts_only_root_or_the_cayvpn_service_group(self):
        with patch("cayvpn.agent.grp.getgrnam", return_value=SimpleNamespace(gr_gid=2000)):
            with patch.object(AgentServer, "_peer_credentials", return_value=(42, 1000, 2000)):
                self.assertTrue(AgentServer._peer_authorized(object()))
            with patch.object(AgentServer, "_peer_credentials", return_value=(42, 1000, 2001)):
                self.assertFalse(AgentServer._peer_authorized(object()))
            with patch.object(AgentServer, "_peer_credentials", return_value=(42, 0, 2001)):
                self.assertTrue(AgentServer._peer_authorized(object()))
            with patch.object(AgentServer, "_peer_credentials", return_value=(0, 1000, 2000)):
                self.assertFalse(AgentServer._peer_authorized(object()))

    def test_disconnected_agent_caller_does_not_crash_the_server(self):
        class Disconnected:
            def sendall(self, _payload):
                raise BrokenPipeError("caller left")

        self.assertFalse(AgentServer._send_response(Disconnected(), AgentResponse("operation-1", "succeeded")))

    def test_root_verification_uses_all_health_checks_without_calling_its_own_socket(self):
        with tempfile.TemporaryDirectory() as directory:
            executor = NodeExecutor(self.settings(Path(directory), apply_network=False), AgentRunner())
            with patch("cayvpn.cli.cmd_verify", return_value=0) as verify:
                self.assertEqual(executor.system_verify({}), {"verified": True})
                verify.assert_called_once_with(executor.settings, _agent_verified=True, _emit=False)
            with patch("cayvpn.cli.cmd_verify", return_value=1):
                self.assertEqual(executor.system_verify({}), {"verified": False})
            with self.assertRaises(ValueError):
                executor.system_verify({"skip_checks": True})

    def settings(self, root: Path, apply_network: bool = True) -> Settings:
        return replace(
            Settings.from_env(root),
            config_dir=root / "config",
            wg_dir=root / "wireguard",
            state_dir=root / "state",
            db_path=root / "state" / "cayvpn.db",
            secret_key_path=root / "config" / "agent.key",
            apply_network=apply_network,
        )

    @staticmethod
    def key(seed: int) -> str:
        return base64.b64encode(bytes([seed]) * 32).decode()

    def test_root_agent_keeps_totp_secret_behind_an_opaque_reference(self):
        with tempfile.TemporaryDirectory() as directory:
            executor = NodeExecutor(self.settings(Path(directory), apply_network=False), AgentRunner())
            created = executor.totp_create({"account": "owner", "issuer": "CayVPN"})
            self.assertTrue(created["secret_ref"].startswith("ref::"))
            self.assertIn("otpauth://totp/", created["provisioning_uri"])
            secret = executor.secrets.reveal(created["secret_ref"])
            with patch("cayvpn.security.time.time", return_value=1_800_000_000):
                self.assertTrue(executor.totp_verify({"secret_ref": created["secret_ref"], "code": totp_code(secret, 1_800_000_000)})["verified"])
                self.assertFalse(executor.totp_verify({"secret_ref": created["secret_ref"], "code": "000000"})["verified"])

    def test_amnezia_interface_uses_pinned_engine_full_config_path_and_real_parameters(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            settings = self.settings(root)
            settings.wg_dir.mkdir(parents=True)
            (settings.wg_dir / "awg-server.key").write_text(self.key(1))
            (settings.wg_dir / "awg-server.pub").write_text(self.key(2))
            (settings.wg_dir / "awg-server.pub").chmod(0o600)
            runner = AgentRunner()
            executor = NodeExecutor(settings, runner)

            executor._ensure_amnezia_interface("/pinned/awg", "/pinned/awg-quick", "/pinned/amneziawg-go")

            config_path = settings.wg_dir / "awg0.conf"
            config = config_path.read_text()
            for field in ("Jc", "Jmin", "Jmax", "S1", "S2", "H1", "H2", "H3", "H4"):
                self.assertIn(f"{field} = ", config)
            quick_call = runner.calls[-1][0]
            self.assertEqual(Path(quick_call[0]).name, "env")
            self.assertIn("WG_QUICK_USERSPACE_IMPLEMENTATION=/pinned/amneziawg-go", quick_call)
            self.assertIn("PATH=/pinned:/usr/sbin:/usr/bin:/sbin:/bin", quick_call)
            self.assertEqual(quick_call[-3:], ["/pinned/awg-quick", "up", str(config_path.resolve())])
            self.assertEqual((settings.wg_dir / "awg-server.pub").stat().st_mode & 0o777, 0o644)

    def test_amnezia_restart_normalizes_separate_and_duplicate_address_lines(self):
        for duplicate in (False, True):
            with self.subTest(duplicate=duplicate), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                settings = self.settings(root)
                settings.wg_dir.mkdir(parents=True)
                (settings.wg_dir / "awg-server.key").write_text(self.key(1))
                (settings.wg_dir / "awg-server.pub").write_text(self.key(2))
                config = settings.wg_dir / "awg0.conf"
                addresses = f"Address = {settings.amnezia_address}"
                if duplicate:
                    addresses += f", {settings.amnezia_address_v6}"
                addresses += f"\nAddress = {settings.amnezia_address_v6}"
                content = "\n".join(["[Interface]", addresses, "PrivateKey = " + self.key(1), "SaveConfig = false",
                    *(f"{key} = {value}" for key, value in NodeExecutor._new_amnezia_parameters().items()),
                    "[Peer]", "PublicKey = " + self.key(3), "AllowedIPs = 10.9.0.2/32", ""])
                config.write_text(content)
                executor = NodeExecutor(settings, AgentRunner())
                executor._ensure_amnezia_interface("/pinned/awg", "/pinned/awg-quick", "/pinned/amneziawg-go")
                normalized = config.read_text()
                self.assertEqual(normalized.count(settings.amnezia_address_v6), 1)
                self.assertIn(f"Address = {settings.amnezia_address}, {settings.amnezia_address_v6}", normalized)
                self.assertEqual(normalized.split("[Peer]")[1], content.split("[Peer]")[1])
                self.assertIn("PrivateKey = " + self.key(1), normalized)
                executor._ensure_amnezia_interface("/pinned/awg", "/pinned/awg-quick", "/pinned/amneziawg-go")
                self.assertEqual(config.read_text(), normalized)

    def test_amnezia_client_configuration_copies_server_obfuscation_parameters(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            settings = self.settings(root, apply_network=False)
            settings.wg_dir.mkdir(parents=True)
            parameters = {
                "Jc": "4",
                "Jmin": "64",
                "Jmax": "128",
                "S1": "32",
                "S2": "32",
                "H1": "101",
                "H2": "202",
                "H3": "303",
                "H4": "404",
            }
            (settings.wg_dir / "awg0.conf").write_text(
                "[Interface]\n" + "\n".join(f"{key} = {value}" for key, value in parameters.items()) + "\n"
            )
            executor = NodeExecutor(settings, AgentRunner())
            reference = executor.secrets.store(self.key(3))

            result = executor.config_render_client(
                {
                    "secret_ref": reference,
                    "address": "10.9.0.2/32, fd12:3456:789a:2::2/128",
                    "server_public_key": self.key(4),
                    "endpoint": "198.51.100.10:43211",
                    "dns": "10.254.0.53",
                    "protocol": "amneziawg",
                    "allowed_ips": "0.0.0.0/0, ::/0",
                    "persistent_keepalive": 25,
                }
            )

            for key, value in parameters.items():
                self.assertIn(f"{key} = {value}", result["config"])
            self.assertIn("Address = 10.9.0.2/32, fd12:3456:789a:2::2/128", result["config"])
            self.assertIn("DNS = 10.254.0.53, cayvpn.home.arpa", result["config"])
            self.assertIn("AllowedIPs = 0.0.0.0/0, ::/0", result["config"])

    def test_admin_configuration_scopes_private_dns_name(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executor = NodeExecutor(self.settings(root, apply_network=False), AgentRunner())
            reference = executor.secrets.store(self.key(3))
            result = executor.config_render_admin(
                {
                    "secret_ref": reference,
                    "address": "10.255.0.2/32",
                    "server_public_key": self.key(4),
                    "endpoint": "198.51.100.10:51821",
                    "dns": "10.255.0.1",
                    "allowed_ips": "10.255.0.1/32",
                }
            )

            self.assertIn("DNS = 10.255.0.1, cayvpn.home.arpa", result["config"])

    def test_wireguard_reconcile_accepts_one_address_from_each_family(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executor = NodeExecutor(self.settings(root, apply_network=False), AgentRunner())
            result = executor.wireguard_reconcile(
                {
                    "interface": "wg0",
                    "protocol": "wireguard",
                    "peers": [
                        {
                            "public_key": self.key(8),
                            "allowed_ips": "10.8.0.2/32, fd12:3456:789a:1::2/128",
                            "persistent_keepalive": 25,
                        }
                    ],
                }
            )
        self.assertEqual(result["peer_count"], 1)

    def test_generic_wireguard_operations_cannot_modify_the_owner_interface(self):
        with tempfile.TemporaryDirectory() as directory:
            executor = NodeExecutor(
                self.settings(Path(directory), apply_network=False), AgentRunner()
            )
            for operation, payload in (
                (
                    executor.wireguard_reconcile,
                    {
                        "interface": "wg-admin",
                        "protocol": "wireguard",
                        "peers": [],
                    },
                ),
                (
                    executor.wireguard_remove_peer,
                    {
                        "interface": "wg-admin",
                        "protocol": "wireguard",
                        "public_key": self.key(9),
                    },
                ),
            ):
                with self.subTest(operation=operation.__name__), self.assertRaisesRegex(
                    ValueError, "not managed"
                ):
                    operation(payload)

    def test_runtime_reconciliation_distinguishes_expected_blocks_from_failures(self):
        with tempfile.TemporaryDirectory() as directory:
            executor = NodeExecutor(
                self.settings(Path(directory), apply_network=False), AgentRunner()
            )
            blocked_route = {
                "client_id": 7,
                "client_address": "10.8.0.7/32",
                "client_ipv6_address": "fd12:3456:789a:1::7/128",
                "ipv6_policy": "auto",
                "ingress_interface": "wg0",
                "profile_id": 4,
                "dns_mode": "standard",
                "profile": {
                    "profile_id": 4,
                    "driver": "direct_ip",
                    "config": {"address": "198.51.100.10"},
                    "capabilities": {},
                    "health_state": "blocked",
                    "ipv6_health_state": "blocked",
                },
            }
            with patch.object(executor.routes, "fail_closed") as fail_closed:
                expected = executor.runtime_reconcile({"routes": [blocked_route]})
            fail_closed.assert_called_once()
            self.assertTrue(expected["verified"])
            self.assertEqual(expected["expected_blocked_clients"], [7])
            self.assertEqual(expected["failed_clients"], [])

            healthy_route = {
                **blocked_route,
                "profile": {
                    **blocked_route["profile"],
                    "health_state": "healthy",
                },
            }
            with patch.object(
                executor.routes, "activate", side_effect=RuntimeError("fixture failure")
            ), patch.object(executor.routes, "fail_closed"):
                failed = executor.runtime_reconcile({"routes": [healthy_route]})
            self.assertFalse(failed["verified"])
            self.assertEqual(failed["failed"], 1)
            self.assertEqual(failed["failed_clients"], [7])

    def test_client_config_rejects_any_route_set_other_than_dual_stack_full_tunnel(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executor = NodeExecutor(self.settings(root, apply_network=False), AgentRunner())
            reference = executor.secrets.store(self.key(3))
            payload = {
                "secret_ref": reference,
                "address": "10.8.0.2/32, fd12:3456:789a:1::2/128",
                "server_public_key": self.key(4),
                "endpoint": "198.51.100.10:43210",
                "dns": "10.254.0.53, fd12:3456:789a:4::53",
                "protocol": "wireguard",
                "persistent_keepalive": 25,
            }
            for unsafe_routes in ("0.0.0.0/0", "::/0", "0.0.0.0/1, ::/0", "0.0.0.0/0, ::/0, 10.0.0.0/8"):
                with self.subTest(allowed_ips=unsafe_routes), self.assertRaisesRegex(ValueError, "IPv4 and IPv6 full-tunnel routes"):
                    executor.config_render_client({**payload, "allowed_ips": unsafe_routes})

    def test_ipv6_reconcile_rejects_unknown_fields_before_routing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executor = NodeExecutor(self.settings(root, apply_network=False), AgentRunner())
            with self.assertRaisesRegex(ValueError, "unsupported IPv6 reconciliation field"):
                executor.route_ipv6_reconcile({"client_id": 1, "raw_route": "default via host"})

    def test_remote_admin_agent_accepts_only_a_boolean_and_empty_renewal(self):
        with tempfile.TemporaryDirectory() as directory:
            executor = NodeExecutor(
                self.settings(Path(directory), apply_network=False), AgentRunner()
            )
            with patch.object(
                executor.remote_admin, "configure", return_value={"enabled": True}
            ) as configure:
                self.assertTrue(executor.remote_admin_configure({"enabled": True})["enabled"])
                configure.assert_called_once_with(True)
            for hostile in ({}, {"enabled": 1}, {"enabled": True, "config": "raw"}):
                with self.subTest(payload=hostile), self.assertRaisesRegex(
                    ValueError, "enabled boolean"
                ):
                    executor.remote_admin_configure(hostile)
            with patch.object(
                executor.remote_admin, "renew", return_value={"renewed": True}
            ) as renew:
                self.assertTrue(executor.remote_admin_renew({})["renewed"])
                renew.assert_called_once_with()
            with self.assertRaisesRegex(ValueError, "does not accept fields"):
                executor.remote_admin_renew({"command": "anything"})

    def test_empty_amnezia_reconcile_is_a_noop_before_interface_setup(self):
        class MissingInterfaceRunner(AgentRunner):
            def run(self, argv, timeout=10):
                self.calls.append((argv, timeout))
                if Path(argv[0]).name == "awg" and argv[1:] == ["show", "awg0", "peers"]:
                    return subprocess.CompletedProcess(argv, 1, "", "Unable to access interface: Protocol not supported")
                if Path(argv[0]).name == "ip" and argv[1:] == ["link", "show", "awg0"]:
                    return subprocess.CompletedProcess(argv, 1, "", "Device awg0 does not exist.")
                return subprocess.CompletedProcess(argv, 0, "", "")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            settings = self.settings(root)
            architecture = {"x86_64": "amd64", "aarch64": "arm64"}.get(os.uname().machine, os.uname().machine)
            component_dir = settings.config_dir / "components" / "amneziawg" / architecture
            component_dir.mkdir(parents=True)
            awg = component_dir / "awg"
            awg.write_text("test")
            awg.chmod(0o755)
            runner = MissingInterfaceRunner()
            with patch("cayvpn.agent.component_binary", return_value=str(awg)):
                result = NodeExecutor(settings, runner).wireguard_reconcile(
                    {"interface": "awg0", "protocol": "amneziawg", "peers": []}
                )
            self.assertEqual(result["state"], "not_configured")
            self.assertFalse(result["applied"])

    def test_amnezia_reconcile_recreates_userspace_interface_before_saved_peers(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            settings = self.settings(root)
            runner = AgentRunner()
            executor = NodeExecutor(settings, runner)
            component = {
                "state": "installed",
                "paths": {
                    "awg": "/pinned/awg",
                    "awg_quick": "/pinned/awg-quick",
                    "amneziawg_go": "/pinned/amneziawg-go",
                },
            }

            with patch("cayvpn.agent.ensure_amneziawg", return_value=component), patch.object(
                executor, "_ensure_amnezia_interface"
            ) as ensure_interface:
                result = executor.wireguard_reconcile(
                    {
                        "interface": "awg0",
                        "protocol": "amneziawg",
                        "peers": [
                            {
                                "public_key": self.key(7),
                                "allowed_ips": "10.9.0.2/32",
                                "persistent_keepalive": 25,
                            }
                        ],
                    }
                )

            ensure_interface.assert_called_once_with(
                "/pinned/awg", "/pinned/awg-quick", "/pinned/amneziawg-go"
            )
            self.assertTrue(result["applied"])
            self.assertEqual(result["peer_count"], 1)
            self.assertFalse(any("save" in call[0] for call in runner.calls))

    def test_empty_amnezia_reconcile_does_not_hide_a_tool_failure(self):
        class FailedToolRunner(AgentRunner):
            def run(self, argv, timeout=10):
                self.calls.append((argv, timeout))
                if Path(argv[0]).name == "awg" and argv[1:] == ["show", "awg0", "peers"]:
                    return subprocess.CompletedProcess(argv, 1, "", "permission denied")
                if Path(argv[0]).name == "ip" and argv[1:] == ["link", "show", "awg0"]:
                    return subprocess.CompletedProcess(argv, 0, "awg0: <POINTOPOINT,UP>", "")
                return subprocess.CompletedProcess(argv, 0, "", "")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            settings = self.settings(root)
            architecture = {"x86_64": "amd64", "aarch64": "arm64"}.get(os.uname().machine, os.uname().machine)
            component_dir = settings.config_dir / "components" / "amneziawg" / architecture
            component_dir.mkdir(parents=True)
            awg = component_dir / "awg"
            awg.write_text("test")
            awg.chmod(0o755)
            with patch("cayvpn.agent.component_binary", return_value=str(awg)):
                with self.assertRaises(RuntimeError):
                    NodeExecutor(settings, FailedToolRunner()).wireguard_reconcile(
                        {"interface": "awg0", "protocol": "amneziawg", "peers": []}
                    )

    def test_update_runner_uses_fixed_systemd_arguments(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            settings = replace(
                self.settings(root),
                active_release=root / "current",
                release_dir=root / "releases",
            )
            runner = AgentRunner()
            unit = NodeExecutor(settings, runner)._start_update_runner("stage", "2.0.1", "a" * 32, 7)

            argv = runner.calls[-1][0]
            self.assertEqual(argv[0], "/usr/bin/systemd-run")
            self.assertIn("--property=Environment=PYTHONDONTWRITEBYTECODE=1", argv)
            self.assertIn("--property=NoNewPrivileges=true", argv)
            self.assertIn("--property=PrivateTmp=true", argv)
            self.assertIn("--property=ProtectHome=true", argv)
            self.assertIn("--property=ProtectSystem=full", argv)
            self.assertTrue(any(item.startswith("--property=ReadWritePaths=") for item in argv))
            self.assertNotIn("sh", [Path(item).name for item in argv])
            self.assertEqual(argv[-7:], ["stage", "--release", "2.0.1", "--operation-id", "a" * 32, "--desired-generation", "7"])
            self.assertTrue(unit.startswith("cayvpn-update-stage-"))

    def test_owner_can_discard_only_the_inactive_staged_release(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            settings = replace(
                self.settings(root),
                active_release=root / "current",
                release_dir=root / "releases",
                update_state_path=root / "state" / "update-status.json",
            )
            active = settings.release_dir / "2.0.0"
            staged = settings.release_dir / "2.0.1"
            active.mkdir(parents=True)
            staged.mkdir()
            settings.active_release.symlink_to(active, target_is_directory=True)
            write_update_state(settings, "staged", current_release="2.0.0", target_release="2.0.1")

            result = NodeExecutor(settings, AgentRunner()).update_discard({"release": "2.0.1"})

            self.assertEqual(result["state"], "discarded")
            self.assertTrue(active.is_dir())
            self.assertFalse(staged.exists())

    def test_verified_download_must_be_resolved_before_another_check(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            settings = replace(
                self.settings(root),
                update_state_path=root / "state" / "update-status.json",
            )
            write_update_state(settings, "staged", current_release="2.0.0", target_release="2.0.1")

            with self.assertRaises(UpdateError) as raised:
                NodeExecutor(settings, AgentRunner()).update_check({})

            self.assertEqual(raised.exception.code, "staged_update_pending")


class ClientSettingsRecoveryTests(unittest.TestCase):
    def test_failed_settings_change_reapplies_the_previous_dns_and_ipv6_policy(self):
        from cayvpn.network import NetworkOperationError
        from unittest.mock import MagicMock

        for protocol in ("wg0", "awg0"):
            for restored in (True, False):
                with self.subTest(protocol=protocol, restored=restored), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    settings = replace(Settings.from_env(root), state_dir=root, config_dir=root / "config", wg_dir=root / "wg")
                    executor = NodeExecutor(settings)
                    executor.routes = MagicMock()
                    failure = NetworkOperationError("fixture_apply_failure", "fixture failure")
                    executor.routes.activate.side_effect = [failure, {"verified": True} if restored else failure]
                    profile = {"profile_id": 1, "driver": "direct_ip", "health_state": "healthy", "ipv6_health_state": "healthy"}
                    with self.assertRaises(NetworkOperationError) as raised:
                        executor.route_switch({"client_id": 1, "client_address": "10.8.0.2/32", "client_ipv6_address": "fd00::2/128",
                            "ingress_interface": protocol, "target_profile_id": 1, "previous_profile_id": 1,
                            "target_profile": profile, "previous_profile": profile, "settings_change": True,
                            "dns_mode": "ad_blocking", "ipv6_policy": "required", "previous_dns_mode": "standard", "previous_ipv6_policy": "auto"})
                    self.assertEqual(raised.exception.code, "route_switch_failed")
                    calls = executor.routes.activate.call_args_list
                    self.assertEqual(calls[0].args[5:], ("ad_blocking", protocol, "fd00::2/128", "required"))
                    self.assertEqual(calls[1].args[5:], ("standard", protocol, "fd00::2/128", "auto"))
                    self.assertEqual(raised.exception.result["restored_verified"], restored)
                    self.assertGreaterEqual(executor.routes.fail_closed.call_count, 2 if restored else 3)


if __name__ == "__main__":
    unittest.main()
