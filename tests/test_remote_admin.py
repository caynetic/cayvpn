import json
import os
import subprocess
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from cayvpn.config import Settings
from cayvpn.remote_admin import RemoteAdminError, RemoteAdminManager


class FakeRunner:
    def __init__(
        self,
        root: Path,
        *,
        fail_lego: bool = False,
        mismatched_key: bool = False,
        missing_listener: bool = False,
        nft_output: str | None = None,
    ):
        self.root = root
        self.fail_lego = fail_lego
        self.mismatched_key = mismatched_key
        self.missing_listener = missing_listener
        self.nft_output = nft_output
        self.calls: list[tuple[list[str], int]] = []
        self.nft_file_contents: list[tuple[list[str], str]] = []

    def run(self, argv: list[str], timeout: int = 10):
        self.calls.append((list(argv), timeout))
        name = Path(argv[0]).name
        if name == "nft" and "-f" in argv:
            nft_path = Path(argv[argv.index("-f") + 1])
            if nft_path.is_file():
                self.nft_file_contents.append((list(argv), nft_path.read_text()))
        if name == "lego":
            if self.fail_lego:
                return subprocess.CompletedProcess(argv, 1, "", "ACME fixture refused")
            certificate_dir = self.root / "config" / "remote-admin" / "acme" / "certificates"
            certificate_dir.mkdir(parents=True, exist_ok=True)
            (certificate_dir / "8.8.8.8.crt").write_text("fixture certificate")
            (certificate_dir / "8.8.8.8.key").write_text("fixture private key")
        if name == "openssl" and "subjectAltName" in argv:
            return subprocess.CompletedProcess(argv, 0, "X509v3 Subject Alternative Name:\n    IP Address:8.8.8.8\n", "")
        if name == "openssl" and "-pubkey" in argv:
            return subprocess.CompletedProcess(argv, 0, "fixture-public-key\n", "")
        if name == "openssl" and "-pubout" in argv:
            value = "different-public-key\n" if self.mismatched_key else "fixture-public-key\n"
            return subprocess.CompletedProcess(argv, 0, value, "")
        if name == "nft" and "list" in argv:
            if self.nft_output is not None:
                return subprocess.CompletedProcess(argv, 0, self.nft_output, "")
            firewall = self.root / "config" / "firewall" / "remote-admin.nft"
            content = (
                firewall.read_text()
                if firewall.is_file()
                else RemoteAdminManager.firewall_config()
            )
            managed_set = {
                "family": "inet",
                "name": "cayvpn_remote_admin_ports",
                "table": "cayvpn",
                "type": "inet_service",
                "handle": 1,
            }
            if "80, 443" in content:
                managed_set["elem"] = [80, 443]
            return subprocess.CompletedProcess(
                argv,
                0,
                json.dumps({"nftables": [{"set": managed_set}]}),
                "",
            )
        if name == "ss":
            nginx = self.root / "config" / "nginx" / "remote-admin.conf"
            enabled = nginx.is_file() and "listen 8.8.8.8:443 ssl;" in nginx.read_text()
            output = ""
            if enabled:
                output = "LISTEN 0 511 8.8.8.8:80 0.0.0.0:*\n"
                if not self.missing_listener:
                    output += "LISTEN 0 511 8.8.8.8:443 0.0.0.0:*\n"
            return subprocess.CompletedProcess(argv, 0, output, "")
        return subprocess.CompletedProcess(argv, 0, "", "")


class RemoteAdminTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        base = Settings.from_env(Path(__file__).resolve().parents[1])
        self.settings = replace(
            base,
            state_dir=self.root / "state",
            config_dir=self.root / "config",
            db_path=self.root / "state" / "cayvpn.db",
            wg_dir=self.root / "wireguard",
            agent_socket=self.root / "agent.sock",
            public_endpoint="8.8.8.8",
            remote_admin_webroot=self.root / "acme-webroot",
            proxy_token="fixture-proxy-token-0123456789abcdef",
            apply_network=True,
        )
        self.nginx_config = self.settings.config_dir / "nginx" / "remote-admin.conf"
        self.firewall_fragment = self.settings.config_dir / "firewall" / "remote-admin.nft"
        self.nginx_config.parent.mkdir(parents=True)
        self.firewall_fragment.parent.mkdir(parents=True)
        self.nginx_config.write_text(RemoteAdminManager.disabled_nginx_config())
        self.firewall_fragment.write_text(RemoteAdminManager.firewall_config())
        self.nftables = self.root / "nftables.conf"
        self.nftables.write_text(
            "table inet cayvpn {\n"
            f'include "{self.firewall_fragment}"\n'
            "chain input { type filter hook input priority 0; policy drop; "
            "iifname \"eth0\" tcp dport @cayvpn_remote_admin_ports accept }\n"
            "}\n"
        )
        self.nginx_link = self.root / "cayvpn-remote"
        self.nginx_link.symlink_to(self.nginx_config)
        self.environment = patch.dict(
            os.environ,
            {
                "CAYVPN_NFTABLES_CONFIG": str(self.nftables),
                "CAYVPN_REMOTE_ADMIN_NGINX_LINK": str(self.nginx_link),
            },
        )
        self.environment.start()

    def tearDown(self):
        self.environment.stop()
        self.temp.cleanup()

    @patch("cayvpn.remote_admin.ensure_lego")
    def test_enable_and_disable_apply_only_fixed_https_and_firewall_templates(self, ensure):
        ensure.return_value = {"paths": {"lego": "/verified/lego"}}
        runner = FakeRunner(self.root)
        manager = RemoteAdminManager(self.settings, runner)

        enabled = manager.configure(True)

        self.assertEqual(enabled["public_origin"], "https://8.8.8.8")
        rendered = self.nginx_config.read_text()
        self.assertIn("listen 8.8.8.8:443 ssl;", rendered)
        self.assertIn("limit_req_zone", rendered)
        self.assertIn("proxy_set_header X-Forwarded-For $remote_addr;", rendered)
        self.assertIn("proxy_set_header X-CayVPN-Proxy-Token", rendered)
        self.assertNotIn("proxy_add_x_forwarded_for", rendered)
        self.assertIn("elements = { 80, 443 }", self.firewall_fragment.read_text())
        full_live_reloads = [
            call
            for call, _timeout in runner.calls
            if Path(call[0]).name == "nft"
            and call[1:] == ["-f", str(self.nftables)]
        ]
        self.assertEqual(full_live_reloads, [])
        runtime_batches = [
            content
            for call, content in runner.nft_file_contents
            if call[1:2] != ["-c"] and Path(call[-1]) != self.nftables
        ]
        self.assertTrue(runtime_batches)
        self.assertTrue(
            all("flush set inet cayvpn cayvpn_remote_admin_ports" in item for item in runtime_batches)
        )
        self.assertTrue(all("flush ruleset" not in item for item in runtime_batches))
        self.assertFalse(self.settings.remote_admin_webroot.is_relative_to(manager.root))
        self.assertEqual(
            self.settings.remote_admin_webroot.stat().st_mode & 0o777,
            0o755,
        )
        lego_calls = [call for call, _timeout in runner.calls if Path(call[0]).name == "lego"]
        self.assertEqual(len(lego_calls), 1)
        self.assertEqual(lego_calls[0][:2], ["/verified/lego", "run"])
        self.assertIn("--accept-tos", lego_calls[0])
        self.assertIn("--profile", lego_calls[0])
        self.assertIn("shortlived", lego_calls[0])
        self.assertIn("--renew-days", lego_calls[0])
        self.assertIn("--no-random-sleep", lego_calls[0])
        self.assertNotIn("renew", lego_calls[0])
        self.assertNotIn("--disable-cn", lego_calls[0])
        self.assertNotIn("--email", lego_calls[0])

        disabled = manager.configure(False)

        self.assertFalse(disabled["enabled"])
        self.assertEqual(self.nginx_config.read_text(), manager.disabled_nginx_config())
        self.assertEqual(self.firewall_fragment.read_text(), manager.firewall_config())

    def test_closed_firewall_template_omits_invalid_empty_elements_statement(self):
        disabled = RemoteAdminManager.firewall_config()

        self.assertIn("type inet_service;", disabled)
        self.assertNotIn("elements", disabled)

    @patch("cayvpn.remote_admin.ensure_lego")
    def test_read_only_verification_detects_remote_listener_drift(self, ensure):
        ensure.return_value = {"paths": {"lego": "/verified/lego"}}
        manager = RemoteAdminManager(self.settings, FakeRunner(self.root))
        manager.configure(True)

        self.assertTrue(manager.verify_state(True)["healthy"])
        missing = RemoteAdminManager(
            self.settings, FakeRunner(self.root, missing_listener=True)
        ).verify_state(True)
        self.assertFalse(missing["listeners"])
        self.assertFalse(missing["healthy"])

    def test_read_only_verification_confirms_the_closed_default(self):
        report = RemoteAdminManager(self.settings, FakeRunner(self.root)).verify_state(False)

        self.assertTrue(report["healthy"])
        self.assertFalse(report["expected_enabled"])

    def test_read_only_verification_rejects_untrusted_nft_json(self):
        wrong_set = json.dumps(
            {
                "nftables": [
                    {
                        "set": {
                            "family": "inet",
                            "name": "attacker_controlled_ports",
                            "table": "cayvpn",
                            "type": "inet_service",
                        }
                    }
                ]
            }
        )
        wrong = RemoteAdminManager(
            self.settings, FakeRunner(self.root, nft_output=wrong_set)
        ).verify_state(False)
        malformed = RemoteAdminManager(
            self.settings, FakeRunner(self.root, nft_output="not-json")
        ).verify_state(False)

        self.assertFalse(wrong["firewall_live"])
        self.assertFalse(wrong["healthy"])
        self.assertFalse(malformed["firewall_live"])
        self.assertFalse(malformed["healthy"])

    @patch("cayvpn.remote_admin.ensure_lego")
    def test_certificate_failure_restores_closed_listener_and_firewall(self, ensure):
        ensure.return_value = {"paths": {"lego": "/verified/lego"}}
        manager = RemoteAdminManager(self.settings, FakeRunner(self.root, fail_lego=True))

        with self.assertRaisesRegex(RemoteAdminError, "could not obtain"):
            manager.configure(True)

        self.assertEqual(self.nginx_config.read_text(), manager.disabled_nginx_config())
        self.assertEqual(self.firewall_fragment.read_text(), manager.firewall_config())

    def test_local_mode_plans_without_touching_network_or_acme(self):
        runner = FakeRunner(self.root)
        manager = RemoteAdminManager(replace(self.settings, apply_network=False), runner)

        result = manager.configure(True)

        self.assertEqual(result["state"], "planned")
        self.assertEqual(result["certificate"], "shortlived_ip")
        self.assertEqual(runner.calls, [])

    def test_non_https_acme_service_is_rejected_before_any_change(self):
        runner = FakeRunner(self.root)
        manager = RemoteAdminManager(
            replace(self.settings, remote_admin_acme_server="http://attacker.example/acme"),
            runner,
        )

        with self.assertRaisesRegex(RemoteAdminError, "certificate authority URL"):
            manager.configure(True)

        self.assertEqual(runner.calls, [])

    def test_untrusted_https_acme_service_is_rejected_before_any_change(self):
        runner = FakeRunner(self.root)
        manager = RemoteAdminManager(
            replace(self.settings, remote_admin_acme_server="https://attacker.example/acme"),
            runner,
        )

        with self.assertRaisesRegex(RemoteAdminError, "fixed Let's Encrypt"):
            manager.configure(True)

        self.assertEqual(runner.calls, [])

    @patch("cayvpn.remote_admin.ensure_lego")
    def test_renewal_uses_v5_run_without_accepting_terms_again(self, ensure):
        ensure.return_value = {"paths": {"lego": "/verified/lego"}}
        runner = FakeRunner(self.root)
        manager = RemoteAdminManager(self.settings, runner)
        manager.configure(True)
        runner.calls.clear()

        result = manager.renew()

        self.assertTrue(result["renewed"])
        lego_call = next(call for call, _timeout in runner.calls if Path(call[0]).name == "lego")
        self.assertEqual(lego_call[:2], ["/verified/lego", "run"])
        self.assertNotIn("--accept-tos", lego_call)
        self.assertIn("--renew-days", lego_call)

    @patch("cayvpn.remote_admin.ensure_lego")
    def test_renewal_cannot_register_a_new_account_without_owner_agreement(self, ensure):
        ensure.return_value = {"paths": {"lego": "/verified/lego"}}
        manager = RemoteAdminManager(self.settings, FakeRunner(self.root))

        with self.assertRaisesRegex(RemoteAdminError, "certificate is missing"):
            manager.renew()

    @patch("cayvpn.remote_admin.ensure_lego")
    def test_certificate_and_private_key_must_match_before_https_opens(self, ensure):
        ensure.return_value = {"paths": {"lego": "/verified/lego"}}
        manager = RemoteAdminManager(
            self.settings, FakeRunner(self.root, mismatched_key=True)
        )

        with self.assertRaisesRegex(RemoteAdminError, "did not verify"):
            manager.configure(True)

        self.assertEqual(self.nginx_config.read_text(), manager.disabled_nginx_config())
        self.assertEqual(self.firewall_fragment.read_text(), manager.firewall_config())

    def test_non_global_installed_address_is_rejected(self):
        runner = FakeRunner(self.root)
        manager = RemoteAdminManager(
            replace(self.settings, public_endpoint="192.0.2.10"), runner
        )

        with self.assertRaisesRegex(RemoteAdminError, "globally routable"):
            manager.configure(True)

        self.assertEqual(runner.calls, [])


if __name__ == "__main__":
    unittest.main()
