import base64
import os
import json
import re
import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from cayvpn.config import Settings
from cayvpn.models import AdminDevice, Client, EgressPool, EgressProfile, ManagedNode, RouteBinding, WizardDraft
from cayvpn.protocol import AgentResponse
from cayvpn.secret_store import RootSecretStore
from cayvpn.security import totp_code
from cayvpn.secret_store import SecretStoreError
from cayvpn.web import create_app


class WebTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(__file__).resolve().parents[1]
        base = Settings.from_env(root)
        self.settings = replace(
            base,
            state_dir=Path(self.temp.name),
            config_dir=Path(self.temp.name) / "config",
            db_path=Path(self.temp.name) / "cayvpn.db",
            wg_dir=Path(self.temp.name) / "wireguard",
            agent_socket=Path(self.temp.name) / "agent.sock",
            secret_key_path=Path(self.temp.name) / "config" / "agent.key",
            agent_inline=True,
            https_enabled=False,
            server_ip="198.51.100.10",
            public_endpoint="198.51.100.10",
            proxy_token="fixture-proxy-token-0123456789abcdef",
        )
        blocklist = self.settings.config_dir / "adblock"
        blocklist.mkdir(parents=True, exist_ok=True)
        (blocklist / "test.txt").write_text("||ads.example^\n")
        self.app = create_app(settings=self.settings)
        self.app.config["WTF_CSRF_ENABLED"] = False
        self.client = self.app.test_client()

    def tearDown(self):
        self.app.extensions["cayvpn_db"].engine.dispose()
        self.temp.cleanup()

    def authenticate(self):
        with self.client.session_transaction() as session:
            session["authenticated"] = True
            session["auth_method"] = "test"
            session.permanent = True

    def mark_direct_location_ready(self):
        with self.app.extensions["cayvpn_db"].session() as session:
            direct = session.query(EgressProfile).filter_by(driver="direct_ip").one()
            direct.health_state = "healthy"
            direct.capabilities_json = json.dumps(
                {
                    "schema": 2,
                    "ipv4": {"tcp": True, "udp": True, "dns": True},
                    "ipv6": {"tcp": False, "udp": False, "dns": False},
                }
            )
            direct.observed_exit_ip = self.settings.server_ip

    def make_route_switch_verified(self):
        operations = self.app.extensions["cayvpn_operations"]
        original_executor = operations.agent.inline_executor

        def executor(request):
            if request.action == "route.switch":
                return AgentResponse(
                    request.operation_id,
                    "succeeded",
                    request.desired_generation,
                    result={
                        "verified": True,
                        "applied": True,
                        "fail_closed": False,
                        "ipv6_state": "blocked",
                    },
                )
            return original_executor(request)

        operations.agent.inline_executor = executor

    def start_wizard(self, kind: str) -> str:
        response = self.client.post(f"/setup/{kind}/new")
        self.assertEqual(response.status_code, 302)
        return response.headers["Location"]

    def settings_client(self, protocol="wireguard"):
        self.authenticate()
        with self.client.session_transaction() as owner:
            owner["passkey_verified_until"] = 2**31
        self.make_route_switch_verified()
        self.mark_direct_location_ready()
        with self.app.extensions["cayvpn_db"].session() as session:
            profile = session.get(EgressProfile, 1)
            profile.ipv6_health_state = "healthy"
            profile.capabilities_json = json.dumps({"schema": 2, **{family: {"tcp": True, "udp": True, "dns": True} for family in ("ipv4", "ipv6")}})
        response = self.client.post("/clients", data={"name": protocol, "ingress_protocol": protocol,
                                    "dns_mode": "standard", "route_mode": "fixed", "fixed_egress_id": "1"})
        self.assertEqual(response.status_code, 302)
        with self.app.extensions["cayvpn_db"].session() as session:
            client = session.query(Client).filter_by(name=protocol).one()
            client.confirmed_config_version = client.generated_config_version
            client_id = client.id
        return next(item for item in self.client.get("/api/v1/clients").json if item["id"] == client_id)

    def test_edit_settings_preserves_both_protocol_clients_and_versions(self):
        for protocol in ("wireguard", "amneziawg"):
            with self.subTest(protocol=protocol):
                before = self.settings_client(protocol)
                path = f'/clients/{before["id"]}/settings'
                self.assertIn(b"Edit connection", self.client.get(path).data)
                response = self.client.post(path, data={"dns_mode": "ad_blocking", "ipv6_policy": "required", "settings_revision": before["settings_revision"]})
                self.assertEqual(response.status_code, 302)
                after = next(item for item in self.client.get("/api/v1/clients").json if item["id"] == before["id"])
                for key in ("id", "public_key", "address", "ipv6_address", "ingress_protocol", "fixed_egress_id", "route_mode"):
                    self.assertEqual(after[key], before[key])
                self.assertEqual((after["dns_mode"], after["ipv6_policy"]), ("ad_blocking", "required"))
                self.assertEqual(after["generated_config_version"], before["generated_config_version"] + 1)
                self.assertTrue(after["configuration_update_available"])
                self.client.post(path, data={"dns_mode": "ad_blocking", "ipv6_policy": "auto", "settings_revision": after["settings_revision"]})
                reverted = next(item for item in self.client.get("/api/v1/clients").json if item["id"] == before["id"])
                self.assertEqual(reverted["generated_config_version"], after["generated_config_version"])
                self.assertEqual(reverted["ipv6_policy"], "auto")

    def test_edit_settings_stale_form_and_incompatible_ipv6_leave_client_unchanged(self):
        before = self.settings_client()
        path = f'/clients/{before["id"]}/settings'
        with self.app.extensions["cayvpn_db"].session() as session:
            session.get(EgressProfile, 1).ipv6_health_state = "failed"
        fields = {"dns_mode": "ad_blocking", "ipv6_policy": "required", "settings_revision": before["settings_revision"]}
        self.assertEqual(self.client.post(path, data=fields).status_code, 409)
        self.assertEqual(self.client.get("/api/v1/clients").json[0], before)
        fields.update(ipv6_policy="auto", settings_revision="stale")
        self.assertIn(b"Reload", self.client.post(path, data=fields).data)
        self.assertEqual(self.client.get("/api/v1/clients").json[0], before)

    def test_edit_settings_api_idempotency_validation_and_owner_approval(self):
        before = self.settings_client()
        path = f'/api/v1/clients/{before["id"]}/settings'
        fields = {"dns_mode": "ad_blocking", "ipv6_policy": "auto", "settings_revision": before["settings_revision"]}
        headers = {"Idempotency-Key": "settings-api-test-0001"}
        self.assertEqual(self.client.post(path, json=fields).status_code, 400)
        self.assertEqual(self.client.post(path, json={**fields, "dns_mode": []}, headers=headers).status_code, 400)
        with self.client.session_transaction() as owner:
            owner.pop("passkey_verified_until")
        self.assertEqual(self.client.post(path, json=fields, headers=headers).status_code, 403)
        with self.client.session_transaction() as owner:
            owner["passkey_verified_until"] = 2**31
        first = self.client.post(path, json=fields, headers=headers)
        self.assertEqual(first.status_code, 200)
        self.assertEqual(self.client.post(path, json=fields, headers=headers).json, first.json)
        self.assertEqual(self.client.post(path, json={**fields, "dns_mode": "standard"}, headers=headers).status_code, 409)

    def test_edit_settings_dns_export_and_stale_import_confirmation(self):
        before = self.settings_client()
        client_id = before["id"]
        original = self.client.get(f'/clients/{client_id}/config').data
        self.client.post(f'/clients/{client_id}/settings', data={"dns_mode": "ad_blocking", "ipv6_policy": "auto", "settings_revision": before["settings_revision"]})
        updated = self.client.get(f'/clients/{client_id}/config').data
        self.assertIn(b'DNS = 10.254.0.53', original)
        self.assertIn(b'DNS = 10.254.0.54', updated)
        for raw in (original, updated):
            self.assertIn(b'AllowedIPs = 0.0.0.0/0, ::/0', raw)
        self.client.post(f'/clients/{client_id}/config/confirm', data={"installed": "on", "config_version": before["generated_config_version"]})
        self.assertTrue(self.client.get('/api/v1/clients').json[0]['configuration_update_available'])
        current = self.client.get('/api/v1/clients').json[0]
        self.client.post(f'/clients/{client_id}/config/confirm', data={"installed": "on", "config_version": current["generated_config_version"]})
        self.assertFalse(self.client.get('/api/v1/clients').json[0]['configuration_update_available'])

    def test_edit_settings_queued_response_keeps_desired_settings_pending(self):
        before = self.settings_client()
        operations = self.app.extensions['cayvpn_operations']
        operations.agent.inline_executor = lambda request: AgentResponse(request.operation_id, 'queued', error_code='agent_unavailable')
        path = f'/api/v1/clients/{before["id"]}/settings'
        fields = {"dns_mode": "ad_blocking", "ipv6_policy": "required", "settings_revision": before["settings_revision"]}
        response = self.client.post(path, json=fields, headers={"Idempotency-Key": "settings-timeout-test-1"})
        self.assertEqual(response.status_code, 202)
        self.assertEqual(response.json['route_state'], 'pending')
        self.assertEqual(response.json['client']['dns_mode'], 'ad_blocking')
        fields['settings_revision'] = response.json['client']['settings_revision']
        self.assertEqual(self.client.post(path, json=fields, headers={"Idempotency-Key": "settings-timeout-test-2"}).status_code, 409)

    def test_edit_settings_failed_apply_restores_previous_preferences(self):
        before = self.settings_client()
        operations = self.app.extensions['cayvpn_operations']
        operations.agent.inline_executor = lambda request: AgentResponse(request.operation_id, 'failed', request.desired_generation,
            result={'restored_profile_id': 1, 'restored_verified': True}, error_code='route_switch_failed')
        response = self.client.post(f'/api/v1/clients/{before["id"]}/settings', json={"dns_mode": "ad_blocking", "ipv6_policy": "required", "settings_revision": before["settings_revision"]}, headers={"Idempotency-Key": "settings-failure-test-1"})
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.json['route_state'], 'active')
        self.assertEqual(response.json['client']['dns_mode'], 'standard')
        self.assertEqual(response.json['client']['ipv6_policy'], 'auto')
        self.assertTrue(response.json['client']['configuration_update_available'])

    def test_edit_settings_keeps_selected_pool_backup_and_noop_does_not_reset_it(self):
        before = self.settings_client()
        database = self.app.extensions['cayvpn_db']
        with database.session() as session:
            direct = session.get(EgressProfile, 1)
            session.add(EgressProfile(id=7, name='Selected backup', driver='direct_ip', health_state='healthy',
                                     ipv6_health_state='healthy', config_json=direct.config_json, capabilities_json=direct.capabilities_json))
            session.add(EgressPool(id=1, name='Approved pool', profile_ids_json='[1, 7]'))
            binding = session.query(RouteBinding).filter_by(client_id=before['id']).one()
            binding.egress_profile_id, binding.pool_id = 7, 1
        service = self.app.extensions['cayvpn_operations']
        with patch.object(service.agent, 'execute', wraps=service.agent.execute) as execute:
            _, response = service.update_client_settings(before['id'], 'standard', 'auto', before['settings_revision'])
            self.assertTrue(response.result['unchanged'])
            execute.assert_not_called()
            service.update_client_settings(before['id'], 'standard', 'required', before['settings_revision'])
            self.assertEqual(execute.call_args.args[0].payload['target_profile_id'], 7)
            self.assertEqual(execute.call_args.args[0].payload['target_pool_id'], 1)
        with database.session() as session:
            binding = session.query(RouteBinding).filter_by(client_id=before['id']).one()
            self.assertEqual((binding.egress_profile_id, binding.pool_id, binding.state), (7, 1, 'active'))
            self.assertEqual(session.get(Client, before['id']).generated_config_version, before['generated_config_version'])

    def test_edit_settings_requires_csrf_and_available_adblocking(self):
        before = self.settings_client()
        path = f'/clients/{before["id"]}/settings'
        fields = {"dns_mode": "ad_blocking", "ipv6_policy": "auto", "settings_revision": before["settings_revision"]}
        self.app.config['WTF_CSRF_ENABLED'] = True
        self.assertEqual(self.client.post(path, data=fields).status_code, 400)
        self.app.config['WTF_CSRF_ENABLED'] = False
        (self.settings.config_dir / 'adblock/test.txt').unlink()
        self.assertIn(b'not available', self.client.post(path, data=fields).data)
        self.assertEqual(self.client.get('/api/v1/clients').json[0], before)

    def test_management_flow(self):
        self.authenticate()
        response = self.client.get("/")
        self.assertIn("script-src 'self'", response.headers["Content-Security-Policy"])
        self.assertIn("style-src 'self'", response.headers["Content-Security-Policy"])
        self.assertNotIn("'unsafe-inline'", response.headers["Content-Security-Policy"])
        self.assertIn(b"/static/app.js", response.data)
        self.assertIn(b'class="skip-link" href="#main-content"', response.data)
        self.assertIn(b'id="main-content" tabindex="-1"', response.data)
        self.assertNotIn(b"onclick=", response.data)
        script = self.client.get("/static/app.js")
        self.assertEqual(script.status_code, 200)
        script_body = script.data
        script.close()
        self.assertIn(b"attachRouteSwitches", script_body)
        self.assertIn(b"attachUniquePoolBackups", script_body)
        self.assertIn(b"attachLocationPickers", script_body)
        self.assertIn(b"attachDeviceStepOneHistory", script_body)
        self.assertIn(b"focusErrorSummary", script_body)
        self.assertIn(b"setPasskeyMessage", script_body)
        self.assertIn(b"Choose a Location to see how CayVPN will protect IPv6.", script_body)
        self.assertIn(b'else if (route === "pool")', script_body)
        self.assertGreaterEqual(script_body.count(b"if (data.ok) window.location.reload();"), 2)
        response = self.client.post("/clients", data={"name": "Test phone", "ingress_protocol": "wireguard", "dns_mode": "standard", "route_mode": "switchable"}, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Test phone", response.data)
        with self.client.session_transaction() as session:
            session["passkey_verified_until"] = 2**31
        response = self.client.get("/config/1")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"AllowedIPs = 0.0.0.0/0, ::/0", response.data)
        with self.app.extensions["cayvpn_db"].session() as session:
            self.assertEqual(session.query(Client).one().address, "10.8.0.2")
        # The fixture can report a single recommended egress slot.  Exercise
        # the owner override explicitly before adding a second profile.
        self.app.extensions["cayvpn_db"].set_setting("capacity_override_active", "1")
        response = self.client.post("/egress", data={"name": "Test SOCKS", "driver": "socks5", "endpoint": "socks5://proxy.example:1080", "password": "secret"}, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Test SOCKS", response.data)
        response = self.client.post("/clients", data={"name": "Fixed laptop", "ingress_protocol": "wireguard", "dns_mode": "standard", "route_mode": "fixed", "fixed_egress_id": "1"}, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        response = self.client.get("/api/v1/clients")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'"fixed_egress_id":1', response.data)

    def test_client_removal_deletes_its_route_binding_and_private_key(self):
        self.authenticate()
        with self.client.session_transaction() as owner_session:
            owner_session["passkey_verified_until"] = 2**31
        created = self.client.post(
            "/clients",
            data={
                "name": "Temporary laptop",
                "ingress_protocol": "wireguard",
                "dns_mode": "standard",
                "route_mode": "switchable",
            },
        )
        self.assertEqual(created.status_code, 302)
        with self.app.extensions["cayvpn_db"].session() as session:
            saved = session.query(Client).filter_by(name="Temporary laptop").one()
            client_id = saved.id
            private_key_ref = saved.private_key_enc
            self.assertIsNotNone(session.query(RouteBinding).filter_by(client_id=client_id).one_or_none())
        secret_store = self.app.extensions["cayvpn_operations"].agent.inline_executor.__self__.secrets

        removed = self.client.post(f"/clients/{client_id}/delete", follow_redirects=True)

        self.assertEqual(removed.status_code, 200)
        self.assertIn(b"removed and its server peer revoked", removed.data)
        with self.app.extensions["cayvpn_db"].session() as session:
            self.assertIsNone(session.get(Client, client_id))
            self.assertIsNone(session.query(RouteBinding).filter_by(client_id=client_id).one_or_none())
        with self.assertRaises(SecretStoreError):
            secret_store.reveal(private_key_ref)

    def test_client_removal_retains_retryable_state_when_private_key_cleanup_fails(self):
        self.authenticate()
        with self.client.session_transaction() as owner_session:
            owner_session["passkey_verified_until"] = 2**31
        created = self.client.post(
            "/clients",
            data={
                "name": "Retry cleanup laptop",
                "ingress_protocol": "wireguard",
                "dns_mode": "standard",
                "route_mode": "switchable",
            },
        )
        self.assertEqual(created.status_code, 302)
        with self.app.extensions["cayvpn_db"].session() as session:
            saved = session.query(Client).filter_by(name="Retry cleanup laptop").one()
            client_id = saved.id
            private_key_ref = saved.private_key_enc
        operations = self.app.extensions["cayvpn_operations"]
        original_executor = operations.agent.inline_executor
        secret_store = original_executor.__self__.secrets

        def executor(request):
            if request.action == "secret.delete":
                return AgentResponse(
                    request.operation_id,
                    "failed",
                    request.desired_generation,
                    error_code="secret_store_unavailable",
                    error_message="unavailable",
                )
            return original_executor(request)

        operations.agent.inline_executor = executor
        pending = self.client.post(f"/clients/{client_id}/delete", follow_redirects=True)

        self.assertEqual(pending.status_code, 200)
        self.assertIn(b"encrypted key cleanup is pending", pending.data)
        self.assertNotIn(private_key_ref.encode(), pending.data)
        with self.app.extensions["cayvpn_db"].session() as session:
            retained = session.get(Client, client_id)
            self.assertIsNotNone(retained)
            self.assertFalse(retained.enabled)
            binding = session.query(RouteBinding).filter_by(client_id=client_id).one()
            self.assertEqual(binding.state, "blocked")
            self.assertEqual(binding.last_error, "private-key cleanup pending")
        self.assertIsNotNone(secret_store.reveal(private_key_ref))

        operations.agent.inline_executor = original_executor
        retried = self.client.post(f"/clients/{client_id}/delete", follow_redirects=True)

        self.assertEqual(retried.status_code, 200)
        self.assertIn(b"removed and its server peer revoked", retried.data)
        with self.app.extensions["cayvpn_db"].session() as session:
            self.assertIsNone(session.get(Client, client_id))
            self.assertIsNone(session.query(RouteBinding).filter_by(client_id=client_id).one_or_none())
        with self.assertRaises(SecretStoreError):
            secret_store.reveal(private_key_ref)

    def test_fresh_admin_tunnel_session_requires_an_active_matching_device(self):
        with self.app.extensions["cayvpn_db"].session() as session:
            session.add(
                AdminDevice(
                    name="Owner Mac",
                    public_key=base64.b64encode(b"a" * 32).decode(),
                    address="10.255.0.2/32",
                    enabled=True,
                )
            )

        accepted = self.client.get("/", environ_base={"REMOTE_ADDR": "10.255.0.2"})
        self.assertEqual(accepted.status_code, 200)
        with self.client.session_transaction() as owner_session:
            self.assertEqual(owner_session["auth_method"], "admin_tunnel")
            self.assertEqual(owner_session["admin_address"], "10.255.0.2")

        protected = self.client.post(
            "/security/admin-devices",
            data={"name": "Second owner device"},
            environ_base={"REMOTE_ADDR": "10.255.0.2"},
        )
        self.assertEqual(protected.status_code, 302)
        self.assertRegex(protected.headers["Location"], r"/security/admin-devices/\d+/config$")
        with self.app.extensions["cayvpn_db"].session() as session:
            self.assertIsNotNone(
                session.query(AdminDevice).filter_by(name="Second owner device").one_or_none()
            )

        unmatched = self.app.test_client().get("/", environ_base={"REMOTE_ADDR": "10.255.0.99"})
        self.assertEqual(unmatched.status_code, 403)

    def test_owner_tunnel_session_cannot_be_reused_from_another_source(self):
        with self.app.extensions["cayvpn_db"].session() as session:
            session.add(AdminDevice(
                name="Owner Mac", public_key=base64.b64encode(b"a" * 32).decode(),
                address="10.255.0.2/32", enabled=True,
            ))
        for address in ("10.8.0.2", "127.0.0.1", "203.0.113.9"):
            with self.subTest(source=address):
                browser = self.app.test_client()
                self.assertEqual(browser.get("/", environ_base={"REMOTE_ADDR": "10.255.0.2"}).status_code, 200)
                response = browser.get("/api/v1/system", environ_base={"REMOTE_ADDR": address})
                self.assertEqual(response.status_code, 403)
                with browser.session_transaction() as owner_session:
                    self.assertFalse(owner_session.get("authenticated", False))

    def test_local_process_cannot_spoof_an_owner_tunnel_with_forwarded_headers(self):
        with self.app.extensions["cayvpn_db"].session() as session:
            session.add(
                AdminDevice(
                    name="Owner Mac",
                    public_key=base64.b64encode(b"z" * 32).decode(),
                    address="10.255.0.2/32",
                    enabled=True,
                )
            )

        untrusted = self.app.test_client().get(
            "/",
            environ_base={"REMOTE_ADDR": "127.0.0.1"},
            headers={"X-Forwarded-For": "10.255.0.2"},
        )
        self.assertEqual(untrusted.status_code, 403)

        trusted = self.app.test_client().get(
            "/",
            environ_base={"REMOTE_ADDR": "127.0.0.1"},
            headers={
                "X-Forwarded-For": "10.255.0.2",
                "X-CayVPN-Proxy-Token": self.settings.proxy_token,
            },
        )
        self.assertEqual(trusted.status_code, 200)

    def test_admin_device_revocation_removes_its_peer_session_and_private_key(self):
        self.authenticate()
        with self.client.session_transaction() as owner_session:
            owner_session["passkey_verified_until"] = 2**31
        added = self.client.post("/security/admin-devices", data={"name": "Temporary admin"})
        self.assertEqual(added.status_code, 302)
        with self.app.extensions["cayvpn_db"].session() as session:
            device = session.query(AdminDevice).filter_by(name="Temporary admin").one()
            device_id = device.id
            device_address = device.address.split("/", 1)[0]
            private_key_ref = device.private_key_enc
        secret_store = self.app.extensions["cayvpn_operations"].agent.inline_executor.__self__.secrets
        device_browser = self.app.test_client()
        self.assertEqual(device_browser.get("/", environ_base={"REMOTE_ADDR": device_address}).status_code, 200)

        revoked = self.client.post(f"/security/admin-devices/{device_id}/revoke", follow_redirects=True)

        self.assertEqual(revoked.status_code, 200)
        self.assertIn(b"Its tunnel is no longer accepted", revoked.data)
        with self.app.extensions["cayvpn_db"].session() as session:
            saved = session.get(AdminDevice, device_id)
            self.assertFalse(saved.enabled)
            self.assertIsNotNone(saved.revoked_at)
            self.assertIsNone(saved.private_key_enc)
        with self.assertRaises(SecretStoreError):
            secret_store.reveal(private_key_ref)
        self.assertEqual(device_browser.get("/", environ_base={"REMOTE_ADDR": device_address}).status_code, 403)

    def test_admin_device_revocation_retains_retryable_key_cleanup(self):
        self.authenticate()
        with self.client.session_transaction() as owner_session:
            owner_session["passkey_verified_until"] = 2**31
        added = self.client.post("/security/admin-devices", data={"name": "Retry admin cleanup"})
        self.assertEqual(added.status_code, 302)
        with self.app.extensions["cayvpn_db"].session() as session:
            device = session.query(AdminDevice).filter_by(name="Retry admin cleanup").one()
            device_id = device.id
            private_key_ref = device.private_key_enc
        operations = self.app.extensions["cayvpn_operations"]
        original_executor = operations.agent.inline_executor
        secret_store = original_executor.__self__.secrets

        def executor(request):
            if request.action == "secret.delete":
                return AgentResponse(
                    request.operation_id,
                    "failed",
                    request.desired_generation,
                    error_code="secret_store_unavailable",
                    error_message="unavailable",
                )
            return original_executor(request)

        operations.agent.inline_executor = executor
        pending = self.client.post(f"/security/admin-devices/{device_id}/revoke", follow_redirects=True)

        self.assertEqual(pending.status_code, 200)
        self.assertIn(b"encrypted key cleanup is pending", pending.data)
        self.assertIn(b"Finish cleanup", pending.data)
        self.assertNotIn(private_key_ref.encode(), pending.data)
        with self.app.extensions["cayvpn_db"].session() as session:
            saved = session.get(AdminDevice, device_id)
            self.assertFalse(saved.enabled)
            self.assertEqual(saved.private_key_enc, private_key_ref)
        self.assertIsNotNone(secret_store.reveal(private_key_ref))

        operations.agent.inline_executor = original_executor
        finished = self.client.post(f"/security/admin-devices/{device_id}/revoke", follow_redirects=True)

        self.assertEqual(finished.status_code, 200)
        self.assertIn(b"encrypted-key cleanup finished", finished.data)
        with self.app.extensions["cayvpn_db"].session() as session:
            saved = session.get(AdminDevice, device_id)
            self.assertFalse(saved.enabled)
            self.assertIsNone(saved.private_key_enc)
        with self.assertRaises(SecretStoreError):
            secret_store.reveal(private_key_ref)

    def test_private_mode_rejects_public_request(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 403)

    def test_login_only_explains_private_admin_access(self):
        response = self.client.get("/login")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"CayVPN connection from your setup folder", response.data)
        self.assertIn(b"Turn off any other active VPN", response.data)
        self.assertNotIn(b"name=\"password\"", response.data)

    def test_authenticated_navigation_does_not_exhaust_public_login_limits(self):
        self.authenticate()
        for _ in range(60):
            self.assertEqual(self.client.get("/").status_code, 200)

        public_browser = self.app.test_client()
        public_request = {"REMOTE_ADDR": "198.51.100.23"}
        for _ in range(50):
            self.assertEqual(
                public_browser.get("/login", environ_base=public_request).status_code,
                200,
            )
        self.assertEqual(
            public_browser.get("/login", environ_base=public_request).status_code,
            429,
        )

        login_browser = self.app.test_client()
        login_request = {"REMOTE_ADDR": "198.51.100.24"}
        for _ in range(5):
            self.assertNotEqual(
                login_browser.post(
                    "/login",
                    data={"password": "incorrect", "totp_code": "000000"},
                    environ_base=login_request,
                ).status_code,
                429,
            )
        self.assertEqual(
            login_browser.post(
                "/login",
                data={"password": "incorrect", "totp_code": "000000"},
                environ_base=login_request,
            ).status_code,
            429,
        )

    def test_owner_login_defaults_to_password_only(self):
        self.authenticate()
        started = self.client.post("/security/owner-login/new")
        step_one = started.headers["Location"]
        step_one_page = self.client.get(step_one)
        self.assertIn(b"Password only", step_one_page.data)
        self.assertIn(b"No authenticator app or extra code", step_one_page.data)
        self.assertIn(b'minlength="12"', step_one_page.data)

        step_two = self.client.post(
            step_one,
            data={
                "password": "simple owner passphrase",
                "password_confirm": "simple owner passphrase",
            },
        )
        self.assertEqual(step_two.status_code, 302)
        self.assertTrue(step_two.headers["Location"].endswith("/2"))
        draft_id = step_one.split("/")[-2]
        with self.app.extensions["cayvpn_db"].session() as session:
            draft = session.get(WizardDraft, draft_id)
            self.assertIsNone(draft.secret_ref)
            self.assertFalse(draft.data["authenticator_enabled"])
            self.assertNotIn("simple owner passphrase", draft.data_json)

        optional_step = self.client.get(step_two.headers["Location"])
        self.assertIn(b"No authenticator needed", optional_step.data)
        self.assertNotIn(b'name="totp_code"', optional_step.data)
        step_three = self.client.post(step_two.headers["Location"])
        self.assertEqual(step_three.status_code, 302)
        self.assertTrue(step_three.headers["Location"].endswith("/3"))
        completed = self.client.post(
            f"/security/owner-login/{draft_id}/complete", follow_redirects=True
        )
        self.assertIn(b"Optional sign-in enabled", completed.data)
        database = self.app.extensions["cayvpn_db"]
        self.assertEqual(database.get_setting("client_panel_totp_required"), "0")
        self.assertEqual(database.get_setting("client_panel_totp_ref"), "")

        with self.client.session_transaction() as owner_session:
            owner_session.clear()
        login_page = self.client.get(
            "/login", environ_base={"REMOTE_ADDR": "10.8.0.2"}
        )
        self.assertIn(b"Optional sign-in", login_page.data)
        self.assertIn(b'name="password"', login_page.data)
        self.assertNotIn(b'name="totp_code"', login_page.data)
        wrong = self.client.post(
            "/login",
            data={"password": "wrong password value"},
            environ_base={"REMOTE_ADDR": "10.8.0.2"},
        )
        self.assertIn(b"owner password was incorrect", wrong.data)
        signed_in = self.client.post(
            "/login",
            data={"password": "simple owner passphrase"},
            environ_base={"REMOTE_ADDR": "10.8.0.2"},
        )
        self.assertEqual(signed_in.status_code, 302)

        protected = self.client.post(
            "/security/owner-login/new",
            environ_base={"REMOTE_ADDR": "10.8.0.2"},
        )
        self.assertIn("/security/confirm", protected.headers["Location"])
        confirmation = self.client.get(
            protected.headers["Location"],
            environ_base={"REMOTE_ADDR": "10.8.0.2"},
        )
        self.assertIn(b"Enter your owner password", confirmation.data)
        self.assertNotIn(b'name="totp_code"', confirmation.data)
        approved = self.client.post(
            "/security/confirm",
            data={"password": "simple owner passphrase", "next": "/security"},
            environ_base={"REMOTE_ADDR": "10.8.0.2"},
        )
        self.assertEqual(approved.status_code, 302)
        self.assertEqual(approved.headers["Location"], "/security")

    def test_owner_login_wizard_supports_optional_authenticator_from_a_cayvpn_client(self):
        self.authenticate()
        started = self.client.post("/security/owner-login/new")
        self.assertEqual(started.status_code, 302)
        step_one = started.headers["Location"]
        step_two = self.client.post(
            step_one,
            data={
                "password": "correct horse battery staple",
                "password_confirm": "correct horse battery staple",
                "authenticator_mode": "authenticator",
            },
        )
        self.assertEqual(step_two.status_code, 302)
        self.assertTrue(step_two.headers["Location"].endswith("/2"))
        draft_id = step_one.split("/")[-2]
        with self.app.extensions["cayvpn_db"].session() as session:
            draft = session.get(WizardDraft, draft_id)
            self.assertNotIn("correct horse", draft.data_json)
            self.assertTrue(draft.secret_ref.startswith("ref::"))
            secret_reference = draft.secret_ref
        secret = RootSecretStore(self.settings).reveal(secret_reference)
        code = totp_code(secret)
        step_three = self.client.post(step_two.headers["Location"], data={"totp_code": code})
        self.assertEqual(step_three.status_code, 302)
        self.assertTrue(step_three.headers["Location"].endswith("/3"))
        completed = self.client.post(f"/security/owner-login/{draft_id}/complete", follow_redirects=True)
        self.assertIn(b"Optional sign-in enabled", completed.data)
        database = self.app.extensions["cayvpn_db"]
        self.assertEqual(database.get_setting("client_panel_login_enabled"), "1")
        self.assertEqual(database.get_setting("client_panel_totp_ref"), secret_reference)
        self.assertEqual(database.get_setting("client_panel_totp_required"), "1")
        # Older installations have the secret reference but no explicit
        # preference key. They must retain their authenticator requirement.
        database.set_setting("client_panel_totp_required", "")
        with self.client.session_transaction() as owner_session:
            self.assertGreater(owner_session["owner_approval_until"], 0)

        with self.client.session_transaction() as owner_session:
            owner_session.pop("owner_approval_until", None)
        protected = self.client.post(
            "/security/admin-devices",
            data={"name": "Protected device"},
            headers={"Referer": "http://localhost/security"},
        )
        self.assertEqual(protected.status_code, 302)
        self.assertIn("/security/confirm?next=/security", protected.headers["Location"])
        future = int(datetime.now(timezone.utc).timestamp()) + 30
        with patch("cayvpn.web.now_epoch", return_value=future):
            approved = self.client.post(
                "/security/confirm",
                data={
                    "password": "correct horse battery staple",
                    "totp_code": totp_code(secret, at_time=future),
                    "next": "/security",
                },
            )
        self.assertEqual(approved.status_code, 302)
        self.assertEqual(approved.headers["Location"], "/security")
        with self.client.session_transaction() as owner_session:
            self.assertEqual(owner_session["owner_approval_until"], future + 300)

        with self.client.session_transaction() as owner_session:
            owner_session.clear()
        redirected = self.client.get("/", environ_base={"REMOTE_ADDR": "10.8.0.2"})
        self.assertEqual(redirected.status_code, 302)
        self.assertIn("/login?next=/", redirected.headers["Location"])
        login_page = self.client.get("/login", environ_base={"REMOTE_ADDR": "10.8.0.2"})
        self.assertIn(b"Optional sign-in", login_page.data)
        self.assertIn(b'name="password"', login_page.data)
        self.assertIn(b"10.255.0.1:8443", login_page.data)
        wrong = self.client.post(
            "/login",
            data={"password": "wrong password value", "totp_code": code},
            environ_base={"REMOTE_ADDR": "10.8.0.2"},
        )
        self.assertIn(b"password or six-digit code was incorrect", wrong.data)
        signed_in = self.client.post(
            "/login",
            data={"password": "correct horse battery staple", "totp_code": code},
            environ_base={"REMOTE_ADDR": "10.8.0.2"},
        )
        self.assertEqual(signed_in.status_code, 302)
        dashboard = self.client.get("/", environ_base={"REMOTE_ADDR": "10.8.0.2"})
        self.assertEqual(dashboard.status_code, 200)
        public = self.client.get("/login", environ_base={"REMOTE_ADDR": "203.0.113.9"})
        self.assertNotIn(b'name="password"', public.data)

        with self.client.session_transaction() as owner_session:
            owner_session["authenticated"] = True
            owner_session["auth_method"] = "owner_login"
            owner_session["owner_address"] = "10.8.0.2"
            owner_session["owner_approval_until"] = 2**31
        changed = self.client.post(
            "/security/owner-login/new",
            environ_base={"REMOTE_ADDR": "10.8.0.2"},
        )
        password_step = self.client.post(
            changed.headers["Location"],
            data={
                "password": "new simple owner passphrase",
                "password_confirm": "new simple owner passphrase",
                "authenticator_mode": "password",
            },
            environ_base={"REMOTE_ADDR": "10.8.0.2"},
        )
        changed_draft_id = changed.headers["Location"].split("/")[-2]
        review_step = self.client.post(
            password_step.headers["Location"],
            environ_base={"REMOTE_ADDR": "10.8.0.2"},
        )
        removed_authenticator = self.client.post(
            f"/security/owner-login/{changed_draft_id}/complete",
            environ_base={"REMOTE_ADDR": "10.8.0.2"},
        )
        self.assertEqual(removed_authenticator.status_code, 302)
        self.assertEqual(removed_authenticator.headers["Location"], "/security")
        self.assertTrue(review_step.headers["Location"].endswith("/3"))
        self.assertEqual(database.get_setting("client_panel_totp_required"), "0")
        self.assertEqual(database.get_setting("client_panel_totp_ref"), "")
        with self.assertRaises(SecretStoreError):
            RootSecretStore(self.settings).reveal(secret_reference)

    def test_remote_owner_login_is_opt_in_and_reapproves_sensitive_changes(self):
        self.authenticate()
        started = self.client.post("/security/owner-login/new")
        step_one = started.headers["Location"]
        step_one_page = self.client.get(step_one)
        self.assertIn(b"normal website access on ports 80 and 443", step_one_page.data)
        self.assertIn(b"separate from the VPN connection port", step_one_page.data)
        self.assertIn(b"Disabling internet access closes both ports again", step_one_page.data)
        step_two = self.client.post(
            step_one,
            data={
                "access_scope": "internet",
                "password": "remote correct horse battery",
                "password_confirm": "remote correct horse battery",
                "authenticator_mode": "authenticator",
            },
        )
        draft_id = step_one.split("/")[-2]
        with self.app.extensions["cayvpn_db"].session() as database_session:
            draft = database_session.get(WizardDraft, draft_id)
            secret = RootSecretStore(self.settings).reveal(draft.secret_ref)
        login_code = totp_code(secret)
        step_three = self.client.post(
            step_two.headers["Location"], data={"totp_code": login_code}
        )
        missing_agreement = self.client.post(
            f"/security/owner-login/{draft_id}/complete"
        )
        self.assertEqual(missing_agreement.status_code, 302)
        self.assertEqual(
            self.app.extensions["cayvpn_db"].get_setting("remote_admin_enabled"),
            "0",
        )
        completed = self.client.post(
            f"/security/owner-login/{draft_id}/complete",
            data={"accept_acme_terms": "yes"},
            follow_redirects=True,
        )
        self.assertIn(b"https://198.51.100.10", completed.data)
        self.assertEqual(
            self.app.extensions["cayvpn_db"].get_setting("remote_admin_enabled"),
            "1",
        )

        public_origin = "http://198.51.100.10"
        public_client = self.app.test_client()
        unauthenticated_api = public_client.get(
            "/api/v1/system",
            base_url=public_origin,
            environ_base={"REMOTE_ADDR": "203.0.113.9"},
        )
        self.assertEqual(unauthenticated_api.status_code, 403)
        login_page = public_client.get(
            "/login",
            base_url=public_origin,
            environ_base={"REMOTE_ADDR": "203.0.113.9"},
        )
        self.assertEqual(login_page.status_code, 200)
        self.assertIn(b"secure remote access", login_page.data)
        signed_in = public_client.post(
            "/login",
            base_url=public_origin,
            data={
                "password": "remote correct horse battery",
                "totp_code": login_code,
            },
            environ_base={"REMOTE_ADDR": "203.0.113.9"},
        )
        self.assertEqual(signed_in.status_code, 302)
        dashboard = public_client.get(
            "/",
            base_url=public_origin,
            environ_base={"REMOTE_ADDR": "203.0.113.9"},
        )
        self.assertEqual(dashboard.status_code, 200)
        passkey = public_client.post(
            "/security/passkey/authenticate/options",
            base_url=public_origin,
            environ_base={"REMOTE_ADDR": "203.0.113.9"},
        )
        self.assertEqual(passkey.status_code, 409)
        self.assertIn(b"Passkeys require the private", passkey.data)

        protected = public_client.post(
            "/security/owner-login/new",
            base_url=public_origin,
            environ_base={"REMOTE_ADDR": "203.0.113.9"},
        )
        self.assertIn("/security/confirm", protected.headers["Location"])
        reused = public_client.post(
            "/security/remote-approve",
            base_url=public_origin,
            data={
                "password": "remote correct horse battery",
                "totp_code": login_code,
                "next": "/security",
            },
            environ_base={"REMOTE_ADDR": "203.0.113.9"},
        )
        self.assertIn(b"Wait for a new authenticator code", reused.data)

        next_time = int(datetime.now(timezone.utc).timestamp()) + 30
        next_code = totp_code(secret, at_time=next_time)
        with patch("cayvpn.security.time.time", return_value=next_time):
            approved = public_client.post(
                "/security/remote-approve",
                base_url=public_origin,
                data={
                    "password": "remote correct horse battery",
                    "totp_code": next_code,
                    "next": "/security",
                },
                environ_base={"REMOTE_ADDR": "203.0.113.9"},
            )
        self.assertEqual(approved.status_code, 302)
        self.assertEqual(approved.headers["Location"], "/security")
        approved_page = public_client.get(
            "/security",
            base_url=public_origin,
            environ_base={"REMOTE_ADDR": "203.0.113.9"},
        )
        self.assertIn(b"approved", approved_page.data)

        disabled = public_client.post(
            "/security/owner-login/disable",
            base_url=public_origin,
            environ_base={"REMOTE_ADDR": "203.0.113.9"},
        )
        self.assertEqual(disabled.status_code, 302)
        closed = public_client.get(
            "/login",
            base_url=public_origin,
            environ_base={"REMOTE_ADDR": "203.0.113.9"},
        )
        self.assertEqual(closed.status_code, 400)

    def test_forwarded_host_cannot_replace_the_validated_request_host(self):
        self.authenticate()
        response = self.client.get(
            "/", headers={"X-Forwarded-Host": "attacker.example"}
        )
        self.assertEqual(response.status_code, 200)

    def test_installed_remote_origin_requires_https_on_standard_port(self):
        remote_root = Path(self.temp.name) / "installed-remote"
        remote_settings = replace(
            self.settings,
            state_dir=remote_root,
            config_dir=remote_root / "config",
            db_path=remote_root / "cayvpn.db",
            agent_socket=remote_root / "agent.sock",
            apply_network=True,
            https_enabled=True,
        )
        installed = create_app(settings=remote_settings)
        installed.config["WTF_CSRF_ENABLED"] = False
        installed.extensions["cayvpn_db"].set_setting("remote_admin_enabled", "1")
        try:
            wrong_scheme = installed.test_client().get(
                "/login", base_url="http://198.51.100.10"
            )
            wrong_port = installed.test_client().get(
                "/login", base_url="https://198.51.100.10:444"
            )
            self.assertEqual(wrong_scheme.status_code, 400)
            self.assertEqual(wrong_port.status_code, 400)
        finally:
            installed.extensions["cayvpn_db"].engine.dispose()

    def test_client_wizard_disables_and_rejects_ad_blocking_without_a_list(self):
        self.authenticate()
        (self.settings.config_dir / "adblock" / "test.txt").write_text("! no usable rules\n")
        step_one = self.start_wizard("client")
        step_two = self.client.post(
            step_one,
            data={"name": "No filter device", "ingress_protocol": "wireguard"},
        ).headers["Location"]
        page = self.client.get(step_two)
        self.assertRegex(page.text, r'name="dns_mode" value="ad_blocking"[^>]*disabled')
        self.assertRegex(page.text, r'name="dns_mode" value="standard"[^>]*checked')
        rejected = self.client.post(
            step_two,
            data={"dns_mode": "ad_blocking", "route_choice": "direct"},
            follow_redirects=True,
        )
        self.assertEqual(rejected.status_code, 200)
        self.assertIn(b"Ad and tracker blocking is not installed", rejected.data)

    def test_secure_forms_keep_strict_csrf_with_a_same_origin_referrer(self):
        self.app.config["WTF_CSRF_ENABLED"] = True
        origin = "https://admin.cayvpn.home.arpa:8443"
        with self.client.session_transaction(base_url=origin) as session:
            session["authenticated"] = True
            session["auth_method"] = "test"
            session.permanent = True
        page = self.client.get("/", base_url=origin)
        self.assertEqual(page.status_code, 200)
        self.assertEqual(page.headers["Referrer-Policy"], "same-origin")
        match = re.search(rb'name="csrf_token" value="([^"]+)"', page.data)
        self.assertIsNotNone(match)
        token = match.group(1).decode()

        missing = self.client.post(
            "/onboarding/start",
            base_url=origin,
            data={"csrf_token": token, "next": "overview"},
        )
        self.assertEqual(missing.status_code, 400)
        self.assertIn(b"referrer header is missing", missing.data)

        hostile = self.client.post(
            "/onboarding/start",
            base_url=origin,
            headers={"Referer": "https://attacker.example/"},
            data={"csrf_token": token, "next": "overview"},
        )
        self.assertEqual(hostile.status_code, 400)

        accepted = self.client.post(
            "/onboarding/start",
            base_url=origin,
            headers={"Referer": f"{origin}/"},
            data={"csrf_token": token, "next": "overview"},
        )
        self.assertEqual(accepted.status_code, 302)

    def test_passkey_registration_options_exist(self):
        self.authenticate()
        blocked = self.client.post("/security/passkey/register/options")
        self.assertEqual(blocked.status_code, 403)
        with self.client.session_transaction() as owner_session:
            owner_session["owner_approval_until"] = 100
        with patch("cayvpn.web.now_epoch", return_value=50):
            response = self.client.post("/security/passkey/register/options")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"challenge", response.data)

    def test_passkey_enrollment_does_not_bootstrap_a_new_approval_window(self):
        self.authenticate()
        with self.client.session_transaction() as owner_session:
            owner_session["owner_approval_until"] = 100
        verified = SimpleNamespace(
            credential_id=b"credential-id",
            credential_public_key=b"credential-public-key",
            sign_count=0,
        )
        with patch("cayvpn.web.now_epoch", return_value=50):
            options = self.client.post("/security/passkey/register/options")
            self.assertEqual(options.status_code, 200)
            with patch(
                "cayvpn.web.verify_registration_response", return_value=verified
            ):
                registered = self.client.post(
                    "/security/passkey/register", json={"id": "fixture"}
                )
        self.assertEqual(registered.status_code, 200)
        with self.client.session_transaction() as owner_session:
            self.assertEqual(owner_session["owner_approval_until"], 100)
            self.assertNotIn("passkey_verified_until", owner_session)

    def test_legacy_location_post_requires_recent_owner_confirmation(self):
        self.authenticate()
        with self.app.extensions["cayvpn_db"].session() as session:
            before = session.query(EgressProfile).count()

        response = self.client.post(
            "/egress",
            data={
                "name": "Unapproved proxy",
                "driver": "socks5",
                "endpoint": "socks5://proxy.example:1080",
                "password": "not-stored",
            },
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/security")
        with self.app.extensions["cayvpn_db"].session() as session:
            self.assertEqual(session.query(EgressProfile).count(), before)

    def test_security_page_makes_passkeys_optional_and_keeps_ssh_recovery(self):
        self.authenticate()
        response = self.client.get("/security")
        self.assertEqual(response.status_code, 200)
        self.assertLess(response.data.index(b"<h2>Secure access</h2>"), response.data.index(b"<h2>Optional sign-in</h2>"))
        self.assertLess(response.data.index(b"<h2>Optional sign-in</h2>"), response.data.index(b"<h2>Passkeys</h2>"))
        self.assertIn(b"No password, authenticator code, or passkey is required", response.data)
        self.assertIn(b"<h2>Settings devices</h2>", response.data)
        self.assertNotIn(b"Owner tunnel connected", response.data)
        self.assertIn(b"Set up optional sign-in", response.data)
        self.assertIn(b"Password-only is the easy default", response.data)
        self.assertIn(b"Optional shortcut", response.data)
        self.assertIn(b"No passkey enrolled. That is completely optional.", response.data)
        self.assertNotIn(b"Approve this setup first", response.data)
        self.assertIn(b"Add device", response.data)
        self.assertIn(b"sudo cayvpnctl recovery approve", response.data)
        self.assertIn(b'action="/security/approve"', response.data)
        self.assertIn(b'name="recovery_code"', response.data)
        self.assertIn(b'id="passkey-secure-context-warning"', response.data)
        self.assertIn(b"cayvpn-ca.crt", response.data)
        self.assertIn(b"Secure Sockets Layer (SSL)", response.data)

        passkey_javascript = self.client.get("/static/app.js")
        self.assertEqual(passkey_javascript.status_code, 200)
        self.assertIn(b"window.isSecureContext", passkey_javascript.data)
        self.assertIn(b"Optional passkey setup is paused until this browser trusts CayVPN.", passkey_javascript.data)
        self.assertIn(b'button.setAttribute("aria-disabled", "true")', passkey_javascript.data)
        self.assertIn(b"if (!response.ok)", passkey_javascript.data)
        passkey_javascript.close()

    def test_direct_exit_is_built_in_and_not_offered_twice(self):
        self.authenticate()
        with self.client.session_transaction() as owner_session:
            owner_session["passkey_verified_until"] = 2**31
        response = self.client.get("/egress")
        self.assertEqual(response.status_code, 200)
        self.assertNotIn(b'<option value="direct_ip">', response.data)
        response = self.client.post("/egress", data={"name": "Duplicate direct", "driver": "direct_ip"}, follow_redirects=True)
        self.assertIn(b"already available as This server", response.data)

    def test_exit_type_requires_an_explicit_selection(self):
        self.authenticate()
        response = self.client.get("/egress")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Add Location", response.data)
        location = self.start_wizard("exit")
        response = self.client.get(location)
        self.assertIn(b'name="driver" value="additional_ip"', response.data)
        self.assertNotRegex(response.text, r'name="driver" value="additional_ip"[^>]*required')
        self.assertIn(b"What kind of Location are you adding?", response.data)
        response = self.client.post(location, data={}, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Choose a Location connection type", response.data)
        with self.app.extensions["cayvpn_db"].session() as session:
            self.assertEqual(session.query(EgressProfile).count(), 1)

    def test_wizard_back_buttons_skip_forward_only_browser_validation(self):
        template = (Path(__file__).resolve().parents[1] / "templates" / "wizard.html").read_text()
        back_buttons = re.findall(r'<button[^>]+name="action" value="back"[^>]*>', template)
        self.assertGreater(len(back_buttons), 0)
        self.assertTrue(all("formnovalidate" in button for button in back_buttons))

    def test_live_wizards_disable_optional_components_that_are_not_installed(self):
        live_root = Path(self.temp.name) / "live-components"
        live_settings = replace(
            self.settings,
            state_dir=live_root / "state",
            config_dir=live_root / "config",
            db_path=live_root / "state" / "cayvpn.db",
            wg_dir=live_root / "wireguard",
            agent_socket=live_root / "agent.sock",
            apply_network=True,
        )
        with patch("cayvpn.web.component_binary", return_value=None):
            live_app = create_app(settings=live_settings)
            live_app.config["WTF_CSRF_ENABLED"] = False
            live_client = live_app.test_client()
            try:
                with live_client.session_transaction() as owner_session:
                    owner_session["authenticated"] = True
                    owner_session["auth_method"] = "test"
                    owner_session.permanent = True

                client_location = live_client.post("/setup/client/new").headers["Location"]
                client_page = live_client.get(client_location)
                self.assertRegex(client_page.text, r'name="ingress_protocol" value="amneziawg"[^>]*disabled')
                self.assertIn(b"Not installed on this CayVPN server", client_page.data)
                rejected_client = live_client.post(
                    client_location,
                    data={"name": "Unavailable stealth", "ingress_protocol": "amneziawg"},
                    follow_redirects=True,
                )
                self.assertIn(b"Amnezia is not installed", rejected_client.data)

                exit_location = live_client.post("/setup/exit/new").headers["Location"]
                exit_page = live_client.get(exit_location)
                self.assertRegex(exit_page.text, r'name="driver" value="socks5"[^>]*disabled')
                rejected_exit = live_client.post(exit_location, data={"driver": "socks5"}, follow_redirects=True)
                self.assertIn(b"SOCKS5 Locations are not installed", rejected_exit.data)
            finally:
                live_app.extensions["cayvpn_db"].engine.dispose()

    def test_floating_ip_form_is_guided_and_accepts_a_dotted_netmask(self):
        self.authenticate()
        with self.client.session_transaction() as owner_session:
            owner_session["passkey_verified_until"] = 2**31
        location = self.start_wizard("exit")
        step_two = self.client.post(location, data={"driver": "additional_ip"})
        self.assertEqual(step_two.status_code, 302)
        response = self.client.get(step_two.headers["Location"])
        self.assertIn(b"IPv4 prefix or netmask", response.data)
        self.assertIn(b"Attach the address", response.data)
        self.app.extensions["cayvpn_db"].set_setting("capacity_override_active", "1")
        response = self.client.post(
            "/egress",
            data={
                "name": "Miami floating IP",
                "driver": "additional_ip",
                "provider_recipe": "cloudzy",
                "address": "8.8.4.4",
                "prefix": "255.255.255.0",
                "gateway": "8.8.4.1",
                "interface": "eth0",
            },
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"was saved, but it is not ready yet", response.data)
        with self.app.extensions["cayvpn_db"].session() as session:
            profile = session.query(EgressProfile).filter_by(name="Miami floating IP").one()
            self.assertEqual(profile.config["prefix"], 24)
            self.assertEqual(profile.health_state, "pending")

    def test_additional_exit_must_not_reuse_the_direct_or_another_saved_address(self):
        self.authenticate()
        with self.client.session_transaction() as owner_session:
            owner_session["passkey_verified_until"] = 2**31
        with self.app.extensions["cayvpn_db"].session() as session:
            direct = session.query(EgressProfile).filter_by(driver="direct_ip").one()
            direct.config_json = json.dumps(
                {"address": "8.8.8.8", "ipv6_address": "2606:4700:4700::1111"}
            )

        first_step = self.start_wizard("exit")
        second_step = self.client.post(
            first_step, data={"driver": "additional_ip"}
        ).headers["Location"]
        duplicate_direct = self.client.post(
            second_step,
            data={
                "name": "Not another exit",
                "address": "8.8.8.8",
                "prefix": "32",
                "interface": "eth0",
            },
            follow_redirects=True,
        )
        self.assertEqual(duplicate_direct.status_code, 200)
        self.assertIn(b"already belongs to This server", duplicate_direct.data)
        self.assertIn(b'role="alert"', duplicate_direct.data)

        with self.app.extensions["cayvpn_db"].session() as session:
            session.add(
                EgressProfile(
                    name="Existing reserved IP",
                    driver="additional_ip",
                    config_json=json.dumps(
                        {"address": "8.8.4.4", "prefix": 32, "interface": "eth0"}
                    ),
                    capabilities_json="{}",
                    health_state="pending",
                    ipv6_health_state="unavailable",
                )
            )

        duplicate_saved = self.client.post(
            "/egress",
            data={
                "name": "Duplicate reserved IP",
                "driver": "additional_ip",
                "address": "8.8.4.4",
                "prefix": "32",
                "interface": "eth0",
            },
            follow_redirects=True,
        )
        self.assertIn(b"already saved as Existing reserved IP", duplicate_saved.data)
        with self.app.extensions["cayvpn_db"].session() as session:
            self.assertEqual(
                session.query(EgressProfile).filter_by(name="Duplicate reserved IP").count(),
                0,
            )

    def test_additional_exit_rechecks_address_uniqueness_at_final_save(self):
        self.authenticate()
        with self.client.session_transaction() as owner_session:
            owner_session["passkey_verified_until"] = 2**31
        first_step = self.start_wizard("exit")
        second_step = self.client.post(
            first_step, data={"driver": "additional_ip"}
        ).headers["Location"]
        third_step = self.client.post(
            second_step,
            data={
                "name": "Reserved address race",
                "address": "8.8.4.4",
                "prefix": "32",
                "interface": "eth0",
            },
        ).headers["Location"]
        fourth_step = self.client.post(third_step).headers["Location"]
        fifth_step = self.client.post(fourth_step).headers["Location"]
        draft_id = first_step.split("/")[3]

        with self.app.extensions["cayvpn_db"].session() as session:
            session.add(
                EgressProfile(
                    name="Saved while wizard was open",
                    driver="additional_ip",
                    config_json=json.dumps(
                        {"address": "8.8.4.4", "prefix": 32, "interface": "eth0"}
                    ),
                    capabilities_json="{}",
                    health_state="pending",
                    ipv6_health_state="unavailable",
                )
            )

        completed = self.client.post(
            f"/setup/exit/{draft_id}/complete", follow_redirects=True
        )
        self.assertIn(b"already saved as Saved while wizard was open", completed.data)
        self.assertIn(b"Step 2 of 5", completed.data)
        with self.app.extensions["cayvpn_db"].session() as session:
            self.assertEqual(
                session.query(EgressProfile).filter_by(name="Reserved address race").count(),
                0,
            )
            self.assertIsNotNone(session.get(WizardDraft, draft_id))

    def test_proxy_capabilities_and_exit_ips_are_saved_and_visible_immediately(self):
        self.authenticate()
        with self.client.session_transaction() as owner_session:
            owner_session["passkey_verified_until"] = 2**31
        self.app.extensions["cayvpn_db"].set_setting("capacity_override_active", "1")
        operations = self.app.extensions["cayvpn_operations"]
        original_executor = operations.agent.inline_executor
        upgraded_endpoints: set[str] = set()

        def executor(request):
            if request.action == "secret.store":
                return AgentResponse(request.operation_id, "succeeded", request.desired_generation, result={"secret_ref": f"ref::{request.operation_id}"})
            if request.action == "egress.activate":
                endpoint = str((request.payload.get("config") or {}).get("endpoint", ""))
                udp = "udp-proxy" in endpoint or endpoint in upgraded_endpoints
                return AgentResponse(
                    request.operation_id,
                    "succeeded",
                    request.desired_generation,
                    result={"verified": True, "tcp": True, "udp": udp, "dns": True, "ipv6": False, "observed_exit_ip": "8.8.8.8" if udp else "8.8.4.4"},
                )
            return original_executor(request)

        operations.agent.inline_executor = executor
        tcp_only = self.client.post(
            "/egress",
            data={"name": "TCP-only proxy", "driver": "socks5", "endpoint": "socks5://tcp-proxy.example:1080", "password": "secret"},
            follow_redirects=True,
        )
        self.assertEqual(tcp_only.status_code, 200)
        self.assertIn(b"TCP + DNS \xc2\xb7 UDP/QUIC blocked \xc2\xb7 IPv6 blocked safely", tcp_only.data)
        self.assertIn(b"8.8.4.4", tcp_only.data)

        udp_proxy = self.client.post(
            "/egress",
            data={"name": "UDP proxy", "driver": "socks5", "endpoint": "socks5://udp-proxy.example:1080", "password": "secret"},
            follow_redirects=True,
        )
        self.assertEqual(udp_proxy.status_code, 200)
        self.assertIn(b"TCP + DNS + UDP \xc2\xb7 IPv6 blocked safely", udp_proxy.data)
        self.assertIn(b"8.8.8.8", udp_proxy.data)

        with self.app.extensions["cayvpn_db"].session() as session:
            profiles = {profile.name: profile for profile in session.query(EgressProfile).all()}
            tcp_only_id = profiles["TCP-only proxy"].id
            self.assertEqual(profiles["TCP-only proxy"].capabilities["families"]["ipv4"], {"dns": True, "tcp": True, "udp": False})
            self.assertEqual(profiles["TCP-only proxy"].observed_exit_ip, "8.8.4.4")
            self.assertEqual(profiles["UDP proxy"].capabilities["families"]["ipv4"], {"dns": True, "tcp": True, "udp": True})
            self.assertEqual(profiles["UDP proxy"].observed_exit_ip, "8.8.8.8")

        overview = self.client.get("/")
        self.assertIn(b"TCP-only proxy", overview.data)
        self.assertIn(b"UDP/QUIC blocked", overview.data)
        add_client = self.client.get("/clients")
        self.assertIn(b"Step 1 of 3", add_client.data)
        self.assertIn(b"What are you connecting?", add_client.data)
        self.assertNotIn(b"Start guided setup", add_client.data)

        upgraded_endpoints.add("socks5://tcp-proxy.example:1080")
        with self.client.session_transaction() as owner_session:
            owner_session["passkey_verified_until"] = 2**31
        checked_again = self.client.post(f"/egress/{tcp_only_id}/activate", follow_redirects=True)
        self.assertEqual(checked_again.status_code, 200)
        self.assertIn(b"TCP + DNS + UDP \xc2\xb7 IPv6 blocked safely", checked_again.data)
        with self.app.extensions["cayvpn_db"].session() as session:
            upgraded = session.get(EgressProfile, tcp_only_id)
            self.assertTrue(upgraded.capabilities["udp"])
            self.assertEqual(upgraded.observed_exit_ip, "8.8.8.8")

    def test_provider_import_retains_and_displays_detected_protocol(self):
        self.authenticate()
        with self.client.session_transaction() as owner_session:
            owner_session["passkey_verified_until"] = 2**31
        self.app.extensions["cayvpn_db"].set_setting("capacity_override_active", "1")
        key = base64.b64encode(b"\0" * 32).decode()
        config = (
            "[Interface]\n"
            f"PrivateKey = {key}\n"
            "Address = 10.0.0.2/32\n"
            "Jc = 4\nJmin = 10\nJmax = 20\nS1 = 1\nS2 = 2\n"
            "H1 = 3\nH2 = 4\nH3 = 5\nH4 = 6\n\n"
            "[Peer]\n"
            f"PublicKey = {key}\n"
            "AllowedIPs = 0.0.0.0/0\n"
            "Endpoint = vpn.example:51820\n"
        )

        response = self.client.post(
            "/egress",
            data={"name": "Imported stealth exit", "driver": "provider_tunnel", "config_text": config},
            follow_redirects=True,
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"AmneziaWG provider tunnel", response.data)
        with self.app.extensions["cayvpn_db"].session() as session:
            profile = session.query(EgressProfile).filter_by(name="Imported stealth exit").one()
            self.assertEqual(profile.config["protocol"], "amneziawg")
            self.assertNotIn("config_text", profile.config)
            self.assertTrue(profile.config["private_key_present"])

    def test_amnezia_client_uses_the_amnezia_ingress_subnet(self):
        self.authenticate()
        response = self.client.post(
            "/clients",
            data={"name": "Amnezia phone", "ingress_protocol": "amneziawg", "dns_mode": "standard", "route_mode": "switchable"},
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        with self.app.extensions["cayvpn_db"].session() as session:
            client = session.query(Client).filter_by(name="Amnezia phone").one()
            self.assertEqual(client.address, "10.9.0.2")

    def test_onboarding_precedes_the_one_time_support_prompt(self):
        self.authenticate()
        database = self.app.extensions["cayvpn_db"]
        with database.session() as session:
            session.get(ManagedNode, 1).install_state = "verified"

        response = self.client.get("/")
        self.assertIn(b"Welcome to CayVPN", response.data)
        self.assertIn(b"Private access", response.data)
        self.assertIn(b"Password sign-in and extra security are optional", response.data)
        self.assertNotIn(b"A note from Caynetic", response.data)

        response = self.client.post("/onboarding/start", data={"next": "overview"}, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertNotIn(b"Welcome to CayVPN", response.data)
        self.assertNotIn(b"A note from Caynetic", response.data)

        response = self.client.post("/clients", data={"name": "First phone", "ingress_protocol": "wireguard", "dns_mode": "standard", "route_mode": "switchable"}, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        response = self.client.get("/")
        self.assertIn(b"A note from Caynetic", response.data)

        response = self.client.post("/support/dismiss", follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertNotIn(b"A note from Caynetic", response.data)

    def test_client_wizard_creates_dual_stack_config_and_tracks_owner_confirmation(self):
        self.authenticate()
        self.mark_direct_location_ready()
        self.make_route_switch_verified()
        entry = self.client.get("/add")
        self.assertIn(b"Step 1 of 3", entry.data)
        step_two = self.client.post(
            "/setup/client/new",
            data={"name": "Travel phone", "ingress_protocol": "wireguard"},
        ).headers["Location"]
        self.assertIn("/2", step_two)
        step_three = self.client.post(
            step_two,
            data={"dns_mode": "ad_blocking", "route_choice": "direct"},
        ).headers["Location"]
        review = self.client.get(step_three)
        self.assertIn(b"Review and create", review.data)
        self.assertIn(b"Blocked safely while the rest stays connected", review.data)
        self.assertNotIn(b"Smart IPv6", review.data)
        draft_id = step_two.split("/")[3]
        ready = self.client.post(f"/setup/client/{draft_id}/complete", follow_redirects=True)
        self.assertEqual(ready.status_code, 200)
        self.assertIn(b"Device ready", ready.data)
        self.assertIn(b"Setup is complete", ready.data)
        self.assertNotIn(b"Step 4 of", ready.data)
        self.assertNotIn(b"Step 5 of", ready.data)
        self.assertIn(b"confirm secure access before showing", ready.data)
        self.assertIn(b"Show QR code", ready.data)
        self.assertIn(b"Download configuration", ready.data)
        with self.app.extensions["cayvpn_db"].session() as session:
            created = session.query(Client).filter_by(name="Travel phone").one()
            self.assertTrue(created.ipv6_address.startswith("fd"))
            self.assertEqual(created.confirmed_config_version, 0)
            client_id = created.id
            ipv6_address = created.ipv6_address
        blocked_config = self.client.get(f"/clients/{client_id}/config")
        self.assertEqual(blocked_config.status_code, 302)
        self.assertEqual(blocked_config.headers["Location"], "/security")
        with self.client.session_transaction() as owner_session:
            owner_session["passkey_verified_until"] = 2**31
        approved_ready = self.client.get(f"/clients/{client_id}/ready")
        self.assertIn(b"Show QR code", approved_ready.data)
        self.assertIn(b"Download configuration", approved_ready.data)
        self.assertIn(b'download="Travel-phone.conf"', approved_ready.data)
        config = self.client.get(f"/clients/{client_id}/config")
        self.assertEqual(config.headers["Content-Disposition"], "attachment; filename=Travel-phone.conf")
        self.assertIn(f"{ipv6_address}/128".encode(), config.data)
        self.assertRegex(config.data, rb"DNS = 10\.254\.0\.54, fd[^,\n]+, cayvpn\.home\.arpa")
        self.assertIn(b"AllowedIPs = 0.0.0.0/0, ::/0", config.data)
        confirmed = self.client.post(f"/clients/{client_id}/config/confirm", data={"installed": "on", "config_version": "3"}, follow_redirects=True)
        self.assertIn(b"marked installed", confirmed.data)
        with self.app.extensions["cayvpn_db"].session() as session:
            self.assertEqual(session.get(Client, client_id).confirmed_config_version, 3)

    def test_add_device_opens_step_one_without_creating_an_empty_draft(self):
        self.authenticate()

        page = self.client.get("/add")

        self.assertEqual(page.status_code, 200)
        self.assertIn(b"Step 1 of 3", page.data)
        self.assertIn(b'action="/setup/client/new"', page.data)
        self.assertIn(b"data-device-step-one-history", page.data)
        self.assertNotIn(b"Start guided setup", page.data)
        self.assertNotIn(b"Saved setups", page.data)
        self.assertNotIn(b"Continue a saved device", page.data)
        with self.app.extensions["cayvpn_db"].session() as session:
            self.assertEqual(session.query(WizardDraft).filter_by(kind="client").count(), 0)

    def test_client_draft_starts_only_after_valid_step_one_and_gets_a_resume_banner(self):
        self.authenticate()

        invalid = self.client.post(
            "/setup/client/new",
            data={"name": "  ", "ingress_protocol": "wireguard"},
        )
        self.assertEqual(invalid.status_code, 400)
        self.assertIn(b"What are you connecting?", invalid.data)
        self.assertIn(b'role="alert"', invalid.data)
        with self.app.extensions["cayvpn_db"].session() as session:
            self.assertEqual(session.query(WizardDraft).filter_by(kind="client").count(), 0)

        started = self.client.post(
            "/setup/client/new",
            data={"name": "Kitchen tablet", "ingress_protocol": "wireguard"},
        )
        self.assertEqual(started.status_code, 302)
        self.assertTrue(started.headers["Location"].endswith("/2"))
        with self.app.extensions["cayvpn_db"].session() as session:
            draft = session.query(WizardDraft).filter_by(kind="client").one()
            self.assertEqual(draft.current_step, 2)
            self.assertEqual(draft.data["name"], "Kitchen tablet")

        resume = self.client.get("/add")
        self.assertIn(b"Continue a saved device", resume.data)
        self.assertIn(b"Kitchen tablet", resume.data)
        self.assertIn(b"Step 2 of 3", resume.data)
        self.assertNotIn(b"Saved setups", resume.data)

    def test_client_wizard_preserves_answers_across_back_navigation(self):
        self.authenticate()
        self.mark_direct_location_ready()
        step_two = self.client.post(
            "/setup/client/new",
            data={"name": "Back button phone", "ingress_protocol": "wireguard"},
        ).headers["Location"]
        step_one = step_two.rsplit("/", 1)[0] + "/1"

        previous = self.client.get(step_one)
        self.assertIn(b'value="Back button phone"', previous.data)
        self.assertRegex(previous.text, r'name="ingress_protocol" value="wireguard"[^>]*checked')

        step_three = self.client.post(
            step_two,
            data={"dns_mode": "standard", "route_choice": "direct"},
        ).headers["Location"]
        review = self.client.get(step_three)
        self.assertIn(b"Review and create", review.data)

        browser_back = self.client.get(step_two)
        self.assertRegex(browser_back.text, r'name="dns_mode" value="standard"[^>]*checked')
        self.assertRegex(browser_back.text, r'name="route_choice" value="direct"[^>]*checked')
        form_back = self.client.post(step_three, data={"action": "back"})
        self.assertEqual(form_back.status_code, 302)
        self.assertTrue(form_back.headers["Location"].endswith("/2"))

    def test_client_wizard_blocks_unready_locations_and_reports_a_waiting_device_truthfully(self):
        self.authenticate()
        with self.app.extensions["cayvpn_db"].session() as session:
            direct = session.query(EgressProfile).filter_by(driver="direct_ip").one()
            direct.health_state = "pending"
        step_two = self.client.post(
            "/setup/client/new",
            data={"name": "Waiting phone", "ingress_protocol": "wireguard"},
        ).headers["Location"]

        page = self.client.get(step_two)
        self.assertRegex(page.text, r'name="route_choice" value="direct"[^>]*disabled')
        self.assertIn(b"Still checking the internet connection", page.data)
        rejected = self.client.post(
            step_two,
            data={"dns_mode": "standard", "route_choice": "direct"},
            follow_redirects=True,
        )
        self.assertEqual(rejected.status_code, 200)
        self.assertIn(b"still checking its internet connection", rejected.data)
        self.assertIn(b'data-error-summary', rejected.data)

        self.mark_direct_location_ready()
        step_three = self.client.post(
            step_two,
            data={"dns_mode": "standard", "route_choice": "direct"},
        ).headers["Location"]
        with self.app.extensions["cayvpn_db"].session() as session:
            direct = session.query(EgressProfile).filter_by(driver="direct_ip").one()
            direct.health_state = "unhealthy"
        draft_id = step_three.split("/")[3]

        waiting = self.client.post(
            f"/setup/client/{draft_id}/complete",
            follow_redirects=True,
        )
        self.assertEqual(waiting.status_code, 200)
        self.assertIn(b"Device saved safely", waiting.data)
        self.assertIn(b"Connection waiting safely", waiting.data)
        self.assertNotIn(b"Setup is complete", waiting.data)

    def test_accessibility_links_errors_and_passkey_updates_are_announced(self):
        self.authenticate()
        overview = self.client.get("/")
        self.assertIn(b'class="skip-link" href="#main-content"', overview.data)
        self.assertIn(b'id="main-content" tabindex="-1"', overview.data)

        invalid = self.client.post(
            "/setup/client/new",
            data={"name": "", "ingress_protocol": "wireguard"},
        )
        self.assertIn(b'id="error-summary" data-error-summary role="alert" tabindex="-1"', invalid.data)
        self.assertIn(b'aria-invalid="true" aria-describedby="error-summary"', invalid.data)

        security = self.client.get("/security")
        self.assertIn(
            b'id="passkey-message" class="muted small" role="status" aria-live="polite" aria-atomic="true"',
            security.data,
        )

    def test_legacy_client_draft_urls_map_to_the_matching_three_step_page(self):
        self.authenticate()
        expiry = datetime.now(timezone.utc) + timedelta(hours=1)
        with self.app.extensions["cayvpn_db"].session() as session:
            complete = WizardDraft(
                kind="client",
                data_json=json.dumps(
                    {
                        "name": "Legacy complete",
                        "ingress_protocol": "wireguard",
                        "dns_mode": "standard",
                        "ipv6_policy": "auto",
                        "route_choice": "direct",
                        "profile_id": 1,
                    }
                ),
                current_step=5,
                expires_at=expiry,
            )
            partial = WizardDraft(
                kind="client",
                data_json=json.dumps(
                    {
                        "name": "Legacy partial",
                        "ingress_protocol": "wireguard",
                        "dns_mode": "standard",
                        "ipv6_policy": "auto",
                    }
                ),
                current_step=3,
                expires_at=expiry,
            )
            session.add_all([complete, partial])
            session.flush()
            complete_id, partial_id = complete.id, partial.id

        old_review = self.client.get(f"/setup/client/{complete_id}/5")
        self.assertEqual(old_review.status_code, 302)
        self.assertTrue(old_review.headers["Location"].endswith("/3"))
        old_location = self.client.get(f"/setup/client/{partial_id}/4")
        self.assertEqual(old_location.status_code, 302)
        self.assertTrue(old_location.headers["Location"].endswith("/2"))

    def test_automatic_ipv6_allows_ipv4_only_and_require_ipv6_needs_a_ready_location(self):
        self.authenticate()
        with self.app.extensions["cayvpn_db"].session() as session:
            ipv4_only = EgressProfile(
                name="IPv4 city",
                driver="additional_ip",
                config_json=json.dumps({"address": "8.8.4.4", "prefix": 32, "interface": "eth0"}),
                capabilities_json=json.dumps(
                    {
                        "schema": 2,
                        "ipv4": {"tcp": True, "udp": True, "dns": True},
                        "ipv6": {"tcp": False, "udp": False, "dns": False},
                    }
                ),
                health_state="healthy",
                ipv6_health_state="unavailable",
            )
            dual_stack = EgressProfile(
                name="Dual city",
                driver="provider_tunnel",
                config_json=json.dumps({"protocol": "wireguard"}),
                capabilities_json=json.dumps(
                    {
                        "schema": 2,
                        "ipv4": {"tcp": True, "udp": True, "dns": True},
                        "ipv6": {"tcp": True, "udp": False, "dns": True},
                    }
                ),
                health_state="healthy",
                ipv6_health_state="healthy",
            )
            session.add_all([ipv4_only, dual_stack])
            session.flush()
            ipv4_only_id, dual_stack_id = ipv4_only.id, dual_stack.id

        auto_step = self.client.post(
            "/setup/client/new",
            data={"name": "Automatic phone", "ingress_protocol": "wireguard"},
        ).headers["Location"]
        page = self.client.get(auto_step)
        self.assertIn(b"IPv6 is handled automatically", page.data)
        self.assertIn(b"IPv6 blocked safely", page.data)
        self.assertIn(b"IPv6 protected", page.data)
        self.assertIn(b"Advanced protection", page.data)
        self.assertIn(b"Create a backup group on the Locations page first.", page.data)

        rejected_post = self.client.post(
            auto_step,
            data={
                "dns_mode": "standard",
                "route_choice": "exit",
                "profile_id": str(ipv4_only_id),
                "require_ipv6": "on",
            },
        )
        self.assertEqual(rejected_post.status_code, 303)
        self.assertEqual(rejected_post.headers["Location"], auto_step)
        rejected = self.client.get(rejected_post.headers["Location"])
        self.assertEqual(rejected.status_code, 200)
        self.assertIn(b"Choose an IPv6-ready Location", rejected.data)
        self.assertRegex(rejected.text, r'<details class="technical-details advanced-settings" open>')
        self.assertRegex(rejected.text, r'name="require_ipv6"[^>]*checked')

        accepted_auto = self.client.post(
            auto_step,
            data={"dns_mode": "standard", "route_choice": "exit", "profile_id": str(ipv4_only_id)},
        )
        self.assertEqual(accepted_auto.status_code, 302)
        with self.app.extensions["cayvpn_db"].session() as session:
            automatic = session.query(WizardDraft).filter_by(kind="client").one()
            self.assertEqual(automatic.data["ipv6_policy"], "auto")

        required_step = self.client.post(
            "/setup/client/new",
            data={"name": "Required phone", "ingress_protocol": "wireguard"},
        ).headers["Location"]
        accepted_required = self.client.post(
            required_step,
            data={
                "dns_mode": "standard",
                "route_choice": "exit",
                "profile_id": str(dual_stack_id),
                "require_ipv6": "on",
            },
        )
        self.assertEqual(accepted_required.status_code, 302)
        with self.app.extensions["cayvpn_db"].session() as session:
            policies = {draft.data.get("name"): draft.data.get("ipv6_policy") for draft in session.query(WizardDraft).filter_by(kind="client").all()}
            self.assertEqual(policies["Required phone"], "required")

    def test_require_ipv6_accepts_only_groups_with_a_dual_stack_candidate(self):
        self.authenticate()
        capabilities_v4 = {
            "schema": 2,
            "ipv4": {"tcp": True, "udp": True, "dns": True},
            "ipv6": {"tcp": False, "udp": False, "dns": False},
        }
        capabilities_dual = {
            "schema": 2,
            "ipv4": {"tcp": True, "udp": True, "dns": True},
            "ipv6": {"tcp": True, "udp": False, "dns": True},
        }
        with self.app.extensions["cayvpn_db"].session() as session:
            v4 = EgressProfile(
                name="IPv4 backup",
                driver="additional_ip",
                config_json=json.dumps({"address": "8.8.4.4", "prefix": 32, "interface": "eth0"}),
                capabilities_json=json.dumps(capabilities_v4),
                health_state="healthy",
                ipv6_health_state="unavailable",
            )
            dual = EgressProfile(
                name="Dual backup",
                driver="provider_tunnel",
                config_json=json.dumps({"protocol": "wireguard"}),
                capabilities_json=json.dumps(capabilities_dual),
                health_state="healthy",
                ipv6_health_state="healthy",
            )
            session.add_all([v4, dual])
            session.flush()
            only_v4 = EgressPool(name="IPv4 group", profile_ids_json=json.dumps([v4.id]))
            mixed = EgressPool(name="Mixed group", profile_ids_json=json.dumps([v4.id, dual.id]))
            session.add_all([only_v4, mixed])
            session.flush()
            only_v4_id, mixed_id = only_v4.id, mixed.id

        rejected_step = self.client.post(
            "/setup/client/new",
            data={"name": "No IPv6 group", "ingress_protocol": "wireguard"},
        ).headers["Location"]
        rejected = self.client.post(
            rejected_step,
            data={
                "dns_mode": "standard",
                "route_choice": "pool",
                "pool_id": str(only_v4_id),
                "require_ipv6": "on",
            },
            follow_redirects=True,
        )
        self.assertEqual(rejected.status_code, 200)
        self.assertIn(b"no IPv6-ready Location", rejected.data)

        accepted_step = self.client.post(
            "/setup/client/new",
            data={"name": "Mixed IPv6 group", "ingress_protocol": "wireguard"},
        ).headers["Location"]
        accepted = self.client.post(
            accepted_step,
            data={
                "dns_mode": "standard",
                "route_choice": "pool",
                "pool_id": str(mixed_id),
                "require_ipv6": "on",
            },
        )
        self.assertEqual(accepted.status_code, 302)
        review = self.client.get(accepted.headers["Location"])
        self.assertIn(b"Mixed group \xc2\xb7 backup group", review.data)
        self.assertIn(b"<dt>IPv6 protection</dt><dd>Required</dd>", review.data)

    def test_owner_ui_uses_locations_while_egress_routes_and_api_stay_compatible(self):
        self.authenticate()
        self.client.post(
            "/clients",
            data={
                "name": "Location labels",
                "ingress_protocol": "wireguard",
                "dns_mode": "standard",
                "route_mode": "switchable",
            },
        )

        overview = self.client.get("/")
        locations = self.client.get("/egress")
        api = self.client.get("/api/v1/egress")

        self.assertEqual(overview.status_code, 200)
        self.assertIn(b">Locations</span>", overview.data)
        self.assertIn(b"<th>Location</th>", overview.data)
        self.assertIn(b"Your server", overview.data)
        self.assertIn(b"Private access", overview.data)
        self.assertNotIn(b"Owner tunnel connected", overview.data)
        self.assertNotIn(b"Secure access active", overview.data)
        self.assertNotIn(b">Exits</span>", overview.data)
        self.assertEqual(locations.status_code, 200)
        self.assertEqual(locations.data.count(b"Locations (exits)"), 1)
        self.assertIn(b"This server", locations.data)
        self.assertEqual(api.status_code, 200)
        self.assertIn(b'"observed_exit_ipv4"', api.data)

    def test_technical_details_has_inline_focus_target_and_twenty_pixel_spacing(self):
        stylesheet = (Path(__file__).resolve().parents[1] / "static" / "style.css").read_text()

        self.assertRegex(stylesheet, r"\.technical-details\s*>\s*summary\s*\{[^}]*width:\s*fit-content")
        self.assertRegex(stylesheet, r"\.technical-details\s*>\s*summary:focus-visible\s*\{[^}]*outline:[^}]*border-radius|\.technical-details\s*>\s*summary\s*\{[^}]*border-radius")
        self.assertIn("margin: 20px 0 0;", stylesheet)
        self.assertRegex(
            stylesheet,
            r"\.exit-row\s+\.technical-details\.table-details\s*\{[^}]*margin-top:\s*23px",
        )

    def test_flat_ui_uses_border_only_surfaces_and_shadow_free_buttons(self):
        stylesheet = (Path(__file__).resolve().parents[1] / "static" / "style.css").read_text()

        self.assertNotIn("box-shadow", stylesheet)
        self.assertRegex(
            stylesheet,
            r"\.button-primary\s*\{[^}]*background:\s*var\(--coral\)[^}]*border-color:\s*var\(--coral\)",
        )
        self.assertRegex(stylesheet, r"\.card,[^{]*\.metric,[^{]*\{[^}]*border:\s*1px solid var\(--line\)")

    def test_dashboard_keeps_protected_client_controls_visible(self):
        self.authenticate()
        created = self.client.post(
            "/clients",
            data={
                "name": "Protected laptop",
                "ingress_protocol": "wireguard",
                "dns_mode": "standard",
                "route_mode": "switchable",
            },
        )
        self.assertEqual(created.status_code, 302)

        dashboard = self.client.get("/")
        self.assertEqual(dashboard.status_code, 200)
        self.assertIn(b"CayVPN asks for owner confirmation before applying a Location change", dashboard.data)
        self.assertIn(b'class="client-table"', dashboard.data)
        self.assertIn(b'data-label="Actions"', dashboard.data)
        self.assertNotRegex(dashboard.text, r'data-route-profile[^>]*disabled')
        self.assertIn(b">Download</a>", dashboard.data)
        self.assertIn(b">QR</a>", dashboard.data)
        self.assertIn(b">Remove</button>", dashboard.data)

        blocked_download = self.client.get("/clients/1/config")
        self.assertEqual(blocked_download.status_code, 302)
        self.assertEqual(blocked_download.headers["Location"], "/security")

        with self.client.session_transaction() as owner_session:
            owner_session["passkey_verified_until"] = 2**31
        approved = self.client.get("/")
        self.assertEqual(approved.status_code, 200)
        self.assertIn(b">Download</a>", approved.data)
        self.assertIn(b">QR</a>", approved.data)
        self.assertIn(b">Remove</button>", approved.data)
        self.assertNotRegex(approved.text, r'data-route-profile[^>]*disabled')

    def test_client_wizard_does_not_duplicate_direct_exit_or_offer_empty_choices(self):
        self.authenticate()
        step_one = self.start_wizard("client")
        step_two = self.client.post(step_one, data={"name": "Simple phone", "ingress_protocol": "wireguard"}).headers["Location"]
        page = self.client.get(step_two)
        self.assertIn(b"Add another Location first", page.data)
        self.assertIn(b"Add another Location, then create a backup group on the Locations page.", page.data)
        self.assertRegex(page.text, r'name="route_choice" value="exit"[^>]*disabled')
        self.assertRegex(page.text, r'name="route_choice" value="pool"[^>]*disabled')
        self.assertIn(b'<select name="profile_id" disabled>', page.data)
        self.assertNotIn(b'<option value="1"', page.data)

        rejected = self.client.post(
            step_two,
            data={"dns_mode": "ad_blocking", "route_choice": "exit", "profile_id": "1"},
            follow_redirects=True,
        )
        self.assertIn(b"Choose an available location", rejected.data)

    def test_exit_wizard_keeps_imported_configuration_out_of_draft_and_html(self):
        self.authenticate()
        key = base64.b64encode(b"\x01" * 32).decode()
        provider_config = (
            "[Interface]\n"
            f"PrivateKey = {key}\n"
            "Address = 10.0.0.2/32, 2001:4860:4860::2/128\n\n"
            "[Peer]\n"
            f"PublicKey = {key}\n"
            "AllowedIPs = 0.0.0.0/0, ::/0\n"
            "Endpoint = vpn.example:51820\n"
        )
        step_one = self.start_wizard("exit")
        step_two = self.client.post(step_one, data={"driver": "provider_tunnel"}).headers["Location"]
        step_three = self.client.post(step_two, data={"name": "Dual provider", "config_text": provider_config}).headers["Location"]
        draft_id = step_one.split("/")[3]
        page = self.client.get(step_three)
        self.assertNotIn(provider_config.encode(), page.data)
        self.assertNotIn(key.encode(), page.data)
        with self.app.extensions["cayvpn_db"].session() as session:
            draft = session.get(WizardDraft, draft_id)
            self.assertNotIn(key, draft.data_json)
            self.assertNotIn("PrivateKey", draft.data_json)
            self.assertTrue(draft.secret_ref.startswith("ref::"))
        step_four = self.client.post(step_three).headers["Location"]
        findings = self.client.get(step_four)
        self.assertIn(b"What CayVPN found", findings.data)
        self.assertNotIn(key.encode(), findings.data)
        step_five = self.client.post(step_four).headers["Location"]
        review = self.client.get(step_five)
        self.assertIn(b"Configuration supplied", review.data)
        self.assertNotIn(key.encode(), review.data)
        self.assertNotIn(b"Approve before saving exit", review.data)
        self.assertIn(b">Save and check</button>", review.data)
        blocked = self.client.post(f"/setup/exit/{draft_id}/complete")
        self.assertEqual(blocked.status_code, 302)
        self.assertEqual(blocked.headers["Location"], "/security")
        with self.app.extensions["cayvpn_db"].session() as session:
            self.assertIsNotNone(session.get(WizardDraft, draft_id))
        with self.client.session_transaction() as owner_session:
            owner_session["passkey_verified_until"] = 2**31
        approved_review = self.client.get(step_five)
        self.assertIn(b">Save and check</button>", approved_review.data)
        saved = self.client.post(f"/setup/exit/{draft_id}/complete", follow_redirects=True)
        self.assertIn(b"traffic remains blocked", saved.data)
        with self.app.extensions["cayvpn_db"].session() as session:
            self.assertIsNone(session.get(WizardDraft, draft_id))
            profile = session.query(EgressProfile).filter_by(name="Dual provider").one()
            self.assertTrue(profile.secret_enc.startswith("ref::"))
            self.assertEqual(profile.config["protocol"], "wireguard")

    def test_cancelled_exit_wizard_deletes_temporary_secret(self):
        self.authenticate()
        step_one = self.start_wizard("exit")
        step_two = self.client.post(step_one, data={"driver": "socks5"}).headers["Location"]
        self.client.post(step_two, data={"name": "Temporary proxy", "endpoint": "socks5://proxy.example:1080", "password": "temporary-password"})
        draft_id = step_one.split("/")[3]
        with self.app.extensions["cayvpn_db"].session() as session:
            reference = session.get(WizardDraft, draft_id).secret_ref
        secret_store = self.app.extensions["cayvpn_operations"].agent.inline_executor.__self__.secrets
        self.assertEqual(secret_store.reveal(reference), "temporary-password")
        cancelled = self.client.post(f"/setup/exit/{draft_id}/cancel", follow_redirects=True)
        self.assertIn(b"temporary configuration was deleted", cancelled.data)
        with self.assertRaises(SecretStoreError):
            secret_store.reveal(reference)
        with self.app.extensions["cayvpn_db"].session() as session:
            self.assertIsNone(session.get(WizardDraft, draft_id))

    def test_expired_wizard_is_retained_when_temporary_secret_deletion_fails(self):
        self.authenticate()
        with self.app.extensions["cayvpn_db"].session() as session:
            draft = WizardDraft(
                kind="exit",
                data_json='{"secret_supplied": true}',
                secret_ref="ref::00000000-0000-0000-0000-000000000001",
                expires_at=datetime.now(timezone.utc) - timedelta(minutes=1),
            )
            session.add(draft)
            session.flush()
            draft_id = draft.id
        operations = self.app.extensions["cayvpn_operations"]
        original_executor = operations.agent.inline_executor

        def executor(request):
            if request.action == "secret.delete":
                return AgentResponse(request.operation_id, "failed", request.desired_generation, error_code="secret_store_unavailable", error_message="unavailable")
            return original_executor(request)

        operations.agent.inline_executor = executor
        response = self.client.get(f"/setup/exit/{draft_id}/1")
        self.assertEqual(response.status_code, 503)
        self.assertIn(b"could not be removed safely", response.data)
        self.assertNotIn(b"ref::", response.data)
        with self.app.extensions["cayvpn_db"].session() as session:
            self.assertIsNotNone(session.get(WizardDraft, draft_id))

    def test_operation_and_audit_apis_redact_opaque_secret_references(self):
        self.authenticate()
        reference = "ref::00000000-0000-0000-0000-000000000001"
        operations = self.app.extensions["cayvpn_operations"]
        original_executor = operations.agent.inline_executor

        def executor(request):
            if request.action == "system.snapshot":
                return AgentResponse(request.operation_id, "succeeded", request.desired_generation, result={"secret_ref": reference})
            return original_executor(request)

        operations.agent.inline_executor = executor
        operations.run("system.snapshot", {"secret_ref": reference}, actor="test")
        for endpoint in ("/api/v1/operations", "/api/v1/audit"):
            response = self.client.get(endpoint)
            self.assertEqual(response.status_code, 200)
            self.assertNotIn(reference.encode(), response.data)
            self.assertIn(b"[redacted]", response.data)

    def test_additional_exit_wizard_uses_a_valid_reserved_probe_id(self):
        self.authenticate()
        operations = self.app.extensions["cayvpn_operations"]
        original_executor = operations.agent.inline_executor
        observed_profile_ids = []

        def executor(request):
            if request.action == "egress.probe":
                observed_profile_ids.append(request.payload.get("profile_id"))
            return original_executor(request)

        operations.agent.inline_executor = executor
        step_one = self.start_wizard("exit")
        step_two = self.client.post(step_one, data={"driver": "additional_ip"}).headers["Location"]
        step_three = self.client.post(
            step_two,
            data={"name": "Reserved address", "address": "8.8.4.4", "prefix": "32", "interface": "eth0"},
        ).headers["Location"]
        self.client.post(step_three)
        self.assertEqual(observed_profile_ids, [999_999])

    def test_provider_wizard_uses_actual_temporary_runtime_capabilities(self):
        self.authenticate()
        key = base64.b64encode(b"\x02" * 32).decode()
        provider_config = (
            "[Interface]\n"
            f"PrivateKey = {key}\n"
            "Address = 10.0.0.2/32, 2001:4860:4860::2/128\n\n"
            "[Peer]\n"
            f"PublicKey = {key}\n"
            "AllowedIPs = 0.0.0.0/0, ::/0\n"
            "Endpoint = vpn.example:51820\n"
        )
        operations = self.app.extensions["cayvpn_operations"]
        original_executor = operations.agent.inline_executor
        runtime_requests = []

        def executor(request):
            if request.action == "egress.activate":
                runtime_requests.append(request)
                return AgentResponse(
                    request.operation_id,
                    "succeeded",
                    request.desired_generation,
                    result={
                        "state": "active",
                        "applied": True,
                        "verified": True,
                        "observed_exit_ipv4": "8.8.8.8",
                        "observed_exit_ipv6": None,
                        "families": {
                            "ipv4": {"tcp": True, "udp": True, "dns": True},
                            "ipv6": {"tcp": False, "udp": False, "dns": False},
                        },
                        "ipv6_health_state": "unhealthy",
                        "ipv6_reason": "provider_ipv6_check_failed",
                    },
                )
            if request.action == "egress.deactivate":
                runtime_requests.append(request)
                return AgentResponse(
                    request.operation_id,
                    "succeeded",
                    request.desired_generation,
                    result={"state": "inactive", "applied": True, "fail_closed": True},
                )
            return original_executor(request)

        operations.agent.inline_executor = executor
        step_one = self.start_wizard("exit")
        step_two = self.client.post(
            step_one, data={"driver": "provider_tunnel"}
        ).headers["Location"]
        step_three = self.client.post(
            step_two,
            data={"name": "Actually IPv4 only", "config_text": provider_config},
        ).headers["Location"]
        step_four = self.client.post(step_three)
        self.assertEqual(step_four.status_code, 302)
        self.assertTrue(step_four.headers["Location"].endswith("/4"))
        self.assertEqual(
            [request.action for request in runtime_requests],
            ["egress.activate", "egress.deactivate"],
        )
        self.assertEqual(runtime_requests[0].payload["profile_id"], 999_999)
        self.assertEqual(
            runtime_requests[1].payload,
            {"profile_id": 999_999, "remove_namespace": True},
        )
        draft_id = step_one.split("/")[3]
        with self.app.extensions["cayvpn_db"].session() as session:
            check = session.get(WizardDraft, draft_id).data["check"]
            self.assertTrue(check["capabilities"]["families"]["ipv4"]["tcp"])
            self.assertFalse(check["capabilities"]["ipv6"])
            self.assertIsNone(check["observed_exit_ipv6"])
            self.assertEqual(check["ipv6_reason"], "provider_ipv6_check_failed")

    def test_socks_wizard_fails_closed_when_temporary_cleanup_fails(self):
        self.authenticate()
        operations = self.app.extensions["cayvpn_operations"]
        original_executor = operations.agent.inline_executor
        runtime_requests = []
        capabilities = {
            "tcp": True,
            "udp": False,
            "dns": True,
            "ipv6": False,
            "families": {
                "ipv4": {"tcp": True, "udp": False, "dns": True},
                "ipv6": {"tcp": False, "udp": False, "dns": False},
            },
        }

        def executor(request):
            if request.action == "egress.activate":
                runtime_requests.append(request)
                return AgentResponse(
                    request.operation_id,
                    "succeeded",
                    request.desired_generation,
                    result={
                        "state": "active",
                        "applied": True,
                        "verified": True,
                        "families": capabilities["families"],
                    },
                )
            if request.action == "egress.deactivate":
                runtime_requests.append(request)
                return AgentResponse(
                    request.operation_id,
                    "failed",
                    request.desired_generation,
                    error_code="runtime_cleanup_failed",
                    error_message="fixture cleanup failure",
                )
            return original_executor(request)

        operations.agent.inline_executor = executor
        step_one = self.start_wizard("exit")
        step_two = self.client.post(
            step_one, data={"driver": "socks5"}
        ).headers["Location"]
        step_three = self.client.post(
            step_two,
            data={
                "name": "Cleanup test",
                "endpoint": "socks5://proxy.example:1080",
                "password": "temporary-password",
            },
        ).headers["Location"]
        with patch(
            "cayvpn.agent.probe_socks5_capabilities", return_value=capabilities
        ):
            failed = self.client.post(step_three, follow_redirects=True)
        self.assertIn(b"could not safely remove the temporary Location check", failed.data)
        self.assertEqual(
            [request.action for request in runtime_requests],
            ["egress.activate", "egress.deactivate"],
        )
        draft_id = step_one.split("/")[3]
        with self.app.extensions["cayvpn_db"].session() as session:
            draft = session.get(WizardDraft, draft_id)
            self.assertEqual(draft.current_step, 3)
            self.assertNotIn("check", draft.data)
            self.assertEqual(
                session.query(EgressProfile).filter_by(name="Cleanup test").count(),
                0,
            )

    def test_completed_socks_wizard_keeps_endpoint_and_transfers_secret_ownership(self):
        self.authenticate()
        step_one = self.start_wizard("exit")
        step_two = self.client.post(step_one, data={"driver": "socks5"}).headers["Location"]
        step_three = self.client.post(
            step_two,
            data={
                "name": "Travel proxy",
                "endpoint": "socks5://owner@proxy.example:1080",
                "password": "temporary-password",
            },
        ).headers["Location"]
        draft_id = step_one.split("/")[3]
        capabilities = {
            "tcp": True,
            "udp": False,
            "dns": True,
            "ipv6": False,
            "families": {
                "ipv4": {"tcp": True, "udp": False, "dns": True},
                "ipv6": {"tcp": False, "udp": False, "dns": False},
            },
        }
        with patch("cayvpn.agent.probe_socks5_capabilities", return_value=capabilities):
            step_four = self.client.post(step_three).headers["Location"]
        step_five = self.client.post(step_four).headers["Location"]
        review = self.client.get(step_five)
        self.assertIn(b"Configuration supplied", review.data)
        self.assertNotIn(b"temporary-password", review.data)
        with self.client.session_transaction() as owner_session:
            owner_session["passkey_verified_until"] = 2**31
        completed = self.client.post(f"/setup/exit/{draft_id}/complete", follow_redirects=True)
        self.assertIn(b"Travel proxy", completed.data)
        with self.app.extensions["cayvpn_db"].session() as session:
            self.assertIsNone(session.get(WizardDraft, draft_id))
            profile = session.query(EgressProfile).filter_by(name="Travel proxy").one()
            self.assertEqual(profile.config["endpoint"], "socks5://owner@proxy.example:1080")
            self.assertNotIn("temporary-password", profile.config_json)
            secret_reference = profile.secret_enc
        secret_store = self.app.extensions["cayvpn_operations"].agent.inline_executor.__self__.secrets
        self.assertEqual(secret_store.reveal(secret_reference), "temporary-password")

    def test_failover_pool_wizard_preserves_order_and_manual_failback(self):
        self.authenticate()
        with self.app.extensions["cayvpn_db"].session() as session:
            backup = EgressProfile(
                name="Backup exit",
                driver="additional_ip",
                config_json=json.dumps({"address": "8.8.4.4", "prefix": 32, "interface": "eth0"}),
                capabilities_json=json.dumps({"tcp": True, "udp": True, "dns": True, "ipv6": False}),
                health_state="healthy",
                ipv6_health_state="unavailable",
            )
            session.add(backup)
            session.flush()
            backup_id = backup.id
        step_one = self.start_wizard("pool")
        step_two = self.client.post(step_one, data={"name": "Safe order", "primary_id": "1"}).headers["Location"]
        step_three = self.client.post(step_two, data={"backup_1": str(backup_id)}).headers["Location"]
        step_four = self.client.post(step_three, data={"all_failed": "block"}).headers["Location"]
        review = self.client.get(step_four)
        self.assertIn(b"Returning to the first Location remains manual", review.data)
        self.assertNotIn(b"Approve before saving pool", review.data)
        self.assertIn(b">Save backup group</button>", review.data)
        draft_id = step_one.split("/")[3]
        blocked = self.client.post(f"/setup/pool/{draft_id}/complete")
        self.assertEqual(blocked.status_code, 302)
        self.assertEqual(blocked.headers["Location"], "/security")
        with self.client.session_transaction() as owner_session:
            owner_session["passkey_verified_until"] = 2**31
        approved_review = self.client.get(step_four)
        self.assertIn(b">Save backup group</button>", approved_review.data)
        saved = self.client.post(f"/setup/pool/{draft_id}/complete", follow_redirects=True)
        self.assertIn(b"Returning to the first Location remains manual", saved.data)
        with self.app.extensions["cayvpn_db"].session() as session:
            pool = session.query(EgressPool).filter_by(name="Safe order").one()
            self.assertEqual(json.loads(pool.profile_ids_json), [1, backup_id])
            self.assertEqual(pool.failback_policy, "manual")

    def test_failover_pool_wizard_keeps_unavailable_location_warnings_visible(self):
        self.authenticate()
        with self.app.extensions["cayvpn_db"].session() as session:
            unavailable = EgressProfile(
                name="Unavailable city",
                driver="provider_tunnel",
                config_json=json.dumps({"protocol": "wireguard"}),
                capabilities_json=json.dumps({"tcp": False, "udp": False, "dns": False, "ipv6": False}),
                health_state="unhealthy",
                ipv6_health_state="unavailable",
            )
            session.add(unavailable)
            session.flush()
            unavailable_id = unavailable.id

        step_one = self.start_wizard("pool")
        first_page = self.client.get(step_one)
        self.assertIn(b"Unavailable city \xc2\xb7 Needs attention \xc2\xb7 traffic stays blocked", first_page.data)

        step_two = self.client.post(
            step_one,
            data={"name": "Visible warning", "primary_id": str(unavailable_id)},
        ).headers["Location"]
        step_three = self.client.post(step_two, data={"backup_1": "1"}).headers["Location"]
        step_four = self.client.post(step_three, data={"all_failed": "block"}).headers["Location"]
        review = self.client.get(step_four)
        self.assertIn(b"Unavailable city</strong> \xc2\xb7 Needs attention \xc2\xb7 traffic stays blocked", review.data)

    def test_failover_pool_wizard_rejects_duplicate_backups_without_javascript(self):
        self.authenticate()
        with self.app.extensions["cayvpn_db"].session() as session:
            backup = EgressProfile(
                name="Only backup",
                driver="additional_ip",
                config_json=json.dumps({"address": "8.8.4.4", "prefix": 32, "interface": "eth0"}),
                capabilities_json=json.dumps({"tcp": True, "udp": True, "dns": True, "ipv6": False}),
                health_state="healthy",
                ipv6_health_state="unavailable",
            )
            session.add(backup)
            session.flush()
            backup_id = backup.id

        step_one = self.start_wizard("pool")
        step_two = self.client.post(step_one, data={"name": "No duplicates", "primary_id": "1"}).headers["Location"]
        page = self.client.get(step_two)
        self.assertEqual(page.data.count(b"data-pool-backup"), 4)
        duplicate = self.client.post(
            step_two,
            data={"backup_1": str(backup_id), "backup_2": str(backup_id)},
            follow_redirects=True,
        )
        self.assertEqual(duplicate.status_code, 200)
        self.assertIn(b"Each Location can appear only once", duplicate.data)
        self.assertIn(b'role="alert"', duplicate.data)
        self.assertIn(b"Step 2 of 4", duplicate.data)

    def test_failover_pool_wizard_requires_a_real_backup_exit(self):
        self.authenticate()
        page = self.client.get("/egress")
        self.assertIn(b"A backup group needs a first Location and at least one backup", page.data)
        self.assertRegex(page.text, r'<button class="button" type="button" disabled>Create group</button>')

        blocked = self.client.post("/setup/pool/new", follow_redirects=True)
        self.assertIn(b"Add at least one backup Location before creating a backup group", blocked.data)
        with self.app.extensions["cayvpn_db"].session() as session:
            self.assertEqual(session.query(WizardDraft).filter_by(kind="pool").count(), 0)

    def test_exit_management_controls_stay_visible_and_enforce_owner_confirmation(self):
        self.authenticate()
        with self.app.extensions["cayvpn_db"].session() as session:
            session.add(
                EgressProfile(
                    name="Managed backup",
                    driver="additional_ip",
                    config_json=json.dumps({"address": "8.8.4.4", "prefix": 32, "interface": "eth0"}),
                    capabilities_json=json.dumps({"tcp": True, "udp": True, "dns": True, "ipv6": False}),
                    health_state="healthy",
                    ipv6_health_state="unavailable",
                )
            )

        page = self.client.get("/egress")
        self.assertNotIn(b"Approve to manage", page.data)
        self.assertIn(b">Check again</button>", page.data)
        self.assertIn(b">Delete</button>", page.data)
        blocked = self.client.post("/egress/2/activate")
        self.assertEqual(blocked.status_code, 302)
        self.assertEqual(blocked.headers["Location"], "/security")

        with self.client.session_transaction() as owner_session:
            owner_session["passkey_verified_until"] = 2**31
        approved = self.client.get("/egress")
        self.assertIn(b">Check again</button>", approved.data)
        self.assertIn(b">Delete</button>", approved.data)

    def test_support_visit_is_post_only_and_external_next_is_rejected(self):
        self.authenticate()
        response = self.client.get("/support/visit")
        self.assertEqual(response.status_code, 405)
        response = self.client.post("/support/visit")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "https://www.buymeacoffee.com/caynetic")

        response = self.client.get("/login?next=https://example.com/")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/")

    def test_update_flow_is_guided_and_install_requires_recent_owner_approval(self):
        self.authenticate()
        operations = self.app.extensions["cayvpn_operations"]
        calls = []
        state = {
            "schema_version": 1,
            "state": "available",
            "release": {
                "version": "2.0.1",
                "title": "CayVPN 2.0.1",
                "notes": "Fixes reconnect handling <script>alert(1)</script>",
                "page_url": "https://github.com/caynetic/cayvpn/releases/tag/v2.0.1",
                "published_at": "2026-08-22T12:00:00+00:00",
                "immutable": True,
                "available": True,
            },
        }

        def executor(request):
            calls.append(request.action)
            if request.action == "update.status":
                return AgentResponse(request.operation_id, "succeeded", request.desired_generation, result=state.copy())
            if request.action == "update.check":
                return AgentResponse(request.operation_id, "succeeded", request.desired_generation, result=state.copy())
            if request.action == "update.stage":
                state.update(state="stage_queued", target_release="2.0.1")
                return AgentResponse(request.operation_id, "queued", request.desired_generation, result=state.copy())
            if request.action == "update.apply":
                state.update(state="install_queued", target_release="2.0.1")
                return AgentResponse(request.operation_id, "queued", request.desired_generation, result=state.copy())
            if request.action == "update.discard":
                state.clear()
                state.update(schema_version=1, state="discarded", current_release="2.0.0", target_release="2.0.1")
                return AgentResponse(request.operation_id, "succeeded", request.desired_generation, result=state.copy())
            raise AssertionError(request.action)

        operations.agent.inline_executor = executor
        page = self.client.get("/settings")
        self.assertIn(b"Download and verify", page.data)
        self.assertIn(b"Every download is verified before you can install it", page.data)
        self.assertIn(b"August 22, 2026", page.data)
        self.assertIn(b"&lt;script&gt;alert(1)&lt;/script&gt;", page.data)
        self.assertNotIn(b"<script>alert(1)</script>", page.data)

        stage = self.client.post("/updates/stage", data={"release": "2.0.1"}, follow_redirects=True)
        self.assertIn(b"downloading and being verified", stage.data)
        state.update(state="staged", target_release="2.0.1")
        staged_page = self.client.get("/settings")
        self.assertNotIn(b"Approve before installing", staged_page.data)
        self.assertIn(b"Install verified update", staged_page.data)
        self.assertIn(b"remove download", staged_page.data)

        before = calls.count("update.apply")
        blocked = self.client.post("/updates/install", data={"release": "2.0.1"}, follow_redirects=True)
        self.assertIn(b"Turn on secure access", blocked.data)
        self.assertEqual(calls.count("update.apply"), before)

        with self.client.session_transaction() as owner_session:
            owner_session["passkey_verified_until"] = 2**31
        approved_staged_page = self.client.get("/settings")
        self.assertIn(b"Install verified update", approved_staged_page.data)
        install = self.client.post("/updates/install", data={"release": "2.0.1"}, follow_redirects=True)
        self.assertIn(b"Installing CayVPN 2.0.1", install.data)
        self.assertEqual(calls.count("update.apply"), before + 1)

        state.update(state="staged", target_release="2.0.1")
        discard = self.client.post("/updates/discard", data={"release": "2.0.1"}, follow_redirects=True)
        self.assertIn(b"package was removed", discard.data)
        self.assertIn("update.discard", calls)

    def test_sensitive_settings_keep_controls_visible_and_enforce_confirmation(self):
        self.authenticate()

        settings_page = self.client.get("/settings")
        self.assertNotIn(b"Approve before creating a backup", settings_page.data)
        self.assertIn(b"Backup passphrase", settings_page.data)
        self.assertIn(b"A backup keeps everything CayVPN needs to restore this setup", settings_page.data)
        self.assertIn(b"This settings page is available only while your CayVPN settings connection is active", settings_page.data)
        self.assertNotIn(b"The root agent creates the archive", settings_page.data)
        self.assertIn(b"asks for owner confirmation before creating the backup", settings_page.data)
        blocked_backup = self.client.post(
            "/backups/create", data={"passphrase": "temporary-test-passphrase"}
        )
        self.assertEqual(blocked_backup.status_code, 302)
        self.assertEqual(blocked_backup.headers["Location"], "/security")

        capacity_page = self.client.get("/capacity")
        self.assertIn(b"asks for confirmation only if you raise or clear", capacity_page.data)
        self.assertRegex(capacity_page.text, r'<option value="override"\s*>')
        self.assertNotRegex(capacity_page.text, r'<input name="reason"[^>]*disabled')
        blocked_override = self.client.post(
            "/capacity", data={"action": "override", "reason": "test"}
        )
        self.assertEqual(blocked_override.status_code, 302)
        self.assertEqual(blocked_override.headers["Location"], "/security")

        with self.client.session_transaction() as owner_session:
            owner_session["passkey_verified_until"] = 2**31

        approved_settings = self.client.get("/settings")
        self.assertIn(b"Backup passphrase", approved_settings.data)
        self.assertNotIn(b"asks for owner confirmation before creating the backup", approved_settings.data)

        approved_capacity = self.client.get("/capacity")
        self.assertRegex(approved_capacity.text, r'<option value="override"\s*>')
        self.assertIn(b"current secure access", approved_capacity.data)


if __name__ == "__main__":
    unittest.main()
