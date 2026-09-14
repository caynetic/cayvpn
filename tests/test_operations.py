import json
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path

from cayvpn.config import Settings
from cayvpn.db import Database
from cayvpn.models import Client, EgressPool, EgressProfile, ManagedNode, Operation, RouteBinding
from cayvpn.operations import OperationService, _redact
from cayvpn.protocol import AgentResponse


class CapturingAgent:
    def __init__(self):
        self.request = None

    def execute(self, request):
        self.request = request
        return AgentResponse(
            request.operation_id,
            "succeeded",
            observed_generation=request.desired_generation,
            result={"verified": True},
        )


class StatusInspectingAgent:
    def __init__(self, database):
        self.database = database
        self.persisted_status = None

    def execute(self, request):
        with self.database.session() as session:
            self.persisted_status = session.get(Operation, request.operation_id).status
        return AgentResponse(
            request.operation_id,
            "succeeded",
            observed_generation=request.desired_generation,
            result={"verified": True},
        )


class FastBackgroundAgent:
    def __init__(self, database):
        self.database = database

    def execute(self, request):
        with self.database.session() as session:
            operation = session.get(Operation, request.operation_id)
            operation.status = "succeeded"
            operation.observed_generation = request.desired_generation
            operation.result_json = json.dumps({"verified": True, "release": "2.0.1"})
        return AgentResponse(
            request.operation_id,
            "queued",
            observed_generation=request.desired_generation,
            result={"unit": "cayvpn-update-stage-fixture"},
        )


class OperationTests(unittest.TestCase):
    def test_desired_generations_are_unique_under_concurrent_requests(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            settings = replace(
                Settings.from_env(root),
                state_dir=root / "state",
                config_dir=root / "config",
                db_path=root / "state" / "cayvpn.db",
                wg_dir=root / "wireguard",
            )
            database = Database(settings)
            database.initialize_defaults(settings)
            service = OperationService(database, CapturingAgent())

            with ThreadPoolExecutor(max_workers=12) as pool:
                generations = list(pool.map(lambda _item: service._generation(), range(40)))

            self.assertEqual(len(set(generations)), 40)
            self.assertEqual(sorted(generations), list(range(1, 41)))
            with database.session() as session:
                self.assertEqual(session.get(ManagedNode, 1).desired_generation, 40)
            database.engine.dispose()
    def test_secret_references_are_redacted_from_persisted_operation_data(self):
        value = _redact(
            {
                "secret_ref": "ref::00000000-0000-0000-0000-000000000001",
                "code": "123456",
                "provisioning_uri": "otpauth://totp/CayVPN?secret=NEVERLOGTHIS",
                "nested": {"private_key_ref": "ref::00000000-0000-0000-0000-000000000002"},
            }
        )

        self.assertEqual(value["secret_ref"], "[redacted]")
        self.assertEqual(value["code"], "[redacted]")
        self.assertEqual(value["provisioning_uri"], "[redacted]")
        self.assertEqual(value["nested"]["private_key_ref"], "[redacted]")

    def test_fast_background_completion_is_not_overwritten_by_queued_acknowledgement(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            settings = replace(
                Settings.from_env(root),
                state_dir=root / "state",
                config_dir=root / "config",
                db_path=root / "state" / "cayvpn.db",
                wg_dir=root / "wireguard",
            )
            database = Database(settings)
            database.initialize_defaults(settings)

            operation, response = OperationService(database, FastBackgroundAgent(database)).run("update.stage", {"release": "2.0.1"})

            self.assertEqual(response.status, "queued")
            self.assertEqual(operation.status, "succeeded")
            self.assertEqual(json.loads(operation.result_json)["release"], "2.0.1")
            database.engine.dispose()

    def test_operation_is_running_until_the_agent_returns(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            settings = replace(
                Settings.from_env(root),
                state_dir=root / "state",
                config_dir=root / "config",
                db_path=root / "state" / "cayvpn.db",
                wg_dir=root / "wireguard",
            )
            database = Database(settings)
            database.initialize_defaults(settings)
            agent = StatusInspectingAgent(database)

            operation, response = OperationService(database, agent).run("system.snapshot", {})

            self.assertEqual(agent.persisted_status, "running")
            self.assertEqual(response.status, "succeeded")
            self.assertEqual(operation.status, "succeeded")
            database.engine.dispose()

    def test_provider_route_switch_nests_the_target_secret_reference(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            settings = replace(
                Settings.from_env(root),
                state_dir=root / "state",
                config_dir=root / "config",
                db_path=root / "state" / "cayvpn.db",
                wg_dir=root / "wireguard",
            )
            database = Database(settings)
            database.initialize_defaults(settings)
            with database.session() as session:
                session.add(
                    Client(
                        id=1,
                        name="Switchable client",
                        public_key="client-public-key",
                        address="10.8.0.2",
                        ingress_protocol="wireguard",
                        dns_mode="standard",
                        route_mode="switchable",
                    )
                )
                session.add(
                    EgressProfile(
                        id=7,
                        name="Provider tunnel",
                        driver="provider_tunnel",
                        config_json=json.dumps({"protocol_hint": "auto", "full_tunnel_required": True}),
                        secret_enc="ref::provider-secret",
                        capabilities_json=json.dumps({"tcp": True}),
                        health_state="healthy",
                    )
                )

            agent = CapturingAgent()
            operation, response = OperationService(database, agent).route_switch(1, profile_id=7)

            self.assertEqual(response.status, "succeeded")
            self.assertEqual(operation.status, "succeeded")
            self.assertEqual(agent.request.payload["target_profile"]["secret_ref"], "ref::provider-secret")
            self.assertNotIn("secret_ref", agent.request.payload)
            with database.session() as session:
                binding = session.query(RouteBinding).filter_by(client_id=1).one()
                self.assertEqual(binding.egress_profile_id, 7)
                self.assertEqual(binding.state, "active")
            database.engine.dispose()

    def test_required_ipv6_skips_ipv4_only_primary_in_a_mixed_failover_group(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            settings = replace(
                Settings.from_env(root),
                state_dir=root / "state",
                config_dir=root / "config",
                db_path=root / "state" / "cayvpn.db",
                wg_dir=root / "wireguard",
            )
            database = Database(settings)
            database.initialize_defaults(settings)
            with database.session() as session:
                session.add(
                    Client(
                        id=1,
                        name="IPv6 required device",
                        public_key="required-client-key",
                        address="10.8.0.2",
                        ipv6_address="fd12:3456:789a:1::2",
                        ipv6_policy="required",
                        ingress_protocol="wireguard",
                        dns_mode="standard",
                        route_mode="switchable",
                    )
                )
                session.add_all(
                    [
                        EgressProfile(
                            id=2,
                            name="IPv4 primary",
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
                        ),
                        EgressProfile(
                            id=3,
                            name="Dual-stack backup",
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
                        ),
                    ]
                )
                session.add(EgressPool(id=1, name="Mixed", profile_ids_json=json.dumps([2, 3])))

            agent = CapturingAgent()
            operation, response = OperationService(database, agent).route_switch(1, pool_id=1)

            self.assertEqual(response.status, "succeeded")
            self.assertEqual(operation.status, "succeeded")
            self.assertEqual(agent.request.payload["target_profile_id"], 3)
            self.assertEqual(agent.request.payload["target_pool_id"], 1)
            with database.session() as session:
                binding = session.query(RouteBinding).filter_by(client_id=1).one()
                self.assertEqual(binding.egress_profile_id, 3)
                self.assertEqual(binding.pool_id, 1)
                self.assertEqual(binding.state, "active")
            database.engine.dispose()


if __name__ == "__main__":
    unittest.main()
