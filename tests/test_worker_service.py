import json
import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from cayvpn.capacity import SystemResources
from cayvpn.config import Settings
from cayvpn.db import Database
from cayvpn.models import AuditEvent, Client, EgressProfile, ManagedNode, Operation, RouteBinding, WizardDraft
from cayvpn.protocol import AgentResponse
from cayvpn.worker_service import HEALTH_PROBE_INTERVAL_SECONDS, MAINTENANCE_REFRESH_INTERVAL_SECONDS, PENDING_ROUTE_GRACE_SECONDS, _close_and_audit_stale_operations, _pending_routes, cleanup_expired_wizard_drafts, close_stale_operations, probe_egresses, reconcile_agent_state, reconcile_runtime, record_reconciliation_completion, refresh


class ReconcileAgent:
    def __init__(self):
        self.requests = []

    def execute(self, request):
        self.requests.append(request)
        client_ids = [int(item["client_id"]) for item in request.payload["routes"]]
        return AgentResponse(
            request.operation_id,
            "succeeded",
            observed_generation=request.desired_generation,
            result={"applied_clients": client_ids, "blocked_clients": [], "verified": True},
        )


class ResponseAgent:
    def __init__(self, responses):
        self.responses = list(responses)
        self.requests = []

    def execute(self, request):
        self.requests.append(request)
        response = self.responses.pop(0)
        return AgentResponse(
            request.operation_id,
            response.get("status", "succeeded"),
            observed_generation=request.desired_generation,
            result=response.get("result", {}),
            error_code=response.get("error_code"),
            error_message=response.get("error_message"),
        )


class WorkerServiceTests(unittest.TestCase):
    @staticmethod
    def settings_for(root: Path) -> Settings:
        return replace(
            Settings.from_env(root),
            state_dir=root / "state",
            config_dir=root / "config",
            db_path=root / "state" / "cayvpn.db",
            wg_dir=root / "wireguard",
            agent_socket=root / "agent.sock",
        )

    def test_ipv4_and_ipv6_health_thresholds_are_independent(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            settings = self.settings_for(root)
            database = Database(settings)
            database.initialize_defaults(settings)
            with database.session() as session:
                profile = session.query(EgressProfile).filter_by(driver="direct_ip").one()
                profile.health_state = "healthy"
                profile.ipv6_health_state = "healthy"
                profile.capabilities_json = json.dumps({"schema": 2, "ipv4": {"tcp": True, "udp": True, "dns": True}, "ipv6": {"tcp": True, "udp": True, "dns": True}})
                profile.observed_exit_ip = "8.8.8.8"
                profile.observed_exit_ipv6 = "2001:4860:4860::8888"

            ipv6_failure = {
                "result": {
                    "health_state": "healthy",
                    "ipv6_health_state": "unhealthy",
                    "verified": True,
                    "observed_exit_ipv4": "8.8.8.8",
                    "observed_exit_ipv6": None,
                    "families": {
                        "ipv4": {"tcp": True, "udp": True, "dns": True},
                        "ipv6": {"tcp": False, "udp": False, "dns": False},
                    },
                    "ipv6_reason": "test_ipv6_failure",
                }
            }
            recovery = {
                "result": {
                    "health_state": "healthy",
                    "ipv6_health_state": "healthy",
                    "verified": True,
                    "observed_exit_ipv4": "8.8.8.8",
                    "observed_exit_ipv6": "2001:4860:4860::8888",
                    "families": {
                        "ipv4": {"tcp": True, "udp": True, "dns": True},
                        "ipv6": {"tcp": True, "udp": True, "dns": True},
                    },
                }
            }
            agent = ResponseAgent([ipv6_failure, ipv6_failure, ipv6_failure, recovery, recovery])
            with patch("cayvpn.worker_service.AgentClient", return_value=agent):
                for _ in range(3):
                    probe_egresses(settings, database)
                with database.session() as session:
                    profile = session.query(EgressProfile).filter_by(driver="direct_ip").one()
                    self.assertEqual(profile.health_state, "healthy")
                    self.assertEqual(profile.ipv6_health_state, "unhealthy")
                    self.assertEqual(profile.ipv6_consecutive_failures, 3)
                    self.assertTrue(profile.capabilities["tcp"])
                    self.assertFalse(profile.capabilities["ipv6"])
                for _ in range(2):
                    probe_egresses(settings, database)
            with database.session() as session:
                profile = session.query(EgressProfile).filter_by(driver="direct_ip").one()
                self.assertEqual(profile.health_state, "healthy")
                self.assertEqual(profile.ipv6_health_state, "healthy")
                self.assertEqual(profile.ipv6_consecutive_successes, 2)
                self.assertTrue(profile.capabilities["ipv6"])
            database.engine.dispose()

    def test_health_checks_run_often_enough_for_prompt_failover(self):
        self.assertEqual(HEALTH_PROBE_INTERVAL_SECONDS, 30)
        self.assertLessEqual(HEALTH_PROBE_INTERVAL_SECONDS * 3, 90)
        self.assertGreater(MAINTENANCE_REFRESH_INTERVAL_SECONDS, HEALTH_PROBE_INTERVAL_SECONDS)

    def test_missing_provider_runtime_is_reactivated_before_health_is_recorded(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            settings = self.settings_for(root)
            database = Database(settings)
            database.initialize_defaults(settings)
            with database.session() as session:
                session.query(EgressProfile).filter_by(driver="direct_ip").one().enabled = False
                session.add(
                    EgressProfile(
                        name="Recover after restart",
                        driver="provider_tunnel",
                        config_json=json.dumps({"protocol": "wireguard"}),
                        secret_enc="ref::00000000-0000-0000-0000-000000000001",
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
                )
            missing = {
                "result": {
                    "health_state": "unhealthy",
                    "verified": False,
                    "reason": "provider_namespace_missing",
                    "families": {
                        "ipv4": {"tcp": False, "udp": False, "dns": False},
                        "ipv6": {"tcp": False, "udp": False, "dns": False},
                    },
                }
            }
            recovered = {
                "result": {
                    "state": "active",
                    "applied": True,
                    "verified": True,
                    "observed_exit_ipv4": "8.8.8.8",
                    "families": {
                        "ipv4": {"tcp": True, "udp": True, "dns": True},
                        "ipv6": {"tcp": False, "udp": False, "dns": False},
                    },
                    "ipv6_health_state": "unavailable",
                    "ipv6_reason": "provider_ipv6_not_configured",
                }
            }
            agent = ResponseAgent([missing, recovered])
            with patch("cayvpn.worker_service.AgentClient", return_value=agent):
                probe_egresses(settings, database)

            self.assertEqual(
                [request.action for request in agent.requests],
                ["egress.probe", "egress.activate"],
            )
            self.assertEqual(
                agent.requests[1].payload["secret_ref"],
                "ref::00000000-0000-0000-0000-000000000001",
            )
            with database.session() as session:
                profile = session.query(EgressProfile).filter_by(
                    name="Recover after restart"
                ).one()
                self.assertEqual(profile.health_state, "healthy")
                self.assertEqual(profile.consecutive_failures, 0)
                self.assertEqual(profile.consecutive_successes, 1)
                self.assertEqual(profile.observed_exit_ip, "8.8.8.8")
            database.engine.dispose()

    def test_failed_runtime_recovery_remains_fail_closed_and_counts_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            settings = self.settings_for(root)
            database = Database(settings)
            database.initialize_defaults(settings)
            with database.session() as session:
                session.query(EgressProfile).filter_by(driver="direct_ip").one().enabled = False
                session.add(
                    EgressProfile(
                        name="Still unavailable",
                        driver="provider_tunnel",
                        config_json=json.dumps({"protocol": "wireguard"}),
                        secret_enc="ref::00000000-0000-0000-0000-000000000001",
                        capabilities_json="{}",
                        health_state="healthy",
                        consecutive_failures=2,
                        ipv6_health_state="unavailable",
                    )
                )
            missing = {
                "result": {
                    "health_state": "unhealthy",
                    "verified": False,
                    "reason": "provider_namespace_missing",
                    "families": {
                        "ipv4": {"tcp": False, "udp": False, "dns": False},
                        "ipv6": {"tcp": False, "udp": False, "dns": False},
                    },
                }
            }
            failed = {
                "status": "failed",
                "error_code": "provider_connectivity_probe_failed",
                "error_message": "fixture provider stayed unavailable",
            }
            agent = ResponseAgent([missing, failed])
            with patch("cayvpn.worker_service.AgentClient", return_value=agent):
                probe_egresses(settings, database)

            self.assertEqual(
                [request.action for request in agent.requests],
                ["egress.probe", "egress.activate"],
            )
            with database.session() as session:
                profile = session.query(EgressProfile).filter_by(
                    name="Still unavailable"
                ).one()
                self.assertEqual(profile.health_state, "unhealthy")
                self.assertEqual(profile.consecutive_failures, 3)
                self.assertEqual(
                    profile.last_failure_reason,
                    "provider_connectivity_probe_failed",
                )
                self.assertIsNone(profile.observed_exit_ip)
            database.engine.dispose()

    def test_expired_wizard_secret_is_deleted_before_its_draft(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            settings = self.settings_for(root)
            database = Database(settings)
            database.initialize_defaults(settings)
            expired_at = datetime.now(timezone.utc) - timedelta(minutes=1)
            with database.session() as session:
                session.add(WizardDraft(id="expired", kind="exit", data_json='{"secret_supplied": true}', secret_ref="ref::00000000-0000-0000-0000-000000000001", expires_at=expired_at))

            failed_agent = ResponseAgent([{"status": "failed", "error_code": "secret_delete_failed", "error_message": "retry"}])
            with patch("cayvpn.worker_service.AgentClient", return_value=failed_agent):
                self.assertEqual(cleanup_expired_wizard_drafts(settings, database), 0)
            with database.session() as session:
                self.assertIsNotNone(session.get(WizardDraft, "expired"))

            successful_agent = ResponseAgent([{"status": "succeeded", "result": {"deleted": True}}])
            with patch("cayvpn.worker_service.AgentClient", return_value=successful_agent):
                self.assertEqual(cleanup_expired_wizard_drafts(settings, database), 1)
            self.assertEqual(successful_agent.requests[0].action, "secret.delete")
            with database.session() as session:
                self.assertIsNone(session.get(WizardDraft, "expired"))
            database.engine.dispose()

    def test_successful_startup_reconciliation_completes_the_update_handshake(self):
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
            database.set_setting("runtime_reconciliation_request", "update-fixture")

            self.assertTrue(record_reconciliation_completion(settings, database))

            self.assertEqual(database.get_setting("runtime_reconciliation_completed"), "update-fixture")
            database.engine.dispose()

    def test_outer_success_does_not_complete_a_failed_runtime_reconciliation(self):
        with tempfile.TemporaryDirectory() as directory:
            settings = self.settings_for(Path(directory))
            database = Database(settings)
            database.initialize_defaults(settings)
            succeeded = AgentResponse(
                "peers",
                "succeeded",
                observed_generation=1,
                result={"verified": True},
            )
            runtime = AgentResponse(
                "runtime",
                "succeeded",
                observed_generation=2,
                result={"verified": False, "failed_clients": [1]},
            )
            with patch(
                "cayvpn.worker_service.OperationService.reconcile_clients",
                return_value=(None, succeeded),
            ), patch(
                "cayvpn.worker_service.reconcile_runtime",
                return_value=(None, runtime),
            ):
                self.assertFalse(reconcile_agent_state(settings, database))
            database.engine.dispose()

    def test_capacity_refresh_updates_the_managed_node_architecture(self):
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
            resources = SystemResources(architecture="test-architecture", vcpus=2, memory_mb=4096, disk_free_mb=1000)

            with patch("cayvpn.worker_service.detect_resources", return_value=resources):
                refresh(settings, database)

            with database.session() as session:
                self.assertEqual(session.get(ManagedNode, 1).architecture, "test-architecture")
            database.engine.dispose()

    def test_stale_operation_cleanup_records_a_redacted_audit_summary(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            settings = replace(
                Settings.from_env(root),
                state_dir=root / "state",
                config_dir=root / "config",
                db_path=root / "state" / "cayvpn.db",
                wg_dir=root / "wireguard",
                agent_socket=root / "agent.sock",
            )
            database = Database(settings)
            database.initialize_defaults(settings)
            old = datetime.now(timezone.utc) - timedelta(minutes=10)
            with database.session() as session:
                session.get(ManagedNode, 1).observed_generation = 10
                session.add(Operation(id="abandoned", action="egress.probe", status="queued", desired_generation=5, request_json="{}", result_json="{}", created_at=old))

            _close_and_audit_stale_operations(settings, database)

            with database.session() as session:
                self.assertEqual(session.get(Operation, "abandoned").status, "failed")
                event = session.query(AuditEvent).filter_by(action="operation.stale_closed").one()
                self.assertEqual(json.loads(event.details_json), {"closed": {"queued:egress.probe": 1}})
            database.engine.dispose()

    def test_stale_operations_close_only_after_a_verified_later_generation(self):
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
            now = datetime.now(timezone.utc)
            old = now - timedelta(minutes=10)
            with database.session() as session:
                node = session.get(ManagedNode, 1)
                node.observed_generation = 20
                session.add(RouteBinding(client_id=1, egress_profile_id=1, state="pending", desired_generation=8, updated_at=old))
                session.add(Operation(id="old-queued", action="egress.probe", status="queued", desired_generation=5, request_json="{}", result_json="{}", created_at=old))
                session.add(Operation(id="old-running", action="runtime.reconcile", status="running", desired_generation=6, request_json="{}", result_json="{}", created_at=old))
                session.add(Operation(id="pending-route", action="route.switch", status="queued", desired_generation=8, request_json="{}", result_json="{}", created_at=old))
                session.add(Operation(id="not-observed", action="egress.probe", status="queued", desired_generation=21, request_json="{}", result_json="{}", created_at=old))
                session.add(Operation(id="still-running", action="egress.probe", status="running", desired_generation=7, request_json="{}", result_json="{}", created_at=now))

            closed = close_stale_operations(database, now=now)

            self.assertEqual(closed, {"queued:egress.probe": 1, "running:runtime.reconcile": 1})
            with database.session() as session:
                for operation_id in ("old-queued", "old-running"):
                    operation = session.get(Operation, operation_id)
                    self.assertEqual(operation.status, "failed")
                    self.assertEqual(operation.error_code, "operation_superseded")
                    self.assertIsNotNone(operation.completed_at)
                self.assertEqual(session.get(Operation, "pending-route").status, "queued")
                self.assertEqual(session.get(Operation, "not-observed").status, "queued")
                self.assertEqual(session.get(Operation, "still-running").status, "running")
                self.assertEqual(session.query(AuditEvent).count(), 0)
            database.engine.dispose()

    def test_in_flight_route_is_not_reconciled_until_queued_or_stale(self):
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
            now = datetime.now(timezone.utc)
            with database.session() as session:
                session.add(RouteBinding(client_id=1, egress_profile_id=1, state="pending", desired_generation=7, updated_at=now))
                session.add(Operation(id="in-flight-route", action="route.switch", status="running", desired_generation=7, request_json="{}", result_json="{}", created_at=now))

            self.assertFalse(_pending_routes(database, now=now))

            with database.session() as session:
                session.get(Operation, "in-flight-route").status = "queued"
            self.assertTrue(_pending_routes(database, now=now))

            with database.session() as session:
                operation = session.get(Operation, "in-flight-route")
                operation.status = "running"
                binding = session.query(RouteBinding).filter_by(client_id=1).one()
                binding.updated_at = now - timedelta(seconds=PENDING_ROUTE_GRACE_SECONDS + 1)
            self.assertTrue(_pending_routes(database, now=now))
            database.engine.dispose()

    def test_pending_route_is_reconciled_and_lost_response_is_closed(self):
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
                session.add(Client(id=1, name="Pending", public_key="pending-key", address="10.8.0.2", ingress_protocol="wireguard", dns_mode="standard", route_mode="switchable"))
                session.add(Client(id=2, name="Active", public_key="active-key", address="10.8.0.3", ingress_protocol="wireguard", dns_mode="standard", route_mode="switchable"))
                session.add(RouteBinding(client_id=1, egress_profile_id=1, state="pending", desired_generation=7))
                session.add(RouteBinding(client_id=2, egress_profile_id=1, state="active", desired_generation=6, observed_generation=6))
                session.add(Operation(id="lost-route", action="route.switch", status="queued", desired_generation=7, request_json="{}", result_json="{}"))

            agent = ReconcileAgent()
            reconciliation, response = reconcile_runtime(settings, database, pending_only=True, agent=agent)

            self.assertEqual(response.status, "succeeded")
            self.assertEqual(len(agent.requests), 1)
            self.assertEqual([item["client_id"] for item in agent.requests[0].payload["routes"]], [1])
            with database.session() as session:
                pending = session.query(RouteBinding).filter_by(client_id=1).one()
                active = session.query(RouteBinding).filter_by(client_id=2).one()
                lost = session.get(Operation, "lost-route")
                self.assertEqual(pending.state, "active")
                self.assertEqual(active.desired_generation, 6)
                self.assertEqual(lost.status, "succeeded")
                result = json.loads(lost.result_json)
                self.assertTrue(result["original_response_lost"])
                self.assertEqual(result["reconciled_by"], reconciliation.id)
            database.engine.dispose()


if __name__ == "__main__":
    unittest.main()
