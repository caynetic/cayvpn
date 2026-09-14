import unittest

from cayvpn.protocol import AgentClient, AgentRequest


class ProtocolTests(unittest.TestCase):
    def test_transactional_actions_have_bounded_extended_timeouts(self):
        self.assertEqual(AgentClient.timeout_for("route.switch"), 90)
        self.assertEqual(AgentClient.timeout_for("route.ipv6_reconcile"), 45)
        self.assertEqual(AgentClient.timeout_for("runtime.reconcile"), 180)
        self.assertEqual(AgentClient.timeout_for("egress.probe"), 30)
        self.assertEqual(AgentClient.timeout_for("system.snapshot"), 15)
        self.assertEqual(AgentClient.timeout_for("remote_admin.configure"), 300)
        self.assertEqual(AgentClient.timeout_for("remote_admin.renew"), 300)

    def test_raw_commands_are_not_accepted(self):
        with self.assertRaises(ValueError):
            AgentRequest("operation-1", "route.switch", payload={"command": "nft flush ruleset"})

    def test_unknown_action_is_not_accepted(self):
        with self.assertRaises(ValueError):
            AgentRequest("operation-1", "shell.execute", payload={})

    def test_typed_request_serializes(self):
        request = AgentRequest("operation-1", "route.switch", desired_generation=4, payload={"client_id": 1, "target_profile_id": 2})
        self.assertEqual(request.to_dict()["protocol_version"], 1)
        self.assertEqual(request.to_dict()["desired_generation"], 4)

    def test_ipv6_reconciliation_is_a_typed_action_and_still_rejects_commands(self):
        request = AgentRequest(
            "operation-2",
            "route.ipv6_reconcile",
            payload={"client_id": 1, "client_ipv6_address": "fd12:3456:789a:1::2/128", "ipv6_policy": "auto"},
        )
        self.assertEqual(request.action, "route.ipv6_reconcile")
        with self.assertRaises(ValueError):
            AgentRequest("operation-3", "route.ipv6_reconcile", payload={"script": "ip -6 route flush table main"})

    def test_remote_administration_is_typed_and_rejects_raw_configuration(self):
        request = AgentRequest(
            "operation-4", "remote_admin.configure", payload={"enabled": True}
        )
        self.assertEqual(request.action, "remote_admin.configure")
        with self.assertRaises(ValueError):
            AgentRequest(
                "operation-5",
                "remote_admin.configure",
                payload={"command": "nginx -s reload"},
            )


if __name__ == "__main__":
    unittest.main()
