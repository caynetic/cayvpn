import unittest

from cayvpn.health import ordered_healthy_profile_ids, record_probe


class HealthTests(unittest.TestCase):
    def test_three_failures_mark_an_exit_unhealthy(self):
        first = record_probe("healthy", 0, 0, False, "timeout")
        second = record_probe(first.state, first.failures, first.successes, False, "timeout")
        third = record_probe(second.state, second.failures, second.successes, False, "timeout")
        self.assertEqual(first.state, "healthy")
        self.assertEqual(second.state, "healthy")
        self.assertEqual(third.state, "unhealthy")
        self.assertEqual(third.failures, 3)

    def test_two_successes_recover_without_failback_action(self):
        first = record_probe("unhealthy", 3, 0, True)
        second = record_probe(first.state, first.failures, first.successes, True)
        self.assertEqual(first.state, "unhealthy")
        self.assertEqual(second.state, "healthy")
        self.assertTrue(second.changed)

    def test_pool_order_excludes_unhealthy_and_disabled_profiles(self):
        class Profile:
            def __init__(self, enabled, state):
                self.enabled = enabled
                self.health_state = state

        profiles = {1: Profile(True, "unhealthy"), 2: Profile(True, "healthy"), 3: Profile(False, "healthy"), 4: Profile(True, "active")}
        self.assertEqual(ordered_healthy_profile_ids([1, 3, 4, 2], profiles, excluded=4), [2])


if __name__ == "__main__":
    unittest.main()
