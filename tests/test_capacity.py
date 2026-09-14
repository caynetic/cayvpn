import unittest

from cayvpn.capacity import SystemResources, calculate_capacity


class CapacityTests(unittest.TestCase):
    def test_baseline_and_driver_overhead_are_conservative(self):
        resources = SystemResources("x86_64", 2, 4096, 100000)
        direct = calculate_capacity(resources, ["direct_ip"])
        socks = calculate_capacity(resources, ["direct_ip", "socks5"])
        self.assertEqual(direct.safe_active_clients, 35)
        self.assertLess(socks.safe_active_clients, direct.safe_active_clients)
        self.assertGreaterEqual(direct.max_stored_configs, direct.safe_active_clients)

    def test_provider_nominal_memory_tiers_allow_normal_reserved_memory(self):
        digitalocean_two_gb = SystemResources("x86_64", 1, 1967, 100000)
        self.assertEqual(calculate_capacity(digitalocean_two_gb, ["direct_ip"]).safe_active_clients, 15)

        materially_smaller = SystemResources("x86_64", 1, 1792, 100000)
        self.assertEqual(calculate_capacity(materially_smaller, ["direct_ip"]).safe_active_clients, 5)

        four_gb_with_reservation = SystemResources("x86_64", 2, 3934, 100000)
        self.assertEqual(calculate_capacity(four_gb_with_reservation, ["direct_ip"]).safe_active_clients, 35)

    def test_transfer_allowance_can_be_limiting_factor(self):
        resources = SystemResources("arm64", 8, 16384, 100000)
        estimate = calculate_capacity(resources, ["direct_ip"], transfer_allowance_gb=20)
        self.assertEqual(estimate.limiting_factor, "monthly transfer allowance")
        self.assertLessEqual(estimate.safe_active_clients, 2)


if __name__ == "__main__":
    unittest.main()
