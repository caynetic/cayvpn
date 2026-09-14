import ipaddress
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from cayvpn.config import Settings, admin_dns_search_domain
from cayvpn.db import Database
from cayvpn.dual_stack import capabilities_for_api, generate_ula_prefix, normalize_ula_prefix, ula_subnet
from cayvpn.models import Client


class DualStackTests(unittest.TestCase):
    def test_admin_dns_search_scope_is_derived_from_a_valid_private_hostname(self):
        self.assertEqual(admin_dns_search_domain("admin.cayvpn.home.arpa"), "cayvpn.home.arpa")
        with self.assertRaisesRegex(ValueError, "valid DNS hostname"):
            admin_dns_search_domain("admin.cayvpn.home.arpa\nDNS = attacker.example")

    def test_each_install_can_generate_its_own_rfc4193_prefix_and_stable_subnets(self):
        first = generate_ula_prefix()
        second = generate_ula_prefix()
        self.assertNotEqual(first, second)
        parent = ipaddress.IPv6Network(first)
        self.assertEqual(parent.prefixlen, 48)
        self.assertEqual(parent.network_address.packed[0], 0xFD)
        subnets = [ipaddress.IPv6Network(ula_subnet(first, identifier)) for identifier in range(1, 5)]
        self.assertEqual(len(set(subnets)), 4)
        self.assertTrue(all(item.subnet_of(parent) and item.prefixlen == 64 for item in subnets))
        self.assertEqual(generate_ula_prefix("fixture"), generate_ula_prefix("fixture"))

    def test_universal_or_non_local_ipv6_prefixes_are_rejected(self):
        for value in ("fd00::/8", "fc00:1234:5678::/48", "2001:db8:1234::/48", "fd12:3456:789a::/64"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                normalize_ula_prefix(value)

    def test_family_capabilities_keep_ipv4_aliases_without_claiming_ipv6(self):
        capabilities = capabilities_for_api(
            {
                "ipv4": {"tcp": True, "udp": True, "dns": True},
                "ipv6": {"tcp": True, "udp": False, "dns": False},
            }
        )
        self.assertTrue(capabilities["tcp"])
        self.assertTrue(capabilities["udp"])
        self.assertTrue(capabilities["dns"])
        self.assertFalse(capabilities["ipv6"])
        self.assertEqual(capabilities["families"]["ipv6"], {"tcp": True, "udp": False, "dns": False})

    def test_internal_ipv6_dns_addresses_cannot_escape_the_installation_prefix(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            os.environ,
            {
                "CAYVPN_ULA_PREFIX": "fd12:3456:789a::/48",
                "CAYVPN_CLIENT_DNS_ADDRESS_V6": "fdff::53",
            },
        ):
            with self.assertRaisesRegex(ValueError, "internal DNS IPv6 network"):
                Settings.from_env(directory)

    def test_location_transport_ipv4_network_must_be_large_private_and_isolated(self):
        cases = (
            ("100.64.0.0/11", "too small"),
            ("64.0.0.0/8", "non-public"),
            ("10.0.0.0/8", "must not overlap"),
        )
        for network, message in cases:
            with self.subTest(network=network), tempfile.TemporaryDirectory() as directory, patch.dict(
                os.environ,
                {"CAYVPN_EGRESS_NETWORK_V4": network},
            ):
                with self.assertRaisesRegex(ValueError, message):
                    Settings.from_env(directory)

    def test_additive_migration_preserves_existing_keys_and_ipv4_then_backfills_ipv6(self):
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as directory:
            temporary = Path(directory)
            database_path = temporary / "legacy.db"
            connection = sqlite3.connect(database_path)
            connection.executescript(
                """
                CREATE TABLE clients (
                    id INTEGER PRIMARY KEY,
                    name VARCHAR(120) NOT NULL,
                    public_key VARCHAR(64) UNIQUE NOT NULL,
                    private_key_enc TEXT,
                    address VARCHAR(64) UNIQUE NOT NULL,
                    ingress_protocol VARCHAR(24) DEFAULT 'wireguard',
                    dns_mode VARCHAR(24) DEFAULT 'standard',
                    route_mode VARCHAR(24) DEFAULT 'switchable',
                    fixed_egress_id INTEGER,
                    pool_id INTEGER,
                    enabled BOOLEAN DEFAULT 1,
                    created_at DATETIME,
                    updated_at DATETIME
                );
                INSERT INTO clients (
                    id, name, public_key, private_key_enc, address,
                    ingress_protocol, dns_mode, route_mode, enabled
                ) VALUES (
                    1, 'Existing phone', 'existing-public-key',
                    'ref::00000000-0000-0000-0000-000000000001',
                    '10.8.0.2', 'wireguard', 'standard', 'switchable', 1
                );
                """
            )
            connection.commit()
            connection.close()
            environment = dict(os.environ)
            environment["CAYVPN_DB_PATH"] = str(database_path)
            migration = subprocess.run(
                [sys.executable, "-m", "alembic", "-c", "alembic.ini", "upgrade", "head"],
                cwd=root,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(migration.returncode, 0, migration.stderr)

            settings = replace(
                Settings.from_env(root),
                state_dir=temporary,
                config_dir=temporary / "config",
                db_path=database_path,
                wg_dir=temporary / "wireguard",
            )
            database = Database(settings)
            database.initialize_defaults(settings)
            with database.session() as session:
                client = session.get(Client, 1)
                self.assertEqual(client.public_key, "existing-public-key")
                self.assertEqual(client.private_key_enc, "ref::00000000-0000-0000-0000-000000000001")
                self.assertEqual(client.address, "10.8.0.2")
                expected = str(ipaddress.IPv6Network(settings.user_network_v6).network_address + 2)
                self.assertEqual(client.ipv6_address, expected)
                self.assertEqual(client.generated_config_version, 3)
                self.assertEqual(client.confirmed_config_version, 1)
            database.engine.dispose()


if __name__ == "__main__":
    unittest.main()
