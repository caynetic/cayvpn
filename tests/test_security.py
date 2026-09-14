import tempfile
import unittest
from pathlib import Path

from cayvpn.security import (
    generate_totp_secret,
    is_admin_network_address,
    totp_code,
    totp_uri,
    verify_totp,
    write_secret_file,
)


class SecurityFileTests(unittest.TestCase):
    def test_admin_tunnel_source_must_be_inside_the_private_admin_network(self):
        self.assertTrue(is_admin_network_address("10.255.0.2", "10.255.0.0/24"))
        self.assertFalse(is_admin_network_address("10.255.1.2", "10.255.0.0/24"))
        self.assertFalse(is_admin_network_address("203.0.113.10", "10.255.0.0/24"))
        self.assertFalse(is_admin_network_address("not-an-address", "10.255.0.0/24"))
        self.assertFalse(is_admin_network_address(None, "10.255.0.0/24"))

    def test_rewrite_enforces_requested_mode_on_an_existing_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "material"
            path.write_text("old")
            path.chmod(0o644)

            write_secret_file(path, "secret")
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

            write_secret_file(path, "public", mode=0o644)
            self.assertEqual(path.stat().st_mode & 0o777, 0o644)

    def test_totp_matches_rfc_vector_and_rejects_wrong_codes(self):
        secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
        self.assertEqual(totp_code(secret, at_time=59, digits=8), "94287082")
        generated = generate_totp_secret()
        code = totp_code(generated, at_time=1_800_000_000)
        self.assertTrue(verify_totp(generated, code, at_time=1_800_000_000))
        self.assertFalse(verify_totp(generated, "000000", at_time=1_800_000_000))
        uri = totp_uri(generated, account="owner@vpn")
        self.assertTrue(uri.startswith("otpauth://totp/CayVPN%3Aowner%40vpn?"))
        self.assertIn("issuer=CayVPN", uri)


if __name__ == "__main__":
    unittest.main()
