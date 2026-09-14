import ipaddress
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cayvpn.dns_service import Resolver, _question_name, blocklist_available
from cayvpn.dns_probe import _query, _resolved_response, _usable_response


def dns_query(name: str, query_type: int = 1) -> bytes:
    packet = bytearray(b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00")
    for label in name.split("."):
        packet.append(len(label))
        packet.extend(label.encode())
    packet.extend(b"\x00" + query_type.to_bytes(2, "big") + b"\x00\x01")
    return bytes(packet)


class DnsServiceTests(unittest.TestCase):
    def test_probe_accepts_answers_and_ad_blocking_nxdomain_only(self):
        query = _query()
        prefix = query[:2]
        self.assertTrue(_usable_response(query, prefix + b"\x81\x80" + b"\0" * 8))
        self.assertTrue(_usable_response(query, prefix + b"\x81\x83" + b"\0" * 8))
        self.assertFalse(_usable_response(query, prefix + b"\x81\x82" + b"\0" * 8))
        self.assertFalse(_usable_response(query, b"\0\0\x81\x80" + b"\0" * 8))

    def test_exit_probe_requires_a_real_answer(self):
        query = _query()
        prefix = query[:2]
        answered = prefix + b"\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00"
        empty = prefix + b"\x81\x80\x00\x01\x00\x00\x00\x00\x00\x00"
        nxdomain = prefix + b"\x81\x83\x00\x01\x00\x00\x00\x00\x00\x00"
        self.assertTrue(_resolved_response(query, answered))
        self.assertFalse(_resolved_response(query, empty))
        self.assertFalse(_resolved_response(query, nxdomain))

    def test_blocked_domain_returns_nxdomain_without_upstream_request(self):
        with tempfile.TemporaryDirectory() as temp:
            blocklist = Path(temp) / "domains.txt"
            blocklist.write_text("||ads.example^\n")
            resolver = Resolver("ad_blocking", blocklist)
            query = dns_query("cdn.ads.example")
            self.assertEqual(_question_name(query), "cdn.ads.example")
            with patch("cayvpn.dns_service._doh", side_effect=AssertionError("blocked DNS must not reach upstream")):
                response = resolver.answer(query)
            self.assertEqual(int.from_bytes(response[2:4], "big") & 0x000F, 3)

    def test_blocked_response_removes_unadvertised_edns_bytes(self):
        with tempfile.TemporaryDirectory() as temp:
            blocklist = Path(temp) / "domains.txt"
            blocklist.write_text("||ads.example^\n")
            resolver = Resolver("ad_blocking", blocklist)
            query = bytearray(dns_query("ads.example"))
            query[10:12] = b"\x00\x01"
            query.extend(b"\x00\x00\x29\x10\x00\x00\x00\x00\x00\x00\x00")
            response = resolver.answer(bytes(query))
            self.assertEqual(response, dns_query("ads.example")[:2] + b"\x81\x83" + dns_query("ads.example")[4:])

    def test_blocklist_exceptions_win_and_empty_lists_are_unavailable(self):
        with tempfile.TemporaryDirectory() as temp:
            blocklist = Path(temp) / "domains.txt"
            blocklist.write_text("! comment\n||doubleclick.net^\n@@||pagead.l.doubleclick.net^\n")
            self.assertTrue(blocklist_available(blocklist))
            resolver = Resolver("ad_blocking", blocklist)
            with patch("cayvpn.dns_service._doh", return_value=b"allowed") as doh:
                self.assertEqual(resolver.answer(dns_query("pagead.l.doubleclick.net")), b"allowed")
                doh.assert_called_once()
            blocked = resolver.answer(dns_query("doubleclick.net"))
            self.assertEqual(int.from_bytes(blocked[2:4], "big") & 0x000F, 3)
            blocklist.write_text("! comments only\n")
            self.assertFalse(blocklist_available(blocklist))

    def test_standard_dns_uses_the_encrypted_upstream_adapter(self):
        query = dns_query("example.com")
        with patch("cayvpn.dns_service._doh", return_value=b"response") as doh:
            self.assertEqual(Resolver("standard").answer(query), b"response")
            doh.assert_called_once_with(query)

    def test_local_admin_record_never_reaches_the_public_upstream(self):
        resolver = Resolver("standard", host_records={"admin.cayvpn.home.arpa": ("10.255.0.1",)})
        with patch("cayvpn.dns_service._doh", side_effect=AssertionError("private name must stay local")):
            response = resolver.answer(dns_query("admin.cayvpn.home.arpa"))
            self.assertEqual(int.from_bytes(response[6:8], "big"), 1)
            self.assertTrue(response.endswith(ipaddress.ip_address("10.255.0.1").packed))
            nodata = resolver.answer(dns_query("admin.cayvpn.home.arpa", query_type=28))
            self.assertEqual(int.from_bytes(nodata[6:8], "big"), 0)


if __name__ == "__main__":
    unittest.main()
