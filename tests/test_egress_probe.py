import unittest
from unittest.mock import patch

from cayvpn.dns_probe import _query
from cayvpn.egress_probe import observed_exit_ip, probe, probe_details


class EgressProbeTests(unittest.TestCase):
    def test_probe_accepts_a_verified_doh_answer(self):
        def answer(query: bytes, timeout: float, **kwargs):
            self.assertEqual(timeout, 2.0)
            self.assertEqual(kwargs["family"], 4)
            return query[:2] + b"\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00"

        with patch("cayvpn.egress_probe._doh", side_effect=answer):
            self.assertTrue(probe(2.0))

    def test_probe_rejects_servfail(self):
        query = _query()
        response = query[:2] + b"\x81\x82" + b"\0" * 8
        with patch("cayvpn.egress_probe._doh", return_value=response):
            self.assertFalse(probe())

    def test_probe_rejects_nxdomain_and_empty_answers(self):
        query = _query()
        responses = (
            query[:2] + b"\x81\x83\x00\x01\x00\x00\x00\x00\x00\x00",
            query[:2] + b"\x81\x80\x00\x01\x00\x00\x00\x00\x00\x00",
        )
        for response in responses:
            with self.subTest(response=response), patch("cayvpn.egress_probe._doh", return_value=response):
                self.assertFalse(probe())

    def test_probe_details_reports_the_verified_public_exit(self):
        class Response:
            status = 200

            @staticmethod
            def read(_limit):
                return b"fl=test\nip=8.8.4.4\n"

        class Connection:
            def request(self, *_args, **_kwargs):
                return None

            def getresponse(self):
                return Response()

            def close(self):
                return None

        with patch("cayvpn.egress_probe._FixedIPHTTPSConnection", return_value=Connection()):
            self.assertEqual(observed_exit_ip(2.0), "8.8.4.4")
        with (
            patch("cayvpn.egress_probe.probe", side_effect=lambda *_args, family=4, **_kwargs: family == 4),
            patch("cayvpn.egress_probe.udp_probe", side_effect=lambda *_args, family=4, **_kwargs: family == 4),
            patch("cayvpn.egress_probe.observed_exit_ip", side_effect=lambda *_args, family=4, **_kwargs: "8.8.4.4" if family == 4 else None),
        ):
            details = probe_details(2.0)
        self.assertTrue(details["connectivity"])
        self.assertEqual(details["observed_exit_ip"], "8.8.4.4")
        self.assertEqual(details["observed_exit_ipv4"], "8.8.4.4")
        self.assertIsNone(details["observed_exit_ipv6"])
        self.assertEqual(details["families"]["ipv4"], {"connectivity": True, "tcp": True, "udp": True, "dns": True})
        self.assertEqual(details["families"]["ipv6"], {"connectivity": False, "tcp": False, "udp": False, "dns": False})


if __name__ == "__main__":
    unittest.main()
