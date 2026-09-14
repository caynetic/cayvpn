from __future__ import annotations

import argparse
import http.client
import ipaddress
import json
import socket

from .dns_probe import _query, _resolved_response
from .dns_service import _FixedIPHTTPSConnection, _doh


def probe(timeout: float = 3.0, family: int = 4, source_address: str | None = None) -> bool:
    """Prove TCP, TLS, and DNS reachability through the current namespace."""
    query = _query("example.com", qtype=28 if family == 6 else 1)
    response = _doh(query, timeout=timeout, family=family, source_address=source_address)
    return _resolved_response(query, response)


def udp_probe(timeout: float = 3.0, family: int = 4, source_address: str | None = None) -> bool:
    """Prove ordinary UDP and an A/AAAA DNS answer independently of TCP."""
    if family not in {4, 6}:
        raise ValueError("unsupported address family")
    target = "1.1.1.1" if family == 4 else "2606:4700:4700::1111"
    socket_family = socket.AF_INET if family == 4 else socket.AF_INET6
    query = _query("example.com", qtype=1 if family == 4 else 28)
    try:
        with socket.socket(socket_family, socket.SOCK_DGRAM) as connection:
            connection.settimeout(timeout)
            if source_address:
                connection.bind((source_address, 0))
            connection.sendto(query, (target, 53))
            response, _ = connection.recvfrom(64 * 1024)
        return _resolved_response(query, response)
    except (OSError, ValueError):
        return False


def observed_exit_ip(timeout: float = 3.0, family: int = 4, source_address: str | None = None) -> str | None:
    """Read the public source through a fixed-address HTTPS endpoint."""
    endpoints = (("1.1.1.1", "1.1.1.1"), ("1.0.0.1", "1.0.0.1")) if family == 4 else (("1.1.1.1", "2606:4700:4700::1111"), ("1.0.0.1", "2606:4700:4700::1001"))
    for host, address in endpoints:
        connection = None
        try:
            connection = _FixedIPHTTPSConnection(host, address, timeout, source_address=source_address)
            connection.request("GET", "/cdn-cgi/trace", headers={"Accept": "text/plain", "User-Agent": "CayVPN egress probe"})
            response = connection.getresponse()
            body = response.read(16 * 1024).decode("ascii", errors="ignore")
            if response.status != 200:
                continue
            value = next((line[3:].strip() for line in body.splitlines() if line.startswith("ip=")), "")
            parsed = ipaddress.ip_address(value)
            if parsed.version == family and not parsed.is_private and not parsed.is_loopback and not parsed.is_link_local and not parsed.is_multicast and not parsed.is_unspecified:
                return str(parsed)
        except (OSError, ValueError, http.client.HTTPException):
            continue
        finally:
            if connection is not None:
                connection.close()
    return None


def probe_details(timeout: float = 3.0, source_v4: str | None = None, source_v6: str | None = None) -> dict:
    dns_v4 = probe(timeout, family=4, source_address=source_v4)
    dns_v6 = probe(timeout, family=6, source_address=source_v6)
    observed_v4 = observed_exit_ip(timeout, family=4, source_address=source_v4) if dns_v4 else None
    observed_v6 = observed_exit_ip(timeout, family=6, source_address=source_v6) if dns_v6 else None
    try:
        observed_v4 = str(ipaddress.IPv4Address(observed_v4)) if observed_v4 else None
    except ValueError:
        observed_v4 = None
    try:
        observed_v6 = str(ipaddress.IPv6Address(observed_v6)) if observed_v6 else None
    except ValueError:
        observed_v6 = None
    tcp_v4 = observed_v4 is not None
    tcp_v6 = observed_v6 is not None
    udp_v4 = udp_probe(timeout, family=4, source_address=source_v4) if dns_v4 else False
    udp_v6 = udp_probe(timeout, family=6, source_address=source_v6) if dns_v6 else False
    connectivity = tcp_v4 and dns_v4
    connectivity_v6 = tcp_v6 and dns_v6
    return {
        "connectivity": connectivity,
        "tcp": tcp_v4,
        "udp": udp_v4,
        "dns": dns_v4,
        "ipv6": connectivity_v6,
        "observed_exit_ip": observed_v4,
        "observed_exit_ipv4": observed_v4,
        "observed_exit_ipv6": observed_v6,
        "families": {
            "ipv4": {"connectivity": connectivity, "tcp": tcp_v4, "udp": udp_v4, "dns": dns_v4},
            "ipv6": {"connectivity": connectivity_v6, "tcp": tcp_v6, "udp": udp_v6, "dns": dns_v6},
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="cayvpn-egress-probe")
    parser.add_argument("--timeout", type=float, default=3.0)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--source-v4")
    parser.add_argument("--source-v6")
    args = parser.parse_args(argv)
    if not 1.0 <= args.timeout <= 5.0:
        return 2
    details = probe_details(args.timeout, args.source_v4, args.source_v6)
    if args.json:
        print(json.dumps(details, sort_keys=True))
    return 0 if details["connectivity"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
