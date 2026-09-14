from __future__ import annotations

import argparse
import ipaddress
import secrets
import socket
import struct


def _query(name: str = "example.com", qtype: int = 1) -> bytes:
    if qtype not in {1, 28}:
        raise ValueError("unsupported DNS query type")
    transaction = secrets.token_bytes(2)
    question = b"".join(bytes([len(label)]) + label.encode("ascii") for label in name.split(".")) + b"\0"
    return transaction + struct.pack("!HHHHH", 0x0100, 1, 0, 0, 0) + question + struct.pack("!HH", qtype, 1)


def _usable_response(query: bytes, response: bytes) -> bool:
    if len(query) < 2 or len(response) < 12 or response[:2] != query[:2]:
        return False
    flags = int.from_bytes(response[2:4], "big")
    # A normal answer and an intentional ad-blocking NXDOMAIN both prove the
    # resolver path. SERVFAIL and every other response code do not.
    return bool(flags & 0x8000) and (flags & 0x000F) in {0, 3}


def _resolved_response(query: bytes, response: bytes) -> bool:
    """Require a successful DNS response containing at least one answer."""
    if not _usable_response(query, response):
        return False
    flags = int.from_bytes(response[2:4], "big")
    answer_count = int.from_bytes(response[6:8], "big")
    return (flags & 0x000F) == 0 and answer_count > 0


def probe(address: str, timeout: float = 2.0) -> bool:
    parsed = ipaddress.ip_address(address)
    if parsed.is_loopback or parsed.is_multicast or parsed.is_unspecified:
        return False
    query = _query()
    family = socket.AF_INET6 if parsed.version == 6 else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as client:
        client.settimeout(timeout)
        client.sendto(query, (str(parsed), 53))
        response, _ = client.recvfrom(64 * 1024)
    return _usable_response(query, response)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="cayvpn-dns-probe")
    parser.add_argument("--address", required=True)
    parser.add_argument("--timeout", type=float, default=2.0)
    args = parser.parse_args(argv)
    if not 0.1 <= args.timeout <= 5.0:
        return 2
    try:
        return 0 if probe(args.address, args.timeout) else 1
    except (OSError, ValueError):
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
