from __future__ import annotations

import argparse
import http.client
import ipaddress
import socket
import socketserver
import ssl
from pathlib import Path


DOH_ENDPOINTS = {
    4: (("cloudflare-dns.com", "1.1.1.1"), ("cloudflare-dns.com", "1.0.0.1")),
    6: (("cloudflare-dns.com", "2606:4700:4700::1111"), ("cloudflare-dns.com", "2606:4700:4700::1001")),
}


def _blocklist_files(path: Path) -> list[Path]:
    if path.is_file():
        return [path]
    if path.is_dir():
        return sorted(path.glob("*.txt"))
    return []


def _domain_rule(raw: str) -> tuple[str, bool] | None:
    """Return a DNS-level domain rule and whether it is an exception.

    CayVPN intentionally accepts only the small, auditable subset needed by
    common DNS blocklists: Adblock-style ``||domain^`` rules, their ``@@``
    exceptions, hosts-file entries, and plain domain names. Browser-only,
    regular-expression, wildcard, and modifier rules are ignored instead of
    being interpreted loosely.
    """

    line = raw.strip().lower()
    if not line or line.startswith(("!", "#", "/")):
        return None
    allowed = line.startswith("@@")
    if allowed:
        line = line[2:]
    if line.startswith("||"):
        line = line[2:].split("^", 1)[0].split("$", 1)[0].split("/", 1)[0]
    elif line.startswith(("0.0.0.0 ", "127.0.0.1 ", ":: ")):
        line = line.split(None, 1)[1].split(None, 1)[0]
    elif any(character in line for character in "|^$/* "):
        return None
    domain = line.strip(".")
    if "." not in domain or len(domain) > 253:
        return None
    labels = domain.split(".")
    if not all(
        label
        and len(label) <= 63
        and not label.startswith("-")
        and not label.endswith("-")
        and all(character.isalnum() or character in "-_" for character in label)
        for label in labels
    ):
        return None
    try:
        if ipaddress.ip_address(domain):
            return None
    except ValueError:
        pass
    return domain, allowed


def blocklist_available(path: Path) -> bool:
    """Return true only when at least one usable blocking rule exists."""

    for candidate in _blocklist_files(path):
        try:
            with candidate.open(errors="ignore") as handle:
                for raw in handle:
                    parsed = _domain_rule(raw)
                    if parsed and not parsed[1]:
                        return True
        except OSError:
            continue
    return False


def _question(packet: bytes) -> tuple[str, int, int, int] | None:
    if len(packet) < 12 or int.from_bytes(packet[4:6], "big") != 1:
        return None
    offset = 12
    labels: list[str] = []
    while offset < len(packet):
        length = packet[offset]
        offset += 1
        if length == 0:
            if offset + 4 > len(packet):
                return None
            return (
                ".".join(labels).lower().rstrip("."),
                int.from_bytes(packet[offset:offset + 2], "big"),
                int.from_bytes(packet[offset + 2:offset + 4], "big"),
                offset + 4,
            )
        if length & 0xC0 or length > 63 or offset + length > len(packet):
            return None
        label = packet[offset:offset + length]
        offset += length
        try:
            labels.append(label.decode("idna"))
        except UnicodeError:
            return None
    return None


def _question_name(packet: bytes) -> str | None:
    parsed = _question(packet)
    return parsed[0] if parsed else None


def _error_response(packet: bytes, rcode: int) -> bytes:
    parsed = _question(packet)
    if not parsed:
        return b""
    question_end = parsed[3]
    # Preserve only the request's RD/CD bits. Advertise recursive service and
    # discard any EDNS OPT record because ARCOUNT is zero in this local error
    # response; retaining it would create malformed trailing bytes.
    flags = (int.from_bytes(packet[2:4], "big") & 0x0110) | 0x8080 | rcode
    return packet[:2] + flags.to_bytes(2, "big") + packet[4:6] + b"\x00\x00\x00\x00\x00\x00" + packet[12:question_end]


def _local_address_response(packet: bytes, addresses: tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, ...]) -> bytes:
    parsed = _question(packet)
    if not parsed:
        return b""
    _name, query_type, query_class, question_end = parsed
    matching = [address for address in addresses if query_class == 1 and query_type == (1 if address.version == 4 else 28)]
    flags = (int.from_bytes(packet[2:4], "big") & 0x0110) | 0x8080
    header = packet[:2] + flags.to_bytes(2, "big") + packet[4:6] + len(matching).to_bytes(2, "big") + b"\x00\x00\x00\x00"
    answers = b"".join(
        b"\xc0\x0c"
        + (b"\x00\x01" if address.version == 4 else b"\x00\x1c")
        + b"\x00\x01\x00\x00\x00\x3c"
        + len(address.packed).to_bytes(2, "big")
        + address.packed
        for address in matching
    )
    return header + packet[12:question_end] + answers


def _servfail(packet: bytes) -> bytes:
    return _error_response(packet, 2)


def _nxdomain(packet: bytes) -> bytes:
    return _error_response(packet, 3)


class _FixedIPHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, address: str, timeout: float, source_address: str | None = None):
        super().__init__(host, timeout=timeout, context=ssl.create_default_context())
        self.address = address
        self.fixed_source_address = source_address

    def connect(self):
        source = (self.fixed_source_address, 0) if self.fixed_source_address else None
        sock = socket.create_connection((self.address, 443), self.timeout, source_address=source)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


def _doh(packet: bytes, timeout: float = 5.0, family: int | None = None, source_address: str | None = None) -> bytes:
    families = (family,) if family in {4, 6} else (4, 6)
    for current_family in families:
        for host, address in DOH_ENDPOINTS[current_family]:
            try:
                ipaddress.ip_address(address)
                connection = _FixedIPHTTPSConnection(host, address, timeout, source_address=source_address)
                connection.request("POST", "/dns-query", body=packet, headers={"Content-Type": "application/dns-message", "Accept": "application/dns-message", "User-Agent": "CayVPN resolver"})
                response = connection.getresponse()
                body = response.read(64 * 1024)
                connection.close()
                if response.status == 200 and body:
                    return body
            except (OSError, ValueError, http.client.HTTPException):
                continue
    return _servfail(packet)


class Resolver:
    def __init__(self, mode: str, blocklist: Path | None = None, host_records: dict[str, tuple[str, ...] | list[str]] | None = None):
        if mode not in {"standard", "ad_blocking"}:
            raise ValueError("unsupported DNS mode")
        self.mode = mode
        self.blocked: set[str] = set()
        self.allowed: set[str] = set()
        self.host_records: dict[str, tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, ...]] = {}
        for name, addresses in (host_records or {}).items():
            parsed_name = _domain_rule(name)
            if not parsed_name or parsed_name[1] or parsed_name[0] != name.lower().rstrip("."):
                raise ValueError("invalid local DNS hostname")
            parsed_addresses = tuple(ipaddress.ip_address(address) for address in addresses)
            if not parsed_addresses:
                raise ValueError("local DNS hostname has no address")
            self.host_records[parsed_name[0]] = parsed_addresses
        if mode == "ad_blocking" and blocklist:
            self.blocked, self.allowed = self._load_blocklist(blocklist)

    @staticmethod
    def _load_blocklist(path: Path) -> tuple[set[str], set[str]]:
        files = _blocklist_files(path)
        domains: set[str] = set()
        exceptions: set[str] = set()
        for candidate in files:
            try:
                lines = candidate.read_text(errors="ignore").splitlines()
            except OSError:
                continue
            for raw in lines:
                parsed = _domain_rule(raw)
                if not parsed:
                    continue
                domain, allowed = parsed
                (exceptions if allowed else domains).add(domain)
            if len(domains) + len(exceptions) >= 500_000:
                break
        return domains, exceptions

    @staticmethod
    def _matches(name: str, domains: set[str]) -> bool:
        labels = name.split(".")
        return any(".".join(labels[index:]) in domains for index in range(max(1, len(labels) - 1)))

    def answer(self, packet: bytes) -> bytes:
        name = _question_name(packet)
        if name in self.host_records:
            return _local_address_response(packet, self.host_records[name])
        if name and self.mode == "ad_blocking":
            if self._matches(name, self.allowed):
                return _doh(packet)
            if self._matches(name, self.blocked):
                return _nxdomain(packet)
        return _doh(packet)


class _UDP(socketserver.BaseRequestHandler):
    def handle(self):
        packet, socket_instance = self.request
        response = self.server.resolver.answer(packet)
        socket_instance.sendto(response, self.client_address)


class _TCP(socketserver.BaseRequestHandler):
    def handle(self):
        length = self.request.recv(2)
        if len(length) != 2:
            return
        size = int.from_bytes(length, "big")
        if size > 64 * 1024:
            return
        chunks: list[bytes] = []
        remaining = size
        while remaining:
            chunk = self.request.recv(remaining)
            if not chunk:
                return
            chunks.append(chunk)
            remaining -= len(chunk)
        packet = b"".join(chunks)
        if len(packet) != size:
            return
        response = self.server.resolver.answer(packet)
        self.request.sendall(len(response).to_bytes(2, "big") + response)


class _ThreadedUDP(socketserver.ThreadingMixIn, socketserver.UDPServer):
    allow_reuse_address = True
    daemon_threads = True


class _ThreadedTCP(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


class _ThreadedUDP6(_ThreadedUDP):
    address_family = socket.AF_INET6


class _ThreadedTCP6(_ThreadedTCP):
    address_family = socket.AF_INET6


def serve(address: str, port: int, mode: str, blocklist: Path | None, address_v6: str | None = None, host_records: dict[str, tuple[str, ...]] | None = None) -> None:
    resolver = Resolver(mode, blocklist, host_records)
    servers = [_ThreadedUDP((address, port), _UDP), _ThreadedTCP((address, port), _TCP)]
    if address_v6:
        servers.extend([_ThreadedUDP6((address_v6, port), _UDP), _ThreadedTCP6((address_v6, port), _TCP)])
    for server in servers:
        server.resolver = resolver
    try:
        import threading

        for server in servers[:-1]:
            threading.Thread(target=server.serve_forever, daemon=True).start()
        servers[-1].serve_forever()
    finally:
        for server in servers:
            server.server_close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="cayvpn-dns")
    parser.add_argument("--address", required=True)
    parser.add_argument("--address-v6")
    parser.add_argument("--port", type=int, default=53)
    parser.add_argument("--mode", choices=["standard", "ad_blocking"], default="standard")
    parser.add_argument("--blocklist")
    parser.add_argument("--host-record", action="append", default=[])
    args = parser.parse_args(argv)
    host_records: dict[str, tuple[str, ...]] = {}
    for record in args.host_record:
        try:
            name, raw_addresses = record.split("=", 1)
            addresses = tuple(item.strip() for item in raw_addresses.split(",") if item.strip())
        except ValueError as exc:
            raise SystemExit("Invalid --host-record; use hostname=address") from exc
        host_records[name.lower().rstrip(".")] = addresses
    serve(args.address, args.port, args.mode, Path(args.blocklist) if args.blocklist else None, args.address_v6, host_records)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
