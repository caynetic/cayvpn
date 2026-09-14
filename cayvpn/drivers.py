from __future__ import annotations

import base64
import binascii
import configparser
import http.client
import ipaddress
import json
import os
import re
import socket
import ssl
import struct
from dataclasses import dataclass, asdict
from urllib.parse import urlsplit

from .dns_probe import _query, _resolved_response
from .dual_stack import capabilities_for_api, normalize_capabilities


class DriverValidationError(ValueError):
    pass


def _public_host(host: str, allow_private: bool = False) -> None:
    if not host or len(host) > 253:
        raise DriverValidationError("A proxy or tunnel endpoint host is required")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    if address is not None:
        if address.is_loopback or address.is_link_local or address.is_multicast or address.is_unspecified:
            raise DriverValidationError("Loopback, link-local, multicast, and unspecified endpoints are not allowed")
        if address.is_private and not allow_private:
            raise DriverValidationError("Private endpoint addresses require explicit advanced approval")
        return
    if not re.fullmatch(r"[A-Za-z0-9.-]+", host) or host.startswith(".") or host.endswith("."):
        raise DriverValidationError("Endpoint host contains invalid characters")
    labels = host.split(".")
    if any(not label or len(label) > 63 or label.startswith("-") or label.endswith("-") for label in labels):
        raise DriverValidationError("Endpoint host contains invalid labels")


def _wireguard_key(value: str, label: str) -> None:
    try:
        decoded = base64.b64decode(value.encode(), validate=True)
    except (binascii.Error, ValueError, AttributeError) as exc:
        raise DriverValidationError(f"Provider {label} is invalid") from exc
    if len(decoded) != 32:
        raise DriverValidationError(f"Provider {label} is invalid")


def parse_socks5(value: str, allow_private: bool = False) -> dict:
    raw = (value or "").strip()
    separator = raw.find("://")
    scheme = raw[:separator].lower() if separator > 0 else ""
    if scheme not in {"socks5", "socks5h"}:
        raise DriverValidationError("SOCKS5 endpoints must use socks5:// or socks5h://")
    # socks5h is the familiar curl-style spelling for proxy-side DNS. CayVPN
    # already keeps client DNS on a TCP-capable resolver inside the egress
    # namespace, so both spellings map to the same fail-closed runtime.
    parsed = urlsplit(f"socks5://{raw[separator + 3:]}")
    if parsed.hostname is None or parsed.port is None:
        raise DriverValidationError("SOCKS5 endpoint must include host and port")
    if not 1 <= parsed.port <= 65535:
        raise DriverValidationError("SOCKS5 port is out of range")
    _public_host(parsed.hostname, allow_private=allow_private)
    username = parsed.username or ""
    password = parsed.password or ""
    if len(username) > 255 or len(password) > 255 or any(ord(character) < 32 or ord(character) == 127 for character in f"{username}{password}"):
        raise DriverValidationError("SOCKS5 credentials contain invalid characters")
    return {
        "scheme": "socks5",
        "host": parsed.hostname,
        "port": parsed.port,
        "username": username,
        "password": password,
        "password_present": bool(password),
        "udp_requested": False,
        "ipv6_requested": False,
    }


def _recv_exact(connection: socket.socket, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = connection.recv(remaining)
        if not chunk:
            raise OSError("SOCKS5 connection closed during capability check")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _socks5_authenticate(connection: socket.socket, parsed: dict, password: str | None) -> bool:
    username = str(parsed.get("username", ""))
    methods = b"\x00" + (b"\x02" if username or password else b"")
    connection.sendall(b"\x05" + bytes([len(methods)]) + methods)
    greeting = _recv_exact(connection, 2)
    if greeting[0] != 5 or greeting[1] == 0xFF:
        return False
    if greeting[1] == 0x02:
        user_bytes = username.encode()
        password_bytes = (password or "").encode()
        if not user_bytes or len(user_bytes) > 255 or len(password_bytes) > 255:
            return False
        connection.sendall(b"\x01" + bytes([len(user_bytes)]) + user_bytes + bytes([len(password_bytes)]) + password_bytes)
        return _recv_exact(connection, 2) == b"\x01\x00"
    return greeting[1] == 0x00


def _socks5_reply(connection: socket.socket) -> tuple[str, int] | None:
    response = _recv_exact(connection, 4)
    if response[0] != 5 or response[1] != 0 or response[2] != 0:
        return None
    address_type = response[3]
    if address_type == 1:
        host = socket.inet_ntoa(_recv_exact(connection, 4))
    elif address_type == 4:
        host = socket.inet_ntop(socket.AF_INET6, _recv_exact(connection, 16))
    elif address_type == 3:
        length = _recv_exact(connection, 1)[0]
        if not length:
            return None
        host = _recv_exact(connection, length).decode("idna")
    else:
        return None
    port = struct.unpack(">H", _recv_exact(connection, 2))[0]
    return host, port


def _public_addresses(host: str, port: int, socket_type: int, family: int = socket.AF_UNSPEC) -> list[str]:
    try:
        resolved = socket.getaddrinfo(host, port, family=family, type=socket_type)
    except OSError:
        return []
    addresses: list[str] = []
    for item in resolved:
        address = item[4][0]
        try:
            parsed_address = ipaddress.ip_address(address)
        except ValueError:
            continue
        if (
            not parsed_address.is_private
            and not parsed_address.is_loopback
            and not parsed_address.is_link_local
            and not parsed_address.is_multicast
            and not parsed_address.is_unspecified
            and address not in addresses
        ):
            addresses.append(address)
    return addresses


def _public_ipv4_addresses(host: str, port: int, socket_type: int) -> list[str]:
    """Compatibility wrapper retained for existing fixtures and callers."""
    return _public_addresses(host, port, socket_type, socket.AF_INET)


def _socks5_command(parsed: dict, password: str | None, command: int, timeout: float = 3.0, target_family: int = 4) -> bool:
    host = str(parsed.get("host", ""))
    port = int(parsed.get("port", 0))
    proxy_addresses = _public_addresses(host, port, socket.SOCK_STREAM)
    for address in proxy_addresses[:2]:
        try:
            with socket.create_connection((address, port), timeout=timeout) as connection:
                if not _socks5_authenticate(connection, parsed, password):
                    return False
                if target_family == 6 and command == 1:
                    address_type = 0x04
                    target_address = socket.inet_pton(socket.AF_INET6, "2606:4700:4700::1111")
                else:
                    address_type = 0x01
                    target_address = socket.inet_aton("1.1.1.1") if command == 1 else socket.inet_aton("0.0.0.0")
                request = b"\x05" + bytes([command, 0x00, address_type]) + target_address + struct.pack(">H", 443 if command == 1 else 0)
                connection.sendall(request)
                return _socks5_reply(connection) is not None
        except (OSError, ValueError, UnicodeError):
            continue
    return False


def _socks5_dns_roundtrip(parsed: dict, password: str | None, timeout: float = 3.0, target_family: int = 4) -> bool:
    """Resolve A or AAAA over certificate-verified DoH through SOCKS5.

    Web proxies commonly block direct TCP/53 even though they safely carry
    HTTPS. CayVPN's client resolver also uses DoH, so probe the same encrypted
    path instead of rejecting an otherwise usable proxy for blocking legacy
    DNS transport.
    """
    host = str(parsed.get("host", ""))
    port = int(parsed.get("port", 0))
    for address in _public_addresses(host, port, socket.SOCK_STREAM)[:2]:
        try:
            with socket.create_connection((address, port), timeout=timeout) as connection:
                if not _socks5_authenticate(connection, parsed, password):
                    return False
                if target_family == 6:
                    address_type = 0x04
                    target = socket.inet_pton(socket.AF_INET6, "2606:4700:4700::1111")
                    query = _query("example.com", qtype=28)
                else:
                    address_type = 0x01
                    target = socket.inet_aton("1.1.1.1")
                    query = _query("example.com", qtype=1)
                connection.sendall(b"\x05\x01\x00" + bytes([address_type]) + target + struct.pack(">H", 443))
                if _socks5_reply(connection) is None:
                    return False
                context = ssl.create_default_context()
                with context.wrap_socket(connection, server_hostname="cloudflare-dns.com") as secure_connection:
                    request = (
                        b"POST /dns-query HTTP/1.1\r\n"
                        b"Host: cloudflare-dns.com\r\n"
                        b"Content-Type: application/dns-message\r\n"
                        b"Accept: application/dns-message\r\n"
                        b"User-Agent: CayVPN SOCKS probe\r\n"
                        b"Connection: close\r\n"
                        + f"Content-Length: {len(query)}\r\n\r\n".encode("ascii")
                        + query
                    )
                    secure_connection.sendall(request)
                    response = http.client.HTTPResponse(secure_connection)
                    response.begin()
                    body = response.read(64 * 1024 + 1)
                    content_type = str(response.getheader("Content-Type", "")).split(";", 1)[0].strip().lower()
                    return response.status == 200 and content_type == "application/dns-message" and len(body) <= 64 * 1024 and _resolved_response(query, body)
        except (OSError, ValueError, UnicodeError, http.client.HTTPException):
            continue
    return False


def _socks5_udp_payload(packet: bytes) -> bytes | None:
    if len(packet) < 7 or packet[:2] != b"\x00\x00" or packet[2] != 0:
        return None
    address_type = packet[3]
    offset = 4
    if address_type == 1:
        offset += 4
    elif address_type == 4:
        offset += 16
    elif address_type == 3:
        if offset >= len(packet):
            return None
        offset += 1 + packet[offset]
    else:
        return None
    if offset + 2 > len(packet):
        return None
    return packet[offset + 2:]


def _socks5_udp_roundtrip(parsed: dict, password: str | None, timeout: float = 3.0, target_family: int = 4) -> bool:
    """Require an actual DNS response through the RFC 1928 UDP relay."""
    host = str(parsed.get("host", ""))
    port = int(parsed.get("port", 0))
    proxy_addresses = _public_addresses(host, port, socket.SOCK_STREAM)
    for address in proxy_addresses[:2]:
        try:
            with socket.create_connection((address, port), timeout=timeout) as connection:
                if not _socks5_authenticate(connection, parsed, password):
                    return False
                connection.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
                relay = _socks5_reply(connection)
                if relay is None or relay[1] == 0:
                    return False
                relay_host = address if relay[0] == "0.0.0.0" else relay[0]
                relay_addresses = _public_ipv4_addresses(relay_host, relay[1], socket.SOCK_DGRAM) if target_family == 4 else _public_addresses(relay_host, relay[1], socket.SOCK_DGRAM)
                if not relay_addresses:
                    return False
                query = _query("example.com", qtype=28 if target_family == 6 else 1)
                if target_family == 6:
                    destination = b"\x04" + socket.inet_pton(socket.AF_INET6, "2606:4700:4700::1111")
                else:
                    destination = b"\x01" + socket.inet_aton("1.1.1.1")
                datagram = b"\x00\x00\x00" + destination + struct.pack(">H", 53) + query
                relay_family = socket.AF_INET6 if ipaddress.ip_address(relay_addresses[0]).version == 6 else socket.AF_INET
                with socket.socket(relay_family, socket.SOCK_DGRAM) as udp_socket:
                    udp_socket.settimeout(timeout)
                    udp_socket.connect((relay_addresses[0], relay[1]))
                    udp_socket.send(datagram)
                    packet = udp_socket.recv(64 * 1024)
                response = _socks5_udp_payload(packet)
                return bool(response and _resolved_response(query, response))
        except (OSError, ValueError, UnicodeError):
            continue
    return False


def probe_socks5_capabilities(parsed: dict, password: str | None, attempts: int = 2) -> dict:
    """Require repeated TCP and end-to-end UDP relay checks before enabling either."""
    checks = max(2, attempts)
    tcp_successes = 0
    dns_successes = 0
    udp_successes = 0
    ipv6_tcp_successes = 0
    ipv6_dns_successes = 0
    ipv6_udp_successes = 0
    for _ in range(checks):
        if _socks5_command(parsed, password, 1):
            tcp_successes += 1
    if tcp_successes >= 2:
        for _ in range(checks):
            if _socks5_dns_roundtrip(parsed, password):
                dns_successes += 1
    if tcp_successes >= 2 and dns_successes >= 2:
        for _ in range(checks):
            if _socks5_udp_roundtrip(parsed, password):
                udp_successes += 1
    for _ in range(checks):
        if _socks5_command(parsed, password, 1, target_family=6):
            ipv6_tcp_successes += 1
    if ipv6_tcp_successes >= 2:
        for _ in range(checks):
            if _socks5_dns_roundtrip(parsed, password, target_family=6):
                ipv6_dns_successes += 1
    if ipv6_tcp_successes >= 2 and ipv6_dns_successes >= 2:
        for _ in range(checks):
            if _socks5_udp_roundtrip(parsed, password, target_family=6):
                ipv6_udp_successes += 1
    families = normalize_capabilities({
        "ipv4": {"tcp": tcp_successes >= 2, "udp": udp_successes >= 2, "dns": dns_successes >= 2},
        "ipv6": {"tcp": ipv6_tcp_successes >= 2, "udp": ipv6_udp_successes >= 2, "dns": ipv6_dns_successes >= 2},
    })
    return {
        **capabilities_for_api(families),
        "tcp": tcp_successes >= 2,
        "udp": udp_successes >= 2,
        "dns": dns_successes >= 2,
        "ipv6": ipv6_tcp_successes >= 2 and ipv6_dns_successes >= 2,
        "tcp_checks": tcp_successes,
        "dns_checks": dns_successes,
        "udp_checks": udp_successes,
        "ipv6_tcp_checks": ipv6_tcp_successes,
        "ipv6_dns_checks": ipv6_dns_successes,
        "ipv6_udp_checks": ipv6_udp_successes,
    }


ALLOWED_PROVIDER_INTERFACE_KEYS = {
    "privatekey",
    "address",
    "listenport",
    "dns",
    "mtu",
    "fwmark",
    "jc",
    "jmin",
    "jmax",
    "s1",
    "s2",
    "h1",
    "h2",
    "h3",
    "h4",
}
ALLOWED_PROVIDER_PEER_KEYS = {
    "publickey",
    "presharedkey",
    "allowedips",
    "endpoint",
    "persistentkeepalive",
}


def _merge_repeated_provider_addresses(config_text: str) -> str:
    """Normalize wg-quick's repeatable Address field without relaxing parsing.

    A number of providers emit one ``Address`` line per family. ConfigParser's
    strict mode correctly rejects repeated sensitive or routing fields, so keep
    that protection and merge only repeated Interface Address values into the
    equivalent comma-separated wg-quick form before parsing.
    """
    lines: list[str] = []
    section = ""
    address_line: int | None = None
    section_pattern = re.compile(r"^\s*\[([^]]+)\]\s*$")
    option_pattern = re.compile(r"^(\s*)([A-Za-z][A-Za-z0-9]*)\s*=\s*(.*?)\s*$")
    for raw_line in config_text.splitlines():
        section_match = section_pattern.match(raw_line)
        if section_match:
            section = section_match.group(1).strip().lower()
            address_line = None
            lines.append(raw_line)
            continue
        option_match = option_pattern.match(raw_line)
        if section == "interface" and option_match and option_match.group(2).lower() == "address":
            value = option_match.group(3).strip()
            if address_line is None:
                address_line = len(lines)
                lines.append(raw_line)
            else:
                previous = lines[address_line].split("=", 1)[1].strip()
                lines[address_line] = f"{option_match.group(1)}Address = {previous}, {value}"
            continue
        lines.append(raw_line)
    return "\n".join(lines)


def parse_provider_wireguard(config_text: str) -> dict:
    if not config_text or len(config_text) > 64 * 1024:
        raise DriverValidationError("Provider configuration is empty or too large")
    parser = configparser.ConfigParser(interpolation=None, strict=True)
    parser.optionxform = str.lower
    try:
        parser.read_string(_merge_repeated_provider_addresses(config_text))
    except configparser.Error as exc:
        raise DriverValidationError(f"Invalid provider configuration: {exc}") from exc
    sections = {section.lower() for section in parser.sections()}
    if sections != {"interface", "peer"}:
        raise DriverValidationError("Provider configuration must contain exactly one Interface and one Peer")
    interface = {key.lower(): value.strip() for key, value in parser.items("Interface")}
    peer = {key.lower(): value.strip() for key, value in parser.items("Peer")}
    forbidden = {"postup", "postdown", "preup", "predown", "table", "saveconfig"}
    if forbidden.intersection(interface):
        raise DriverValidationError("Provider hooks and unmanaged routing directives are not allowed")
    unknown_interface = set(interface) - ALLOWED_PROVIDER_INTERFACE_KEYS
    unknown_peer = set(peer) - ALLOWED_PROVIDER_PEER_KEYS
    if unknown_interface or unknown_peer:
        unknown = sorted(unknown_interface or unknown_peer)
        raise DriverValidationError(f"Unsupported provider configuration field: {unknown[0]}")
    if any("\n" in value or "\r" in value for value in [*interface.values(), *peer.values()]):
        raise DriverValidationError("Provider configuration contains an invalid multiline value")
    for required in ("privatekey", "address"):
        if not interface.get(required):
            raise DriverValidationError(f"Provider Interface is missing {required}")
    for required in ("publickey", "endpoint", "allowedips"):
        if not peer.get(required):
            raise DriverValidationError(f"Provider Peer is missing {required}")
    endpoint = peer["endpoint"]
    endpoint_host = endpoint.rsplit(":", 1)[0].strip("[]") if ":" in endpoint else endpoint
    try:
        endpoint_port = int(endpoint.rsplit(":", 1)[1])
    except (IndexError, ValueError) as exc:
        raise DriverValidationError("Provider endpoint must include a port") from exc
    if not 1 <= endpoint_port <= 65535:
        raise DriverValidationError("Provider endpoint port is out of range")
    _public_host(endpoint_host)
    _wireguard_key(interface["privatekey"], "private key")
    _wireguard_key(peer["publickey"], "public key")
    if peer.get("presharedkey"):
        _wireguard_key(peer["presharedkey"], "preshared key")
    try:
        interface_addresses = [ipaddress.ip_interface(address.strip()) for address in interface["address"].split(",")]
    except ValueError as exc:
        raise DriverValidationError("Provider interface address is invalid") from exc
    allowed = [item.strip() for item in peer["allowedips"].split(",") if item.strip()]
    try:
        for item in allowed:
            ipaddress.ip_network(item, strict=False)
    except ValueError as exc:
        raise DriverValidationError("Provider AllowedIPs contains an invalid network") from exc
    has_interface_v4 = any(address.version == 4 for address in interface_addresses)
    has_interface_v6 = any(address.version == 6 for address in interface_addresses)
    full_tunnel_v4 = "0.0.0.0/0" in allowed and has_interface_v4
    full_tunnel_v6 = "::/0" in allowed and has_interface_v6
    is_amnezia = any(key in interface for key in {"jc", "jmin", "jmax", "s1", "s2", "h1", "h2", "h3", "h4"})
    return {
        "protocol": "amneziawg" if is_amnezia else "wireguard",
        "interface": interface,
        "peer": peer,
        "allowed_ips": allowed,
        "full_tunnel_ipv4": full_tunnel_v4,
        "full_tunnel_ipv6": full_tunnel_v6,
        "capabilities": capabilities_for_api({
            "ipv4": {"tcp": full_tunnel_v4, "udp": full_tunnel_v4, "dns": full_tunnel_v4},
            "ipv6": {"tcp": full_tunnel_v6, "udp": full_tunnel_v6, "dns": full_tunnel_v6},
        }),
        "redacted": {
            "protocol": "amneziawg" if is_amnezia else "wireguard",
            "endpoint": endpoint,
            "allowed_ips": allowed,
            "private_key_present": bool(interface.get("privatekey")),
        },
    }


def parse_additional_ip(config: dict, allow_private: bool = False) -> dict:
    address = str(config.get("address", "")).strip()
    raw_prefix = str(config.get("prefix", 32)).strip()
    gateway = str(config.get("gateway", "")).strip()
    interface = str(config.get("interface", "")).strip()
    try:
        address_value = ipaddress.ip_address(address)
        if "." in raw_prefix:
            prefix = ipaddress.IPv4Network(f"0.0.0.0/{raw_prefix}").prefixlen
        else:
            prefix = int(raw_prefix)
        max_prefix = 32 if address_value.version == 4 else 128
        if not 1 <= prefix <= max_prefix:
            raise ValueError
        if gateway:
            gateway_value = ipaddress.ip_address(gateway)
            if gateway_value.version != address_value.version:
                raise ValueError
    except (ValueError, TypeError) as exc:
        raise DriverValidationError("Additional IP address, prefix, or gateway is invalid") from exc
    if address_value.version != 4:
        raise DriverValidationError("IPv6-only exits are not supported yet; add an IPv4 address as well")
    if not interface or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,15}", interface):
        raise DriverValidationError("A valid network interface is required")
    if address_value.is_loopback or address_value.is_link_local or address_value.is_multicast or address_value.is_unspecified:
        raise DriverValidationError("Additional IP must be a routable address")
    if address_value.is_private and not allow_private:
        raise DriverValidationError("Private additional IPs require explicit advanced approval")
    parsed = {"address": address, "prefix": prefix, "gateway": gateway, "interface": interface}
    ipv6_address = str(config.get("ipv6_address", "")).strip()
    ipv6_gateway = str(config.get("ipv6_gateway", "")).strip()
    raw_ipv6_prefix = str(config.get("ipv6_prefix", "128")).strip()
    if ipv6_address or ipv6_gateway:
        try:
            address_v6 = ipaddress.IPv6Address(ipv6_address)
            prefix_v6 = int(raw_ipv6_prefix)
            if not 1 <= prefix_v6 <= 128:
                raise ValueError
            gateway_v6 = ipaddress.IPv6Address(ipv6_gateway) if ipv6_gateway else None
        except ValueError as exc:
            raise DriverValidationError("Additional IPv6 address, prefix, or gateway is invalid") from exc
        if address_v6.is_private and not allow_private:
            raise DriverValidationError("Private additional IPv6 addresses require explicit advanced approval")
        if address_v6.is_loopback or address_v6.is_link_local or address_v6.is_multicast or address_v6.is_unspecified:
            raise DriverValidationError("Additional IPv6 must be a globally routable address")
        if gateway_v6 and (gateway_v6.is_loopback or gateway_v6.is_multicast or gateway_v6.is_unspecified):
            raise DriverValidationError("Additional IPv6 gateway is invalid")
        parsed.update({"ipv6_address": str(address_v6), "ipv6_prefix": prefix_v6, "ipv6_gateway": str(gateway_v6) if gateway_v6 else ""})
    return parsed


@dataclass(frozen=True)
class DriverResult:
    driver: str
    valid: bool
    capabilities: dict
    redacted_config: dict
    warnings: list[str]


def validate_driver(driver: str, config: dict, secret: str | None = None, allow_private: bool = False) -> DriverResult:
    driver = (driver or "").strip().lower()
    warnings: list[str] = []
    if driver == "direct_ip":
        address = str(config.get("address", "")).strip()
        try:
            address_value = ipaddress.ip_address(address)
        except ValueError as exc:
            raise DriverValidationError("Direct IP is invalid") from exc
        if address_value.is_loopback or address_value.is_link_local or address_value.is_multicast or address_value.is_unspecified:
            raise DriverValidationError("Direct IP must be a routable address")
        if address_value.is_private and not allow_private:
            raise DriverValidationError("Private direct IPs require explicit advanced approval")
        if address_value.version != 4:
            raise DriverValidationError("IPv6-only exits are not supported yet; the direct exit needs IPv4")
        ipv6_address = str(config.get("ipv6_address", "") or "").strip()
        if ipv6_address:
            try:
                parsed_v6 = ipaddress.IPv6Address(ipv6_address)
            except ValueError as exc:
                raise DriverValidationError("Direct IPv6 address is invalid") from exc
            if parsed_v6.is_private or parsed_v6.is_loopback or parsed_v6.is_link_local or parsed_v6.is_multicast or parsed_v6.is_unspecified:
                raise DriverValidationError("Direct IPv6 address must be globally routable")
        capabilities = capabilities_for_api({
            "ipv4": {"tcp": True, "udp": True, "dns": True},
            "ipv6": {"tcp": bool(ipv6_address), "udp": bool(ipv6_address), "dns": bool(ipv6_address)},
        })
        return DriverResult(driver, True, capabilities, {"address": address, "ipv6_address": ipv6_address or None}, warnings)
    if driver == "additional_ip":
        parsed = parse_additional_ip(config, allow_private=allow_private)
        has_ipv6 = bool(parsed.get("ipv6_address"))
        capabilities = capabilities_for_api({
            "ipv4": {"tcp": True, "udp": True, "dns": True},
            "ipv6": {"tcp": has_ipv6, "udp": has_ipv6, "dns": has_ipv6},
        })
        return DriverResult(driver, True, capabilities, parsed, warnings)
    if driver == "socks5":
        endpoint = parse_socks5(str(config.get("endpoint", "")), allow_private=allow_private)
        if secret:
            endpoint["password_present"] = True
            endpoint["password"] = ""
        if not endpoint["password_present"]:
            warnings.append("This SOCKS5 endpoint has no password; use an authenticated provider when possible.")
        warnings.append("SOCKS5 is TCP-only until repeated end-to-end UDP relay checks pass on this provider.")
        endpoint.pop("password", None)
        return DriverResult(driver, True, capabilities_for_api({"tcp": True, "udp": False, "dns": True, "ipv6": False}), {**endpoint, "password_present": endpoint["password_present"]}, warnings)
    if driver == "provider_tunnel":
        parsed = parse_provider_wireguard(str(config.get("config_text", "")))
        if not parsed["full_tunnel_ipv4"]:
            if parsed["full_tunnel_ipv6"]:
                raise DriverValidationError("IPv6-only exits are not supported yet; this provider tunnel also needs a full IPv4 route and IPv4 interface address")
            raise DriverValidationError("This provider tunnel needs a full IPv4 route and IPv4 interface address")
        if "::/0" in parsed["allowed_ips"] and not parsed["full_tunnel_ipv6"]:
            warnings.append("IPv6 is blocked because the provider configuration has no IPv6 interface address.")
        return DriverResult(driver, parsed["full_tunnel_ipv4"], parsed["capabilities"], parsed["redacted"], warnings)
    raise DriverValidationError("Unsupported egress driver")


def generate_keypair() -> tuple[str, str]:
    """Generate WireGuard-compatible X25519 keys without invoking a shell."""
    try:
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        from cryptography.hazmat.primitives import serialization

        private = X25519PrivateKey.generate()
        private_bytes = private.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
        public_bytes = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    except ImportError as exc:
        raise RuntimeError("cryptography is required to generate WireGuard keys") from exc
    return base64.b64encode(private_bytes).decode(), base64.b64encode(public_bytes).decode()


def redacted_profile(driver: str, config: dict, secret_present: bool = False) -> dict:
    data = dict(config)
    for key in ("password", "private_key", "config_text"):
        if key in data:
            data[key] = "[stored securely]"
    if secret_present:
        data["secret_present"] = True
    if driver == "socks5" and isinstance(data.get("endpoint"), str):
        parsed = urlsplit(data["endpoint"])
        if parsed.password:
            host = parsed.hostname or ""
            if ":" in host and not host.startswith("["):
                host = f"[{host}]"
            user = f"{parsed.username}@" if parsed.username else ""
            data["endpoint"] = f"socks5://{user}{host}:{parsed.port}"
    return data
