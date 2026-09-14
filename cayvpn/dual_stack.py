from __future__ import annotations

import hashlib
import ipaddress
import secrets
from typing import Any


CAPABILITY_FIELDS = ("tcp", "udp", "dns")


def generate_ula_prefix(seed: str | bytes | None = None) -> str:
    """Return an RFC 4193 locally assigned /48 prefix.

    Installed nodes persist an explicitly random value in cayvpn.env.  The
    seeded path is a deterministic compatibility fallback for pre-release
    nodes upgraded from an environment that predates that variable.
    """
    if seed is None:
        global_id = secrets.token_bytes(5)
    else:
        raw = seed.encode() if isinstance(seed, str) else seed
        global_id = hashlib.sha256(raw).digest()[:5]
    value = int.from_bytes(b"\xfd" + global_id + (b"\x00" * 10), "big")
    return str(ipaddress.IPv6Network((value, 48)))


def normalize_ula_prefix(value: str) -> str:
    try:
        network = ipaddress.IPv6Network(value, strict=True)
    except ValueError as exc:
        raise ValueError("CayVPN's private IPv6 prefix must be a valid /48 network") from exc
    if network.prefixlen != 48 or network.network_address.packed[0] != 0xFD:
        raise ValueError("CayVPN's private IPv6 prefix must be a randomly assigned fd00::/8 /48")
    return str(network)


def ula_subnet(prefix: str, subnet_id: int) -> str:
    network = ipaddress.IPv6Network(normalize_ula_prefix(prefix), strict=True)
    if not 0 <= subnet_id <= 0xFFFF:
        raise ValueError("IPv6 subnet id is out of range")
    address = int(network.network_address) | (subnet_id << 64)
    return str(ipaddress.IPv6Network((address, 64)))


def normalize_ula_subnet(prefix: str, value: str, label: str = "IPv6 network") -> str:
    """Validate that a configured /64 belongs to this installation's ULA."""
    parent = ipaddress.IPv6Network(normalize_ula_prefix(prefix), strict=True)
    try:
        network = ipaddress.IPv6Network(value, strict=True)
    except ValueError as exc:
        raise ValueError(f"{label} must be a valid IPv6 /64 network") from exc
    if network.prefixlen != 64 or not network.subnet_of(parent):
        raise ValueError(f"{label} must be a /64 inside CayVPN's private IPv6 prefix")
    return str(network)


def normalize_ula_interface(network: str, value: str, label: str = "IPv6 interface") -> str:
    """Validate one stable interface address inside a managed ULA /64."""
    parent = ipaddress.IPv6Network(network, strict=True)
    try:
        interface = ipaddress.IPv6Interface(value)
    except ValueError as exc:
        raise ValueError(f"{label} must be a valid IPv6 interface address") from exc
    if interface.network.prefixlen != 64 or interface.ip not in parent or interface.ip == parent.network_address:
        raise ValueError(f"{label} must use a host address inside {parent}")
    return str(interface)


def address_in_network(network: str, host_id: int, prefixlen: int = 128) -> str:
    parsed = ipaddress.ip_network(network, strict=False)
    if host_id < 1:
        raise ValueError("IPv6 host id must be positive")
    address = parsed.network_address + host_id
    if address > parsed.broadcast_address:
        raise ValueError("The configured IPv6 network is full")
    return f"{address}/{prefixlen}"


def _family(value: Any) -> dict[str, bool]:
    source = value if isinstance(value, dict) else {}
    return {field: bool(source.get(field, False)) for field in CAPABILITY_FIELDS}


def normalize_capabilities(value: Any) -> dict[str, Any]:
    """Translate legacy flat capability records into the v2 family schema."""
    source = value if isinstance(value, dict) else {}
    families = source.get("families") if isinstance(source.get("families"), dict) else None
    if families is not None:
        ipv4 = _family(families.get("ipv4"))
        ipv6 = _family(families.get("ipv6"))
    elif isinstance(source.get("ipv4"), dict) or isinstance(source.get("ipv6"), dict):
        ipv4 = _family(source.get("ipv4"))
        ipv6 = _family(source.get("ipv6"))
    else:
        ipv4 = _family(source)
        legacy_ipv6 = bool(source.get("ipv6", False))
        ipv6 = {
            "tcp": legacy_ipv6 and ipv4["tcp"],
            "udp": legacy_ipv6 and ipv4["udp"],
            "dns": legacy_ipv6 and ipv4["dns"],
        }
    return {"schema": 2, "ipv4": ipv4, "ipv6": ipv6}


def capabilities_for_api(value: Any) -> dict[str, Any]:
    normalized = normalize_capabilities(value)
    ipv4 = normalized["ipv4"]
    ipv6 = normalized["ipv6"]
    return {
        "tcp": ipv4["tcp"],
        "udp": ipv4["udp"],
        "dns": ipv4["dns"],
        "ipv6": ipv6["tcp"] and ipv6["dns"],
        "schema": 2,
        "families": {"ipv4": dict(ipv4), "ipv6": dict(ipv6)},
    }


def family_capabilities(value: Any, family: str) -> dict[str, bool]:
    if family not in {"ipv4", "ipv6"}:
        raise ValueError("Unsupported address family")
    return dict(normalize_capabilities(value)[family])


def ipv6_usable(value: Any) -> bool:
    ipv6 = family_capabilities(value, "ipv6")
    return ipv6["tcp"] and ipv6["dns"]


def merge_capability_observation(current: Any, observation: Any) -> dict[str, Any]:
    merged = normalize_capabilities(current)
    source = observation if isinstance(observation, dict) else {}
    observed_families = source.get("families") if isinstance(source.get("families"), dict) else None
    if observed_families is None and (isinstance(source.get("ipv4"), dict) or isinstance(source.get("ipv6"), dict)):
        observed_families = {"ipv4": source.get("ipv4"), "ipv6": source.get("ipv6")}
    if observed_families is not None:
        for family in ("ipv4", "ipv6"):
            values = observed_families.get(family)
            if isinstance(values, dict):
                for field in CAPABILITY_FIELDS:
                    if field in values:
                        merged[family][field] = bool(values[field])
        return merged

    for field in CAPABILITY_FIELDS:
        if field in source:
            merged["ipv4"][field] = bool(source[field])
    if "ipv6" in source and not isinstance(source.get("ipv6"), dict):
        enabled = bool(source["ipv6"])
        for field in CAPABILITY_FIELDS:
            merged["ipv6"][field] = enabled and merged["ipv4"][field]
    return merged
