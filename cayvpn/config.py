from __future__ import annotations

import ipaddress
import os
import re
from dataclasses import dataclass
from pathlib import Path

from .dual_stack import (
    generate_ula_prefix,
    normalize_ula_interface,
    normalize_ula_prefix,
    normalize_ula_subnet,
    ula_subnet,
)


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def admin_dns_search_domain(hostname: str) -> str:
    """Return the private DNS scope used by generated WireGuard configs."""

    normalized = hostname.strip().rstrip(".").lower()
    if not normalized or len(normalized) > 253:
        raise ValueError("CAYVPN_ADMIN_HOSTNAME must be a valid DNS hostname")
    labels = normalized.split(".")
    if any(
        not label
        or len(label) > 63
        or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
        for label in labels
    ):
        raise ValueError("CAYVPN_ADMIN_HOSTNAME must be a valid DNS hostname")
    return ".".join(labels[1:]) if len(labels) > 1 else normalized


@dataclass(frozen=True)
class Settings:
    """Runtime configuration with safe local defaults.

    Production installation writes explicit paths into the service
    environment.  Keeping the defaults relative to the repository makes the
    management plane testable without root privileges or a live WireGuard
    interface.
    """

    project_dir: Path
    state_dir: Path
    config_dir: Path
    db_path: Path
    wg_dir: Path
    agent_socket: Path
    release_dir: Path
    active_release: Path
    release_trust_key: Path
    update_state_path: Path
    update_metadata_path: Path
    update_repository: str
    server_ip: str
    server_ipv6: str
    server_region: str
    public_endpoint: str
    out_interface: str
    user_interface: str
    user_port: int
    user_network: str
    user_address: str
    ula_prefix: str
    user_network_v6: str
    user_address_v6: str
    client_dns_address: str
    client_adblock_dns_address: str
    client_dns_address_v6: str
    client_adblock_dns_address_v6: str
    amnezia_interface: str
    amnezia_port: int
    amnezia_network: str
    amnezia_address: str
    amnezia_network_v6: str
    amnezia_address_v6: str
    egress_network_v4: str
    egress_network_v6: str
    admin_interface: str
    admin_port: int
    admin_network: str
    admin_address: str
    admin_hostname: str
    admin_https_port: int
    remote_admin_port: int
    remote_admin_acme_server: str
    remote_admin_acme_profile: str
    remote_admin_webroot: Path
    proxy_token: str
    https_enabled: bool
    tls_cert_path: Path
    tls_key_path: Path
    trust_cert_path: Path
    secret_key_path: Path
    agent_inline: bool
    apply_network: bool
    log_level: str

    @classmethod
    def from_env(cls, project_dir: str | Path | None = None) -> "Settings":
        root = Path(project_dir or os.environ.get("CAYVPN_PROJECT_DIR") or Path.cwd()).resolve()
        state = Path(os.environ.get("CAYVPN_STATE_DIR", root / "data")).expanduser()
        config = Path(os.environ.get("CAYVPN_CONFIG_DIR", "/etc/cayvpn" if os.geteuid() == 0 else root / "config"))
        wg_dir = Path(os.environ.get("CAYVPN_WG_DIR", "/etc/wireguard" if os.geteuid() == 0 else root / "wireguard"))
        explicit_ula = os.environ.get("CAYVPN_ULA_PREFIX", "").strip()
        # Signed installs always persist a randomly generated prefix. The
        # deterministic path-based fallback exists only so an early 2.0
        # development node cannot change addresses merely because its web
        # session secret was rotated before the new setting was introduced.
        fallback_seed = f"{state.resolve()}:cayvpn-2"
        ula_prefix = normalize_ula_prefix(explicit_ula or generate_ula_prefix(fallback_seed))
        user_network_v6 = normalize_ula_subnet(
            ula_prefix,
            os.environ.get("CAYVPN_USER_NETWORK_V6", ula_subnet(ula_prefix, 1)),
            "The standard client IPv6 network",
        )
        amnezia_network_v6 = normalize_ula_subnet(
            ula_prefix,
            os.environ.get("CAYVPN_AMNEZIA_NETWORK_V6", ula_subnet(ula_prefix, 2)),
            "The Amnezia client IPv6 network",
        )
        egress_network_v6 = normalize_ula_subnet(
            ula_prefix,
            os.environ.get("CAYVPN_EGRESS_NETWORK_V6", ula_subnet(ula_prefix, 3)),
            "The exit namespace IPv6 network",
        )
        dns_network_v6 = ula_subnet(ula_prefix, 4)
        if len({user_network_v6, amnezia_network_v6, egress_network_v6, dns_network_v6}) != 4:
            raise ValueError("CayVPN's private IPv6 networks must not overlap")
        user_address_v6 = normalize_ula_interface(
            user_network_v6,
            os.environ.get("CAYVPN_USER_ADDRESS_V6", f"{ipaddress.ip_network(user_network_v6).network_address + 1}/64"),
            "The standard WireGuard IPv6 address",
        )
        amnezia_address_v6 = normalize_ula_interface(
            amnezia_network_v6,
            os.environ.get("CAYVPN_AMNEZIA_ADDRESS_V6", f"{ipaddress.ip_network(amnezia_network_v6).network_address + 1}/64"),
            "The AmneziaWG IPv6 address",
        )
        dns_network = ipaddress.IPv6Network(dns_network_v6, strict=True)

        def managed_dns_address(name: str, default_host: int) -> str:
            try:
                address = ipaddress.IPv6Address(
                    os.environ.get(name, str(dns_network.network_address + default_host))
                )
            except ValueError as exc:
                raise ValueError(f"{name} must be a valid private IPv6 address") from exc
            if address not in dns_network or address == dns_network.network_address:
                raise ValueError(f"{name} must be inside CayVPN's internal DNS IPv6 network")
            return str(address)

        client_dns_address_v6 = managed_dns_address("CAYVPN_CLIENT_DNS_ADDRESS_V6", 0x53)
        client_adblock_dns_address_v6 = managed_dns_address("CAYVPN_CLIENT_ADBLOCK_DNS_ADDRESS_V6", 0x54)
        if client_dns_address_v6 == client_adblock_dns_address_v6:
            raise ValueError("CayVPN's standard and ad-blocking IPv6 DNS addresses must be different")
        public_ipv6 = os.environ.get("CAYVPN_PUBLIC_IPV6", "").strip()
        if public_ipv6:
            try:
                observed_public_ipv6 = ipaddress.IPv6Address(public_ipv6)
            except ValueError as exc:
                raise ValueError("CAYVPN_PUBLIC_IPV6 must be a valid public IPv6 address") from exc
            if not observed_public_ipv6.is_global:
                raise ValueError("CAYVPN_PUBLIC_IPV6 must be globally routable")
            public_ipv6 = str(observed_public_ipv6)
        try:
            egress_network_v4 = ipaddress.IPv4Network(
                os.environ.get("CAYVPN_EGRESS_NETWORK_V4", "100.64.0.0/10"),
                strict=True,
            )
        except ValueError as exc:
            raise ValueError("CAYVPN_EGRESS_NETWORK_V4 must be a valid IPv4 network") from exc
        required_transport_addresses = (999999 * 4) + 3
        if egress_network_v4.num_addresses <= required_transport_addresses:
            raise ValueError(
                "CAYVPN_EGRESS_NETWORK_V4 is too small for CayVPN's Location transport addresses"
            )
        try:
            managed_networks_v4 = {
                "standard clients": ipaddress.IPv4Network(
                    os.environ.get("CAYVPN_USER_NETWORK", "10.8.0.0/24"),
                    strict=False,
                ),
                "Amnezia clients": ipaddress.IPv4Network(
                    os.environ.get("CAYVPN_AMNEZIA_NETWORK", "10.9.0.0/24"),
                    strict=False,
                ),
                "owner access": ipaddress.IPv4Network(
                    os.environ.get("CAYVPN_ADMIN_NETWORK", "10.255.0.0/24"),
                    strict=False,
                ),
            }
            managed_dns_v4 = (
                ipaddress.IPv4Address(
                    os.environ.get("CAYVPN_CLIENT_DNS_ADDRESS", "10.254.0.53")
                ),
                ipaddress.IPv4Address(
                    os.environ.get("CAYVPN_CLIENT_ADBLOCK_DNS_ADDRESS", "10.254.0.54")
                ),
            )
        except ValueError as exc:
            raise ValueError("CayVPN's managed IPv4 settings are invalid") from exc
        if (
            egress_network_v4.is_global
            or egress_network_v4.is_loopback
            or egress_network_v4.is_link_local
            or egress_network_v4.is_multicast
            or egress_network_v4.is_reserved
            or egress_network_v4.is_unspecified
        ):
            raise ValueError(
                "CAYVPN_EGRESS_NETWORK_V4 must be a non-public private transport network"
            )
        for label, managed_network in managed_networks_v4.items():
            if egress_network_v4.overlaps(managed_network):
                raise ValueError(
                    f"CAYVPN_EGRESS_NETWORK_V4 must not overlap {label}"
                )
        if any(address in egress_network_v4 for address in managed_dns_v4):
            raise ValueError(
                "CAYVPN_EGRESS_NETWORK_V4 must not contain CayVPN's DNS addresses"
            )
        proxy_token = os.environ.get("CAYVPN_PROXY_TOKEN", "").strip()
        if proxy_token and (
            len(proxy_token) < 32
            or len(proxy_token) > 128
            or not re.fullmatch(r"[A-Za-z0-9_-]+", proxy_token)
        ):
            raise ValueError("CAYVPN_PROXY_TOKEN must be a strong URL-safe token")

        return cls(
            project_dir=root,
            state_dir=state,
            config_dir=config,
            db_path=Path(os.environ.get("CAYVPN_DB_PATH", state / "cayvpn.db")),
            wg_dir=wg_dir,
            agent_socket=Path(os.environ.get("CAYVPN_AGENT_SOCKET", "/run/cayvpn/agent.sock" if os.geteuid() == 0 else state / "agent.sock")),
            release_dir=Path(os.environ.get("CAYVPN_RELEASE_DIR", "/opt/cayvpn/releases" if os.geteuid() == 0 else root / "releases")),
            active_release=Path(os.environ.get("CAYVPN_ACTIVE_RELEASE", "/opt/cayvpn/current" if os.geteuid() == 0 else root)),
            release_trust_key=Path(os.environ.get("CAYVPN_RELEASE_TRUST_KEY", config / "release.pub")),
            update_state_path=Path(os.environ.get("CAYVPN_UPDATE_STATE", state / "update-status.json")),
            update_metadata_path=Path(os.environ.get("CAYVPN_UPDATE_METADATA", config / "update-metadata.json")),
            update_repository=os.environ.get("CAYVPN_UPDATE_REPOSITORY", "caynetic/cayvpn"),
            server_ip=os.environ.get("SERVER_IP", "127.0.0.1"),
            server_ipv6=public_ipv6,
            server_region=os.environ.get("SERVER_REGION", "Unknown"),
            public_endpoint=os.environ.get("CAYVPN_PUBLIC_ENDPOINT", os.environ.get("SERVER_IP", "127.0.0.1")),
            out_interface=os.environ.get("CAYVPN_OUT_IFACE", ""),
            user_interface=os.environ.get("CAYVPN_USER_INTERFACE", "wg0"),
            user_port=int(os.environ.get("CAYVPN_USER_PORT", os.environ.get("WG_PORT", "43210"))),
            user_network=os.environ.get("CAYVPN_USER_NETWORK", "10.8.0.0/24"),
            user_address=os.environ.get("CAYVPN_USER_ADDRESS", "10.8.0.1/24"),
            ula_prefix=ula_prefix,
            user_network_v6=user_network_v6,
            user_address_v6=user_address_v6,
            client_dns_address=os.environ.get("CAYVPN_CLIENT_DNS_ADDRESS", "10.254.0.53"),
            client_adblock_dns_address=os.environ.get("CAYVPN_CLIENT_ADBLOCK_DNS_ADDRESS", "10.254.0.54"),
            client_dns_address_v6=client_dns_address_v6,
            client_adblock_dns_address_v6=client_adblock_dns_address_v6,
            amnezia_interface=os.environ.get("CAYVPN_AMNEZIA_INTERFACE", "awg0"),
            amnezia_port=int(os.environ.get("CAYVPN_AMNEZIA_PORT", "43211")),
            amnezia_network=os.environ.get("CAYVPN_AMNEZIA_NETWORK", "10.9.0.0/24"),
            amnezia_address=os.environ.get("CAYVPN_AMNEZIA_ADDRESS", "10.9.0.1/24"),
            amnezia_network_v6=amnezia_network_v6,
            amnezia_address_v6=amnezia_address_v6,
            egress_network_v4=str(egress_network_v4),
            egress_network_v6=egress_network_v6,
            admin_interface=os.environ.get("CAYVPN_ADMIN_INTERFACE", "wg-admin"),
            admin_port=int(os.environ.get("CAYVPN_ADMIN_PORT", "51821")),
            admin_network=os.environ.get("CAYVPN_ADMIN_NETWORK", "10.255.0.0/24"),
            admin_address=os.environ.get("CAYVPN_ADMIN_ADDRESS", "10.255.0.1/24"),
            admin_hostname=os.environ.get("CAYVPN_ADMIN_HOSTNAME", "admin.cayvpn.home.arpa"),
            admin_https_port=int(os.environ.get("CAYVPN_ADMIN_HTTPS_PORT", "8443")),
            remote_admin_port=int(os.environ.get("CAYVPN_REMOTE_ADMIN_PORT", "443")),
            remote_admin_acme_server=os.environ.get(
                "CAYVPN_REMOTE_ADMIN_ACME_SERVER",
                "https://acme-v02.api.letsencrypt.org/directory",
            ),
            remote_admin_acme_profile=os.environ.get(
                "CAYVPN_REMOTE_ADMIN_ACME_PROFILE", "shortlived"
            ),
            remote_admin_webroot=Path(
                os.environ.get(
                    "CAYVPN_REMOTE_ADMIN_WEBROOT",
                    "/run/cayvpn-public-acme"
                    if os.geteuid() == 0
                    else root / "config" / "remote-admin-webroot",
                )
            ),
            proxy_token=proxy_token,
            https_enabled=_env_bool("ENABLE_HTTPS", True),
            tls_cert_path=Path(os.environ.get("CAYVPN_TLS_CERT", "/etc/cayvpn/tls/server.crt")),
            tls_key_path=Path(os.environ.get("CAYVPN_TLS_KEY", "/etc/cayvpn/tls/server.key")),
            trust_cert_path=Path(os.environ.get("CAYVPN_TRUST_CERT", "/etc/cayvpn/tls/ca.crt")),
            secret_key_path=Path(os.environ.get("CAYVPN_SECRET_KEY_FILE", "/etc/cayvpn/agent.key" if os.geteuid() == 0 else root / "config" / "agent.key")),
            agent_inline=_env_bool("CAYVPN_AGENT_INLINE", False),
            apply_network=_env_bool("CAYVPN_APPLY_NETWORK", False),
            log_level=os.environ.get("CAYVPN_LOG_LEVEL", "INFO"),
        )

    def ensure_directories(self) -> None:
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.wg_dir.mkdir(parents=True, exist_ok=True)
