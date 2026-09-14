from __future__ import annotations

import ipaddress
import hmac
import json
import os
import shutil
import stat
from pathlib import Path
from urllib.parse import urlsplit

from .components import ensure_lego
from .config import Settings


LETS_ENCRYPT_DIRECTORY = "https://acme-v02.api.letsencrypt.org/directory"


class RemoteAdminError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


class RemoteAdminManager:
    """Apply the fixed public-admin TLS, nginx, and firewall design.

    The web process can request only enable, disable, or renewal.  Paths,
    listeners, ACME service, certificate profile, nginx directives, and
    nftables syntax all come from root-controlled settings and this template;
    no raw configuration or command reaches the restricted agent.
    """

    def __init__(self, settings: Settings, runner):
        self.settings = settings
        self.runner = runner
        self.root = settings.config_dir / "remote-admin"
        # The ACME challenge contains no key material and must be readable by
        # nginx's unprivileged worker. Keep it outside the root-only directory
        # that stores the ACME account and certificate private key.
        self.webroot = settings.remote_admin_webroot
        self.acme_path = self.root / "acme"
        self.nginx_config = settings.config_dir / "nginx" / "remote-admin.conf"
        self.firewall_fragment = settings.config_dir / "firewall" / "remote-admin.nft"
        self.nftables_config = Path(
            os.environ.get("CAYVPN_NFTABLES_CONFIG", "/etc/nftables.conf")
        )
        self.nginx_link = Path(
            os.environ.get(
                "CAYVPN_REMOTE_ADMIN_NGINX_LINK",
                "/etc/nginx/sites-enabled/cayvpn-remote",
            )
        )
        self.nginx = shutil.which("nginx") or "nginx"
        self.nft = shutil.which("nft") or "nft"
        self.systemctl = shutil.which("systemctl") or "systemctl"
        self.openssl = shutil.which("openssl") or "openssl"
        self.ss = shutil.which("ss") or "ss"

    def _public_ipv4(self) -> str:
        try:
            address = ipaddress.ip_address(self.settings.public_endpoint)
        except ValueError as exc:
            raise RemoteAdminError(
                "remote_admin_address_invalid",
                "The VPS public IPv4 address is invalid",
            ) from exc
        if address.version != 4 or (
            self.settings.apply_network and not address.is_global
        ):
            raise RemoteAdminError(
                "remote_admin_address_invalid",
                "Remote administration requires the VPS's globally routable IPv4 address",
            )
        return str(address)

    def public_origin(self) -> str:
        address = self._public_ipv4()
        suffix = "" if self.settings.remote_admin_port == 443 else f":{self.settings.remote_admin_port}"
        return f"https://{address}{suffix}"

    def _validate_fixed_settings(self) -> None:
        if self.settings.apply_network and not self.settings.proxy_token:
            raise RemoteAdminError(
                "remote_admin_proxy_auth_missing",
                "The authenticated CayVPN web proxy is not configured",
            )
        if self.settings.remote_admin_port != 443:
            raise RemoteAdminError(
                "remote_admin_port_invalid",
                "Remote administration must use the standard HTTPS port 443",
            )
        parsed = urlsplit(self.settings.remote_admin_acme_server)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.fragment
        ):
            raise RemoteAdminError(
                "remote_admin_acme_invalid",
                "The configured certificate authority URL is invalid",
            )
        if self.settings.remote_admin_acme_server != LETS_ENCRYPT_DIRECTORY:
            raise RemoteAdminError(
                "remote_admin_acme_invalid",
                "Remote administration must use CayVPN's fixed Let's Encrypt certificate service",
            )
        if self.settings.remote_admin_acme_profile != "shortlived":
            raise RemoteAdminError(
                "remote_admin_acme_invalid",
                "Public-IP certificates must use the short-lived ACME profile",
            )

    @staticmethod
    def disabled_nginx_config() -> str:
        return "# CayVPN remote administration is disabled.\n"

    @staticmethod
    def firewall_config(ports: tuple[int, ...] = ()) -> str:
        values = ", ".join(str(port) for port in ports)
        elements = f"    elements = {{ {values} }}\n" if ports else ""
        return (
            "  set cayvpn_remote_admin_ports {\n"
            "    type inet_service;\n"
            f"{elements}"
            "  }\n"
        )

    def challenge_nginx_config(self) -> str:
        address = self._public_ipv4()
        return f"""server {{
  listen {address}:80;
  server_name {address};
  access_log off;
  location ^~ /.well-known/acme-challenge/ {{
    root {self.webroot};
    default_type text/plain;
    try_files $uri =404;
  }}
  location / {{ return 404; }}
}}
"""

    def enabled_nginx_config(self, certificate: Path, private_key: Path) -> str:
        address = self._public_ipv4()
        origin = self.public_origin()
        proxy = f"""    proxy_pass http://127.0.0.1:8080;
    proxy_set_header Host $http_host;
    proxy_set_header X-Forwarded-Proto https;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $remote_addr;
    proxy_set_header X-CayVPN-Proxy-Token {self.settings.proxy_token};
"""
        return f"""limit_req_zone $binary_remote_addr zone=cayvpn_remote_login:10m rate=10r/m;

server {{
  listen {address}:80;
  server_name {address};
  access_log off;
  location ^~ /.well-known/acme-challenge/ {{
    root {self.webroot};
    default_type text/plain;
    try_files $uri =404;
  }}
  location / {{ return 308 {origin}$request_uri; }}
}}

server {{
  listen {address}:{self.settings.remote_admin_port} ssl;
  server_name {address};
  ssl_certificate {certificate};
  ssl_certificate_key {private_key};
  ssl_protocols TLSv1.2 TLSv1.3;
  ssl_session_tickets off;
  client_max_body_size 2m;
  add_header X-Content-Type-Options nosniff always;
  add_header X-Frame-Options DENY always;
  add_header Referrer-Policy same-origin always;
  location = /login {{
    limit_req zone=cayvpn_remote_login burst=5 nodelay;
    limit_req_status 429;
{proxy}  }}
  location / {{
{proxy}  }}
}}
"""

    def _write(self, path: Path, content: str, mode: int = 0o640) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(f".{path.name}.new")
        temporary.write_text(content, encoding="utf-8")
        temporary.chmod(mode)
        os.replace(temporary, path)

    def _run_required(self, argv: list[str], timeout: int, message: str):
        result = self.runner.run(argv, timeout=timeout)
        if result.returncode != 0:
            detail = (result.stderr or result.stdout or "").strip()
            raise RemoteAdminError(
                "remote_admin_apply_failed",
                f"{message}{': ' + detail[:300] if detail else ''}",
            )
        return result

    def _require_install_hooks(self) -> None:
        if not self.nftables_config.is_file():
            raise RemoteAdminError(
                "remote_admin_not_installed",
                "The CayVPN firewall configuration is missing",
            )
        nftables = self.nftables_config.read_text(encoding="utf-8")
        expected_include = f'include "{self.firewall_fragment}"'
        expected_rule = "tcp dport @cayvpn_remote_admin_ports accept"
        if expected_include not in nftables or expected_rule not in nftables:
            raise RemoteAdminError(
                "remote_admin_not_installed",
                "This CayVPN installation needs the remote-access firewall update first",
            )
        if not self.nginx_link.is_symlink():
            raise RemoteAdminError(
                "remote_admin_not_installed",
                "This CayVPN installation needs the remote-access HTTPS update first",
            )
        try:
            link_target = self.nginx_link.resolve(strict=False)
        except OSError as exc:
            raise RemoteAdminError(
                "remote_admin_not_installed",
                "The remote-access HTTPS configuration link is invalid",
            ) from exc
        if link_target != self.nginx_config.resolve(strict=False):
            raise RemoteAdminError(
                "remote_admin_not_installed",
                "The remote-access HTTPS configuration link is not managed by CayVPN",
            )

    @classmethod
    def _firewall_ports(cls, content: str) -> tuple[int, ...]:
        for ports in ((), (80,), (80, 443)):
            if hmac.compare_digest(content, cls.firewall_config(ports)):
                return ports
        raise RemoteAdminError(
            "remote_admin_firewall_invalid",
            "The saved remote-access firewall state is not managed by CayVPN",
        )

    @staticmethod
    def _firewall_runtime_batch(ports: tuple[int, ...]) -> str:
        lines = ["flush set inet cayvpn cayvpn_remote_admin_ports"]
        if ports:
            values = ", ".join(str(port) for port in ports)
            lines.append(
                f"add element inet cayvpn cayvpn_remote_admin_ports {{ {values} }}"
            )
        return "\n".join(lines) + "\n"

    def _apply_firewall(self, ports: tuple[int, ...]) -> None:
        ports = tuple(ports)
        if ports not in {(), (80,), (80, 443)}:
            raise RemoteAdminError(
                "remote_admin_firewall_invalid",
                "CayVPN accepts only its fixed remote-access ports",
            )
        self._write(self.firewall_fragment, self.firewall_config(ports))
        self._run_required(
            [self.nft, "-c", "-f", str(self.nftables_config)],
            20,
            "The updated firewall configuration did not validate",
        )
        runtime_batch = (
            self.settings.config_dir
            / "runtime"
            / f"remote-admin-ports-{os.getpid()}.nft"
        )
        self._write(runtime_batch, self._firewall_runtime_batch(ports), 0o600)
        try:
            self._run_required(
                [self.nft, "-c", "-f", str(runtime_batch)],
                20,
                "The live firewall update did not validate",
            )
            self._run_required(
                [self.nft, "-f", str(runtime_batch)],
                20,
                "The updated firewall configuration could not be applied",
            )
        finally:
            runtime_batch.unlink(missing_ok=True)

    def _apply_nginx(self, content: str) -> None:
        self._write(self.nginx_config, content)
        self._run_required(
            [self.nginx, "-t"],
            20,
            "The updated HTTPS configuration did not validate",
        )
        self._run_required(
            [self.systemctl, "reload", "nginx"],
            30,
            "The HTTPS service could not reload",
        )

    def _certificate_paths(self) -> tuple[Path, Path]:
        name = self._public_ipv4()
        directory = self.acme_path / "certificates"
        return directory / f"{name}.crt", directory / f"{name}.key"

    def _certificate_valid(self, certificate: Path, private_key: Path) -> bool:
        if not certificate.is_file() or not private_key.is_file():
            return False
        cert = self.runner.run(
            [self.openssl, "x509", "-in", str(certificate), "-noout", "-checkend", "86400"],
            timeout=15,
        )
        key = self.runner.run(
            [self.openssl, "pkey", "-in", str(private_key), "-check"],
            timeout=15,
        )
        san = self.runner.run(
            [self.openssl, "x509", "-in", str(certificate), "-noout", "-ext", "subjectAltName"],
            timeout=15,
        )
        cert_public_key = self.runner.run(
            [self.openssl, "x509", "-in", str(certificate), "-noout", "-pubkey"],
            timeout=15,
        )
        private_public_key = self.runner.run(
            [self.openssl, "pkey", "-in", str(private_key), "-pubout"],
            timeout=15,
        )
        matching_key = (
            cert_public_key.returncode == 0
            and private_public_key.returncode == 0
            and bool((cert_public_key.stdout or "").strip())
            and hmac.compare_digest(
                (cert_public_key.stdout or "").strip(),
                (private_public_key.stdout or "").strip(),
            )
        )
        return (
            cert.returncode == 0
            and key.returncode == 0
            and san.returncode == 0
            and f"IP Address:{self._public_ipv4()}" in (san.stdout or "")
            and matching_key
        )

    def _obtain_or_renew_certificate(
        self, lego: str, *, accept_terms: bool
    ) -> tuple[Path, Path]:
        certificate, private_key = self._certificate_paths()
        if not accept_terms and not certificate.is_file():
            raise RemoteAdminError(
                "remote_admin_certificate_missing",
                "Remote administration is enabled but its HTTPS certificate is missing; review and enable owner login again",
            )
        command = [
            lego,
            "run",
            "--server",
            self.settings.remote_admin_acme_server,
            "--path",
            str(self.acme_path),
            "--http",
            "--http.webroot",
            str(self.webroot),
            "--domains",
            self._public_ipv4(),
            "--key-type",
            "EC256",
            "--profile",
            self.settings.remote_admin_acme_profile,
            "--renew-days",
            "3",
            # The systemd timer already randomizes renewal by six hours. Avoid
            # an additional client-side sleep exceeding the bounded agent call.
            "--no-random-sleep",
            "--ipv4only",
        ]
        if accept_terms:
            command.insert(2, "--accept-tos")
        self._run_required(
            command,
            240,
            "CayVPN could not obtain the short-lived HTTPS certificate",
        )
        if not self._certificate_valid(certificate, private_key):
            raise RemoteAdminError(
                "remote_admin_certificate_invalid",
                "The new HTTPS certificate did not verify for this VPS address",
            )
        private_key.chmod(stat.S_IRUSR | stat.S_IWUSR)
        return certificate, private_key

    def configure(self, enabled: bool) -> dict:
        self._validate_fixed_settings()
        origin = self.public_origin()
        if not self.settings.apply_network:
            return {
                "state": "planned",
                "enabled": bool(enabled),
                "public_origin": origin,
                "certificate": "shortlived_ip" if enabled else "none",
            }
        self._require_install_hooks()
        old_nginx = (
            self.nginx_config.read_text(encoding="utf-8")
            if self.nginx_config.is_file()
            else self.disabled_nginx_config()
        )
        old_firewall = (
            self.firewall_fragment.read_text(encoding="utf-8")
            if self.firewall_fragment.is_file()
            else self.firewall_config()
        )
        old_ports = self._firewall_ports(old_firewall)

        def restore_previous_state() -> None:
            errors: list[str] = []
            try:
                # Close public access first. Restoring content must never leave
                # ports open merely because an nginx rollback also failed.
                self._apply_firewall(())
            except Exception as exc:
                errors.append(str(exc))
            try:
                self._apply_nginx(old_nginx)
            except Exception as exc:
                errors.append(str(exc))
            if not errors and old_ports:
                try:
                    self._apply_firewall(old_ports)
                except Exception as exc:
                    errors.append(str(exc))
            if not errors:
                report = self.verify_state(bool(old_ports))
                if not report.get("healthy"):
                    errors.append("the restored remote-access state did not verify")
            if errors:
                raise RemoteAdminError(
                    "remote_admin_rollback_failed",
                    "Remote-access rollback needs SSH recovery: "
                    + "; ".join(errors)[:500],
                )

        if not enabled:
            try:
                self._apply_firewall(())
                self._apply_nginx(self.disabled_nginx_config())
                if not self.verify_state(False).get("healthy"):
                    raise RemoteAdminError(
                        "remote_admin_apply_failed",
                        "The closed remote-access state did not verify",
                    )
            except Exception as exc:
                try:
                    restore_previous_state()
                except Exception as rollback_exc:
                    raise rollback_exc from exc
                raise
            return {"state": "disabled", "enabled": False, "public_origin": origin}

        component = ensure_lego(self.settings)
        lego = component.get("paths", {}).get("lego")
        if not lego:
            raise RemoteAdminError(
                "remote_admin_component_missing",
                "The pinned HTTPS certificate component is not installed",
            )
        self.webroot.mkdir(parents=True, exist_ok=True)
        self.acme_path.mkdir(parents=True, exist_ok=True)
        self.root.chmod(0o700)
        self.webroot.chmod(0o755)
        self.acme_path.chmod(0o700)
        try:
            self._apply_nginx(self.challenge_nginx_config())
            self._apply_firewall((80,))
            certificate, private_key = self._obtain_or_renew_certificate(
                str(lego), accept_terms=True
            )
            self._apply_nginx(self.enabled_nginx_config(certificate, private_key))
            self._apply_firewall((80, 443))
            if not self.verify_state(True).get("healthy"):
                raise RemoteAdminError(
                    "remote_admin_apply_failed",
                    "The enabled remote-access state did not verify",
                )
        except Exception as exc:
            try:
                restore_previous_state()
            except Exception as rollback_exc:
                raise rollback_exc from exc
            raise
        return {
            "state": "enabled",
            "enabled": True,
            "public_origin": origin,
            "certificate": "shortlived_ip",
        }

    def renew(self) -> dict:
        self._validate_fixed_settings()
        if not self.settings.apply_network:
            return {"state": "planned", "renewed": False}
        self._require_install_hooks()
        component = ensure_lego(self.settings)
        lego = component.get("paths", {}).get("lego")
        if not lego:
            raise RemoteAdminError(
                "remote_admin_component_missing",
                "The pinned HTTPS certificate component is not installed",
            )
        certificate, private_key = self._obtain_or_renew_certificate(
            str(lego), accept_terms=False
        )
        self._apply_nginx(self.enabled_nginx_config(certificate, private_key))
        return {
            "state": "enabled",
            "renewed": True,
            "public_origin": self.public_origin(),
        }

    def verify_state(self, expected_enabled: bool) -> dict:
        """Verify the persisted and live public-admin state without changing it."""

        self._validate_fixed_settings()
        if not self.settings.apply_network:
            return {
                "expected_enabled": bool(expected_enabled),
                "configuration": True,
                "nginx_config": True,
                "firewall_live": True,
                "listeners": True,
                "certificate": True,
                "healthy": True,
                "simulated": True,
            }
        self._require_install_hooks()
        certificate, private_key = self._certificate_paths()
        expected_nginx = (
            self.enabled_nginx_config(certificate, private_key)
            if expected_enabled
            else self.disabled_nginx_config()
        )
        expected_firewall = self.firewall_config((80, 443) if expected_enabled else ())
        try:
            configuration_matches = (
                self.nginx_config.is_file()
                and self.firewall_fragment.is_file()
                and hmac.compare_digest(
                    self.nginx_config.read_text(encoding="utf-8"), expected_nginx
                )
                and hmac.compare_digest(
                    self.firewall_fragment.read_text(encoding="utf-8"),
                    expected_firewall,
                )
            )
        except OSError:
            configuration_matches = False

        nginx_check = self.runner.run([self.nginx, "-t"], timeout=20)
        live_firewall = self.runner.run(
            [
                self.nft,
                "-j",
                "-n",
                "list",
                "set",
                "inet",
                "cayvpn",
                "cayvpn_remote_admin_ports",
            ],
            timeout=15,
        )
        live_ports = None
        if live_firewall.returncode == 0:
            try:
                payload = json.loads(live_firewall.stdout or "")
                matching_sets = [
                    item["set"]
                    for item in payload.get("nftables", [])
                    if isinstance(item, dict)
                    and isinstance(item.get("set"), dict)
                    and item["set"].get("family") == "inet"
                    and item["set"].get("table") == "cayvpn"
                    and item["set"].get("name") == "cayvpn_remote_admin_ports"
                    and item["set"].get("type") == "inet_service"
                ]
                if len(matching_sets) == 1:
                    elements = matching_sets[0].get("elem", [])
                    if isinstance(elements, list) and all(
                        isinstance(value, int)
                        and not isinstance(value, bool)
                        and 1 <= value <= 65535
                        for value in elements
                    ):
                        live_ports = set(elements)
            except (AttributeError, json.JSONDecodeError, TypeError, ValueError):
                live_ports = None
        firewall_live = live_ports == ({80, 443} if expected_enabled else set())

        listeners = True
        if expected_enabled:
            address = self._public_ipv4()
            sockets = self.runner.run([self.ss, "-H", "-lnt"], timeout=15)
            fields = {
                field
                for line in (sockets.stdout or "").splitlines()
                for field in line.split()
            }
            listeners = sockets.returncode == 0 and all(
                f"{address}:{port}" in fields for port in (80, 443)
            )

        certificate_valid = (
            self._certificate_valid(certificate, private_key)
            if expected_enabled
            else True
        )
        report = {
            "expected_enabled": bool(expected_enabled),
            "configuration": configuration_matches,
            "nginx_config": nginx_check.returncode == 0,
            "firewall_live": firewall_live,
            "listeners": listeners,
            "certificate": certificate_valid,
        }
        report["healthy"] = all(
            report[key]
            for key in (
                "configuration",
                "nginx_config",
                "firewall_live",
                "listeners",
                "certificate",
            )
        )
        return report
