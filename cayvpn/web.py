from __future__ import annotations

import base64
import hashlib
import hmac
import io
import ipaddress
import json
import logging
import os
import secrets
import time
import uuid
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path

import qrcode
from cachelib.file import FileSystemCache
from flask import Flask, abort, flash, jsonify, redirect, render_template, request, send_file, session, url_for
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_session import Session
from flask_wtf.csrf import CSRFProtect
from sqlalchemy import desc, func, select
from urllib.parse import urlsplit
from werkzeug.middleware.proxy_fix import ProxyFix
from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url, options_to_json
from webauthn.helpers.structs import AuthenticatorSelectionCriteria, ResidentKeyRequirement, UserVerificationRequirement

from . import __version__
from .agent import NodeExecutor
from .backup import create_backup
from .capacity import CapacityEstimate, calculate_capacity, detect_resources, transfer_forecast
from .components import component_binary
from .config import Settings, admin_dns_search_domain
from .db import Database
from .dual_stack import address_in_network, capabilities_for_api, family_capabilities, ipv6_usable, merge_capability_observation, normalize_capabilities
from .drivers import DriverValidationError, generate_keypair, parse_socks5, redacted_profile, validate_driver
from .dns_service import blocklist_available
from .models import (
    AdminDevice,
    AuditEvent,
    BackupRecord,
    CLIENT_CONFIG_VERSION,
    CapacitySnapshot,
    Client,
    EgressPool,
    EgressProfile,
    IngressEndpoint,
    ManagedNode,
    Operation,
    PasskeyCredential,
    RouteBinding,
    Setting,
    WizardDraft,
)
from .operations import OperationService, effective_profile_capabilities, profile_supports_required_ipv6
from .protocol import AgentClient, AgentRequest
from .security import SecretBox, hash_password, is_admin_network_address, is_network_address, now_epoch, token, verify_password


logger = logging.getLogger(__name__)


def _config_download_name(name: str) -> str:
    """Return a recognizable, browser-safe WireGuard configuration filename."""
    cleaned = "".join(character if character.isalnum() or character in "._-" else "-" for character in name.strip())
    while "--" in cleaned:
        cleaned = cleaned.replace("--", "-")
    return f"{cleaned.strip('._-') or 'CayVPN-device'}.conf"


def _client_ip(network: str, offset: int) -> str:
    parsed = ipaddress.ip_network(network, strict=False)
    candidate = parsed.network_address + offset + 1
    if candidate >= parsed.broadcast_address:
        raise ValueError("The configured client network is full")
    return str(candidate)


def _available_ipv6_address(network: str, used: set[str], host_id: int) -> str:
    while True:
        candidate = address_in_network(network, host_id).split("/", 1)[0]
        if candidate not in used:
            return candidate
        host_id += 1


def _server_address(settings: Settings) -> str:
    return str(ipaddress.ip_interface(settings.user_address).ip)


def _safe_text(value: str | None, limit: int = 120) -> str:
    value = " ".join((value or "").split())
    return value[:limit]


def _friendly_location_message(value: object) -> str:
    """Translate internal routing terms only when showing them in the owner UI."""
    message = str(value)
    for internal, friendly in (
        ("Failover pools", "Backup groups"),
        ("Failover pool", "Backup group"),
        ("failover pools", "backup groups"),
        ("failover pool", "backup group"),
        ("Exits", "Locations"),
        ("Exit", "Location"),
        ("exits", "Locations"),
        ("exit", "Location"),
    ):
        message = message.replace(internal, friendly)
    return message


def _qr_b64(value: str) -> str:
    image = qrcode.make(value)
    buffer = io.BytesIO()
    image.save(buffer, "PNG")
    return base64.b64encode(buffer.getvalue()).decode()


def _json(value, default=None):
    try:
        return json.loads(value or "{}")
    except (TypeError, ValueError):
        return default if default is not None else {}


def _apply_egress_observation(profile: EgressProfile, result: dict) -> None:
    """Persist only typed, display-safe observations returned by the agent."""
    if not isinstance(result, dict):
        return
    capabilities = merge_capability_observation(profile.capabilities_storage, result)
    profile.capabilities_json = json.dumps(capabilities, sort_keys=True)

    def observed_address(*keys: str, version: int) -> str | None:
        observed = next((str(result.get(key) or "").strip() for key in keys if key in result), "")
        if not observed:
            return None
        try:
            parsed = ipaddress.ip_address(observed)
            if parsed.version != version or not parsed.is_global:
                raise ValueError("invalid observed exit")
            return str(parsed)
        except ValueError:
            return None

    if "observed_exit_ipv4" in result or "observed_exit_ip" in result:
        profile.observed_exit_ip = observed_address("observed_exit_ipv4", "observed_exit_ip", version=4)
    if "observed_exit_ipv6" in result:
        profile.observed_exit_ipv6 = observed_address("observed_exit_ipv6", version=6)
    if "ipv6_health_state" in result:
        reported_state = str(result.get("ipv6_health_state") or "pending")
        profile.ipv6_health_state = reported_state if reported_state in {"pending", "healthy", "active", "unhealthy", "blocked", "unavailable"} else "pending"
    elif profile.observed_exit_ipv6 and ipv6_usable(capabilities):
        profile.ipv6_health_state = "healthy"


def create_app(project_dir: str | Path | None = None, settings: Settings | None = None) -> Flask:
    settings = settings or Settings.from_env(project_dir)
    settings.ensure_directories()
    db = Database(settings)
    db.initialize_defaults(settings)
    secret_box = SecretBox()
    executor = NodeExecutor(settings) if settings.agent_inline else None
    agent = AgentClient(settings.agent_socket, inline_executor=executor.execute if executor else None)
    operations = OperationService(db, agent)

    def agent_secret_store(value: str, label: str) -> str:
        _, response = operations.run("secret.store", {"value": value, "label": label}, actor="owner")
        if response.status != "succeeded" or not response.result.get("secret_ref"):
            raise ValueError(response.error_message or "The root agent could not store the secret")
        return str(response.result["secret_ref"])

    def reveal_secret(reference: str | None) -> str | None:
        if not reference:
            return None
        if not reference.startswith("ref::"):
            # Fresh installed state always stores a root-agent reference.
            # Keep locally rendered values readable for development fixtures.
            return secret_box.decrypt(reference)

    def delete_secret(reference: str | None, actor: str = "owner") -> bool:
        if reference and reference.startswith("ref::"):
            _operation, response = operations.run("secret.delete", {"secret_ref": reference}, actor=actor)
            return response.status == "succeeded"
        return True

    wizard_steps = {"client": 3, "exit": 5, "pool": 4}
    legacy_client_steps = 5

    def client_wizard_step_for_data(data: dict) -> int:
        """Map both current and legacy client drafts onto the three-step flow."""
        if not data.get("name") or data.get("ingress_protocol") not in {"wireguard", "amneziawg"}:
            return 1
        if data.get("dns_mode") not in {"standard", "ad_blocking"} or data.get("route_choice") not in {
            "direct",
            "exit",
            "pool",
        }:
            return 2
        return 3

    def wizard_resume_step(draft: WizardDraft) -> int:
        if draft.kind == "client":
            return client_wizard_step_for_data(draft.data)
        return min(draft.current_step, wizard_steps.get(draft.kind, draft.current_step))

    def wizard_total_steps(kind: str) -> int:
        return wizard_steps.get(kind, 1)

    def create_wizard_draft(kind: str) -> WizardDraft:
        if kind not in wizard_steps:
            raise ValueError("Unsupported setup type")
        with db.session() as session_db:
            draft = WizardDraft(kind=kind, data_json="{}", current_step=1, expires_at=datetime.now(timezone.utc) + timedelta(hours=24))
            session_db.add(draft)
            session_db.flush()
            draft_id = draft.id
        with db.session() as session_db:
            return session_db.get(WizardDraft, draft_id)

    def load_wizard_draft(draft_id: str, kind: str | None = None) -> WizardDraft:
        with db.session() as session_db:
            draft = session_db.get(WizardDraft, draft_id)
        if draft is None or (kind is not None and draft.kind != kind):
            abort(404)
        expires_at = draft.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if expires_at <= datetime.now(timezone.utc):
            if draft.secret_ref and not delete_secret(draft.secret_ref, actor="wizard-expiry"):
                abort(503, description="This saved setup expired, but its temporary configuration could not be removed safely. Nothing was discarded; try again after the root agent is available.")
            with db.session() as session_db:
                expired = session_db.get(WizardDraft, draft_id)
                if expired is not None:
                    session_db.delete(expired)
            abort(410, description="This saved setup expired after 24 hours. Start again; any temporary configuration was removed.")
        return draft

    def save_wizard_draft(draft_id: str, data: dict, step: int, secret_ref: str | None | object = ...) -> None:
        with db.session() as session_db:
            draft = session_db.get(WizardDraft, draft_id)
            if draft is None:
                abort(404)
            draft.data_json = json.dumps(data, sort_keys=True)
            draft.current_step = step
            draft.expires_at = datetime.now(timezone.utc) + timedelta(hours=24)
            if secret_ref is not ...:
                draft.secret_ref = secret_ref

    def delete_wizard_draft(draft_id: str, *, keep_secret: bool = False, actor: str = "owner") -> bool:
        with db.session() as session_db:
            draft = session_db.get(WizardDraft, draft_id)
            if draft is None:
                return True
            secret_ref = draft.secret_ref
        if secret_ref and not keep_secret and not delete_secret(secret_ref, actor=actor):
            return False
        with db.session() as session_db:
            draft = session_db.get(WizardDraft, draft_id)
            if draft is not None:
                session_db.delete(draft)
        return True

    def active_wizard_drafts(kind: str | None = None) -> list[WizardDraft]:
        now = datetime.now(timezone.utc)
        with db.session() as session_db:
            query = select(WizardDraft).order_by(WizardDraft.updated_at.desc())
            if kind:
                query = query.where(WizardDraft.kind == kind)
            drafts = session_db.scalars(query).all()
        active = []
        for draft in drafts:
            expires_at = draft.expires_at
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)
            if expires_at > now:
                active.append(draft)
        return active

    app = Flask(__name__, template_folder=str(settings.project_dir / "templates"), static_folder=str(settings.project_dir / "static"))
    app.config.update(
        SECRET_KEY=os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32),
        SESSION_TYPE="cachelib",
        SESSION_FILE_DIR=str(settings.state_dir / "sessions"),
        SESSION_CACHELIB=FileSystemCache(str(settings.state_dir / "sessions"), threshold=500, mode=0o700),
        SESSION_PERMANENT=True,
        PERMANENT_SESSION_LIFETIME=3600,
        SESSION_COOKIE_SECURE=settings.https_enabled,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",
        SESSION_COOKIE_NAME="cayvpn_session",
        MAX_CONTENT_LENGTH=2 * 1024 * 1024,
        CAYVPN_SETTINGS=settings,
    )
    # The private and optional public nginx listeners authenticate their hop
    # to Gunicorn with a root-installed token. A different localhost process
    # can reach the loopback port, but cannot make an X-Forwarded-For value
    # look like an owner tunnel address. Forwarded Host is never trusted.
    direct_wsgi_app = app.wsgi_app
    proxied_wsgi_app = ProxyFix(direct_wsgi_app, x_for=1, x_proto=1, x_host=0)

    def authenticated_proxy(environ, start_response):
        supplied = str(environ.pop("HTTP_X_CAYVPN_PROXY_TOKEN", ""))
        trusted = bool(settings.proxy_token) and hmac.compare_digest(
            supplied, settings.proxy_token
        )
        if trusted:
            return proxied_wsgi_app(environ, start_response)
        for header in (
            "HTTP_X_FORWARDED_FOR",
            "HTTP_X_FORWARDED_PROTO",
            "HTTP_X_FORWARDED_HOST",
            "HTTP_X_FORWARDED_PORT",
            "HTTP_X_FORWARDED_PREFIX",
            "HTTP_X_REAL_IP",
        ):
            environ.pop(header, None)
        return direct_wsgi_app(environ, start_response)

    app.wsgi_app = authenticated_proxy
    (settings.state_dir / "sessions").mkdir(parents=True, exist_ok=True)
    Session(app)
    csrf = CSRFProtect(app)
    # CayVPN has no required hosted dependency.  A node can opt into a local
    # Redis instance through the environment; otherwise an explicit in-process
    # store keeps the security default visible and avoids the library's silent
    # fallback warning.
    limiter = Limiter(
        key_func=get_remote_address,
        app=app,
        storage_uri=os.environ.get("CAYVPN_RATE_LIMIT_STORAGE_URI", "memory://"),
        default_limits=["200 per day", "50 per hour"],
        # Once an owner session is authenticated, ordinary read-only page and
        # asset navigation must not consume the small unauthenticated budget.
        # Mutating requests still use the global ceiling, and the login and
        # approval POST routes retain their stricter endpoint limits.
        default_limits_exempt_when=lambda: request.method in {"GET", "HEAD", "OPTIONS"}
        and session.get("authenticated") is True,
    )
    app.extensions.update(cayvpn_db=db, cayvpn_settings=settings, cayvpn_secret_box=secret_box, cayvpn_operations=operations)

    admin_ip = str(ipaddress.ip_interface(settings.admin_address).ip)
    private_hosts = {settings.admin_hostname.lower(), admin_ip, "localhost", "127.0.0.1"}
    try:
        remote_admin_host = str(ipaddress.IPv4Address(settings.public_endpoint))
    except ValueError:
        remote_admin_host = ""

    def remote_admin_enabled() -> bool:
        return db.get_setting("remote_admin_enabled", "0") == "1"

    def allowed_hosts() -> set[str]:
        hosts = set(private_hosts)
        if remote_admin_enabled() and remote_admin_host:
            hosts.add(remote_admin_host)
        return hosts

    def request_hostname() -> str:
        try:
            return (urlsplit(f"//{request.host}").hostname or "").lower()
        except ValueError:
            return ""

    def request_effective_port() -> int | None:
        try:
            parsed = urlsplit(f"//{request.host}")
            return parsed.port or (443 if request.is_secure else 80)
        except ValueError:
            return None

    def request_uses_remote_origin() -> bool:
        return bool(
            remote_admin_enabled()
            and remote_admin_host
            and request_hostname() == remote_admin_host
        )

    def remote_admin_available() -> bool:
        if not settings.apply_network:
            return True
        return component_binary(settings, "lego") is not None

    def remote_admin_origin() -> str:
        if not remote_admin_host:
            return ""
        suffix = "" if settings.remote_admin_port == 443 else f":{settings.remote_admin_port}"
        return f"https://{remote_admin_host}{suffix}"

    def local_redirect(value: str | None, fallback: str) -> str:
        if not value:
            return fallback
        parsed = urlsplit(value)
        if parsed.scheme or parsed.netloc:
            if parsed.scheme not in {"http", "https"} or (parsed.hostname or "").lower() not in allowed_hosts():
                return fallback
            target = parsed.path or "/"
            return f"{target}?{parsed.query}" if parsed.query else target
        if not value.startswith("/") or value.startswith("//"):
            return fallback
        return value

    @app.before_request
    def enforce_private_origin():
        host = request_hostname()
        if host not in allowed_hosts():
            abort(400, description="This CayVPN origin is not allowed.")
        if settings.apply_network and host == remote_admin_host:
            if not request.is_secure or request_effective_port() != settings.remote_admin_port:
                abort(400, description="Remote administration requires the standard secure HTTPS address.")
        origin = request.headers.get("Origin")
        if origin:
            try:
                parsed = urlsplit(origin)
                origin_host = (parsed.hostname or "").lower()
                origin_port = parsed.port or (443 if parsed.scheme == "https" else 80)
            except ValueError:
                abort(403, description="The request origin is not allowed.")
            if parsed.scheme not in {"http", "https"} or origin_host not in allowed_hosts():
                abort(403, description="The request origin is not allowed.")
            if settings.apply_network and host == remote_admin_host and (
                parsed.scheme != "https"
                or origin_host != remote_admin_host
                or origin_port != settings.remote_admin_port
            ):
                abort(403, description="The request origin is not allowed.")

    def api_idempotency_record() -> tuple[str, dict | None]:
        key = (request.headers.get("Idempotency-Key") or "").strip()
        if not 16 <= len(key) <= 160:
            abort(400, description="Mutating API requests require an Idempotency-Key header.")
        record_key = "idempotency:" + hashlib.sha256(f"{request.method}:{request.path}:{key}".encode()).hexdigest()
        body_digest = hashlib.sha256(request.get_data(cache=True)).hexdigest()
        stored = db.get_setting(record_key)
        if not stored:
            return record_key, None
        try:
            record = json.loads(stored)
        except (TypeError, ValueError):
            abort(409, description="The idempotency record is invalid and must be retried with a new key.")
        if record.get("request_digest") != body_digest:
            abort(409, description="The idempotency key was already used for a different request.")
        return record_key, record

    def save_api_idempotency(record_key: str, request_digest: str, body: dict, status: int = 200) -> None:
        db.set_setting(record_key, json.dumps({"request_digest": request_digest, "body": body, "status": status}, sort_keys=True))

    def admin_device_active(address: str | None) -> bool:
        if not address or not is_admin_network_address(address, settings.admin_network):
            return False
        with db.session() as session_db:
            devices = session_db.scalars(select(AdminDevice).where(AdminDevice.enabled.is_(True))).all()
            return any(str(device.address).split("/", 1)[0] == address for device in devices)

    def owner_login_enabled() -> bool:
        return db.get_setting("client_panel_login_enabled", "0") == "1"

    def owner_totp_enabled() -> bool:
        configured = db.get_setting("client_panel_totp_required", "")
        if configured in {"0", "1"}:
            return configured == "1"
        # Existing installations predate the explicit preference. Preserve
        # their authenticator requirement whenever a secret is already saved.
        return db.get_setting("client_panel_totp_ref", "").startswith("ref::")

    def owner_login_source(address: str | None) -> bool:
        return is_network_address(address, settings.user_network, settings.amnezia_network)

    def remote_login_source() -> bool:
        return request_uses_remote_origin()

    def login_source_ready() -> bool:
        return owner_login_source(request.remote_addr) or remote_login_source()

    def totp_proof(code: str) -> str:
        return hmac.new(
            str(app.secret_key).encode(),
            code.encode(),
            hashlib.sha256,
        ).hexdigest()

    def active_admin_session() -> bool:
        return (
            session.get("auth_method") == "admin_tunnel"
            and session.get("admin_address") == request.remote_addr
            and admin_device_active(request.remote_addr)
        )

    def authenticated() -> bool:
        if session.get("authenticated") is True:
            if session.get("auth_method") == "admin_tunnel" and not active_admin_session():
                session.clear()
                return False
            if session.get("auth_method") == "owner_login" and (not owner_login_enabled() or not owner_login_source(request.remote_addr)):
                session.clear()
                return False
            if session.get("auth_method") == "remote_owner_login" and (
                not owner_login_enabled()
                or not remote_admin_enabled()
                or not request_uses_remote_origin()
            ):
                session.clear()
                return False
            if session.get("auth_method") == "admin_tunnel":
                db.set_setting("private_panel_verified", "1")
            return True
        if admin_device_active(request.remote_addr):
            session["authenticated"] = True
            session["auth_method"] = "admin_tunnel"
            session["admin_address"] = request.remote_addr
            session.permanent = True
            db.set_setting("private_panel_verified", "1")
            return True
        return False

    def ad_blocking_ready() -> bool:
        return blocklist_available(settings.config_dir / "adblock")

    def require_auth(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if authenticated():
                return view(*args, **kwargs)
            if login_source_ready() and not request.path.startswith("/api/"):
                next_path = request.path
                if request.query_string:
                    next_path += "?" + request.query_string.decode(errors="ignore")
                return redirect(url_for("login", next=next_path))
            abort(403, description="Turn on the CayVPN connection from your setup folder, then open this page again.")
        return wrapped

    def high_risk(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if not authenticated():
                return redirect(url_for("login"))
            if recent_owner_approval():
                return view(*args, **kwargs)
            return owner_confirmation_required()
        return wrapped

    def owner_confirmation_required(destination: str | None = None):
        fallback = url_for("security_page")
        if destination is None:
            destination = (
                request.full_path.rstrip("?")
                if request.method in {"GET", "HEAD"}
                else request.referrer
            )
        destination = local_redirect(destination, fallback)
        if request.path.startswith("/api/"):
            return jsonify({"error": "recent owner confirmation required"}), 403
        if owner_login_enabled():
            flash(
                (
                    "Confirm this sensitive change with your owner password and authenticator code."
                    if owner_totp_enabled()
                    else "Confirm this sensitive change with your owner password."
                ),
                "warning",
            )
            return redirect(url_for("remote_owner_approval", next=destination))
        flash(
            "Turn on secure access, or use an optional sign-in, passkey, or server-recovery code.",
            "warning",
        )
        return redirect(fallback)

    def private_passkey_origin(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if request_uses_remote_origin():
                return jsonify(
                    {
                        "error": (
                            "Passkeys require the private CayVPN hostname. "
                            "Use the remote owner-confirmation form for sensitive changes."
                        )
                    }
                ), 409
            return view(*args, **kwargs)

        return wrapped

    def recent_owner_approval() -> bool:
        if active_admin_session():
            return True
        deadlines = []
        for key in ("owner_approval_until", "remote_approval_until", "passkey_verified_until"):
            try:
                deadlines.append(int(session.get(key, 0)))
            except (TypeError, ValueError):
                deadlines.append(0)
        return max(deadlines, default=0) >= now_epoch()

    @app.context_processor
    def inject_context():
        node = None
        with db.session() as session_db:
            node = session_db.get(ManagedNode, 1)
            active_client_count = session_db.scalar(select(func.count(Client.id)).where(Client.enabled.is_(True))) or 0
            passkey_count = session_db.scalar(select(func.count(PasskeyCredential.id))) or 0
            extra_exit_count = session_db.scalar(select(func.count(EgressProfile.id)).where(EgressProfile.driver != "direct_ip")) or 0
            onboarding = session_db.get(Setting, "onboarding_prompt_seen")
            donation = session_db.get(Setting, "donation_prompt_seen")
            onboarding_seen = bool(onboarding and onboarding.value == "1")
            donation_seen = bool(donation and donation.value == "1")
        verified = bool(node and node.install_state == "verified")
        return {
            "version": node.release if node and node.release else __version__,
            "server_ip": settings.server_ip,
            "server_region": db.get_setting("server_region", settings.server_region),
            "admin_hostname": settings.admin_hostname,
            "admin_origin": f"{'https' if settings.https_enabled else 'http'}://{settings.admin_hostname}:{settings.admin_https_port}",
            "admin_private_origin": f"{'https' if settings.https_enabled else 'http'}://{admin_ip}:{settings.admin_https_port}",
            "node": node,
            "onboarding_prompt": bool(verified and not onboarding_seen),
            "onboarding_status": {
                "security": active_admin_session()
                or owner_login_enabled()
                or passkey_count > 0,
                "client": active_client_count > 0,
                "exit": extra_exit_count > 0,
            },
            "passkey_count": passkey_count,
            "owner_approval_ready": recent_owner_approval(),
            "donation_prompt": bool(verified and onboarding_seen and active_client_count > 0 and not donation_seen),
            "admin_tunnel_only": not remote_admin_enabled(),
            "client_panel_login_enabled": owner_login_enabled(),
            "owner_totp_enabled": owner_totp_enabled(),
            "trusted_owner_tunnel": active_admin_session(),
            "remote_admin_enabled": remote_admin_enabled(),
            "remote_admin_available": remote_admin_available(),
            "remote_admin_origin": remote_admin_origin(),
            "remote_owner_session": session.get("auth_method") == "remote_owner_login",
            "wizard_resume_step": wizard_resume_step,
            "wizard_total_steps": wizard_total_steps,
        }

    @app.after_request
    def security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        # Flask-WTF deliberately verifies the Referer on secure form posts.
        # Keep it available for same-origin navigation without disclosing it
        # to any external destination.
        response.headers["Referrer-Policy"] = "same-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        response.headers["Content-Security-Policy"] = "default-src 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; form-action 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'"
        if settings.https_enabled:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        if request.path not in {"/login"} and not request.path.startswith("/static/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.route("/login", methods=["GET", "POST"])
    @limiter.limit("5 per minute", methods=["POST"])
    def login():
        if authenticated():
            return redirect(local_redirect(request.args.get("next"), url_for("index")))
        source_ready = login_source_ready()
        remote_source = remote_login_source()
        login_ready = source_ready and owner_login_enabled()
        totp_required = owner_totp_enabled()
        error = None
        if request.method == "POST":
            password_hash = db.get_setting("client_panel_password_hash", "")
            totp_reference = db.get_setting("client_panel_totp_ref", "")
            password_ok = login_ready and verify_password(request.form.get("password", ""), password_hash)
            totp_ok = not totp_required
            if password_ok and totp_required and totp_reference.startswith("ref::"):
                _operation, response = operations.run(
                    "totp.verify",
                    {"secret_ref": totp_reference, "code": request.form.get("totp_code", "")},
                    actor="owner-login",
                )
                totp_ok = response.status == "succeeded" and response.result.get("verified") is True
            if password_ok and totp_ok:
                session.clear()
                session["authenticated"] = True
                session["auth_method"] = "remote_owner_login" if remote_source else "owner_login"
                session["owner_address"] = request.remote_addr
                if totp_required:
                    session["last_totp_proof"] = totp_proof(request.form.get("totp_code", ""))
                    session["last_totp_step"] = now_epoch() // 30
                session.permanent = True
                source = request.remote_addr or "unknown"
                source_label = (
                    "public:" + hashlib.sha256(source.encode()).hexdigest()[:16]
                    if remote_source
                    else source
                )
                operations.audit("owner-login", "session.start", {"source": source_label, "remote": remote_source})
                return redirect(local_redirect(request.form.get("next") or request.args.get("next"), url_for("index")))
            error = (
                "The owner password or six-digit code was incorrect."
                if totp_required
                else "The owner password was incorrect."
            )
        return render_template(
            "login.html",
            private_only=not source_ready,
            login_ready=login_ready,
            first_time=source_ready and not owner_login_enabled(),
            remote_source=remote_source,
            totp_required=totp_required,
            error=error,
            next_path=local_redirect(request.args.get("next"), url_for("index")),
        )

    @app.route("/logout", methods=["POST"])
    def logout():
        session.clear()
        return redirect(url_for("login"))

    @app.route("/security/remote-approve", methods=["GET", "POST"])
    @app.route("/security/confirm", methods=["GET", "POST"])
    @require_auth
    @limiter.limit("3 per minute", methods=["POST"])
    def remote_owner_approval():
        if not owner_login_enabled():
            flash("Set up optional sign-in before using password confirmation.", "warning")
            return redirect(url_for("security_page"))
        destination = local_redirect(
            request.form.get("next") or request.args.get("next"),
            url_for("security_page"),
        )
        error = None
        totp_required = owner_totp_enabled()
        try:
            previous_totp_step = int(session.get("last_totp_step", -1)) if totp_required else -1
        except (TypeError, ValueError):
            previous_totp_step = -1
        if request.method == "POST":
            password = request.form.get("password", "")
            code = request.form.get("totp_code", "")
            password_ok = verify_password(
                password, db.get_setting("client_panel_password_hash", "")
            )
            proof = totp_proof(code) if totp_required else ""
            current_totp_step = now_epoch() // 30
            fresh_code = (
                not totp_required
                or previous_totp_step < 0
                or current_totp_step > previous_totp_step
                and proof != session.get("last_totp_proof")
            )
            totp_ok = not totp_required
            reference = db.get_setting("client_panel_totp_ref", "")
            if password_ok and totp_required and fresh_code and reference.startswith("ref::"):
                _operation, response = operations.run(
                    "totp.verify",
                    {"secret_ref": reference, "code": code},
                    actor="remote-owner-approval",
                )
                totp_ok = (
                    response.status == "succeeded"
                    and response.result.get("verified") is True
                )
            if password_ok and totp_ok:
                if totp_required:
                    session["last_totp_proof"] = proof
                    session["last_totp_step"] = current_totp_step
                session["owner_approval_until"] = now_epoch() + 300
                if session.get("auth_method") == "remote_owner_login":
                    session["remote_approval_until"] = session["owner_approval_until"]
                operations.audit(
                    "owner",
                    "sensitive-approval.start",
                    {"duration_seconds": 300},
                )
                flash("Sensitive changes are approved for five minutes.", "success")
                return redirect(destination)
            error = (
                "Wait for a new authenticator code, then try again."
                if totp_required and password_ok and not fresh_code
                else (
                    "The owner password or authenticator code was incorrect."
                    if totp_required
                    else "The owner password was incorrect."
                )
            )
        return render_template(
            "remote_approval.html",
            error=error,
            next_path=destination,
            totp_required=totp_required,
            fresh_code_required=totp_required and previous_totp_step >= 0,
        )

    @app.route("/")
    @require_auth
    def index():
        with db.session() as session_db:
            clients = session_db.scalars(select(Client).order_by(Client.id)).all()
            profiles = session_db.scalars(select(EgressProfile).order_by(EgressProfile.id)).all()
            pools = session_db.scalars(select(EgressPool).order_by(EgressPool.id)).all()
            capacity = session_db.scalar(select(CapacitySnapshot).order_by(desc(CapacitySnapshot.observed_at)))
            routes = {route.client_id: route for route in session_db.scalars(select(RouteBinding)).all() if route.client_id}
        if capacity is None:
            capacity = refresh_capacity()
        drafts = [draft for draft in active_wizard_drafts() if draft.kind in wizard_steps]
        return render_template(
            "management_dashboard.html",
            clients=clients,
            profiles=profiles,
            profile_map={profile.id: profile for profile in profiles},
            pools=pools,
            routes=routes,
            capacity=capacity,
            drafts=drafts,
        )

    def client_identity_from_form(form) -> tuple[str, str]:
        name = _safe_text(form.get("name"), 120)
        protocol = str(form.get("ingress_protocol", "wireguard")).lower()
        if not name:
            raise ValueError("Name this device so you can recognize it later")
        if protocol not in {"wireguard", "amneziawg"}:
            raise ValueError("Choose Standard WireGuard or Amnezia")
        amnezia_ready, _socks5_ready = _optional_component_readiness()
        if protocol == "amneziawg" and not amnezia_ready:
            raise ValueError("Amnezia is not installed on this CayVPN server yet")
        return name, protocol

    def render_add_device(*, form_data=None, errors: list[str] | None = None, status: int = 200):
        amnezia_ready, _socks5_ready = _optional_component_readiness()
        response = render_template(
            "add_peer.html",
            drafts=active_wizard_drafts("client"),
            form_data=form_data or {},
            errors=errors or [],
            amnezia_ready=amnezia_ready,
            management_mode=True,
        )
        return response, status

    @app.route("/clients", methods=["GET", "POST"])
    @app.route("/add", methods=["GET", "POST"])
    @require_auth
    def clients():
        if request.method == "POST":
            try:
                name = _safe_text(request.form.get("name"), 120)
                if not name:
                    raise ValueError("Client name is required")
                ingress_protocol = request.form.get("ingress_protocol", "wireguard").lower()
                if ingress_protocol not in {"wireguard", "amneziawg"}:
                    raise ValueError("Unsupported client protocol")
                dns_mode = request.form.get("dns_mode", "ad_blocking").lower()
                if dns_mode not in {"standard", "ad_blocking"}:
                    raise ValueError("Unsupported DNS mode")
                if dns_mode == "ad_blocking" and not ad_blocking_ready():
                    raise ValueError("Ad and tracker blocking is not installed on this CayVPN server yet")
                ipv6_policy = request.form.get("ipv6_policy", "auto").lower()
                if ipv6_policy not in {"auto", "required"}:
                    raise ValueError("Choose Smart IPv6 or Require IPv6")
                route_mode = request.form.get("route_mode", "switchable").lower()
                if route_mode not in {"switchable", "fixed"}:
                    raise ValueError("Unsupported route mode")
                fixed_egress_id = request.form.get("fixed_egress_id", type=int)
                fixed_pool_id = request.form.get("fixed_pool_id", type=int)
                if route_mode == "fixed":
                    if bool(fixed_egress_id) == bool(fixed_pool_id):
                        raise ValueError("Choose exactly one Location or backup group")
                    with db.session() as session_db:
                        if fixed_egress_id:
                            fixed_profile = session_db.get(EgressProfile, fixed_egress_id)
                            if fixed_profile is None or not fixed_profile.enabled:
                                raise ValueError("The selected fixed Location is not available")
                            if fixed_profile.health_state not in {"healthy", "active"}:
                                raise ValueError("Verify the selected fixed Location before creating this device")
                            if ipv6_policy == "required" and not profile_supports_required_ipv6(fixed_profile):
                                raise ValueError("Require IPv6 needs a Location that has passed both IPv4 and IPv6 checks")
                        if fixed_pool_id:
                            fixed_pool = session_db.get(EgressPool, fixed_pool_id)
                            if fixed_pool is None or not fixed_pool.enabled:
                                raise ValueError("The selected backup group is not available")
                else:
                    fixed_egress_id = None
                    fixed_pool_id = None
                if ingress_protocol == "amneziawg":
                    _, component_response = operations.run("component.install", {"component": "amneziawg"}, actor="owner")
                    if component_response.status == "failed":
                        raise ValueError(f"AmneziaWG is not ready on this node: {component_response.error_message}")
                with db.session() as session_db:
                    existing_count = session_db.query(Client).count()
                    latest_capacity = session_db.scalar(select(CapacitySnapshot).order_by(desc(CapacitySnapshot.observed_at)))
                    override_active = db.get_setting("capacity_override_active", "0") == "1"
                    if latest_capacity and existing_count >= latest_capacity.safe_active_clients and not override_active:
                        raise ValueError("The safe active-client limit has been reached")
                    if latest_capacity and existing_count >= latest_capacity.max_stored_configs and not override_active:
                        raise ValueError("The safe stored-configuration limit has been reached")
                private_key, public_key = generate_keypair()
                private_key_ref = agent_secret_store(private_key, f"client-{name}")
                with db.session() as session_db:
                    used = {item.address for item in session_db.scalars(select(Client)).all()}
                    used_v6 = {item.ipv6_address for item in session_db.scalars(select(Client)).all() if item.ipv6_address}
                    client_network = settings.amnezia_network if ingress_protocol == "amneziawg" else settings.user_network
                    client_network_v6 = settings.amnezia_network_v6 if ingress_protocol == "amneziawg" else settings.user_network_v6
                    ingress_address = settings.amnezia_address if ingress_protocol == "amneziawg" else settings.user_address
                    server_address = str(ipaddress.ip_interface(ingress_address).ip)
                    offset = 0
                    while True:
                        address = _client_ip(client_network, offset)
                        if address != server_address and address not in used:
                            break
                        offset += 1
                    ipv6_address = _available_ipv6_address(client_network_v6, used_v6, existing_count + 2)
                    client = Client(name=name, public_key=public_key, private_key_enc=private_key_ref, address=address, ipv6_address=ipv6_address, ipv6_policy=ipv6_policy, generated_config_version=CLIENT_CONFIG_VERSION, confirmed_config_version=0, ingress_protocol=ingress_protocol, dns_mode=dns_mode, route_mode=route_mode, fixed_egress_id=fixed_egress_id, pool_id=fixed_pool_id)
                    session_db.add(client)
                    session_db.flush()
                    session_db.add(RouteBinding(client_id=client.id, mode=route_mode, state="pending"))
                    client_id = client.id
                operation, response = operations.reconcile_clients(actor="owner")
                ingress_interface = settings.amnezia_interface if ingress_protocol == "amneziawg" else settings.user_interface
                _, fail_closed_response = operations.run("route.fail_closed", {"client_id": client_id, "client_address": f"{address}/32", "client_ipv6_address": f"{ipv6_address}/128", "ingress_interface": ingress_interface, "profile_id": 1}, actor="owner")
                if response.status == "failed":
                    flash(f"Client saved but WireGuard reconciliation failed: {response.error_message}", "warning")
                elif fail_closed_response.status != "succeeded":
                    flash(f"Client saved but its default route is still pending root-agent application: {fail_closed_response.error_message or 'agent unavailable'}", "warning")
                elif response.status == "succeeded":
                    if route_mode == "fixed":
                        _, fixed_response = operations.route_switch(client_id, profile_id=fixed_egress_id, pool_id=fixed_pool_id, actor="owner")
                        if fixed_response.status != "succeeded" or not fixed_response.result.get("verified"):
                            flash(f"Device {name} was created, but its route remains blocked until the selected Location verifies.", "warning")
                        else:
                            flash(f"Client {name} created with its fixed route verified. Download its configuration before closing this page.", "success")
                    else:
                        flash(f"Client {name} created. Download its configuration before closing this page.", "success")
                else:
                    flash(f"Client {name} saved; the root agent is unavailable, so its peer remains pending.", "warning")
                return redirect(url_for("index"))
            except (ValueError, DriverValidationError) as exc:
                flash(_friendly_location_message(exc), "danger")
        return render_add_device(form_data=request.form)

    @app.route("/setup/<kind>/new", methods=["POST"])
    @require_auth
    def start_wizard(kind: str):
        if kind not in wizard_steps:
            abort(404)
        if kind == "client" and ("name" in request.form or "ingress_protocol" in request.form):
            try:
                name, protocol = client_identity_from_form(request.form)
            except ValueError as exc:
                return render_add_device(form_data=request.form, errors=[str(exc)], status=400)
            draft = create_wizard_draft(kind)
            save_wizard_draft(
                draft.id,
                {"name": name, "ingress_protocol": protocol},
                2,
            )
            return redirect(url_for("wizard_step", kind=kind, draft_id=draft.id, step=2))
        if kind == "pool":
            profiles, _pools = _wizard_profiles_and_pools()
            if len(profiles) < 2:
                flash("Add at least one backup Location before creating a backup group.", "warning")
                return redirect(url_for("egress"))
        draft = create_wizard_draft(kind)
        return redirect(url_for("wizard_step", kind=kind, draft_id=draft.id, step=1))

    @app.route("/setup/<kind>/<draft_id>/cancel", methods=["POST"])
    @require_auth
    def cancel_wizard(kind: str, draft_id: str):
        draft = load_wizard_draft(draft_id, kind)
        if delete_wizard_draft(draft.id, actor="wizard-cancel"):
            flash("Saved setup removed. Any temporary configuration was deleted.", "success")
        else:
            flash("CayVPN could not remove the temporary secret yet, so the saved setup was retained for a safe retry.", "warning")
        destination = "clients" if kind == "client" else "security_page" if kind == "owner_login" else "egress"
        return redirect(url_for(destination))

    def _wizard_profiles_and_pools() -> tuple[list[EgressProfile], list[EgressPool]]:
        with db.session() as session_db:
            profiles = session_db.scalars(select(EgressProfile).where(EgressProfile.enabled.is_(True)).order_by(EgressProfile.id)).all()
            pools = session_db.scalars(select(EgressPool).where(EgressPool.enabled.is_(True)).order_by(EgressPool.id)).all()
        return profiles, pools

    def _profile_ready(profile: EgressProfile | None) -> bool:
        return bool(profile and profile.enabled and profile.health_state in {"healthy", "active"})

    def _pool_candidates(pool: EgressPool, profile_map: dict[int, EgressProfile]) -> list[EgressProfile]:
        candidates: list[EgressProfile] = []
        for value in _json(pool.profile_ids_json, []):
            try:
                profile = profile_map.get(int(value))
            except (TypeError, ValueError):
                continue
            if profile is not None:
                candidates.append(profile)
        return candidates

    def _optional_component_readiness() -> tuple[bool, bool]:
        # Dry-run environments intentionally plan component installation
        # without executing binaries. A live node should advertise an option
        # only when its signed, pinned component is actually present.
        if not settings.apply_network:
            return True, True
        amnezia_ready = all(component_binary(settings, name) for name in ("awg", "awg-quick", "amneziawg-go"))
        socks5_ready = component_binary(settings, "hev-socks5-tunnel") is not None
        return amnezia_ready, socks5_ready

    def _ensure_additional_addresses_are_new(config: dict, *, exclude_profile_id: int | None = None) -> None:
        """Keep an additional-address exit distinct from every saved IP exit."""
        address = str(ipaddress.ip_address(str(config.get("address", "")).strip()))
        ipv6_address = str(config.get("ipv6_address") or "").strip()
        if ipv6_address:
            ipv6_address = str(ipaddress.ip_address(ipv6_address))
        with db.session() as session_db:
            profiles = session_db.scalars(
                select(EgressProfile).where(EgressProfile.driver.in_(("direct_ip", "additional_ip")))
            ).all()
        for profile in profiles:
            if exclude_profile_id is not None and profile.id == exclude_profile_id:
                continue
            existing = profile.config
            existing_address = str(existing.get("address") or "").strip()
            existing_ipv6 = str(existing.get("ipv6_address") or "").strip()
            if existing_address:
                try:
                    existing_address = str(ipaddress.ip_address(existing_address))
                except ValueError:
                    existing_address = ""
            if existing_ipv6:
                try:
                    existing_ipv6 = str(ipaddress.ip_address(existing_ipv6))
                except ValueError:
                    existing_ipv6 = ""
            if address == existing_address:
                if profile.driver == "direct_ip":
                    raise ValueError(
                        "That IPv4 address already belongs to This server. Enter a separate address that your provider attached to this server."
                    )
                raise ValueError(
                    f"That IPv4 address is already saved as {profile.name}. Remove the old Location before reusing it."
                )
            if ipv6_address and ipv6_address == existing_ipv6:
                if profile.driver == "direct_ip":
                    raise ValueError(
                        "That IPv6 address already belongs to This server. Enter the separate IPv6 address attached for this Location."
                    )
                raise ValueError(
                    f"That IPv6 address is already saved as {profile.name}. Remove the old Location before reusing it."
                )

    def _save_exit_details(draft: WizardDraft, data: dict) -> dict:
        name = _safe_text(request.form.get("name"), 120)
        if not name:
            raise ValueError("Give this Location a recognizable name, such as Miami or London")
        driver = str(data.get("driver", ""))
        old_reference = draft.secret_ref
        new_reference = old_reference
        secret_value: str | None = None
        if driver == "additional_ip":
            config = {
                "address": request.form.get("address", "").strip(),
                "prefix": request.form.get("prefix", "32").strip(),
                "gateway": request.form.get("gateway", "").strip(),
                "interface": request.form.get("interface", "").strip(),
                "ipv6_address": request.form.get("ipv6_address", "").strip(),
                "ipv6_prefix": request.form.get("ipv6_prefix", "128").strip(),
                "ipv6_gateway": request.form.get("ipv6_gateway", "").strip(),
            }
            validated = validate_driver(driver, config)
            config = dict(validated.redacted_config)
            _ensure_additional_addresses_are_new(config)
            new_reference = None
        elif driver == "socks5":
            raw_endpoint = request.form.get("endpoint", "").strip()
            parsed = parse_socks5(raw_endpoint)
            secret_value = request.form.get("password") or parsed.get("password") or None
            host = str(parsed["host"])
            if ":" in host and not host.startswith("["):
                host = f"[{host}]"
            user = f"{parsed['username']}@" if parsed.get("username") else ""
            config = {"endpoint": f"socks5://{user}{host}:{parsed['port']}"}
            if secret_value:
                new_reference = agent_secret_store(str(secret_value), f"wizard-exit-{name}")
        elif driver == "provider_tunnel":
            secret_value = request.form.get("config_text") or None
            if secret_value:
                new_reference = agent_secret_store(str(secret_value), f"wizard-exit-{name}")
            if not new_reference:
                raise ValueError("Paste the provider WireGuard or Amnezia configuration")
            config = {"protocol_hint": "auto", "full_tunnel_required": True}
        else:
            raise ValueError("Choose a supported connection type")
        if new_reference != old_reference and old_reference:
            if not delete_secret(old_reference, actor="wizard-secret-replaced"):
                if new_reference:
                    delete_secret(new_reference, actor="wizard-secret-rollback")
                raise ValueError("The previous temporary configuration could not be removed safely. Try again.")
        data.update({"name": name, "config": config, "secret_supplied": bool(new_reference)})
        data.pop("check", None)
        save_wizard_draft(draft.id, data, 2, new_reference)
        return data

    def _run_exit_wizard_checks(draft: WizardDraft, data: dict) -> dict:
        driver = str(data.get("driver") or "")
        payload = {
            "driver": driver,
            "config": data.get("config") or {},
            "secret_ref": draft.secret_ref,
            "live_checks": True,
        }
        _operation, response = operations.run("egress.validate", payload, actor="wizard-check")
        if response.status != "succeeded" or not response.result.get("valid"):
            raise ValueError(_friendly_location_message(response.error_message or "CayVPN rejected this Location configuration"))
        checked = response.result or {}
        if driver in {"provider_tunnel", "socks5"}:
            temporary_profile_id = 999_999
            activation_response = None
            cleanup_response = None
            try:
                _activation_operation, activation_response = operations.run(
                    "egress.activate",
                    {
                        "profile_id": temporary_profile_id,
                        "driver": driver,
                        "config": data.get("config") or {},
                        "secret_ref": draft.secret_ref,
                    },
                    actor="wizard-check",
                )
            finally:
                _cleanup_operation, cleanup_response = operations.run(
                    "egress.deactivate",
                    {"profile_id": temporary_profile_id, "remove_namespace": True},
                    actor="wizard-check-cleanup",
                )
            if cleanup_response.status != "succeeded":
                raise ValueError("CayVPN could not safely remove the temporary Location check. Nothing was saved; try again.")
            if activation_response is None or activation_response.status != "succeeded":
                message = activation_response.error_message if activation_response is not None else None
                raise ValueError(_friendly_location_message(message or "This Location did not pass its live connection checks"))
            live = activation_response.result or {}
            live_capabilities = capabilities_for_api(live)
            live_ipv4 = (live_capabilities.get("families") or {}).get("ipv4") or {}
            live_applied = bool(live.get("applied")) or str(live.get("state") or "") == "active"
            if live_applied and (
                not live.get("verified")
                or not live_ipv4.get("tcp")
                or not live_ipv4.get("dns")
            ):
                raise ValueError("This Location could not verify a safe IPv4 connection, so it was not saved.")
            if not live_applied:
                live_capabilities = capabilities_for_api({})
            checked = {
                **checked,
                **live,
                "verified": bool(live.get("verified")) if live_applied else False,
                "health_state": "healthy" if live_applied and live.get("verified") else "pending",
                "capabilities": live_capabilities,
            }
        elif driver == "additional_ip":
            _probe_operation, probe_response = operations.run(
                "egress.probe",
                # This check does not create a profile, but the root agent
                # still enforces its bounded typed-id contract. Reserve the
                # highest valid id for the temporary pre-save observation.
                {"profile_id": 999_999, "driver": "additional_ip", "config": data.get("config") or {}},
                actor="wizard-check",
            )
            if probe_response.status == "succeeded":
                checked = {**checked, **(probe_response.result or {})}
        result = {
            "valid": True,
            "verified": bool(checked.get("verified", False)),
            "health_state": str(checked.get("health_state", "pending")),
            "ipv6_health_state": str(checked.get("ipv6_health_state", "pending" if ipv6_usable(checked.get("capabilities") or checked) else "unavailable")),
            "capabilities": capabilities_for_api(checked.get("capabilities") or checked),
            "observed_exit_ipv4": checked.get("observed_exit_ipv4") or checked.get("observed_exit_ip"),
            "observed_exit_ipv6": checked.get("observed_exit_ipv6"),
            "reason": _safe_text(str(checked.get("reason") or ""), 240),
            "ipv6_reason": _safe_text(str(checked.get("ipv6_reason") or ""), 240),
            "warnings": [_safe_text(str(item), 240) for item in (checked.get("warnings") or [])[:12]],
            "redacted_config": checked.get("redacted_config") if isinstance(checked.get("redacted_config"), dict) else data.get("config") or {},
        }
        data["check"] = result
        # SOCKS needs its sanitized endpoint for later activation and health
        # checks. The validator's redacted result is descriptive metadata,
        # not the runtime configuration shape. Provider tunnels can retain
        # the useful detected protocol because their actual configuration is
        # read only from the opaque root-secret reference.
        if driver != "socks5":
            data["config"] = result["redacted_config"]
        save_wizard_draft(draft.id, data, 3)
        return data

    @app.route("/setup/<kind>/<draft_id>/<int:step>", methods=["GET", "POST"])
    @require_auth
    def wizard_step(kind: str, draft_id: str, step: int):
        if kind not in wizard_steps:
            abort(404)
        client_legacy_step = kind == "client" and 1 <= step <= legacy_client_steps
        if not client_legacy_step and not 1 <= step <= wizard_steps[kind]:
            abort(404)
        draft = load_wizard_draft(draft_id, kind)
        data = draft.data
        if kind == "client":
            available_step = client_wizard_step_for_data(data)
            if step > available_step or step > wizard_steps[kind]:
                return redirect(url_for("wizard_step", kind=kind, draft_id=draft.id, step=available_step))
        elif step > draft.current_step:
            return redirect(url_for("wizard_step", kind=kind, draft_id=draft.id, step=draft.current_step))
        error_session_key = f"wizard-errors:{kind}:{draft.id}:{step}"
        stored_errors = session.pop(error_session_key, []) if request.method == "GET" else []
        errors = [str(item)[:500] for item in stored_errors if isinstance(item, str)]
        amnezia_ready, socks5_ready = _optional_component_readiness()
        if request.method == "POST":
            if request.form.get("action") == "back":
                return redirect(url_for("wizard_step", kind=kind, draft_id=draft.id, step=max(1, step - 1)))
            try:
                if kind == "client":
                    if step == 1:
                        name, protocol = client_identity_from_form(request.form)
                        data.update({"name": name, "ingress_protocol": protocol})
                    elif step == 2:
                        dns_mode = request.form.get("dns_mode", "ad_blocking").lower()
                        if dns_mode not in {"standard", "ad_blocking"}:
                            raise ValueError("Choose a web protection setting")
                        if dns_mode == "ad_blocking" and not ad_blocking_ready():
                            raise ValueError("Ad and tracker blocking is not installed on this CayVPN server yet")
                        legacy_policy = str(request.form.get("ipv6_policy", "")).lower()
                        ipv6_policy = "required" if request.form.get("require_ipv6") == "on" or legacy_policy == "required" else "auto"
                        choice = request.form.get("route_choice", "")
                        profiles, pools = _wizard_profiles_and_pools()
                        profile_map = {item.id: item for item in profiles}
                        pool_map = {item.id: item for item in pools}
                        target_id = None
                        pool_id = None
                        target = None
                        pool = None
                        if choice == "direct":
                            target = next((item for item in profiles if item.driver == "direct_ip"), None)
                            if target is None:
                                raise ValueError("This server's Location is not available")
                            target_id, pool_id = target.id, None
                        elif choice == "exit":
                            target_id, pool_id = request.form.get("profile_id", type=int), None
                            target = profile_map.get(target_id)
                            if target is None or target.driver == "direct_ip":
                                raise ValueError("Choose an available location")
                        elif choice == "pool":
                            target_id, pool_id = None, request.form.get("pool_id", type=int)
                            pool = pool_map.get(pool_id)
                            if pool is None:
                                raise ValueError("Choose an available backup group")
                        else:
                            raise ValueError("Choose This server, another Location, or a backup group")
                        data.update(
                            {
                                "dns_mode": dns_mode,
                                "ipv6_policy": ipv6_policy,
                                "route_choice": choice,
                                "profile_id": target_id,
                                "pool_id": pool_id,
                            }
                        )
                        if target is not None and not _profile_ready(target):
                            if target.driver == "direct_ip":
                                raise ValueError("This server is still checking its internet connection. Choose another ready Location or try again shortly.")
                            raise ValueError("Choose a Location that is ready to use")
                        pool_candidates = _pool_candidates(pool, profile_map) if pool is not None else []
                        ready_pool_candidates = [item for item in pool_candidates if _profile_ready(item)]
                        if pool is not None and not ready_pool_candidates:
                            raise ValueError("This backup group has no ready Location yet")
                        if ipv6_policy == "required":
                            if target is not None and not profile_supports_required_ipv6(target):
                                raise ValueError("Choose an IPv6-ready Location or turn off Require IPv6")
                            if pool is not None and not any(profile_supports_required_ipv6(item) for item in ready_pool_candidates):
                                raise ValueError("This backup group has no IPv6-ready Location for Require IPv6")
                    else:
                        raise ValueError("Use the review button to create this client")
                    save_wizard_draft(draft.id, data, min(step + 1, wizard_steps[kind]))
                elif kind == "exit":
                    if step == 1:
                        driver = request.form.get("driver", "").lower()
                        if driver not in {"additional_ip", "socks5", "provider_tunnel"}:
                            raise ValueError("Choose a Location connection type")
                        if driver == "socks5" and not socks5_ready:
                            raise ValueError("SOCKS5 Locations are not installed on this CayVPN server yet")
                        if data.get("driver") and data.get("driver") != driver and draft.secret_ref:
                            if not delete_secret(draft.secret_ref, actor="wizard-type-changed"):
                                raise ValueError("The previous temporary configuration could not be removed safely")
                            save_wizard_draft(draft.id, {}, 1, None)
                            data = {}
                        data["driver"] = driver
                        save_wizard_draft(draft.id, data, 2)
                    elif step == 2:
                        data = _save_exit_details(draft, data)
                        save_wizard_draft(draft.id, data, 3)
                    elif step == 3:
                        data = _run_exit_wizard_checks(draft, data)
                        save_wizard_draft(draft.id, data, 4)
                    elif step == 4:
                        save_wizard_draft(draft.id, data, 5)
                    else:
                        raise ValueError("Use Save and verify after reviewing this Location")
                else:
                    profiles, _pools = _wizard_profiles_and_pools()
                    profile_map = {item.id: item for item in profiles}
                    if step == 1:
                        name = _safe_text(request.form.get("name"), 120)
                        primary_id = request.form.get("primary_id", type=int)
                        if not name:
                            raise ValueError("Give this backup group a name")
                        if primary_id not in profile_map:
                            raise ValueError("Choose a primary Location")
                        data.update({"name": name, "primary_id": primary_id})
                    elif step == 2:
                        backups = [request.form.get(f"backup_{index}", type=int) for index in range(1, 5)]
                        backups = [item for item in backups if item is not None]
                        ordered = [int(data.get("primary_id")), *backups]
                        if len(ordered) < 2:
                            raise ValueError("Add at least one backup Location before continuing")
                        if len(set(ordered)) != len(ordered):
                            raise ValueError("Each Location can appear only once")
                        if any(item not in profile_map for item in ordered):
                            raise ValueError("Choose only available Locations")
                        data["profile_ids"] = ordered
                    elif step == 3:
                        if request.form.get("all_failed") != "block":
                            raise ValueError("Confirm that traffic must stay blocked when every Location fails")
                        data["all_failed"] = "block"
                    else:
                        raise ValueError("Use the review button to save this backup group")
                    save_wizard_draft(draft.id, data, min(step + 1, wizard_steps[kind]))
                return redirect(url_for("wizard_step", kind=kind, draft_id=draft.id, step=min(step + 1, wizard_steps[kind])))
            except (ValueError, DriverValidationError) as exc:
                # Redirect after an invalid submission so browser Back never
                # asks the owner to resubmit a POST. The draft contains only
                # non-secret or already-redacted answers; temporary secrets
                # remain behind their opaque root-store reference.
                save_wizard_draft(draft.id, data, draft.current_step)
                session[error_session_key] = [str(exc)[:500]]
                return redirect(
                    url_for("wizard_step", kind=kind, draft_id=draft.id, step=step),
                    code=303,
                )
        profiles, pools = _wizard_profiles_and_pools()
        additional_profiles = [profile for profile in profiles if profile.driver != "direct_ip"]
        ready_additional_profiles = [profile for profile in additional_profiles if _profile_ready(profile)]
        profile_map = {profile.id: profile for profile in profiles}
        ready_pool_ids = {
            pool.id
            for pool in pools
            if any(_profile_ready(profile) for profile in _pool_candidates(pool, profile_map))
        }
        return render_template(
            "wizard.html",
            kind=kind,
            draft=draft,
            data=data,
            step=step,
            total_steps=wizard_steps[kind],
            errors=errors,
            profiles=profiles,
            additional_profiles=additional_profiles,
            ready_additional_profiles=ready_additional_profiles,
            ready_pool_ids=ready_pool_ids,
            pools=pools,
            out_interface=settings.out_interface or "eth0",
            amnezia_ready=amnezia_ready,
            socks5_ready=socks5_ready,
            ad_blocking_ready=ad_blocking_ready(),
        )

    def _create_client_from_wizard(data: dict) -> tuple[int, list[str]]:
        required = {"name", "ingress_protocol", "dns_mode", "ipv6_policy", "route_choice"}
        if not required.issubset(data):
            raise ValueError("This client setup is incomplete. Return to the missing step.")
        protocol = str(data["ingress_protocol"])
        if data.get("dns_mode") == "ad_blocking" and not ad_blocking_ready():
            raise ValueError("Ad and tracker blocking is not installed on this CayVPN server yet")
        if protocol == "amneziawg":
            _component_operation, component = operations.run("component.install", {"component": "amneziawg"}, actor="owner")
            if component.status == "failed":
                raise ValueError(component.error_message or "Amnezia is not ready on this server")
        with db.session() as session_db:
            existing_count = session_db.query(Client).count()
            latest_capacity = session_db.scalar(select(CapacitySnapshot).order_by(desc(CapacitySnapshot.observed_at)))
            override_active = db.get_setting("capacity_override_active", "0") == "1"
            if latest_capacity and existing_count >= latest_capacity.safe_active_clients and not override_active:
                raise ValueError("The safe active-client limit has been reached")
            if latest_capacity and existing_count >= latest_capacity.max_stored_configs and not override_active:
                raise ValueError("The safe stored-configuration limit has been reached")
        private_key, public_key = generate_keypair()
        private_key_ref = agent_secret_store(private_key, f"client-{data['name']}")
        try:
            with db.session() as session_db:
                clients_now = session_db.scalars(select(Client)).all()
                used_v4 = {item.address for item in clients_now}
                used_v6 = {item.ipv6_address for item in clients_now if item.ipv6_address}
                client_network = settings.amnezia_network if protocol == "amneziawg" else settings.user_network
                client_network_v6 = settings.amnezia_network_v6 if protocol == "amneziawg" else settings.user_network_v6
                server_address = str(ipaddress.ip_interface(settings.amnezia_address if protocol == "amneziawg" else settings.user_address).ip)
                offset = 0
                while True:
                    address = _client_ip(client_network, offset)
                    if address != server_address and address not in used_v4:
                        break
                    offset += 1
                ipv6_address = _available_ipv6_address(client_network_v6, used_v6, existing_count + 2)
                client = Client(
                    name=str(data["name"]),
                    public_key=public_key,
                    private_key_enc=private_key_ref,
                    address=address,
                    ipv6_address=ipv6_address,
                    ipv6_policy=str(data["ipv6_policy"]),
                    generated_config_version=CLIENT_CONFIG_VERSION,
                    confirmed_config_version=0,
                    ingress_protocol=protocol,
                    dns_mode=str(data["dns_mode"]),
                    route_mode="switchable",
                )
                session_db.add(client)
                session_db.flush()
                session_db.add(RouteBinding(client_id=client.id, mode="switchable", state="pending"))
                client_id = client.id
        except Exception:
            delete_secret(private_key_ref, actor="client-create-rollback")
            raise
        warnings: list[str] = []
        _peer_operation, peer_response = operations.reconcile_clients(actor="owner")
        ingress_interface = settings.amnezia_interface if protocol == "amneziawg" else settings.user_interface
        _block_operation, blocked_response = operations.run(
            "route.fail_closed",
            {
                "client_id": client_id,
                "client_address": f"{address}/32",
                "client_ipv6_address": f"{ipv6_address}/128",
                "ingress_interface": ingress_interface,
                "profile_id": int(data.get("profile_id") or 1),
            },
            actor="owner",
        )
        if peer_response.status != "succeeded":
            warnings.append("The client was saved, but its server connection is still pending.")
        if blocked_response.status != "succeeded":
            warnings.append("The client was saved with traffic blocked until the root agent is available.")
        try:
            if data.get("pool_id"):
                _route_operation, route_response = operations.route_switch(client_id, pool_id=int(data["pool_id"]), actor="owner")
            else:
                _route_operation, route_response = operations.route_switch(client_id, profile_id=int(data.get("profile_id") or 1), actor="owner")
            if route_response.status != "succeeded" or not route_response.result.get("verified"):
                warnings.append("The selected Location is not verified yet, so this device remains safely blocked.")
        except ValueError as exc:
            warnings.append(f"The device was created, but its selected Location was not assigned: {_friendly_location_message(exc)}")
        return client_id, warnings

    @app.route("/setup/client/<draft_id>/complete", methods=["POST"])
    @require_auth
    def complete_client_wizard(draft_id: str):
        draft = load_wizard_draft(draft_id, "client")
        try:
            client_id, warnings = _create_client_from_wizard(draft.data)
        except (ValueError, DriverValidationError) as exc:
            flash(str(exc), "danger")
            return redirect(url_for("wizard_step", kind="client", draft_id=draft.id, step=3))
        delete_wizard_draft(draft.id, keep_secret=True)
        for warning in warnings:
            flash(warning, "warning")
        if not warnings:
            flash("Client created. Install its configuration on the device, then confirm the update.", "success")
        return redirect(url_for("client_ready", client_id=client_id))

    @app.route("/clients/<int:client_id>/ready")
    @require_auth
    def client_ready(client_id: int):
        with db.session() as session_db:
            client = session_db.get(Client, client_id)
            if client is None:
                abort(404)
            binding = session_db.scalar(select(RouteBinding).where(RouteBinding.client_id == client_id))
            profile = session_db.get(EgressProfile, binding.egress_profile_id) if binding and binding.egress_profile_id else None
        location_label = "This server" if profile and profile.driver == "direct_ip" else profile.name if profile else "Checking Location"
        connection_ready = bool(binding and binding.state == "active" and _profile_ready(profile))
        ipv6_protected = bool(connection_ready and profile and profile_supports_required_ipv6(profile))
        if connection_ready:
            connection_wait_reason = ""
        elif client.ipv6_policy == "required":
            connection_wait_reason = "A Location with working IPv6 is not ready yet."
        elif profile is None:
            connection_wait_reason = "CayVPN is still assigning the selected Location."
        else:
            connection_wait_reason = "The selected Location has not passed its safety checks yet."
        return render_template(
            "client_ready.html",
            client=client,
            config_download_name=_config_download_name(client.name),
            location_label=location_label,
            connection_ready=connection_ready,
            connection_wait_reason=connection_wait_reason,
            ipv6_protected=ipv6_protected,
        )

    @app.route("/clients/<int:client_id>/config/confirm", methods=["POST"])
    @require_auth
    def confirm_client_config(client_id: int):
        if request.form.get("installed") != "on":
            flash("Confirm that you imported and activated the current configuration first.", "warning")
            return redirect(local_redirect(request.referrer, url_for("index")))
        with db.session() as session_db:
            client = session_db.get(Client, client_id)
            if client is None:
                abort(404)
            if request.form.get("config_version", type=int) != client.generated_config_version:
                flash("The configuration changed. Download and import the latest connection before marking it installed.", "warning")
                return redirect(url_for("client_ready", client_id=client_id))
            binding = session_db.scalar(select(RouteBinding).where(RouteBinding.client_id == client_id))
            if binding is not None and binding.state == "pending":
                flash("Wait for the connection checks to finish before marking this configuration installed.", "warning")
                return redirect(url_for("client_ready", client_id=client_id))
            client.confirmed_config_version = client.generated_config_version
            name = client.name
            generation = client.generated_config_version
        operations.audit("owner", "client.config_confirmed", {"client_id": client_id, "generation": generation})
        flash(f"{name}'s current CayVPN connection is marked installed.", "success")
        return redirect(local_redirect(request.referrer, url_for("index")))

    @app.route("/setup/exit/<draft_id>/complete", methods=["POST"])
    @high_risk
    def complete_exit_wizard(draft_id: str):
        draft = load_wizard_draft(draft_id, "exit")
        data = draft.data
        checked = data.get("check") if isinstance(data.get("check"), dict) else None
        if not checked or not checked.get("valid"):
            flash("Run the Location checks before saving it.", "danger")
            return redirect(url_for("wizard_step", kind="exit", draft_id=draft.id, step=3))
        if data.get("driver") == "additional_ip":
            try:
                _ensure_additional_addresses_are_new(data.get("config") or {})
            except ValueError as exc:
                flash(_friendly_location_message(exc), "danger")
                return redirect(url_for("wizard_step", kind="exit", draft_id=draft.id, step=2))
        with db.session() as session_db:
            existing_count = session_db.query(EgressProfile).count()
            latest_capacity = session_db.scalar(select(CapacitySnapshot).order_by(desc(CapacitySnapshot.observed_at)))
            if latest_capacity and existing_count >= latest_capacity.max_egress_profiles and db.get_setting("capacity_override_active", "0") != "1":
                flash("The safe Location limit has been reached.", "danger")
                return redirect(url_for("wizard_step", kind="exit", draft_id=draft.id, step=5))
            profile = EgressProfile(
                name=str(data["name"]),
                driver=str(data["driver"]),
                config_json=json.dumps(redacted_profile(str(data["driver"]), data.get("config") or {}, bool(draft.secret_ref)), sort_keys=True),
                secret_enc=draft.secret_ref,
                capabilities_json=json.dumps(normalize_capabilities(checked.get("capabilities") or {}), sort_keys=True),
                health_state="pending",
                ipv6_health_state="pending" if ipv6_usable(checked.get("capabilities") or {}) else "unavailable",
            )
            session_db.add(profile)
            session_db.flush()
            profile_id = profile.id
        # The secret is now owned by the exit record. Remove the temporary
        # draft reference before any runtime operation so cancellation can
        # never delete a permanent exit secret.
        save_wizard_draft(draft.id, data, 5, None)
        delete_wizard_draft(draft.id, keep_secret=True)
        _operation, response = operations.run(
            "egress.activate",
            {"profile_id": profile_id, "driver": data["driver"], "config": data.get("config") or {}, "secret_ref": draft.secret_ref},
            actor="owner",
        )
        verified = response.status == "succeeded" and bool(response.result.get("verified"))
        with db.session() as session_db:
            saved = session_db.get(EgressProfile, profile_id)
            saved.health_state = "healthy" if verified else "pending"
            saved.last_failure_reason = None if verified else _safe_text(str(response.result.get("reason") or response.error_message or "verification_pending"), 240)
            saved.last_check_at = datetime.now(timezone.utc)
            _apply_egress_observation(saved, response.result or {})
        if verified:
            flash(f"Location {data['name']} is saved and verified. No device was changed automatically.", "success")
        else:
            flash(f"Location {data['name']} is saved, but traffic remains blocked until its live checks pass.", "warning")
        return redirect(url_for("egress"))

    @app.route("/setup/pool/<draft_id>/complete", methods=["POST"])
    @high_risk
    def complete_pool_wizard(draft_id: str):
        draft = load_wizard_draft(draft_id, "pool")
        data = draft.data
        try:
            name, profile_ids = validate_pool_input(str(data.get("name", "")), data.get("profile_ids") or [])
        except ValueError as exc:
            flash(_friendly_location_message(exc), "danger")
            return redirect(url_for("wizard_step", kind="pool", draft_id=draft.id, step=2))
        if data.get("all_failed") != "block":
            flash("Confirm that traffic stays blocked when every backup Location is unavailable.", "danger")
            return redirect(url_for("wizard_step", kind="pool", draft_id=draft.id, step=3))
        with db.session() as session_db:
            pool = EgressPool(name=name, profile_ids_json=json.dumps(profile_ids), failover_policy="ordered", failback_policy="manual", enabled=True)
            session_db.add(pool)
            session_db.flush()
            pool_id = pool.id
        operations.audit("owner", "egress_pool.create", {"pool_id": pool_id, "name": name, "profile_ids": profile_ids})
        delete_wizard_draft(draft.id, keep_secret=True)
        flash(f"Backup group {name} saved. Returning to the first Location remains manual.", "success")
        return redirect(url_for("egress"))

    @app.route("/clients/<int:client_id>/delete", methods=["POST"])
    @app.route("/remove/<int:client_id>", methods=["POST"])
    @high_risk
    def delete_client(client_id: int):
        with db.session() as session_db:
            client = session_db.get(Client, client_id)
            if client is None:
                abort(404)
            name, public_key, protocol, private_key_ref, client_address, client_ipv6_address = client.name, client.public_key, client.ingress_protocol, client.private_key_enc, client.address, client.ipv6_address
            binding = session_db.scalar(select(RouteBinding).where(RouteBinding.client_id == client_id))
            route_profile_id = binding.egress_profile_id if binding and binding.egress_profile_id else 1
        interface = settings.amnezia_interface if protocol == "amneziawg" else settings.user_interface
        _, peer_response = operations.run("wireguard.remove_peer", {"interface": interface, "protocol": protocol, "public_key": public_key}, actor="owner")
        if peer_response.status != "succeeded":
            flash(f"Client {name} was not deleted because its server peer could not be revoked: {peer_response.error_message or 'agent unavailable'}", "warning")
            return redirect(url_for("index"))
        _, route_response = operations.run("route.remove", {"client_id": client_id, "client_address": f"{client_address}/32", "client_ipv6_address": f"{client_ipv6_address}/128" if client_ipv6_address else None, "ingress_interface": interface, "profile_id": route_profile_id}, actor="owner")
        if route_response.status != "succeeded":
            with db.session() as session_db:
                current = session_db.get(Client, client_id)
                if current is not None:
                    current.enabled = False
                current_binding = session_db.scalar(select(RouteBinding).where(RouteBinding.client_id == client_id))
                if current_binding is not None:
                    current_binding.state = "blocked"
                    current_binding.last_error = route_response.error_message or "route removal pending"
            flash(f"Client {name} was revoked and disabled, but its route cleanup is pending: {route_response.error_message or 'agent unavailable'}", "warning")
            return redirect(url_for("index"))
        if not delete_secret(private_key_ref):
            with db.session() as session_db:
                current = session_db.get(Client, client_id)
                if current is not None:
                    current.enabled = False
                current_binding = session_db.scalar(select(RouteBinding).where(RouteBinding.client_id == client_id))
                if current_binding is not None:
                    current_binding.state = "blocked"
                    current_binding.last_error = "private-key cleanup pending"
            flash(
                f"Client {name} was revoked and disabled, but its encrypted key cleanup is pending. Retry Remove to finish safely.",
                "warning",
            )
            return redirect(url_for("index"))
        with db.session() as session_db:
            current_binding = session_db.scalar(select(RouteBinding).where(RouteBinding.client_id == client_id))
            if current_binding is not None:
                session_db.delete(current_binding)
            current = session_db.get(Client, client_id)
            if current is not None:
                session_db.delete(current)
        operations.audit("owner", "client.delete", {"client_id": client_id, "name": name})
        flash(f"Client {name} removed and its server peer revoked.", "success")
        return redirect(url_for("index"))

    def _server_public_key(protocol: str = "wireguard") -> str:
        path = settings.wg_dir / ("awg-server.pub" if protocol == "amneziawg" else "server.pub")
        try:
            if path.exists():
                return path.read_text().strip()
        except OSError as exc:
            raise ValueError("The server public key is not readable; run sudo cayvpnctl repair over SSH") from exc
        fallback = os.environ.get("CAYVPN_SERVER_PUBLIC_KEY")
        if fallback:
            return fallback
        if settings.apply_network:
            raise ValueError("The server public key is not installed")
        return base64.b64encode(b"\0" * 32).decode()

    def _client_config(client: Client) -> str:
        with db.session() as session_db:
            ingress = session_db.scalar(select(IngressEndpoint).where(IngressEndpoint.protocol == client.ingress_protocol))
        if ingress is None:
            interface = settings.user_interface if client.ingress_protocol == "wireguard" else settings.amnezia_interface
            port = settings.user_port if client.ingress_protocol == "wireguard" else settings.amnezia_port
        else:
            interface, port = ingress.interface, ingress.listen_port
        dns_v4 = settings.client_adblock_dns_address if client.dns_mode == "ad_blocking" else settings.client_dns_address
        dns_v6 = settings.client_adblock_dns_address_v6 if client.dns_mode == "ad_blocking" else settings.client_dns_address_v6
        dns = ", ".join(item for item in (dns_v4, dns_v6 if client.ipv6_address else "") if item)
        rendered_dns = f"{dns}, {admin_dns_search_domain(settings.admin_hostname)}"
        address = ", ".join(item for item in (f"{client.address}/32", f"{client.ipv6_address}/128" if client.ipv6_address else "") if item)
        server_public_key = _server_public_key(client.ingress_protocol)
        endpoint = f"{settings.public_endpoint}:{port}"
        if client.private_key_enc and client.private_key_enc.startswith("ref::"):
            _, response = operations.run("config.render_client", {"secret_ref": client.private_key_enc, "address": address, "server_public_key": server_public_key, "endpoint": endpoint, "dns": dns, "protocol": client.ingress_protocol, "ipv6_policy": client.ipv6_policy, "allowed_ips": "0.0.0.0/0, ::/0", "persistent_keepalive": 25}, actor="owner")
            if response.status != "succeeded" or not response.result.get("config"):
                raise ValueError(response.error_message or "The root agent could not render this configuration")
            return str(response.result["config"])
        private_key = reveal_secret(client.private_key_enc)
        if not private_key:
            raise ValueError("This client has no stored private key")
        lines = [
            "# Managed by CayVPN. This is a full-tunnel configuration.",
            f"# Ingress protocol: {client.ingress_protocol}",
            f"# IPv6 protection: {'required' if client.ipv6_policy == 'required' else 'smart'}",
            "[Interface]",
            f"PrivateKey = {private_key}",
            f"Address = {address}",
            f"DNS = {rendered_dns}",
            "",
            "[Peer]",
            f"PublicKey = {server_public_key}",
            f"Endpoint = {endpoint}",
            "AllowedIPs = 0.0.0.0/0, ::/0",
            "PersistentKeepalive = 25",
            "",
        ]
        return "\n".join(lines)

    @app.route("/clients/<int:client_id>/config")
    @app.route("/config/<int:client_id>")
    @high_risk
    def download_config(client_id: int):
        with db.session() as session_db:
            client = session_db.get(Client, client_id)
            if client is None:
                abort(404)
            name = client.name
        try:
            config = _client_config(client)
        except ValueError as exc:
            flash(str(exc), "warning")
            return redirect(url_for("index"))
        return send_file(
            io.BytesIO(config.encode()),
            as_attachment=True,
            download_name=_config_download_name(name),
            mimetype="text/plain",
        )

    @app.route("/clients/<int:client_id>/qr")
    @app.route("/qr/<int:client_id>")
    @high_risk
    def client_qr(client_id: int):
        with db.session() as session_db:
            client = session_db.get(Client, client_id)
            if client is None:
                abort(404)
            name = client.name
        try:
            config = _client_config(client)
        except ValueError as exc:
            flash(str(exc), "warning")
            return redirect(url_for("index"))
        return render_template("qr.html", qr_b64=_qr_b64(config), name=name, management_mode=True)

    @app.route("/egress", methods=["GET", "POST"])
    @require_auth
    def egress():
        if request.method == "POST":
            if not recent_owner_approval():
                return owner_confirmation_required(url_for("egress"))
            try:
                name = _safe_text(request.form.get("name"), 120)
                driver = request.form.get("driver", "").lower()
                if not name:
                    raise ValueError("Give this Location a recognizable name, such as Miami or London")
                config: dict = {}
                secret: str | None = None
                if driver == "direct_ip":
                    raise ValueError("The server's normal address is already available as This server")
                elif driver == "additional_ip":
                    config = {
                        "address": request.form.get("address", "").strip(),
                        "prefix": request.form.get("prefix", "32").strip(),
                        "gateway": request.form.get("gateway", "").strip(),
                        "interface": request.form.get("interface", "").strip(),
                        "ipv6_address": request.form.get("ipv6_address", "").strip(),
                        "ipv6_prefix": request.form.get("ipv6_prefix", "128").strip(),
                        "ipv6_gateway": request.form.get("ipv6_gateway", "").strip(),
                    }
                elif driver == "socks5":
                    config = {"endpoint": request.form.get("endpoint", "").strip()}
                    secret = request.form.get("password") or None
                    parsed_endpoint = parse_socks5(config["endpoint"])
                    if secret is None and parsed_endpoint.get("password"):
                        secret = str(parsed_endpoint["password"])
                    if parsed_endpoint.get("password"):
                        user = f"{parsed_endpoint.get('username')}@" if parsed_endpoint.get("username") else ""
                        config["endpoint"] = f"socks5://{user}{parsed_endpoint['host']}:{parsed_endpoint['port']}"
                elif driver == "provider_tunnel":
                    secret = request.form.get("config_text") or None
                    config = {"protocol_hint": "auto", "full_tunnel_required": True}
                else:
                    raise ValueError("Choose a supported Location type")
                validation_config = dict(config)
                if driver == "socks5" and secret:
                    validation_config["endpoint"] = validation_config["endpoint"]
                if driver == "provider_tunnel":
                    validation_config["config_text"] = secret or ""
                validated = validate_driver(driver, validation_config, secret)
                if driver in {"additional_ip", "provider_tunnel"}:
                    config = dict(validated.redacted_config)
                if driver == "additional_ip":
                    _ensure_additional_addresses_are_new(config)
                with db.session() as session_db:
                    existing_count = session_db.query(EgressProfile).count()
                    latest_capacity = session_db.scalar(select(CapacitySnapshot).order_by(desc(CapacitySnapshot.observed_at)))
                    override_active = db.get_setting("capacity_override_active", "0") == "1"
                    if latest_capacity and existing_count >= latest_capacity.max_egress_profiles and not override_active:
                        raise ValueError("The safe Location limit has been reached")
                secret_ref = agent_secret_store(secret, f"egress-{name}") if secret else None
                with db.session() as session_db:
                    profile = EgressProfile(name=name, driver=driver, config_json=json.dumps(redacted_profile(driver, config, bool(secret))), secret_enc=secret_ref, capabilities_json=json.dumps(normalize_capabilities(validated.capabilities), sort_keys=True), health_state="healthy" if driver == "direct_ip" else "pending", ipv6_health_state="pending" if ipv6_usable(validated.capabilities) else "unavailable")
                    session_db.add(profile)
                    session_db.flush()
                    profile_id = profile.id
                agent_config = dict(config)
                agent_payload = {"profile_id": profile_id, "driver": driver, "config": agent_config, "secret_ref": secret_ref}
                if secret is not None and not secret_ref:
                    agent_payload["secret"] = secret
                _op, response = operations.run("egress.activate", agent_payload, actor="owner")
                verified = response.status == "succeeded" and bool(response.result.get("verified"))
                with db.session() as session_db:
                    saved_profile = session_db.get(EgressProfile, profile_id)
                    if saved_profile is not None:
                        saved_profile.health_state = "healthy" if verified else "pending"
                        _apply_egress_observation(saved_profile, response.result or {})
                        saved_profile.last_check_at = datetime.now(timezone.utc)
                        saved_profile.last_failure_reason = None if verified else str(response.result.get("reason") or response.error_message or "verification_pending")[:240]
                        if verified:
                            saved_profile.consecutive_failures = 0
                if verified:
                    flash(f"Location {name} saved and verified. It is ready to assign to a device.", "success")
                elif response.status != "succeeded":
                    flash(f"Location {name} was saved, but verification could not finish: {response.error_message or 'agent unavailable'}. Traffic remains blocked.", "warning")
                else:
                    reason = str(response.result.get("reason") or "the new connection is not active on this server yet").replace("_", " ")
                    flash(f"Location {name} was saved, but it is not ready yet ({reason}). Traffic remains blocked until it verifies.", "warning")
                return redirect(url_for("egress"))
            except (ValueError, DriverValidationError) as exc:
                flash(_friendly_location_message(exc), "danger")
        with db.session() as session_db:
            profiles = session_db.scalars(select(EgressProfile).order_by(EgressProfile.id)).all()
            pools = session_db.scalars(select(EgressPool).order_by(EgressPool.id)).all()
        pool_rows = [(pool, _json(pool.profile_ids_json, [])) for pool in pools]
        can_create_pool = len([profile for profile in profiles if profile.enabled]) >= 2
        location_drafts = [draft for draft in active_wizard_drafts() if draft.kind in {"exit", "pool"}]
        return render_template("egress.html", profiles=profiles, pools=pool_rows, drafts=location_drafts, out_interface=settings.out_interface or "eth0", form_data=request.form, can_create_pool=can_create_pool)

    def validate_pool_input(name: str, profile_ids: list[object]) -> tuple[str, list[int]]:
        clean_name = _safe_text(name, 120)
        if not clean_name:
            raise ValueError("Backup group name is required")
        try:
            ids = [int(item) for item in profile_ids]
        except (TypeError, ValueError) as exc:
            raise ValueError("Backup group contains an invalid Location") from exc
        if not ids or len(ids) > 32 or len(set(ids)) != len(ids):
            raise ValueError("Choose one or more unique Locations for the group")
        with db.session() as session_db:
            profiles = {profile.id: profile for profile in session_db.scalars(select(EgressProfile).where(EgressProfile.id.in_(ids))).all()}
        if set(ids) != set(profiles) or any(not profiles[item].enabled for item in ids):
            raise ValueError("A backup group may contain only enabled Locations")
        return clean_name, ids

    @app.route("/egress/pools", methods=["POST"])
    @high_risk
    def create_pool():
        try:
            name, profile_ids = validate_pool_input(request.form.get("name", ""), request.form.getlist("profile_ids"))
            with db.session() as session_db:
                session_db.add(EgressPool(name=name, profile_ids_json=json.dumps(profile_ids), failover_policy="ordered", failback_policy="manual", enabled=True))
            operations.audit("owner", "egress_pool.create", {"name": name, "profile_ids": profile_ids})
            flash(f"Backup group {name} saved. Returning to the first Location remains manual.", "success")
        except ValueError as exc:
            flash(_friendly_location_message(exc), "danger")
        return redirect(url_for("egress"))

    @app.route("/egress/pools/<int:pool_id>/delete", methods=["POST"])
    @high_risk
    def delete_pool(pool_id: int):
        with db.session() as session_db:
            pool = session_db.get(EgressPool, pool_id)
            if pool is None:
                abort(404)
            if session_db.scalar(select(RouteBinding.id).where(RouteBinding.pool_id == pool_id)):
                flash("Move devices off this backup group before deleting it.", "warning")
                return redirect(url_for("egress"))
            name = pool.name
            session_db.delete(pool)
        operations.audit("owner", "egress_pool.delete", {"pool_id": pool_id, "name": name})
        flash(f"Backup group {name} removed.", "success")
        return redirect(url_for("egress"))

    @app.route("/egress/<int:profile_id>/activate", methods=["POST"])
    @high_risk
    def activate_egress(profile_id: int):
        with db.session() as session_db:
            profile = session_db.get(EgressProfile, profile_id)
            if profile is None:
                abort(404)
            config = _json(profile.config_json)
            secret_ref = profile.secret_enc if profile.secret_enc and profile.secret_enc.startswith("ref::") else None
            secret = None if secret_ref else reveal_secret(profile.secret_enc)
            if profile.driver == "socks5" and secret is not None:
                config["endpoint"] = config.get("endpoint", "")
        payload = {"profile_id": profile_id, "driver": profile.driver, "config": config, "secret_ref": secret_ref}
        if secret is not None:
            payload["secret"] = secret
        _, response = operations.run("egress.activate", payload, actor="owner")
        with db.session() as session_db:
            profile = session_db.get(EgressProfile, profile_id)
            if response.status == "succeeded" and response.result.get("verified"):
                profile.health_state = "healthy"
                profile.last_failure_reason = None
                profile.consecutive_failures = 0
            else:
                profile.health_state = "pending"
                profile.last_failure_reason = str(response.result.get("reason") or response.error_message or "verification_pending")[:240]
            _apply_egress_observation(profile, response.result or {})
            profile.last_check_at = datetime.now(timezone.utc)
        flash("Location check submitted. CayVPN will keep traffic blocked until verification passes.", "success" if response.status == "succeeded" else "warning")
        return redirect(url_for("egress"))

    @app.route("/egress/<int:profile_id>/delete", methods=["POST"])
    @high_risk
    def delete_egress(profile_id: int):
        with db.session() as session_db:
            profile = session_db.get(EgressProfile, profile_id)
            if profile is None:
                abort(404)
            if profile.driver == "direct_ip":
                flash("This server is the built-in Location and cannot be deleted.", "warning")
                return redirect(url_for("egress"))
            bound = session_db.scalar(select(RouteBinding.id).where(RouteBinding.egress_profile_id == profile_id))
            if bound:
                flash("Move devices off this Location before deleting it.", "warning")
                return redirect(url_for("egress"))
            pools = session_db.scalars(select(EgressPool).where(EgressPool.enabled.is_(True))).all()
            pool_references = []
            for pool in pools:
                try:
                    pool_references.append({int(item) for item in _json(pool.profile_ids_json, [])})
                except (TypeError, ValueError):
                    continue
            if any(profile_id in referenced for referenced in pool_references):
                flash("Remove this Location from its backup groups before deleting it.", "warning")
                return redirect(url_for("egress"))
            name, secret_ref = profile.name, profile.secret_enc
        _, response = operations.run("egress.deactivate", {"profile_id": profile_id, "remove_namespace": True}, actor="owner")
        if response.status != "succeeded":
            flash(f"Location {name} was not deleted because its connection could not be stopped: {response.error_message or 'agent unavailable'}", "warning")
            return redirect(url_for("egress"))
        with db.session() as session_db:
            profile = session_db.get(EgressProfile, profile_id)
            if profile is not None:
                session_db.delete(profile)
        delete_secret(secret_ref)
        flash(f"Location {name} removed and disabled.", "success")
        return redirect(url_for("egress"))

    @app.route("/clients/<int:client_id>/settings", methods=["GET", "POST"])
    @require_auth
    def client_settings(client_id: int):
        if request.method == "POST" and not recent_owner_approval():
            return owner_confirmation_required(url_for("client_settings", client_id=client_id))
        errors = []
        if request.method == "POST":
            try:
                _, response = operations.update_client_settings(
                    client_id, request.form.get("dns_mode", ""), request.form.get("ipv6_policy", ""),
                    request.form.get("settings_revision", ""), actor="owner",
                )
            except ValueError as exc:
                errors.append(_friendly_location_message(exc))
            else:
                if response.status == "succeeded" and response.result.get("verified"):
                    if response.result.get("unchanged"):
                        flash("This connection already uses those settings.", "info")
                    else:
                        flash("Connection settings applied and verified. IPv6 protection takes effect on the server immediately.", "success")
                    with db.session() as session_db:
                        client = session_db.get(Client, client_id)
                        needs_import = client.confirmed_config_version < client.generated_config_version
                    if needs_import:
                        flash("Download and import the current configuration to use the selected web protection on your device.", "warning")
                    return redirect(url_for("client_ready", client_id=client_id) if needs_import else url_for("index"))
                if response.error_code == "route_switch_failed":
                    errors.append("The new settings could not be applied. Previous settings were restored; traffic stays blocked if the previous connection cannot be verified.")
                else:
                    errors.append("Settings are saved but not yet verified. CayVPN will retry the connection checks. Wait before making another change.")
        with db.session() as session_db:
            client = session_db.get(Client, client_id)
            if client is None or not client.enabled:
                abort(404)
            binding = session_db.scalar(select(RouteBinding).where(RouteBinding.client_id == client_id))
            profile = session_db.get(EgressProfile, binding.egress_profile_id) if binding and binding.egress_profile_id else None
        return render_template("client_settings.html", client=client, binding=binding, profile=profile,
                               errors=errors, ad_blocking_ready=ad_blocking_ready()), (409 if errors else 200)

    @app.route("/clients/<int:client_id>/route", methods=["POST"])
    @high_risk
    def switch_route(client_id: int):
        profile_id = request.form.get("profile_id", type=int)
        pool_id = request.form.get("pool_id", type=int)
        try:
            _, response = operations.route_switch(client_id, profile_id=profile_id, pool_id=pool_id)
            flash("Routing change applied and verified." if response.status == "succeeded" else "Routing change queued; traffic remains fail-closed until the agent verifies it.", "success" if response.status == "succeeded" else "warning")
        except ValueError as exc:
            flash(_friendly_location_message(exc), "danger")
        return redirect(local_redirect(request.referrer, url_for("index")))

    @app.route("/capacity", methods=["GET", "POST"])
    @require_auth
    def capacity():
        if request.method == "POST":
            action = request.form.get("action")
            if action in {"override", "clear_override"} and not recent_owner_approval():
                return owner_confirmation_required(url_for("capacity"))
            if action == "override":
                reason = _safe_text(request.form.get("reason"), 300)
                reason = reason or "Owner override"
                db.set_setting("capacity_override_active", "1")
                db.set_setting("capacity_override_reason", reason)
                refresh_capacity()
                operations.audit("owner", "capacity.override", {"reason": reason})
                operations.run("system.snapshot", {}, actor="owner")
                flash("Capacity override recorded. Monitor the node closely.", "warning")
            elif action == "clear_override":
                db.set_setting("capacity_override_active", "0")
                db.set_setting("capacity_override_reason", "")
                refresh_capacity()
                operations.audit("owner", "capacity.override.clear", {})
                operations.run("system.snapshot", {}, actor="owner")
                flash("Capacity override cleared; safe limits are enforced again.", "success")
            else:
                refresh_capacity()
                operations.run("system.snapshot", {}, actor="owner")
                flash("Capacity refreshed from the current server resources.", "success")
            return redirect(url_for("capacity"))
        with db.session() as session_db:
            snapshot = session_db.scalar(select(CapacitySnapshot).order_by(desc(CapacitySnapshot.observed_at)))
        if snapshot is None:
            snapshot = refresh_capacity()
        return render_template("capacity.html", capacity=snapshot)

    def refresh_capacity() -> CapacitySnapshot:
        with db.session() as session_db:
            profiles = session_db.scalars(select(EgressProfile).where(EgressProfile.enabled.is_(True))).all()
            drivers = [profile.driver for profile in profiles] or ["direct_ip"]
            active_clients = session_db.query(Client).filter(Client.enabled.is_(True)).count()
            active_driver_processes = sum(1 for profile in profiles if profile.driver != "direct_ip")
            resources = detect_resources(active_clients=active_clients, active_driver_processes=active_driver_processes)
            transfer = db.get_setting("transfer_allowance_gb")
            advertised = db.get_setting("advertised_mbps")
            estimate = calculate_capacity(resources, drivers, int(transfer) if transfer and transfer.isdigit() else None, int(advertised) if advertised and advertised.isdigit() else None)
            used_gb, forecast_gb = transfer_forecast(resources.traffic_bytes)
            override_active = db.get_setting("capacity_override_active", "0") == "1"
            node = session_db.get(ManagedNode, 1)
            if node is not None:
                node.architecture = resources.architecture
            snapshot = CapacitySnapshot(architecture=resources.architecture, vcpus=resources.vcpus, memory_mb=resources.memory_mb, disk_free_mb=resources.disk_free_mb, load_1m=resources.load_1m, active_clients=resources.active_clients, active_driver_processes=resources.active_driver_processes, interface_speed_mbps=resources.interface_speed_mbps, transfer_allowance_gb=int(transfer) if transfer and transfer.isdigit() else None, transfer_used_gb=used_gb, transfer_forecast_gb=forecast_gb, safe_active_clients=estimate.safe_active_clients, max_stored_configs=estimate.max_stored_configs, max_egress_profiles=estimate.max_egress_profiles, estimated_mbps=estimate.estimated_mbps, limiting_factor=estimate.limiting_factor, confidence=estimate.confidence, over_capacity=estimate.over_capacity, override_active=override_active, override_reason=db.get_setting("capacity_override_reason", "") if override_active else None)
            session_db.add(snapshot)
            return snapshot

    def update_status() -> dict:
        response = agent.execute(AgentRequest(uuid.uuid4().hex, "update.status", payload={}))
        if response.status == "succeeded" and isinstance(response.result, dict):
            return response.result
        return {"schema_version": 1, "state": "unavailable", "error_code": response.error_code, "error_message": "Update status is temporarily unavailable."}

    def reboot_status() -> tuple[bool, list[str]]:
        reboot_marker = Path("/var/run/reboot-required")
        packages_marker = Path("/var/run/reboot-required.pkgs")
        try:
            packages = packages_marker.read_text(errors="replace").splitlines() if packages_marker.is_file() else []
        except OSError:
            packages = []
        return reboot_marker.is_file(), packages[:100]

    def release_date(value: object) -> str:
        try:
            published = datetime.fromisoformat(str(value).replace("Z", "+00:00")).astimezone(timezone.utc)
        except (TypeError, ValueError):
            return ""
        return published.strftime("%B %d, %Y").replace(" 0", " ")

    @app.route("/settings", methods=["GET", "POST"])
    @require_auth
    def settings_page():
        if request.method == "POST":
            region = _safe_text(request.form.get("server_region"), 500)
            transfer = request.form.get("transfer_allowance_gb", "").strip()
            advertised = request.form.get("advertised_mbps", "").strip()
            if transfer and not transfer.isdigit():
                flash("Transfer allowance must be a whole number of GB.", "danger")
                return redirect(url_for("settings_page"))
            if advertised and not advertised.isdigit():
                flash("Advertised speed must be a whole number of Mbps.", "danger")
                return redirect(url_for("settings_page"))
            db.set_setting("server_region", region or settings.server_region)
            db.set_setting("transfer_allowance_gb", transfer)
            db.set_setting("advertised_mbps", advertised)
            refresh_capacity()
            operations.run("system.snapshot", {}, actor="owner")
            flash("Node settings and capacity estimate updated.", "success")
            return redirect(url_for("settings_page"))
        with db.session() as session_db:
            node = session_db.get(ManagedNode, 1)
        reboot_required, reboot_packages = reboot_status()
        current_update_status = update_status()
        offered_release = current_update_status.get("release") or {}
        return render_template(
            "management_settings.html",
            transfer_allowance=db.get_setting("transfer_allowance_gb", ""),
            advertised_mbps=db.get_setting("advertised_mbps", ""),
            current_release=node.release if node else __version__,
            update_status=current_update_status,
            update_release_date=release_date(offered_release.get("published_at")),
            reboot_required=reboot_required,
            reboot_packages=reboot_packages,
        )

    @app.route("/updates/check", methods=["POST"])
    @require_auth
    def check_updates_from_panel():
        _operation, response = operations.run("update.check", {}, actor="owner")
        if response.status == "succeeded":
            release = response.result.get("release") or {}
            if response.result.get("state") == "available":
                flash(f"CayVPN {release.get('version', 'update')} is available. Review it before downloading.", "success")
            else:
                flash("This server is already on the latest stable CayVPN release.", "success")
        else:
            flash(response.error_message or "CayVPN could not check for updates. Nothing was changed.", "warning")
        return redirect(url_for("settings_page"))

    @app.route("/updates/stage", methods=["POST"])
    @require_auth
    def stage_update_from_panel():
        release = _safe_text(request.form.get("release"), 80)
        _operation, response = operations.run("update.stage", {"release": release}, actor="owner")
        if response.status == "queued":
            flash(f"CayVPN {release} is downloading and being verified in the background. The active VPN is unchanged.", "success")
        else:
            flash(response.error_message or "The update could not be queued. Nothing was changed.", "warning")
        return redirect(url_for("settings_page"))

    @app.route("/updates/install", methods=["POST"])
    @high_risk
    def install_update_from_panel():
        release = _safe_text(request.form.get("release"), 80)
        _operation, response = operations.run("update.apply", {"release": release}, actor="owner")
        if response.status == "queued":
            flash(f"Installing CayVPN {release}. This settings page may reconnect while services restart; a failed health check restores the previous release.", "success")
        else:
            flash(response.error_message or "The update could not start. The active release was not changed.", "warning")
        return redirect(url_for("settings_page"))

    @app.route("/updates/discard", methods=["POST"])
    @require_auth
    def discard_update_from_panel():
        release = _safe_text(request.form.get("release"), 80)
        _operation, response = operations.run("update.discard", {"release": release}, actor="owner")
        if response.status == "succeeded":
            flash(f"The downloaded CayVPN {release} package was removed. The active VPN was unchanged.", "success")
        else:
            flash(response.error_message or "The downloaded update could not be removed. The active release was unchanged.", "warning")
        return redirect(url_for("settings_page"))

    @app.route("/onboarding/start", methods=["POST"])
    @require_auth
    def start_onboarding():
        db.set_setting("onboarding_prompt_seen", "1")
        destination = request.form.get("next", "security")
        endpoints = {"security": "security_page", "clients": "clients", "overview": "index"}
        return redirect(url_for(endpoints.get(destination, "security_page")))

    @app.route("/support/dismiss", methods=["POST"])
    @require_auth
    def dismiss_support():
        db.set_setting("donation_prompt_seen", "1")
        return redirect(local_redirect(request.referrer, url_for("index")))

    @app.route("/support/visit", methods=["POST"])
    @require_auth
    def visit_support():
        db.set_setting("donation_prompt_seen", "1")
        return redirect("https://www.buymeacoffee.com/caynetic")

    @app.route("/backups/create", methods=["POST"])
    @high_risk
    def create_backup_from_panel():
        passphrase = request.form.get("passphrase", "")
        if len(passphrase) < 12:
            flash("Use a backup passphrase of at least 12 characters.", "danger")
            return redirect(local_redirect(request.referrer, url_for("settings_page")))
        _, response = operations.run("backup.create", {"passphrase": passphrase}, actor="owner")
        if response.status == "succeeded":
            flash(f"Encrypted backup created at {response.result.get('path', 'the server backup directory')}. Copy it off the server.", "success")
        else:
            flash(response.error_message or "The backup could not be created.", "warning")
        return redirect(local_redirect(request.referrer, url_for("settings_page")))

    @app.route("/security/approve", methods=["POST"])
    @require_auth
    def approve_security():
        code = request.form.get("recovery_code", "")
        approval_hash = db.get_setting("recovery_approval_hash", "")
        approval_until = db.get_setting("recovery_approval_until", "0")
        try:
            approved = int(approval_until or "0") >= now_epoch() and verify_password(code, approval_hash)
        except ValueError:
            approved = False
        if approved:
            session["owner_approval_until"] = now_epoch() + 300
            session["passkey_verified_until"] = session["owner_approval_until"]
            db.set_setting("recovery_approval_hash", "")
            db.set_setting("recovery_approval_until", "0")
            flash("High-risk actions are approved for five minutes.", "success")
        else:
            flash("Recovery approval was rejected.", "danger")
        return redirect(local_redirect(request.referrer, url_for("index")))

    def passkey_origin() -> str:
        scheme = "https" if settings.https_enabled else "http"
        return f"{scheme}://{settings.admin_hostname}:{settings.admin_https_port}"

    @app.route("/security")
    @require_auth
    def security_page():
        with db.session() as session_db:
            credentials = session_db.scalars(select(PasskeyCredential).order_by(PasskeyCredential.id)).all()
            devices = session_db.scalars(select(AdminDevice).order_by(AdminDevice.id)).all()
        return render_template(
            "security.html",
            credentials=credentials,
            devices=devices,
            owner_login_enabled=owner_login_enabled(),
            owner_totp_enabled=owner_totp_enabled(),
            owner_login_drafts=active_wizard_drafts("owner_login"),
        )

    @app.route("/security/owner-login/new", methods=["POST"])
    @require_auth
    def start_owner_login_setup():
        if owner_login_enabled() and not recent_owner_approval():
            return owner_confirmation_required(url_for("security_page"))
        with db.session() as session_db:
            draft = WizardDraft(
                kind="owner_login",
                data_json="{}",
                current_step=1,
                expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
            )
            session_db.add(draft)
            session_db.flush()
            draft_id = draft.id
        return redirect(url_for("owner_login_setup", draft_id=draft_id, step=1))

    @app.route("/security/owner-login/<draft_id>/<int:step>", methods=["GET", "POST"])
    @require_auth
    def owner_login_setup(draft_id: str, step: int):
        if not 1 <= step <= 3:
            abort(404)
        draft = load_wizard_draft(draft_id, "owner_login")
        if step > draft.current_step:
            return redirect(url_for("owner_login_setup", draft_id=draft.id, step=draft.current_step))
        data = draft.data
        errors: list[str] = []
        if request.method == "POST":
            if request.form.get("action") == "back":
                return redirect(url_for("owner_login_setup", draft_id=draft.id, step=max(1, step - 1)))
            try:
                if step == 1:
                    password = request.form.get("password", "")
                    confirmation = request.form.get("password_confirm", "")
                    access_scope = request.form.get("access_scope", "cayvpn")
                    authenticator_mode = request.form.get("authenticator_mode", "password")
                    if access_scope not in {"cayvpn", "internet"}:
                        raise ValueError("Choose where optional sign-in should work")
                    if authenticator_mode not in {"password", "authenticator"}:
                        raise ValueError("Choose password only or password plus an authenticator")
                    if access_scope == "internet" and not remote_admin_available():
                        raise ValueError(
                            "Secure internet access is not installed in this CayVPN build"
                        )
                    if len(password) < 12 or len(password) > 256:
                        raise ValueError("Use an owner password between 12 and 256 characters")
                    if password != confirmation:
                        raise ValueError("The owner passwords did not match")
                    if draft.secret_ref and not delete_secret(draft.secret_ref, actor="owner-login-restart"):
                        raise ValueError("The previous temporary sign-in secret could not be removed safely")
                    data = {
                        "password_hash": hash_password(password),
                        "authenticator_enabled": authenticator_mode == "authenticator",
                        "totp_verified": authenticator_mode == "password",
                        "access_scope": access_scope,
                    }
                    new_secret_ref = None
                    if authenticator_mode == "authenticator":
                        _operation, response = operations.run(
                            "totp.create",
                            {"account": "owner", "issuer": "CayVPN"},
                            actor="owner-login-setup",
                        )
                        if response.status != "succeeded" or not response.result.get("secret_ref"):
                            save_wizard_draft(draft.id, data, 1, None)
                            raise ValueError(response.error_message or "CayVPN could not create the authenticator setup")
                        new_secret_ref = str(response.result["secret_ref"])
                    save_wizard_draft(draft.id, data, 2, new_secret_ref)
                    return redirect(url_for("owner_login_setup", draft_id=draft.id, step=2))
                if step == 2:
                    if data.get("authenticator_enabled") is not True:
                        data["totp_verified"] = True
                        save_wizard_draft(draft.id, data, 3, None)
                        return redirect(url_for("owner_login_setup", draft_id=draft.id, step=3))
                    _operation, response = operations.run(
                        "totp.verify",
                        {"secret_ref": str(draft.secret_ref or ""), "code": request.form.get("totp_code", "")},
                        actor="owner-login-setup",
                    )
                    if response.status != "succeeded" or response.result.get("verified") is not True:
                        raise ValueError("That six-digit authenticator code was not accepted. Wait for a fresh code and try again")
                    session["last_totp_proof"] = totp_proof(request.form.get("totp_code", ""))
                    session["last_totp_step"] = now_epoch() // 30
                    data["totp_verified"] = True
                    save_wizard_draft(draft.id, data, 3)
                    return redirect(url_for("owner_login_setup", draft_id=draft.id, step=3))
                raise ValueError("Use Enable sign-in after reviewing this setup")
            except ValueError as exc:
                errors.append(str(exc))
                draft = load_wizard_draft(draft_id, "owner_login")
                data = draft.data
        provisioning_qr = None
        if step == 2 and draft.secret_ref:
            _operation, response = operations.run(
                "totp.uri",
                {"secret_ref": draft.secret_ref, "account": "owner", "issuer": "CayVPN"},
                actor="owner-login-setup",
            )
            if response.status == "succeeded" and response.result.get("provisioning_uri"):
                provisioning_qr = _qr_b64(str(response.result["provisioning_uri"]))
            else:
                errors.append(response.error_message or "CayVPN could not display the authenticator QR code")
        return render_template(
            "owner_login_wizard.html",
            draft=draft,
            data=data,
            step=step,
            total_steps=3,
            errors=errors,
            provisioning_qr=provisioning_qr,
        )

    @app.route("/security/owner-login/<draft_id>/complete", methods=["POST"])
    @require_auth
    def complete_owner_login_setup(draft_id: str):
        draft = load_wizard_draft(draft_id, "owner_login")
        data = draft.data
        authenticator_enabled = data.get("authenticator_enabled") is True
        setup_complete = (
            draft.current_step >= 3
            and bool(data.get("password_hash"))
            and (
                not authenticator_enabled
                or data.get("totp_verified") is True
                and bool(draft.secret_ref)
            )
        )
        if not setup_complete:
            flash("Finish the optional sign-in setup before enabling it.", "danger")
            return redirect(url_for("owner_login_setup", draft_id=draft.id, step=draft.current_step))
        if owner_login_enabled() and not recent_owner_approval():
            return owner_confirmation_required(
                url_for("owner_login_setup", draft_id=draft.id, step=3)
            )
        access_scope = str(data.get("access_scope", "cayvpn"))
        remote_requested = access_scope == "internet"
        previous_remote_enabled = remote_admin_enabled()
        if remote_requested and request.form.get("accept_acme_terms") != "yes":
            flash(
                "Confirm the Let's Encrypt agreement before enabling secure internet access.",
                "danger",
            )
            return redirect(url_for("owner_login_setup", draft_id=draft.id, step=3))
        if remote_requested or previous_remote_enabled:
            _operation, response = operations.run(
                "remote_admin.configure",
                {"enabled": remote_requested},
                actor="owner-login-setup",
            )
            if response.status != "succeeded":
                flash(
                    response.error_message
                    or "CayVPN could not safely change remote administration. The existing access path was preserved.",
                    "danger",
                )
                return redirect(url_for("owner_login_setup", draft_id=draft.id, step=3))
        new_reference = str(draft.secret_ref or "") if authenticator_enabled else ""
        old_reference = db.get_setting("client_panel_totp_ref", "")
        try:
            with db.session() as session_db:
                for key, value in {
                    "client_panel_login_enabled": "1",
                    "client_panel_password_hash": str(data["password_hash"]),
                    "client_panel_totp_ref": new_reference,
                    "client_panel_totp_required": "1" if authenticator_enabled else "0",
                    "remote_admin_enabled": "1" if remote_requested else "0",
                    "remote_admin_terms_accepted_at": (
                        datetime.now(timezone.utc).isoformat() if remote_requested else ""
                    ),
                }.items():
                    setting = session_db.get(Setting, key)
                    if setting is None:
                        session_db.add(Setting(key=key, value=value))
                    else:
                        setting.value = value
                current = session_db.get(WizardDraft, draft.id)
                if current is not None:
                    current.secret_ref = None
                    session_db.delete(current)
        except Exception:
            # Keep the database and public listener in the same state if the
            # credential transaction cannot commit after the network change.
            if remote_requested != previous_remote_enabled:
                try:
                    _rollback_operation, rollback_response = operations.run(
                        "remote_admin.configure",
                        {"enabled": previous_remote_enabled},
                        actor="owner-login-setup-rollback",
                    )
                    if rollback_response.status != "succeeded":
                        logger.error("Remote administration state rollback did not complete")
                except Exception:
                    logger.exception("Remote administration state rollback failed")
            logger.exception("Owner-login settings could not be committed")
            flash(
                "CayVPN could not safely save optional sign-in. The previous access method was preserved; review and try again.",
                "danger",
            )
            return redirect(url_for("owner_login_setup", draft_id=draft.id, step=3))
        if old_reference and old_reference != new_reference and not delete_secret(old_reference, actor="owner-login-rotate"):
            logger.warning("Old owner-login TOTP secret could not be removed after a safe rotation")
        operations.audit(
            "owner",
            "owner-login.enable",
            {
                "scope": "internet" if remote_requested else "cayvpn_clients",
                "authenticator_enabled": authenticator_enabled,
            },
        )
        session["owner_approval_until"] = now_epoch() + 300
        flash(
            (
                f"Optional sign-in enabled. You can now open {remote_admin_origin()} without a VPN."
                if remote_requested
                else "Optional sign-in enabled. CayVPN devices can now open settings without switching to the separate settings connection."
            ),
            "success",
        )
        return redirect(url_for("security_page"))

    @app.route("/security/owner-login/disable", methods=["POST"])
    @high_risk
    def disable_owner_login():
        if remote_admin_enabled():
            _operation, response = operations.run(
                "remote_admin.configure", {"enabled": False}, actor="owner-login-disable"
            )
            if response.status != "succeeded":
                flash(
                    response.error_message
                    or "Remote access could not be closed safely, so optional sign-in was left enabled.",
                    "danger",
                )
                return redirect(url_for("security_page"))
        old_reference = db.get_setting("client_panel_totp_ref", "")
        with db.session() as session_db:
            for key in (
                "client_panel_login_enabled",
                "client_panel_password_hash",
                "client_panel_totp_ref",
                "client_panel_totp_required",
                "remote_admin_enabled",
                "remote_admin_terms_accepted_at",
            ):
                setting = session_db.get(Setting, key)
                if setting is not None:
                    setting.value = "0" if key in {
                        "client_panel_login_enabled",
                        "client_panel_totp_required",
                        "remote_admin_enabled",
                    } else ""
        removed = not old_reference or delete_secret(old_reference, actor="owner-login-disable")
        operations.audit("owner", "owner-login.disable", {"secret_removed": removed})
        flash(
            "Optional sign-in disabled. Existing signed-in sessions are no longer accepted."
            if removed
            else "Optional sign-in disabled. Its old encrypted authenticator secret is retained for a safe cleanup retry.",
            "success" if removed else "warning",
        )
        return redirect(url_for("security_page"))

    @app.route("/security/passkey/register/options", methods=["POST"])
    @require_auth
    @private_passkey_origin
    def passkey_register_options():
        if not recent_owner_approval():
            return jsonify({"error": "recent owner confirmation required"}), 403
        from webauthn.helpers.structs import PublicKeyCredentialDescriptor
        with db.session() as session_db:
            existing = session_db.scalars(select(PasskeyCredential)).all()
        options = generate_registration_options(
            rp_id=settings.admin_hostname,
            rp_name="CayVPN",
            user_name="owner",
            user_id=b"cayvpn-owner-v1",
            user_display_name="CayVPN owner",
            timeout=60000,
            authenticator_selection=AuthenticatorSelectionCriteria(
                resident_key=ResidentKeyRequirement.PREFERRED,
                user_verification=UserVerificationRequirement.REQUIRED,
            ),
            exclude_credentials=[PublicKeyCredentialDescriptor(id=base64url_to_bytes(item.credential_id)) for item in existing],
        )
        session["passkey_register_challenge"] = bytes_to_base64url(options.challenge)
        return app.response_class(options_to_json(options), mimetype="application/json")

    @app.route("/security/passkey/register", methods=["POST"])
    @require_auth
    @private_passkey_origin
    def passkey_register():
        if not recent_owner_approval():
            session.pop("passkey_register_challenge", None)
            return jsonify({"error": "recent owner confirmation required"}), 403
        challenge = session.pop("passkey_register_challenge", None)
        credential = request.get_json(silent=True)
        if not challenge or not isinstance(credential, dict):
            return jsonify({"error": "registration challenge or credential is missing"}), 400
        try:
            verified = verify_registration_response(
                credential=credential,
                expected_challenge=base64url_to_bytes(challenge),
                expected_rp_id=settings.admin_hostname,
                expected_origin=passkey_origin(),
                require_user_presence=True,
                require_user_verification=True,
            )
        except Exception as exc:
            logger.warning("Passkey registration rejected: %s", exc)
            return jsonify({"error": "passkey verification failed"}), 400
        with db.session() as session_db:
            session_db.add(PasskeyCredential(credential_id=bytes_to_base64url(verified.credential_id), public_key_json=bytes_to_base64url(verified.credential_public_key), sign_count=verified.sign_count, label="Owner passkey"))
        operations.audit("owner", "passkey.register", {"credential_id": bytes_to_base64url(verified.credential_id)})
        return jsonify({"ok": True})

    @app.route("/security/passkey/authenticate/options", methods=["POST"])
    @require_auth
    @private_passkey_origin
    def passkey_authenticate_options():
        from webauthn.helpers.structs import PublicKeyCredentialDescriptor
        with db.session() as session_db:
            existing = session_db.scalars(select(PasskeyCredential)).all()
        if not existing:
            return jsonify({"error": "enroll a passkey first"}), 400
        options = generate_authentication_options(
            rp_id=settings.admin_hostname,
            timeout=60000,
            allow_credentials=[PublicKeyCredentialDescriptor(id=base64url_to_bytes(item.credential_id)) for item in existing],
            user_verification=UserVerificationRequirement.REQUIRED,
        )
        session["passkey_auth_challenge"] = bytes_to_base64url(options.challenge)
        return app.response_class(options_to_json(options), mimetype="application/json")

    @app.route("/security/passkey/authenticate", methods=["POST"])
    @require_auth
    @private_passkey_origin
    def passkey_authenticate():
        challenge = session.pop("passkey_auth_challenge", None)
        credential = request.get_json(silent=True)
        if not challenge or not isinstance(credential, dict):
            return jsonify({"error": "authentication challenge or credential is missing"}), 400
        credential_id = credential.get("id") or credential.get("rawId")
        with db.session() as session_db:
            item = session_db.scalar(select(PasskeyCredential).where(PasskeyCredential.credential_id == credential_id))
            if item is None:
                return jsonify({"error": "unknown passkey"}), 403
            try:
                verified = verify_authentication_response(
                    credential=credential,
                    expected_challenge=base64url_to_bytes(challenge),
                    expected_rp_id=settings.admin_hostname,
                    expected_origin=passkey_origin(),
                    credential_public_key=base64url_to_bytes(item.public_key_json),
                    credential_current_sign_count=item.sign_count,
                    require_user_verification=True,
                )
            except Exception as exc:
                logger.warning("Passkey authentication rejected: %s", exc)
                return jsonify({"error": "passkey verification failed"}), 403
            item.sign_count = verified.new_sign_count
            item.last_used_at = datetime.now(timezone.utc)
        session["owner_approval_until"] = now_epoch() + 300
        session["passkey_verified_until"] = session["owner_approval_until"]
        return jsonify({"ok": True, "expires_in": 300})

    @app.route("/security/admin-devices", methods=["POST"])
    @high_risk
    def add_admin_device():
        name = _safe_text(request.form.get("name"), 120)
        if not name:
            flash("Admin device name is required.", "danger")
            return redirect(url_for("security_page"))
        try:
            private_key, public_key = generate_keypair()
            private_key_ref = agent_secret_store(private_key, f"admin-device-{name}")
            with db.session() as session_db:
                existing = {device.address for device in session_db.scalars(select(AdminDevice)).all()}
                address = None
                for host in ipaddress.ip_network(settings.admin_network, strict=False).hosts():
                    candidate = f"{host}/32"
                    if candidate not in existing and str(host) != str(ipaddress.ip_interface(settings.admin_address).ip):
                        address = candidate
                        break
                if address is None:
                    raise ValueError("The admin network has no free address")
                device = AdminDevice(name=name, public_key=public_key, address=address, private_key_enc=private_key_ref, enabled=True)
                session_db.add(device)
                session_db.flush()
                device_id = device.id
                admin_peers = [{"public_key": item.public_key, "allowed_ips": item.address} for item in session_db.scalars(select(AdminDevice).where(AdminDevice.enabled.is_(True))).all()]
            _, response = operations.run("admin.reconcile", {"interface": settings.admin_interface, "listen_port": settings.admin_port, "address_cidr": settings.admin_address, "peers": admin_peers}, actor="owner")
            if response.status == "succeeded":
                flash(f"Admin device {name} added. Download its tunnel configuration now.", "success")
            else:
                flash(f"Admin device {name} is saved but remains pending until the root agent applies it.", "warning")
            return redirect(url_for("admin_device_config", device_id=device_id))
        except ValueError as exc:
            flash(str(exc), "danger")
            return redirect(url_for("security_page"))

    @app.route("/security/admin-devices/<int:device_id>/revoke", methods=["POST"])
    @high_risk
    def revoke_admin_device(device_id: int):
        with db.session() as session_db:
            device = session_db.get(AdminDevice, device_id)
            if device is None:
                abort(404)
            name = device.name
            was_enabled = device.enabled
            secret_ref = device.private_key_enc
            peers = [{"public_key": item.public_key, "allowed_ips": item.address} for item in session_db.scalars(select(AdminDevice).where(AdminDevice.enabled.is_(True), AdminDevice.id != device_id)).all()]
        if was_enabled:
            _, response = operations.run("admin.reconcile", {"interface": settings.admin_interface, "listen_port": settings.admin_port, "address_cidr": settings.admin_address, "peers": peers}, actor="owner")
            if response.status != "succeeded":
                flash("Admin device remains active because the root agent could not apply the revocation.", "warning")
                return redirect(url_for("security_page"))
            with db.session() as session_db:
                current = session_db.get(AdminDevice, device_id)
                if current is not None:
                    current.enabled = False
                    current.revoked_at = datetime.now(timezone.utc)
        secret_removed = delete_secret(secret_ref, actor="admin-device-revoke")
        if secret_removed:
            with db.session() as session_db:
                current = session_db.get(AdminDevice, device_id)
                if current is not None:
                    current.private_key_enc = None
            operations.audit("owner", "admin-device.revoke", {"device_id": device_id, "name": name, "secret_removed": True})
            flash(
                "Admin device revoked. Its tunnel is no longer accepted."
                if was_enabled
                else "Admin device encrypted-key cleanup finished.",
                "success",
            )
        else:
            operations.audit("owner", "admin-device.revoke", {"device_id": device_id, "name": name, "secret_removed": False})
            flash(
                "Admin device revoked, but its encrypted key cleanup is pending. Use Finish cleanup to retry safely.",
                "warning",
            )
        return redirect(url_for("security_page"))

    @app.route("/security/admin-devices/<int:device_id>/config")
    @high_risk
    def admin_device_config(device_id: int):
        with db.session() as session_db:
            device = session_db.get(AdminDevice, device_id)
            if device is None or not device.enabled:
                abort(404)
            if device.private_key_enc and device.private_key_enc.startswith("ref::"):
                private_key = None
            else:
                private_key = reveal_secret(device.private_key_enc)
            if not private_key and not (device.private_key_enc and device.private_key_enc.startswith("ref::")):
                abort(410, description="The initial admin configuration is available only through the SSH recovery path.")
        server_key_path = settings.wg_dir / "admin-server.pub"
        server_public_key = server_key_path.read_text().strip() if server_key_path.exists() else os.environ.get("CAYVPN_ADMIN_SERVER_PUBLIC_KEY")
        if not server_public_key:
            if settings.apply_network:
                abort(503, description="The admin server public key is not installed.")
            server_public_key = base64.b64encode(b"\0" * 32).decode()
        address = device.address
        endpoint = f"{settings.public_endpoint}:{settings.admin_port}"
        if device.private_key_enc and device.private_key_enc.startswith("ref::"):
            _, response = operations.run("config.render_admin", {"secret_ref": device.private_key_enc, "address": address, "server_public_key": server_public_key, "endpoint": endpoint, "dns": admin_ip, "allowed_ips": f"{admin_ip}/32"}, actor="owner")
            if response.status != "succeeded" or not response.result.get("config"):
                abort(503, description=response.error_message or "The root agent could not render this admin configuration.")
            config = str(response.result["config"])
            return send_file(io.BytesIO(config.encode()), as_attachment=True, download_name=f"{device.name.replace(' ', '-')}-admin.conf", mimetype="text/plain")
        config = "\n".join([
            "# CayVPN secure settings connection. Keep this file private.",
            "[Interface]",
            f"PrivateKey = {private_key}",
            f"Address = {address}",
            f"DNS = {admin_ip}, {admin_dns_search_domain(settings.admin_hostname)}",
            "",
            "[Peer]",
            f"PublicKey = {server_public_key}",
            f"Endpoint = {endpoint}",
            f"AllowedIPs = {admin_ip}/32",
            "PersistentKeepalive = 25",
            "",
        ])
        return send_file(io.BytesIO(config.encode()), as_attachment=True, download_name=f"{device.name.replace(' ', '-')}-admin.conf", mimetype="text/plain")

    @app.route("/api/v1/system")
    @require_auth
    def api_system():
        with db.session() as session_db:
            node = session_db.get(ManagedNode, 1)
            snapshot = session_db.scalar(select(CapacitySnapshot).order_by(desc(CapacitySnapshot.observed_at)))
        return jsonify({"node": {"id": node.id, "install_state": node.install_state, "release": node.release, "desired_generation": node.desired_generation, "observed_generation": node.observed_generation}, "capacity": snapshot_to_dict(snapshot)})

    @app.route("/api/v1/clients")
    @require_auth
    def api_clients():
        with db.session() as session_db:
            clients_list = session_db.scalars(select(Client).order_by(Client.id)).all()
        return jsonify([client_to_dict(client) for client in clients_list])

    @app.route("/api/v1/egress")
    @require_auth
    def api_egress():
        with db.session() as session_db:
            profiles = session_db.scalars(select(EgressProfile).order_by(EgressProfile.id)).all()
        return jsonify([profile_to_dict(profile) for profile in profiles])

    @app.route("/api/v1/capacity")
    @require_auth
    def api_capacity():
        with db.session() as session_db:
            snapshot = session_db.scalar(select(CapacitySnapshot).order_by(desc(CapacitySnapshot.observed_at)))
        return jsonify(snapshot_to_dict(snapshot))

    @app.route("/api/v1/admin/devices")
    @require_auth
    def api_admin_devices():
        with db.session() as session_db:
            devices = session_db.scalars(select(AdminDevice).order_by(AdminDevice.id)).all()
        return jsonify([{"id": device.id, "name": device.name, "address": device.address, "enabled": device.enabled, "created_at": device.created_at.isoformat()} for device in devices])

    @app.route("/api/v1/ingress")
    @require_auth
    def api_ingress():
        with db.session() as session_db:
            endpoints = session_db.scalars(select(IngressEndpoint).order_by(IngressEndpoint.id)).all()
        return jsonify([{"id": item.id, "name": item.name, "protocol": item.protocol, "interface": item.interface, "listen_port": item.listen_port, "address_cidr": item.address_cidr, "ipv6_address_cidr": item.ipv6_address_cidr, "enabled": item.enabled, "health_state": item.health_state} for item in endpoints])

    @app.route("/api/v1/pools")
    @require_auth
    def api_pools():
        with db.session() as session_db:
            pools = session_db.scalars(select(EgressPool).order_by(EgressPool.id)).all()
        return jsonify([pool_to_dict(pool) for pool in pools])

    @app.route("/api/v1/pools", methods=["POST"])
    @high_risk
    def api_pool_create():
        record_key, cached = api_idempotency_record()
        if cached:
            return jsonify(cached["body"]), cached["status"]
        body = request.get_json(silent=True) or {}
        if not isinstance(body, dict) or set(body) - {"name", "profile_ids", "failover_policy", "failback_policy"}:
            return jsonify({"error": "unsupported pool field"}), 400
        if body.get("failover_policy", "ordered") != "ordered" or body.get("failback_policy", "manual") != "manual":
            return jsonify({"error": "only ordered failover with manual failback is supported"}), 400
        try:
            name, profile_ids = validate_pool_input(body.get("name", ""), body.get("profile_ids") or [])
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        with db.session() as session_db:
            pool = EgressPool(name=name, profile_ids_json=json.dumps(profile_ids), failover_policy="ordered", failback_policy="manual", enabled=True)
            session_db.add(pool)
            session_db.flush()
            result = pool_to_dict(pool)
        operations.audit("owner-api", "egress_pool.create", {"pool_id": result["id"], "name": name, "profile_ids": profile_ids})
        save_api_idempotency(record_key, hashlib.sha256(request.get_data(cache=True)).hexdigest(), result, 201)
        return jsonify(result), 201

    @app.route("/api/v1/pools/<int:pool_id>", methods=["DELETE"])
    @high_risk
    def api_pool_delete(pool_id: int):
        record_key, cached = api_idempotency_record()
        if cached:
            return jsonify(cached["body"]), cached["status"]
        with db.session() as session_db:
            pool = session_db.get(EgressPool, pool_id)
            if pool is None:
                return jsonify({"error": "pool not found"}), 404
            if session_db.scalar(select(RouteBinding.id).where(RouteBinding.pool_id == pool_id)):
                return jsonify({"error": "move clients off this pool first"}), 409
            name = pool.name
            session_db.delete(pool)
        result = {"deleted": pool_id, "name": name}
        operations.audit("owner-api", "egress_pool.delete", result)
        save_api_idempotency(record_key, hashlib.sha256(request.get_data(cache=True)).hexdigest(), result)
        return jsonify(result)

    @app.route("/api/v1/operations")
    @require_auth
    def api_operations():
        with db.session() as session_db:
            items = session_db.scalars(select(Operation).order_by(desc(Operation.created_at)).limit(100)).all()
        return jsonify([{"id": item.id, "action": item.action, "status": item.status, "desired_generation": item.desired_generation, "observed_generation": item.observed_generation, "result": _json(item.result_json), "error_code": item.error_code, "error_message": item.error_message, "created_at": item.created_at.isoformat()} for item in items])

    @app.route("/api/v1/audit")
    @require_auth
    def api_audit():
        with db.session() as session_db:
            items = session_db.scalars(select(AuditEvent).order_by(desc(AuditEvent.created_at)).limit(100)).all()
        return jsonify([{"id": item.id, "actor": item.actor, "action": item.action, "details": _json(item.details_json), "previous_hash": item.previous_hash, "event_hash": item.event_hash, "created_at": item.created_at.isoformat()} for item in items])

    @app.route("/api/v1/backups")
    @require_auth
    def api_backups():
        with db.session() as session_db:
            items = session_db.scalars(select(BackupRecord).order_by(desc(BackupRecord.created_at))).all()
        return jsonify([{"id": item.id, "path": item.path, "sha256": item.sha256, "includes_secrets": item.includes_secrets, "created_at": item.created_at.isoformat()} for item in items])

    @app.route("/api/v1/backups", methods=["POST"])
    @high_risk
    def api_backup_create():
        record_key, cached = api_idempotency_record()
        if cached:
            return jsonify(cached["body"]), cached["status"]
        body = request.get_json(silent=True) or {}
        if not isinstance(body, dict) or set(body) != {"passphrase"} or len(str(body.get("passphrase", ""))) < 12:
            return jsonify({"error": "a backup passphrase of at least 12 characters is required"}), 400
        operation, response = operations.run("backup.create", {"passphrase": str(body["passphrase"])}, actor="owner-api")
        result = {"operation_id": operation.id, "status": response.status, "result": response.result, "error_code": response.error_code, "error_message": response.error_message}
        status = 201 if response.status == "succeeded" else 409
        save_api_idempotency(record_key, hashlib.sha256(request.get_data(cache=True)).hexdigest(), result, status)
        return jsonify(result), status

    @app.route("/api/v1/updates")
    @require_auth
    def api_updates():
        with db.session() as session_db:
            node = session_db.get(ManagedNode, 1)
        reboot_required, packages = reboot_status()
        return jsonify({"current_release": node.release, "owner_approval_required": True, "automatic_updates": False, "status": update_status(), "security_updates": "unattended-upgrades", "reboot_required": reboot_required, "reboot_packages": packages})

    @app.route("/api/v1/updates/check", methods=["POST"])
    @require_auth
    def api_update_check():
        record_key, cached = api_idempotency_record()
        if cached:
            return jsonify(cached["body"]), cached["status"]
        body = request.get_json(silent=True) or {}
        if not isinstance(body, dict) or body:
            return jsonify({"error": "the update check does not accept fields"}), 400
        operation, response = operations.run("update.check", {}, actor="owner-api")
        result = {"operation_id": operation.id, "status": response.status, "result": response.result, "error_code": response.error_code, "error_message": response.error_message}
        status = 200 if response.status == "succeeded" else 409
        save_api_idempotency(record_key, hashlib.sha256(request.get_data(cache=True)).hexdigest(), result, status)
        return jsonify(result), status

    @app.route("/api/v1/updates/stage", methods=["POST"])
    @require_auth
    def api_update_stage():
        record_key, cached = api_idempotency_record()
        if cached:
            return jsonify(cached["body"]), cached["status"]
        body = request.get_json(silent=True) or {}
        if not isinstance(body, dict) or set(body) != {"release"}:
            return jsonify({"error": "exactly one release field is required"}), 400
        operation, response = operations.run("update.stage", {"release": _safe_text(str(body.get("release") or ""), 80)}, actor="owner-api")
        result = {"operation_id": operation.id, "status": response.status, "result": response.result, "error_code": response.error_code, "error_message": response.error_message}
        status = 202 if response.status == "queued" else 409
        save_api_idempotency(record_key, hashlib.sha256(request.get_data(cache=True)).hexdigest(), result, status)
        return jsonify(result), status

    @app.route("/api/v1/updates/install", methods=["POST"])
    @high_risk
    def api_update_install():
        record_key, cached = api_idempotency_record()
        if cached:
            return jsonify(cached["body"]), cached["status"]
        body = request.get_json(silent=True) or {}
        if not isinstance(body, dict) or set(body) != {"release"}:
            return jsonify({"error": "exactly one release field is required"}), 400
        operation, response = operations.run("update.apply", {"release": _safe_text(str(body.get("release") or ""), 80)}, actor="owner-api")
        result = {"operation_id": operation.id, "status": response.status, "result": response.result, "error_code": response.error_code, "error_message": response.error_message}
        status = 202 if response.status == "queued" else 409
        save_api_idempotency(record_key, hashlib.sha256(request.get_data(cache=True)).hexdigest(), result, status)
        return jsonify(result), status

    @app.route("/api/v1/updates/discard", methods=["POST"])
    @require_auth
    def api_update_discard():
        record_key, cached = api_idempotency_record()
        if cached:
            return jsonify(cached["body"]), cached["status"]
        body = request.get_json(silent=True) or {}
        if not isinstance(body, dict) or set(body) != {"release"}:
            return jsonify({"error": "exactly one release field is required"}), 400
        operation, response = operations.run("update.discard", {"release": _safe_text(str(body.get("release") or ""), 80)}, actor="owner-api")
        result = {"operation_id": operation.id, "status": response.status, "result": response.result, "error_code": response.error_code, "error_message": response.error_message}
        status = 200 if response.status == "succeeded" else 409
        save_api_idempotency(record_key, hashlib.sha256(request.get_data(cache=True)).hexdigest(), result, status)
        return jsonify(result), status

    @app.route("/api/v1/clients/<int:client_id>/settings", methods=["POST"])
    @high_risk
    def api_client_settings(client_id: int):
        record_key, cached = api_idempotency_record()
        if cached:
            return jsonify(cached["body"]), cached["status"]
        body = request.get_json(silent=True)
        if not isinstance(body, dict) or set(body) != {"dns_mode", "ipv6_policy", "settings_revision"} or not all(isinstance(value, str) for value in body.values()):
            return jsonify({"error": "dns_mode, ipv6_policy and settings_revision must be supplied as strings"}), 400
        try:
            operation, response = operations.update_client_settings(client_id, **body, actor="owner-api")
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 409
        with db.session() as session_db:
            client = session_db.get(Client, client_id)
            binding = session_db.scalar(select(RouteBinding).where(RouteBinding.client_id == client_id))
            result = {"operation_id": operation.id if operation else None, "status": response.status,
                      "result": response.result, "error_code": response.error_code, "error_message": response.error_message,
                      "client": client_to_dict(client), "route_state": binding.state if binding else "blocked"}
        status = 200 if response.status == "succeeded" and response.result.get("verified") else 202 if response.status == "queued" else 409
        save_api_idempotency(record_key, hashlib.sha256(request.get_data(cache=True)).hexdigest(), result, status)
        return jsonify(result), status

    @app.route("/api/v1/clients/<int:client_id>/route", methods=["POST"])
    @high_risk
    def api_route_switch(client_id: int):
        record_key, cached = api_idempotency_record()
        if cached:
            return jsonify(cached["body"]), cached["status"]
        body = request.get_json(silent=True) or {}
        if not isinstance(body, dict) or set(body) - {"profile_id", "pool_id"}:
            return jsonify({"error": "unsupported route field"}), 400
        try:
            profile_id = int(body["profile_id"]) if body.get("profile_id") is not None else None
            pool_id = int(body["pool_id"]) if body.get("pool_id") is not None else None
            operation, response = operations.route_switch(client_id, profile_id=profile_id, pool_id=pool_id, actor="owner-api")
        except (KeyError, TypeError, ValueError) as exc:
            return jsonify({"error": str(exc)}), 400
        result = {"operation_id": operation.id, "status": response.status, "observed_generation": response.observed_generation, "result": response.result, "error_code": response.error_code, "error_message": response.error_message}
        status = 200 if response.status == "succeeded" else 409
        save_api_idempotency(record_key, hashlib.sha256(request.get_data(cache=True)).hexdigest(), result, status)
        return jsonify(result), status

    @app.route("/api/v1/egress/<int:profile_id>/activate", methods=["POST"])
    @high_risk
    def api_activate_egress(profile_id: int):
        record_key, cached = api_idempotency_record()
        if cached:
            return jsonify(cached["body"]), cached["status"]
        with db.session() as session_db:
            profile = session_db.get(EgressProfile, profile_id)
            if profile is None or not profile.enabled:
                return jsonify({"error": "exit not found"}), 404
            config = _json(profile.config_json)
            secret_ref = profile.secret_enc if profile.secret_enc and profile.secret_enc.startswith("ref::") else None
            secret = None if secret_ref else reveal_secret(profile.secret_enc)
            if profile.driver == "provider_tunnel" and secret is not None:
                config["config_text"] = secret
        payload = {"profile_id": profile_id, "driver": profile.driver, "config": config, "secret_ref": secret_ref}
        if secret is not None:
            payload["secret"] = secret
        operation, response = operations.run("egress.activate", payload, actor="owner-api")
        with db.session() as session_db:
            profile = session_db.get(EgressProfile, profile_id)
            profile.health_state = "healthy" if response.status == "succeeded" and response.result.get("verified") else "pending"
            if profile.health_state == "healthy":
                profile.last_failure_reason = None
                profile.consecutive_failures = 0
            else:
                profile.last_failure_reason = str(response.result.get("reason") or response.error_message or "verification_pending")[:240]
            _apply_egress_observation(profile, response.result or {})
            profile.last_check_at = datetime.now(timezone.utc)
        result = {"operation_id": operation.id, "status": response.status, "result": response.result, "error_code": response.error_code, "error_message": response.error_message}
        status = 200 if response.status == "succeeded" else 409
        save_api_idempotency(record_key, hashlib.sha256(request.get_data(cache=True)).hexdigest(), result, status)
        return jsonify(result), status

    @app.route("/api/v1/capacity/refresh", methods=["POST"])
    @require_auth
    def api_capacity_refresh():
        record_key, cached = api_idempotency_record()
        if cached:
            return jsonify(cached["body"]), cached["status"]
        snapshot = refresh_capacity()
        operations.run("system.snapshot", {}, actor="owner-api")
        result = snapshot_to_dict(snapshot) or {}
        save_api_idempotency(record_key, hashlib.sha256(request.get_data(cache=True)).hexdigest(), result)
        return jsonify(result)

    @app.route("/server")
    @require_auth
    def server():
        with db.session() as session_db:
            node = session_db.get(ManagedNode, 1)
        return render_template("system.html", node=node, agent_socket=str(settings.agent_socket), apply_network=settings.apply_network, reboot_required=Path("/var/run/reboot-required").is_file())

    @app.route("/test_dns")
    @require_auth
    def test_dns():
        return render_template("test_dns.html", results={"local_dns": {"success": False, "output": "DNS checks run after the selected Location is active."}, "dns_ports": {"success": False, "output": "Pending agent verification"}, "adguard_status": {"success": False, "output": "Pending agent verification"}, "external_dns": {"success": False, "output": "Pending agent verification"}})

    @app.route("/api/peer_stats")
    @require_auth
    def api_peer_stats():
        with db.session() as session_db:
            clients_list = session_db.scalars(select(Client).order_by(Client.id)).all()
        return jsonify([{"id": client.id, "name": client.name, "ip": client.address, "rx_bytes": 0, "tx_bytes": 0, "last_seen": "Agent pending"} for client in clients_list])

    return app


def client_to_dict(client: Client) -> dict:
    return {"id": client.id, "name": client.name, "settings_revision": client.updated_at.isoformat(), "public_key": client.public_key, "address": client.address, "ipv6_address": client.ipv6_address, "ipv6_policy": client.ipv6_policy, "generated_config_version": client.generated_config_version, "confirmed_config_version": client.confirmed_config_version, "configuration_update_available": client.confirmed_config_version < client.generated_config_version, "ingress_protocol": client.ingress_protocol, "dns_mode": client.dns_mode, "route_mode": client.route_mode, "fixed_egress_id": client.fixed_egress_id, "pool_id": client.pool_id, "enabled": client.enabled}


def profile_to_dict(profile: EgressProfile) -> dict:
    capabilities = profile.capabilities
    return {"id": profile.id, "name": profile.name, "driver": profile.driver, "config": _json(profile.config_json), "capabilities": capabilities, "families": capabilities["families"], "tcp": capabilities["tcp"], "udp": capabilities["udp"], "dns": capabilities["dns"], "ipv6": capabilities["ipv6"], "observed_exit_ip": profile.observed_exit_ip, "observed_exit_ipv4": profile.observed_exit_ip, "observed_exit_ipv6": profile.observed_exit_ipv6, "health_state": profile.health_state, "ipv4_health_state": profile.health_state, "ipv6_health_state": profile.ipv6_health_state, "enabled": profile.enabled, "consecutive_failures": profile.consecutive_failures, "consecutive_successes": profile.consecutive_successes, "ipv6_consecutive_failures": profile.ipv6_consecutive_failures, "ipv6_consecutive_successes": profile.ipv6_consecutive_successes, "last_failure_reason": profile.last_failure_reason, "ipv6_last_failure_reason": profile.ipv6_last_failure_reason, "last_check_at": profile.last_check_at.isoformat() if profile.last_check_at else None, "ipv6_last_check_at": profile.ipv6_last_check_at.isoformat() if profile.ipv6_last_check_at else None}


def pool_to_dict(pool: EgressPool) -> dict:
    return {"id": pool.id, "name": pool.name, "profile_ids": _json(pool.profile_ids_json, []), "failover_policy": pool.failover_policy, "failback_policy": pool.failback_policy, "enabled": pool.enabled}


def snapshot_to_dict(snapshot: CapacitySnapshot | None) -> dict | None:
    if snapshot is None:
        return None
    return {"architecture": snapshot.architecture, "vcpus": snapshot.vcpus, "memory_mb": snapshot.memory_mb, "load_1m": snapshot.load_1m, "active_clients": snapshot.active_clients, "active_driver_processes": snapshot.active_driver_processes, "disk_free_mb": snapshot.disk_free_mb, "interface_speed_mbps": snapshot.interface_speed_mbps, "transfer_allowance_gb": snapshot.transfer_allowance_gb, "transfer_used_gb": snapshot.transfer_used_gb, "transfer_forecast_gb": snapshot.transfer_forecast_gb, "safe_active_clients": snapshot.safe_active_clients, "max_stored_configs": snapshot.max_stored_configs, "max_egress_profiles": snapshot.max_egress_profiles, "estimated_mbps": snapshot.estimated_mbps, "limiting_factor": snapshot.limiting_factor, "confidence": snapshot.confidence, "over_capacity": snapshot.over_capacity, "override_active": snapshot.override_active, "observed_at": snapshot.observed_at.isoformat()}
