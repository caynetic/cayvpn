from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import uuid

from sqlalchemy import Boolean, DateTime, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from .dual_stack import capabilities_for_api, normalize_capabilities


CLIENT_CONFIG_VERSION = 3


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def wizard_expiry() -> datetime:
    return utcnow() + timedelta(hours=24)


class Base(DeclarativeBase):
    pass


class ManagedNode(Base):
    __tablename__ = "managed_nodes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    name: Mapped[str] = mapped_column(String(120), default="CayVPN node")
    provider_label: Mapped[str] = mapped_column(String(120), default="manual")
    architecture: Mapped[str] = mapped_column(String(32), default="unknown")
    desired_generation: Mapped[int] = mapped_column(Integer, default=0)
    observed_generation: Mapped[int] = mapped_column(Integer, default=0)
    install_state: Mapped[str] = mapped_column(String(32), default="unverified")
    release: Mapped[str] = mapped_column(String(80), default="2.0.0-dev")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class Setting(Base):
    __tablename__ = "settings"

    key: Mapped[str] = mapped_column(String(160), primary_key=True)
    value: Mapped[str] = mapped_column(Text, default="")
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class Client(Base):
    __tablename__ = "clients"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    node_id: Mapped[int] = mapped_column(Integer, default=1, nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    public_key: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    private_key_enc: Mapped[str | None] = mapped_column(Text)
    address: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    ipv6_address: Mapped[str | None] = mapped_column(String(64), unique=True)
    ipv6_policy: Mapped[str] = mapped_column(String(16), default="auto", nullable=False)
    generated_config_version: Mapped[int] = mapped_column(Integer, default=CLIENT_CONFIG_VERSION, nullable=False)
    confirmed_config_version: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    ingress_protocol: Mapped[str] = mapped_column(String(24), default="wireguard")
    dns_mode: Mapped[str] = mapped_column(String(24), default="ad_blocking")
    route_mode: Mapped[str] = mapped_column(String(24), default="switchable")
    fixed_egress_id: Mapped[int | None] = mapped_column(Integer)
    pool_id: Mapped[int | None] = mapped_column(Integer)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class IngressEndpoint(Base):
    __tablename__ = "ingress_endpoints"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    node_id: Mapped[int] = mapped_column(Integer, default=1, nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    protocol: Mapped[str] = mapped_column(String(24), nullable=False)
    interface: Mapped[str] = mapped_column(String(32), nullable=False)
    listen_port: Mapped[int] = mapped_column(Integer, nullable=False)
    address_cidr: Mapped[str] = mapped_column(String(64), nullable=False)
    ipv6_address_cidr: Mapped[str | None] = mapped_column(String(64))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    health_state: Mapped[str] = mapped_column(String(24), default="pending")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class EgressProfile(Base):
    __tablename__ = "egress_profiles"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    node_id: Mapped[int] = mapped_column(Integer, default=1, nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    driver: Mapped[str] = mapped_column(String(32), nullable=False)
    config_json: Mapped[str] = mapped_column(Text, default="{}")
    secret_enc: Mapped[str | None] = mapped_column(Text)
    capabilities_json: Mapped[str] = mapped_column(Text, default="{}")
    observed_exit_ip: Mapped[str | None] = mapped_column(String(64))
    observed_exit_ipv6: Mapped[str | None] = mapped_column(String(64))
    health_state: Mapped[str] = mapped_column(String(24), default="pending")
    ipv6_health_state: Mapped[str] = mapped_column(String(24), default="pending", nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    desired_generation: Mapped[int] = mapped_column(Integer, default=0)
    observed_generation: Mapped[int] = mapped_column(Integer, default=0)
    consecutive_failures: Mapped[int] = mapped_column(Integer, default=0)
    consecutive_successes: Mapped[int] = mapped_column(Integer, default=0)
    last_failure_reason: Mapped[str | None] = mapped_column(Text)
    last_check_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    ipv6_consecutive_failures: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    ipv6_consecutive_successes: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    ipv6_last_failure_reason: Mapped[str | None] = mapped_column(Text)
    ipv6_last_check_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    @property
    def capabilities(self) -> dict:
        try:
            value = json.loads(self.capabilities_json or "{}")
            return capabilities_for_api(value)
        except (TypeError, ValueError):
            return capabilities_for_api({})

    @property
    def capabilities_storage(self) -> dict:
        try:
            return normalize_capabilities(json.loads(self.capabilities_json or "{}"))
        except (TypeError, ValueError):
            return normalize_capabilities({})

    @property
    def config(self) -> dict:
        try:
            return json.loads(self.config_json or "{}")
        except (TypeError, ValueError):
            return {}


class EgressPool(Base):
    __tablename__ = "egress_pools"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    node_id: Mapped[int] = mapped_column(Integer, default=1, nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    profile_ids_json: Mapped[str] = mapped_column(Text, default="[]")
    failover_policy: Mapped[str] = mapped_column(String(24), default="ordered")
    failback_policy: Mapped[str] = mapped_column(String(24), default="manual")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)


class RouteBinding(Base):
    __tablename__ = "route_bindings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    node_id: Mapped[int] = mapped_column(Integer, default=1, nullable=False, index=True)
    client_id: Mapped[int | None] = mapped_column(Integer, unique=True)
    pool_id: Mapped[int | None] = mapped_column(Integer)
    egress_profile_id: Mapped[int | None] = mapped_column(Integer)
    mode: Mapped[str] = mapped_column(String(24), default="switchable")
    state: Mapped[str] = mapped_column(String(24), default="pending")
    desired_generation: Mapped[int] = mapped_column(Integer, default=0)
    observed_generation: Mapped[int] = mapped_column(Integer, default=0)
    last_error: Mapped[str | None] = mapped_column(Text)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class CapacitySnapshot(Base):
    __tablename__ = "capacity_snapshots"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    node_id: Mapped[int] = mapped_column(Integer, default=1, nullable=False, index=True)
    architecture: Mapped[str] = mapped_column(String(32), default="unknown")
    vcpus: Mapped[int] = mapped_column(Integer, default=1)
    memory_mb: Mapped[int] = mapped_column(Integer, default=0)
    load_1m: Mapped[float] = mapped_column(default=0.0)
    active_clients: Mapped[int] = mapped_column(Integer, default=0)
    active_driver_processes: Mapped[int] = mapped_column(Integer, default=0)
    disk_free_mb: Mapped[int] = mapped_column(Integer, default=0)
    interface_speed_mbps: Mapped[int | None] = mapped_column(Integer)
    transfer_allowance_gb: Mapped[int | None] = mapped_column(Integer)
    transfer_used_gb: Mapped[int] = mapped_column(Integer, default=0)
    transfer_forecast_gb: Mapped[int] = mapped_column(Integer, default=0)
    plan_name: Mapped[str | None] = mapped_column(String(120))
    safe_active_clients: Mapped[int] = mapped_column(Integer, default=5)
    max_stored_configs: Mapped[int] = mapped_column(Integer, default=20)
    max_egress_profiles: Mapped[int] = mapped_column(Integer, default=1)
    estimated_mbps: Mapped[int] = mapped_column(Integer, default=0)
    limiting_factor: Mapped[str] = mapped_column(String(120), default="unknown")
    confidence: Mapped[str] = mapped_column(String(24), default="low")
    over_capacity: Mapped[bool] = mapped_column(Boolean, default=False)
    override_active: Mapped[bool] = mapped_column(Boolean, default=False)
    override_reason: Mapped[str | None] = mapped_column(Text)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Operation(Base):
    __tablename__ = "operations"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    node_id: Mapped[int] = mapped_column(Integer, default=1, nullable=False, index=True)
    action: Mapped[str] = mapped_column(String(80), nullable=False)
    status: Mapped[str] = mapped_column(String(24), default="queued")
    desired_generation: Mapped[int] = mapped_column(Integer, default=0)
    observed_generation: Mapped[int | None] = mapped_column(Integer)
    request_json: Mapped[str] = mapped_column(Text, default="{}")
    result_json: Mapped[str] = mapped_column(Text, default="{}")
    error_code: Mapped[str | None] = mapped_column(String(80))
    error_message: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class AdminDevice(Base):
    __tablename__ = "admin_devices"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    node_id: Mapped[int] = mapped_column(Integer, default=1, nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    public_key: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    address: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    private_key_enc: Mapped[str | None] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class PasskeyCredential(Base):
    __tablename__ = "passkey_credentials"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    node_id: Mapped[int] = mapped_column(Integer, default=1, nullable=False, index=True)
    credential_id: Mapped[str] = mapped_column(String(512), unique=True, nullable=False)
    public_key_json: Mapped[str] = mapped_column(Text, nullable=False)
    sign_count: Mapped[int] = mapped_column(Integer, default=0)
    label: Mapped[str] = mapped_column(String(120), default="Owner passkey")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class BackupRecord(Base):
    __tablename__ = "backup_records"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    node_id: Mapped[int] = mapped_column(Integer, default=1, nullable=False, index=True)
    path: Mapped[str] = mapped_column(Text, nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    includes_secrets: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    node_id: Mapped[int] = mapped_column(Integer, default=1, nullable=False, index=True)
    actor: Mapped[str] = mapped_column(String(120), default="system")
    action: Mapped[str] = mapped_column(String(120), nullable=False)
    details_json: Mapped[str] = mapped_column(Text, default="{}")
    previous_hash: Mapped[str | None] = mapped_column(String(64))
    event_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class WizardDraft(Base):
    __tablename__ = "wizard_drafts"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: uuid.uuid4().hex)
    node_id: Mapped[int] = mapped_column(Integer, default=1, nullable=False, index=True)
    kind: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    data_json: Mapped[str] = mapped_column(Text, default="{}", nullable=False)
    secret_ref: Mapped[str | None] = mapped_column(Text)
    current_step: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=wizard_expiry, nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    @property
    def data(self) -> dict:
        try:
            value = json.loads(self.data_json or "{}")
            return value if isinstance(value, dict) else {}
        except (TypeError, ValueError):
            return {}
