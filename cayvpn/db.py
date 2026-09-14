from __future__ import annotations

import json
import os
from contextlib import contextmanager, nullcontext
from pathlib import Path
from typing import Iterator

from sqlalchemy import create_engine, event, inspect, select, text
from sqlalchemy.engine import Connection
from sqlalchemy.orm import Session, sessionmaker

from .config import Settings
from .dual_stack import address_in_network, normalize_capabilities
from .models import (
    Base,
    CLIENT_CONFIG_VERSION,
    Client,
    EgressProfile,
    IngressEndpoint,
    ManagedNode,
    Setting,
)


class Database:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.settings.ensure_directories()
        self.engine = create_engine(
            f"sqlite:///{Path(settings.db_path).resolve()}",
            connect_args={"check_same_thread": False},
            future=True,
        )
        event.listen(self.engine, "connect", self._configure_connection)
        self.Session = sessionmaker(self.engine, expire_on_commit=False, class_=Session)

    def close(self) -> None:
        self.engine.dispose()

    def __enter__(self) -> "Database":
        return self

    def __exit__(self, _exception_type, _exception, _traceback) -> None:
        self.close()

    @staticmethod
    def _configure_connection(dbapi_connection, _connection_record) -> None:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA busy_timeout=5000")
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    def create_schema(self) -> None:
        Base.metadata.create_all(self.engine)
        self._ensure_compatibility_columns()

    def _ensure_compatibility_columns(self) -> None:
        """Apply the small additive migrations needed for early 2.0 state.

        Early 2.0 development builds used ``create_all`` before every
        node-owned record carried a node id.  Keep upgrades safe for those
        local databases while the Alembic history is established.
        """
        tables = (
            "clients",
            "ingress_endpoints",
            "egress_profiles",
            "egress_pools",
            "route_bindings",
            "capacity_snapshots",
            "operations",
            "admin_devices",
            "passkey_credentials",
            "backup_records",
            "audit_events",
        )
        inspector = inspect(self.engine)
        missing = [table for table in tables if table in inspector.get_table_names() and "node_id" not in {column["name"] for column in inspector.get_columns(table)}]
        capacity_columns = {column["name"] for column in inspector.get_columns("capacity_snapshots")} if "capacity_snapshots" in inspector.get_table_names() else set()
        egress_columns = {column["name"] for column in inspector.get_columns("egress_profiles")} if "egress_profiles" in inspector.get_table_names() else set()
        client_columns = {column["name"] for column in inspector.get_columns("clients")} if "clients" in inspector.get_table_names() else set()
        ingress_columns = {column["name"] for column in inspector.get_columns("ingress_endpoints")} if "ingress_endpoints" in inspector.get_table_names() else set()
        with self.engine.begin() as connection:
            for table in missing:
                # The table names come only from the static tuple above.
                connection.execute(text(f'ALTER TABLE "{table}" ADD COLUMN node_id INTEGER NOT NULL DEFAULT 1'))
            if "transfer_used_gb" not in capacity_columns:
                connection.execute(text('ALTER TABLE "capacity_snapshots" ADD COLUMN transfer_used_gb INTEGER NOT NULL DEFAULT 0'))
            if "transfer_forecast_gb" not in capacity_columns:
                connection.execute(text('ALTER TABLE "capacity_snapshots" ADD COLUMN transfer_forecast_gb INTEGER NOT NULL DEFAULT 0'))
            if "load_1m" not in capacity_columns:
                connection.execute(text('ALTER TABLE "capacity_snapshots" ADD COLUMN load_1m REAL NOT NULL DEFAULT 0'))
            if "active_clients" not in capacity_columns:
                connection.execute(text('ALTER TABLE "capacity_snapshots" ADD COLUMN active_clients INTEGER NOT NULL DEFAULT 0'))
            if "active_driver_processes" not in capacity_columns:
                connection.execute(text('ALTER TABLE "capacity_snapshots" ADD COLUMN active_driver_processes INTEGER NOT NULL DEFAULT 0'))
            if "over_capacity" not in capacity_columns:
                connection.execute(text('ALTER TABLE "capacity_snapshots" ADD COLUMN over_capacity BOOLEAN NOT NULL DEFAULT 0'))
            if "consecutive_failures" not in egress_columns:
                connection.execute(text('ALTER TABLE "egress_profiles" ADD COLUMN consecutive_failures INTEGER NOT NULL DEFAULT 0'))
            if "consecutive_successes" not in egress_columns:
                connection.execute(text('ALTER TABLE "egress_profiles" ADD COLUMN consecutive_successes INTEGER NOT NULL DEFAULT 0'))
            if "last_failure_reason" not in egress_columns:
                connection.execute(text('ALTER TABLE "egress_profiles" ADD COLUMN last_failure_reason TEXT'))
            if "last_check_at" not in egress_columns:
                connection.execute(text('ALTER TABLE "egress_profiles" ADD COLUMN last_check_at DATETIME'))
            if "ipv6_address" not in client_columns:
                connection.execute(text('ALTER TABLE "clients" ADD COLUMN ipv6_address VARCHAR(64)'))
            if "ipv6_policy" not in client_columns:
                connection.execute(text('ALTER TABLE "clients" ADD COLUMN ipv6_policy VARCHAR(16) NOT NULL DEFAULT "auto"'))
            if "generated_config_version" not in client_columns:
                connection.execute(text('ALTER TABLE "clients" ADD COLUMN generated_config_version INTEGER NOT NULL DEFAULT 2'))
            if "confirmed_config_version" not in client_columns:
                connection.execute(text('ALTER TABLE "clients" ADD COLUMN confirmed_config_version INTEGER NOT NULL DEFAULT 1'))
            if "ipv6_address_cidr" not in ingress_columns:
                connection.execute(text('ALTER TABLE "ingress_endpoints" ADD COLUMN ipv6_address_cidr VARCHAR(64)'))
            if "observed_exit_ipv6" not in egress_columns:
                connection.execute(text('ALTER TABLE "egress_profiles" ADD COLUMN observed_exit_ipv6 VARCHAR(64)'))
            if "ipv6_health_state" not in egress_columns:
                connection.execute(text('ALTER TABLE "egress_profiles" ADD COLUMN ipv6_health_state VARCHAR(24) NOT NULL DEFAULT "pending"'))
            if "ipv6_consecutive_failures" not in egress_columns:
                connection.execute(text('ALTER TABLE "egress_profiles" ADD COLUMN ipv6_consecutive_failures INTEGER NOT NULL DEFAULT 0'))
            if "ipv6_consecutive_successes" not in egress_columns:
                connection.execute(text('ALTER TABLE "egress_profiles" ADD COLUMN ipv6_consecutive_successes INTEGER NOT NULL DEFAULT 0'))
            if "ipv6_last_failure_reason" not in egress_columns:
                connection.execute(text('ALTER TABLE "egress_profiles" ADD COLUMN ipv6_last_failure_reason TEXT'))
            if "ipv6_last_check_at" not in egress_columns:
                connection.execute(text('ALTER TABLE "egress_profiles" ADD COLUMN ipv6_last_check_at DATETIME'))

    @contextmanager
    def session(self) -> Iterator[Session]:
        session = self.Session()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    @contextmanager
    def _initialization_session(
        self,
    ) -> Iterator[tuple[Connection, Session]]:
        connection = self.engine.connect()
        session = None
        try:
            connection.exec_driver_sql("BEGIN IMMEDIATE")
            session = Session(bind=connection, expire_on_commit=False)
            yield connection, session
            session.flush()
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            if session is not None:
                session.close()
            connection.close()

    def initialize_defaults(self, settings: Settings) -> None:
        self.create_schema()
        with self._initialization_session() as (connection, session):
            node = session.get(ManagedNode, 1)
            if node is None:
                node = ManagedNode(id=1, install_state="unverified")
                session.add(node)

            defaults = {
                "server_ip": settings.server_ip,
                "server_region": settings.server_region,
                "admin_hostname": settings.admin_hostname,
                "onboarding_prompt_seen": "0",
                "donation_prompt_seen": "0",
                "last_audit_hash": "",
                "private_panel_verified": "0",
                "client_panel_login_enabled": "0",
                "client_panel_password_hash": "",
                "client_panel_totp_ref": "",
                "remote_admin_enabled": "0",
                "remote_admin_terms_accepted_at": "",
                "schema_version": "3",
                "ula_prefix": settings.ula_prefix,
                "capacity_override_active": "0",
                "capacity_override_reason": "",
            }
            for key, value in defaults.items():
                existing = session.get(Setting, key)
                if existing is None:
                    session.add(Setting(key=key, value=value))

            if session.scalar(select(IngressEndpoint.id).where(IngressEndpoint.interface == settings.user_interface)) is None:
                session.add(
                    IngressEndpoint(
                        name="Primary client ingress",
                        protocol="wireguard",
                        interface=settings.user_interface,
                        listen_port=settings.user_port,
                        address_cidr=settings.user_address,
                        ipv6_address_cidr=settings.user_address_v6,
                        health_state="pending",
                    )
                )
            if session.scalar(select(IngressEndpoint.id).where(IngressEndpoint.interface == settings.admin_interface)) is None:
                session.add(
                    IngressEndpoint(
                        name="Private admin ingress",
                        protocol="wireguard",
                        interface=settings.admin_interface,
                        listen_port=settings.admin_port,
                        address_cidr=settings.admin_address,
                        ipv6_address_cidr=None,
                        health_state="pending",
                    )
                )
            if session.scalar(select(IngressEndpoint.id).where(IngressEndpoint.interface == settings.amnezia_interface)) is None:
                session.add(
                    IngressEndpoint(
                        name="Optional AmneziaWG client ingress",
                        protocol="amneziawg",
                        interface=settings.amnezia_interface,
                        listen_port=settings.amnezia_port,
                        address_cidr=settings.amnezia_address,
                        ipv6_address_cidr=settings.amnezia_address_v6,
                        health_state="pending",
                    )
                )
            if session.scalar(select(EgressProfile.id).where(EgressProfile.driver == "direct_ip")) is None:
                session.add(
                    EgressProfile(
                        name="VPS direct IP",
                        driver="direct_ip",
                        config_json=json.dumps({"address": settings.server_ip, "ipv6_address": settings.server_ipv6 or None}),
                        capabilities_json=json.dumps(normalize_capabilities({"tcp": True, "udp": True, "dns": True, "ipv6": False})),
                        observed_exit_ip=settings.server_ip,
                        health_state="healthy",
                        ipv6_health_state="pending" if settings.server_ipv6 else "unavailable",
                    )
                )
            self._backfill_dual_stack(settings, session=session)
            session.flush()
            connection.execute(text('CREATE UNIQUE INDEX IF NOT EXISTS ux_clients_ipv6_address ON clients (ipv6_address)'))

    def _backfill_dual_stack(
        self,
        settings: Settings,
        session: Session | None = None,
    ) -> None:
        """Finish additive migration state without rotating any client key."""
        session_context = nullcontext(session) if session is not None else self.session()
        with session_context as session:
            ingress_by_interface = {
                item.interface: item for item in session.scalars(select(IngressEndpoint)).all()
            }
            if settings.user_interface in ingress_by_interface:
                ingress_by_interface[settings.user_interface].ipv6_address_cidr = settings.user_address_v6
            if settings.amnezia_interface in ingress_by_interface:
                ingress_by_interface[settings.amnezia_interface].ipv6_address_cidr = settings.amnezia_address_v6

            used = {
                item.ipv6_address for item in session.scalars(select(Client)).all() if item.ipv6_address
            }
            clients = session.scalars(select(Client).order_by(Client.id)).all()
            for client in clients:
                if not client.ipv6_address:
                    network = settings.amnezia_network_v6 if client.ingress_protocol == "amneziawg" else settings.user_network_v6
                    host_id = client.id + 1
                    candidate = address_in_network(network, host_id).split("/", 1)[0]
                    while candidate in used:
                        host_id += 1
                        candidate = address_in_network(network, host_id).split("/", 1)[0]
                    client.ipv6_address = candidate
                    used.add(candidate)
                if client.ipv6_policy not in {"auto", "required"}:
                    client.ipv6_policy = "auto"
                client.generated_config_version = max(
                    int(client.generated_config_version or 1), CLIENT_CONFIG_VERSION
                )
                if client.confirmed_config_version is None:
                    client.confirmed_config_version = 1

            for profile in session.scalars(select(EgressProfile)).all():
                profile.capabilities_json = json.dumps(normalize_capabilities(profile.capabilities_storage), sort_keys=True)
                if profile.driver == "direct_ip":
                    config = profile.config
                    config.setdefault("ipv6_address", settings.server_ipv6 or None)
                    profile.config_json = json.dumps(config, sort_keys=True)
                    if not settings.server_ipv6 and profile.ipv6_health_state == "pending":
                        profile.ipv6_health_state = "unavailable"

    def get_setting(self, key: str, default: str | None = None) -> str | None:
        with self.session() as session:
            item = session.get(Setting, key)
            return item.value if item else default

    def set_setting(self, key: str, value: str) -> None:
        with self.session() as session:
            item = session.get(Setting, key)
            if item is None:
                session.add(Setting(key=key, value=value))
            else:
                item.value = value
