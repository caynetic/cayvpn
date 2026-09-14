"""Add dual-stack state and resumable setup drafts."""

from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect


revision = "0006_dual_stack_wizards"
down_revision = "0005_capacity_runtime"
branch_labels = None
depends_on = None


def _add(table: str, name: str, column: sa.Column) -> None:
    columns = {item["name"] for item in inspect(op.get_bind()).get_columns(table)}
    if name not in columns:
        op.add_column(table, column)


def upgrade() -> None:
    _add("clients", "ipv6_address", sa.Column("ipv6_address", sa.String(length=64), nullable=True))
    _add("clients", "ipv6_policy", sa.Column("ipv6_policy", sa.String(length=16), nullable=False, server_default="auto"))
    _add("clients", "generated_config_version", sa.Column("generated_config_version", sa.Integer(), nullable=False, server_default="2"))
    # Every row present when this migration runs used the IPv4-only v1
    # configuration. New rows use the model default of zero until the owner
    # confirms importing the generated configuration.
    _add("clients", "confirmed_config_version", sa.Column("confirmed_config_version", sa.Integer(), nullable=False, server_default="1"))
    client_indexes = {item["name"] for item in inspect(op.get_bind()).get_indexes("clients")}
    if "ux_clients_ipv6_address" not in client_indexes:
        op.create_index("ux_clients_ipv6_address", "clients", ["ipv6_address"], unique=True)
    _add("ingress_endpoints", "ipv6_address_cidr", sa.Column("ipv6_address_cidr", sa.String(length=64), nullable=True))
    _add("egress_profiles", "observed_exit_ipv6", sa.Column("observed_exit_ipv6", sa.String(length=64), nullable=True))
    _add("egress_profiles", "ipv6_health_state", sa.Column("ipv6_health_state", sa.String(length=24), nullable=False, server_default="pending"))
    _add("egress_profiles", "ipv6_consecutive_failures", sa.Column("ipv6_consecutive_failures", sa.Integer(), nullable=False, server_default="0"))
    _add("egress_profiles", "ipv6_consecutive_successes", sa.Column("ipv6_consecutive_successes", sa.Integer(), nullable=False, server_default="0"))
    _add("egress_profiles", "ipv6_last_failure_reason", sa.Column("ipv6_last_failure_reason", sa.Text(), nullable=True))
    _add("egress_profiles", "ipv6_last_check_at", sa.Column("ipv6_last_check_at", sa.DateTime(timezone=True), nullable=True))

    inspector = inspect(op.get_bind())
    if "wizard_drafts" not in inspector.get_table_names():
        op.create_table(
            "wizard_drafts",
            sa.Column("id", sa.String(length=64), nullable=False),
            sa.Column("node_id", sa.Integer(), nullable=False, server_default="1"),
            sa.Column("kind", sa.String(length=32), nullable=False),
            sa.Column("data_json", sa.Text(), nullable=False, server_default="{}"),
            sa.Column("secret_ref", sa.Text(), nullable=True),
            sa.Column("current_step", sa.Integer(), nullable=False, server_default="1"),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index("ix_wizard_drafts_node_id", "wizard_drafts", ["node_id"])
        op.create_index("ix_wizard_drafts_kind", "wizard_drafts", ["kind"])
        op.create_index("ix_wizard_drafts_expires_at", "wizard_drafts", ["expires_at"])


def downgrade() -> None:
    # Release rollback restores the matching database snapshot. Keeping these
    # additive columns is safer than rebuilding live SQLite tables.
    pass
