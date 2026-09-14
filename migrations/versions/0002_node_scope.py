"""Add node scope to records created by early 2.0 builds."""

from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect


revision = "0002_node_scope"
down_revision = "0001_management_foundation"
branch_labels = None
depends_on = None

TABLES = (
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


def upgrade() -> None:
    inspector = inspect(op.get_bind())
    for table in TABLES:
        if table in inspector.get_table_names() and "node_id" not in {column["name"] for column in inspector.get_columns(table)}:
            op.add_column(table, sa.Column("node_id", sa.Integer(), nullable=False, server_default="1"))


def downgrade() -> None:
    # Preserve state during an owner rollback; the next release can continue
    # to read this additive column.
    pass
