"""Record runtime load and capacity pressure."""

from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect


revision = "0005_capacity_runtime"
down_revision = "0004_egress_health"
branch_labels = None
depends_on = None


def upgrade() -> None:
    inspector = inspect(op.get_bind())
    columns = {column["name"] for column in inspector.get_columns("capacity_snapshots")}
    if "load_1m" not in columns:
        op.add_column("capacity_snapshots", sa.Column("load_1m", sa.Float(), nullable=False, server_default="0"))
    if "active_clients" not in columns:
        op.add_column("capacity_snapshots", sa.Column("active_clients", sa.Integer(), nullable=False, server_default="0"))
    if "active_driver_processes" not in columns:
        op.add_column("capacity_snapshots", sa.Column("active_driver_processes", sa.Integer(), nullable=False, server_default="0"))
    if "over_capacity" not in columns:
        op.add_column("capacity_snapshots", sa.Column("over_capacity", sa.Boolean(), nullable=False, server_default=sa.false()))


def downgrade() -> None:
    # Keep additive capacity evidence during rollback.
    pass
