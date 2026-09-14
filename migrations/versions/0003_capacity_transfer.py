"""Record transfer usage and forecast in capacity snapshots."""

from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect


revision = "0003_capacity_transfer"
down_revision = "0002_node_scope"
branch_labels = None
depends_on = None


def upgrade() -> None:
    inspector = inspect(op.get_bind())
    columns = {column["name"] for column in inspector.get_columns("capacity_snapshots")}
    if "transfer_used_gb" not in columns:
        op.add_column("capacity_snapshots", sa.Column("transfer_used_gb", sa.Integer(), nullable=False, server_default="0"))
    if "transfer_forecast_gb" not in columns:
        op.add_column("capacity_snapshots", sa.Column("transfer_forecast_gb", sa.Integer(), nullable=False, server_default="0"))


def downgrade() -> None:
    pass
