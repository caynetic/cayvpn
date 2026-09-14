"""Track consecutive egress probe results for failover decisions."""

from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect


revision = "0004_egress_health"
down_revision = "0003_capacity_transfer"
branch_labels = None
depends_on = None


def upgrade() -> None:
    inspector = inspect(op.get_bind())
    columns = {column["name"] for column in inspector.get_columns("egress_profiles")}
    if "consecutive_failures" not in columns:
        op.add_column("egress_profiles", sa.Column("consecutive_failures", sa.Integer(), nullable=False, server_default="0"))
    if "consecutive_successes" not in columns:
        op.add_column("egress_profiles", sa.Column("consecutive_successes", sa.Integer(), nullable=False, server_default="0"))
    if "last_failure_reason" not in columns:
        op.add_column("egress_profiles", sa.Column("last_failure_reason", sa.Text(), nullable=True))
    if "last_check_at" not in columns:
        op.add_column("egress_profiles", sa.Column("last_check_at", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    # SQLite cannot safely drop columns on every supported fixture.  The
    # fields are additive and keeping them is safer than rebuilding a live
    # node table during rollback.
    pass
