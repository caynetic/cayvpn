"""Create or reconcile the CayVPN management schema."""

from alembic import op

from cayvpn.models import Base


revision = "0001_management_foundation"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # The model metadata is the canonical schema for a new appliance. The
    # following additive revision handles older development databases.
    bind = op.get_bind()
    Base.metadata.create_all(bind=bind)


def downgrade() -> None:
    # A downgrade must not silently destroy owner state. Rollback is handled
    # by the release snapshot/restore workflow instead.
    pass
