"""Mark client configurations for the private DNS scope refresh."""

from alembic import op


revision = "0007_client_dns_scope"
down_revision = "0006_dual_stack_wizards"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        "UPDATE clients SET generated_config_version = 3 "
        "WHERE generated_config_version < 3"
    )


def downgrade() -> None:
    # A release rollback restores the matching database snapshot. Keeping the
    # newer generation marker prevents an older config from looking current.
    pass
