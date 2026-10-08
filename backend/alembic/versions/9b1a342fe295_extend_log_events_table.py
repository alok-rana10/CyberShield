"""extend_log_events_table

Revision ID: 9b1a342fe295
Revises: 65488bb5b1c3
Create Date: 2026-10-08 09:47:59.674850

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "9b1a342fe295"
down_revision: Union[str, Sequence[str], None] = "65488bb5b1c3"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema to support extended log event attributes."""
    with op.batch_alter_table("log_events", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column(
                "source_file",
                sa.String(length=1024),
                nullable=True,
            )
        )
        batch_op.add_column(
            sa.Column(
                "username",
                sa.String(length=100),
                nullable=True,
            )
        )
        batch_op.add_column(
            sa.Column(
                "message_summary",
                sa.String(length=500),
                nullable=True,
            )
        )
        batch_op.create_index("ix_log_events_source_file", ["source_file"], unique=False)
        batch_op.create_index("ix_log_events_username", ["username"], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table("log_events", schema=None) as batch_op:
        batch_op.drop_index("ix_log_events_username")
        batch_op.drop_index("ix_log_events_source_file")
        batch_op.drop_column("message_summary")
        batch_op.drop_column("username")
        batch_op.drop_column("source_file")
