"""add_fim_timestamps

Revision ID: 65488bb5b1c3
Revises: 864de687a681
Create Date: 2026-10-08 00:11:21.614757

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '65488bb5b1c3'
down_revision: Union[str, Sequence[str], None] = '864de687a681'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    with op.batch_alter_table("file_integrity_records", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column(
                "updated_at",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.func.now(),
            )
        )
        batch_op.add_column(
            sa.Column(
                "file_modified_at",
                sa.DateTime(timezone=True),
                nullable=True,
            )
        )


def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table("file_integrity_records", schema=None) as batch_op:
        batch_op.drop_column("file_modified_at")
        batch_op.drop_column("updated_at")

