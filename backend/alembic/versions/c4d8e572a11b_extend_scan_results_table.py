"""extend_scan_results_table

Revision ID: c4d8e572a11b
Revises: 9b1a342fe295
Create Date: 2026-10-09 09:54:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "c4d8e572a11b"
down_revision: Union[str, Sequence[str], None] = "9b1a342fe295"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema to extend scan_results with detailed breakdown columns."""
    with op.batch_alter_table("scan_results", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column(
                "scanned_ports",
                sa.JSON(),
                nullable=True,
            )
        )
        batch_op.add_column(
            sa.Column(
                "port_details",
                sa.JSON(),
                nullable=True,
            )
        )
        batch_op.add_column(
            sa.Column(
                "total_ports_scanned",
                sa.Integer(),
                nullable=True,
            )
        )
        batch_op.add_column(
            sa.Column(
                "open_ports_count",
                sa.Integer(),
                nullable=True,
            )
        )


def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table("scan_results", schema=None) as batch_op:
        batch_op.drop_column("open_ports_count")
        batch_op.drop_column("total_ports_scanned")
        batch_op.drop_column("port_details")
        batch_op.drop_column("scanned_ports")
