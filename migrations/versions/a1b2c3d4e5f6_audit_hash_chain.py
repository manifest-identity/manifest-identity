"""audit hash chain

Revision ID: a1b2c3d4e5f6
Revises: 7cf677d4953f
Create Date: 2026-09-21 15:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = 'a1b2c3d4e5f6'
down_revision: str | Sequence[str] | None = '7cf677d4953f'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Nullable on purpose: rows written before chaining existed stay
    # readable and are reported as the unchained prefix, never rewritten.
    op.add_column('audit_events', sa.Column('prev_hash', sa.String(length=64), nullable=True))
    op.add_column('audit_events', sa.Column('row_hash', sa.String(length=64), nullable=True))


def downgrade() -> None:
    op.drop_column('audit_events', 'row_hash')
    op.drop_column('audit_events', 'prev_hash')
