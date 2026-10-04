"""Sessions remember when their password was last given (D-089).

One column on auth_sessions. Conditional for the reason 0002 gives:
revision 0001 creates every table the models declare, so a fresh
database already has the column, while one upgraded before it existed
does not; adding it only when absent brings both to the same place.

Revision ID: 0003
Revises: 0002
Create Date: 2026-10-05
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0003"
down_revision: str | Sequence[str] | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    columns = {c["name"] for c in sa.inspect(op.get_bind()).get_columns("auth_sessions")}
    if "stepped_up_at" in columns:
        return
    op.add_column(
        "auth_sessions",
        sa.Column("stepped_up_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("auth_sessions", "stepped_up_at")
