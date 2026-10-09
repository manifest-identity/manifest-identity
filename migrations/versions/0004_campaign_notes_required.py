"""Each campaign records which answers need a note (D-092).

One column on campaigns, conditional for the reason 0002 gives: revision
0001 creates every table the models declare, so a fresh database already
has the column, while one upgraded before it existed does not. Campaigns
that already exist get the rule they ran under, a note for insufficient
evidence and for delegated, before the column becomes required.

Revision ID: 0004
Revises: 0003
Create Date: 2026-10-08
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0004"
down_revision: str | Sequence[str] | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

RULE_THEY_RAN_UNDER = ["delegated", "insufficient_evidence"]


def upgrade() -> None:
    columns = {c["name"] for c in sa.inspect(op.get_bind()).get_columns("campaigns")}
    if "notes_required" in columns:
        return
    with op.batch_alter_table("campaigns") as batch:
        batch.add_column(sa.Column("notes_required", sa.JSON(), nullable=True))
    op.execute(
        # Bound as JSON so each database receives its own JSON type;
        # PostgreSQL refuses a text value in a json column.
        sa.text("UPDATE campaigns SET notes_required = :rule WHERE notes_required IS NULL")
        .bindparams(sa.bindparam("rule", RULE_THEY_RAN_UNDER, type_=sa.JSON()))
    )
    with op.batch_alter_table("campaigns") as batch:
        batch.alter_column("notes_required", existing_type=sa.JSON(), nullable=False)


def downgrade() -> None:
    with op.batch_alter_table("campaigns") as batch:
        batch.drop_column("notes_required")
