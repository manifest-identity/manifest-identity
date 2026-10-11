"""Drop two columns the importer wrote and nothing read.

credentials.last_used_service held the service an access key last
called, and identity_observations.last_activity_detail held where the
last activity came from. No page, report, campaign, or API read either.
Each drop is conditional for the reason 0002 gives: revision 0001
creates every table the models declare, so a fresh database never had
the columns. The downgrade adds them back empty; what they held is not
restored.

Revision ID: 0005
Revises: 0004
Create Date: 2026-10-10
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0005"
down_revision: str | Sequence[str] | None = "0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

DROPPED = (("credentials", "last_used_service"), ("identity_observations", "last_activity_detail"))


def _has(table: str, column: str) -> bool:
    return column in {c["name"] for c in sa.inspect(op.get_bind()).get_columns(table)}


def upgrade() -> None:
    for table, column in DROPPED:
        if _has(table, column):
            with op.batch_alter_table(table) as batch:
                batch.drop_column(column)


def downgrade() -> None:
    for table, column in DROPPED:
        if not _has(table, column):
            with op.batch_alter_table(table) as batch:
                batch.add_column(sa.Column(column, sa.String(64), nullable=True))
