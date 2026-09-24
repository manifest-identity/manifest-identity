"""The first migration of manifest-identity: every table, greenfield.

The tables are the models (D-071): this revision creates exactly what
manifest_identity.models declares, and seeds the single global scope
node that every organization-wide binding names (D-072). There is no
data to carry from role-call, because none exists outside a demo that
regenerates; the migrations before this one were deleted with their
tables.

Revision ID: 0001
Revises:
Create Date: 2026-09-23
"""

import sqlalchemy as sa
from alembic import op

import manifest_identity.models  # noqa: F401  (registers the tables on Base.metadata)
from manifest_identity.core.db import Base

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    Base.metadata.create_all(bind=bind)
    bind.execute(
        sa.text(
            "insert into scope_nodes (provider, partition, kind, external_id, "
            "display_name, parent_id, created_at) "
            "values ('generic', 'none', 'global', 'global', 'global', null, "
            "current_timestamp)"
        )
    )


def downgrade() -> None:
    Base.metadata.drop_all(bind=op.get_bind())
