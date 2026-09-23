#!/usr/bin/env python3
"""The privilege split D-013 promised (honored at D-051).

Run as the owner role after migrations, this creates or updates the
runtime role and grants it data rights only: read and write rows,
never schema. The application never deletes rows by design, so the
runtime role cannot: clears and revocations are updates, and the
append-only tables stay append-only against the application's own
credential. Idempotent on purpose; runs at every migrate step.

Environment: MANIFEST_IDENTITY_OWNER_DATABASE_URL (the migrating owner),
MANIFEST_IDENTITY_APP_DB_PASSWORD (the runtime role's password, set or synced).
"""

import os
import sys

import psycopg


def main() -> int:
    # Accept the SQLAlchemy-flavored scheme the rest of the stack uses;
    # psycopg itself wants the plain one.
    owner_url = os.environ["MANIFEST_IDENTITY_OWNER_DATABASE_URL"].replace(
        "postgresql+psycopg://", "postgresql://"
    )
    app_password = os.environ["MANIFEST_IDENTITY_APP_DB_PASSWORD"]
    with psycopg.connect(owner_url, autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute("select 1 from pg_roles where rolname = 'manifest_identity_app'")
            if cur.fetchone() is None:
                cur.execute(
                    psycopg.sql.SQL(
                        "create role manifest_identity_app login password {}"
                    ).format(psycopg.sql.Literal(app_password))
                )
            else:
                cur.execute(
                    psycopg.sql.SQL(
                        "alter role manifest_identity_app login password {}"
                    ).format(psycopg.sql.Literal(app_password))
                )
            cur.execute("grant usage on schema public to manifest_identity_app")
            cur.execute(
                "grant select, insert, update on all tables in schema "
                "public to manifest_identity_app"
            )
            cur.execute(
                "grant usage, select on all sequences in schema public "
                "to manifest_identity_app"
            )
            # Tables created by future migrations inherit the same
            # data-only grants without anyone remembering to add them.
            cur.execute(
                "alter default privileges in schema public "
                "grant select, insert, update on tables to manifest_identity_app"
            )
            cur.execute(
                "alter default privileges in schema public "
                "grant usage, select on sequences to manifest_identity_app"
            )
    print("runtime role holds data rights only")
    return 0


if __name__ == "__main__":
    sys.exit(main())
