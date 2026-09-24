#!/usr/bin/env python3
"""Walk the audit trail and recompute every hash (issue 39).

    python3 manifest_identity/verify_chain.py [--anchor HEX]

Reads the database the application is configured for, recomputes each
row's hash from its content and the previous row's hash, and stops at
the first row that does not match. With --anchor, the chain head from
a campaign evidence export held outside the database, it also
confirms the trail reaches that head, which is the check that catches
history altered after the export was taken. Exit 0 when the trail
verifies, 1 when it does not.
"""

import argparse
import sys

from sqlalchemy.orm import Session, sessionmaker

from manifest_identity.core import audit
from manifest_identity.core.db import get_engine


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--anchor", help="a chain head from an evidence export")
    args = parser.parse_args()
    with sessionmaker(bind=get_engine())() as db:
        result = audit.verify(db)
        if not result.ok:
            print(f"audit chain broken at row {result.first_bad_id} of {result.rows}",
                  file=sys.stderr)
            return 1
        if args.anchor:
            if not _reaches(db, args.anchor):
                print("audit chain does not reach the anchored head; history after "
                      "the export was altered or the anchor is from another trail",
                      file=sys.stderr)
                return 1
            print(f"audit chain intact through the anchor, {result.rows} rows")
            return 0
        print(f"audit chain intact, {result.rows} rows, head {result.head[:12]}")
        return 0


def _reaches(db: Session, anchor: str) -> bool:
    from sqlalchemy import select

    from manifest_identity.models import AuditEvent
    return db.execute(
        select(AuditEvent.id).where(AuditEvent.row_hash == anchor)
    ).first() is not None


if __name__ == "__main__":
    raise SystemExit(main())
