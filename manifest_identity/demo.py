"""One command to a populated instance.

python -m manifest_identity.demo migrates the schema, creates the
administrator from the environment, imports the three shipped sample
months for both sources oldest first, and opens one review campaign,
so a fresh clone lands in an inventory of nineteen identities with
tiered findings and a review in progress. Idempotent on purpose:
running it again converges, re-imports are refused as duplicates and
an existing campaign is kept, so the command is safe to run twice.

The sample account comes from the generator in memory, not from
disk, so this command works wherever the package does.
"""

from __future__ import annotations

import sys
from datetime import timedelta
from pathlib import Path

from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from manifest_identity.core import audit
from manifest_identity.core.bootstrap import bootstrap_admin
from manifest_identity.core.config import get_settings
from manifest_identity.core.db import get_engine
from manifest_identity.decide.routes_campaigns import build_campaign
from manifest_identity.models import Campaign, CampaignItem, Identity, User
from manifest_identity.observe.importer import (
    DuplicateSnapshot,
    import_authorization_details,
    import_credential_report,
)
from manifest_identity.observe.providers.aws.authorization_details import (
    parse_authorization_details,
)
from manifest_identity.observe.providers.aws.credential_report import parse_credential_report
from manifest_identity.sample_data import GENERATIONS, file_set

DEMO_CAMPAIGN = "Quarterly access review (demo)"


def _migrate() -> str:
    from alembic import command as alembic_command
    from alembic.config import Config as AlembicConfig

    ini = Path(__file__).resolve().parent.parent / "alembic.ini"
    cfg = AlembicConfig(str(ini))
    # Leave the host process's logging alone; see migrations/env.py.
    cfg.attributes["configure_logger"] = False
    try:
        alembic_command.upgrade(cfg, "head")
        return "schema migrated"
    except Exception as exc:  # noqa: BLE001
        # Under the split-privilege runtime role the schema is managed
        # by the migrate step and this role may not touch it; if the
        # tables exist, that is fine and the demo continues.
        return f"migration skipped ({type(exc).__name__}); assuming a managed schema"


def main() -> int:
    settings = get_settings()
    if not settings.admin_username or not settings.admin_password:
        print(
            "demo: set MANIFEST_IDENTITY_ADMIN_USERNAME and MANIFEST_IDENTITY_ADMIN_PASSWORD "
            "first; the demo needs an administrator to attribute imports to"
        )
        return 1

    print(_migrate())
    maker = sessionmaker(bind=get_engine())
    db: Session = maker()
    try:
        bootstrap_admin(db, settings)
        db.commit()
        admin = db.execute(
            select(User).where(User.username == settings.admin_username)
        ).scalar_one()

        files = file_set()
        for captured in GENERATIONS:
            day = captured.strftime("%Y-%m-%d")
            for kind in ("credential-report", "authorization-details"):
                suffix = "csv" if kind == "credential-report" else "json"
                name = f"{day}-{kind}.{suffix}"
                data = files[name].encode()
                try:
                    if kind == "credential-report":
                        import_credential_report(
                            db,
                            report=parse_credential_report(data),
                            captured_at=captured,
                            source_filename=name,
                            actor_user_id=admin.id,
                            actor_username=admin.username,
                        )
                    else:
                        import_authorization_details(
                            db,
                            report=parse_authorization_details(data),
                            captured_at=captured,
                            source_filename=name,
                            actor_user_id=admin.id,
                            actor_username=admin.username,
                        )
                    db.commit()
                    print(f"imported {name}")
                except DuplicateSnapshot:
                    db.rollback()
                    print(f"already imported {name}, kept")

        existing = db.execute(
            select(Campaign).where(Campaign.name == DEMO_CAMPAIGN)
        ).scalar_one_or_none()
        if existing is None:
            campaign, items = build_campaign(
                db,
                name=DEMO_CAMPAIGN,
                scope="everything",
                due_at=GENERATIONS[-1] + timedelta(days=30),
                recurrence="none",
                created_by=admin.username,
            )
            db.add_all(items)
            audit.record(
                db,
                actor_user_id=admin.id,
                actor_username=admin.username,
                action="campaign_created",
                target=f"campaign:{campaign.id}",
                detail=f"{DEMO_CAMPAIGN}: scope everything, {len(items)} item(s)",
            )
            db.commit()
            print(f"campaign created with {len(items)} items")
        else:
            print("campaign already present, kept")

        # Groups are identities of kind group (D-019); the count the
        # README states is the people, services, and roles.
        identities = db.execute(
            select(func.count()).select_from(Identity).where(Identity.kind != "group")
        ).scalar_one()
        items_count = db.execute(
            select(func.count()).select_from(CampaignItem)
        ).scalar_one()
        print(
            f"ready: {identities} identities, {items_count} campaign "
            "items. Start the server and sign in as "
            f"{settings.admin_username}."
        )
        return 0
    finally:
        db.close()


if __name__ == "__main__":
    sys.exit(main())
