"""Administrator bootstrap, idempotent, from environment.

Runs at startup. If both keys are configured and no user with that
name exists, the administrator is created; an existing user is never
modified, so re-running with a changed environment converges to
"present" and nothing else. A configured password that violates the
policy stops startup, per the fail-fast rule.
"""

from sqlalchemy.orm import Session

from manifest_identity.core import audit, security
from manifest_identity.core.config import Settings
from manifest_identity.core.logs import log_event
from manifest_identity.core.roles import Role
from manifest_identity.core.scope import bind, global_node
from manifest_identity.models import User


def bootstrap_admin(db: Session, settings: Settings) -> None:
    if not settings.admin_username or not settings.admin_password:
        log_event("bootstrap_skipped", detail="admin keys not configured")
        return
    existing = (
        db.query(User).filter(User.username == settings.admin_username).one_or_none()
    )
    if existing is not None:
        log_event("bootstrap_admin_present", actor=settings.admin_username)
        return
    user = User(
        username=settings.admin_username,
        password_hash=security.hash_password(settings.admin_password),
    )
    db.add(user)
    db.flush()
    bind(db, user, Role.administrator, global_node(db), None)
    audit.record(
        db,
        actor_username="system:bootstrap",
        action="bootstrap_admin_created",
        target=settings.admin_username,
    )
    db.commit()
    log_event("bootstrap_admin_created", actor=settings.admin_username)
