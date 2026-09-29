"""What every native importer does the same way, written once.

Each provider's importer turns its own vocabulary into the neutral rows
(D-071), and the bookkeeping around that is the same for all of them:
the provider's root node and provider row made on first sight, the
identities already at that node loaded so a re-import finds them, a
new identity created once, an observation written once per import.
Five importers had five copies of it by the time the fifth provider
arrived, which is how a fix in one copy stays out of the other four;
this module is the one copy.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from manifest_identity.core.models import Partition, Provider, ScopeNode
from manifest_identity.core.scope import find_or_create_node
from manifest_identity.observe.models import (
    Home,
    Identity,
    IdentityKind,
    IdentityObservation,
    Import,
    ProviderInstance,
)


def provider_root(
    db: Session, provider: Provider, partition: Partition, kind: str,
    external_id: str, display_name: str,
) -> tuple[ProviderInstance, ScopeNode]:
    """The provider's root node (an organization, a cluster, a project,
    a tenant) and the provider row that names it, made on first sight."""
    node = find_or_create_node(db, provider, partition, kind, external_id, display_name, None)
    instance = db.execute(
        select(ProviderInstance).where(
            ProviderInstance.provider == provider.value,
            ProviderInstance.root_scope_node_id == node.id,
        )
    ).scalar_one_or_none()
    if instance is None:
        instance = ProviderInstance(
            provider=provider.value, display_name=display_name, root_scope_node_id=node.id,
        )
        db.add(instance)
        db.flush()
    return instance, node


def root_node_id(db: Session, provider: Provider, kind: str, external_id: str) -> int | None:
    """The root node's id if the provider has been imported before, so a
    route can check the scope the person may write to; None means the
    check falls to the global node."""
    return db.execute(
        select(ScopeNode.id).where(
            ScopeNode.provider == provider.value,
            ScopeNode.kind == kind,
            ScopeNode.external_id == external_id,
        )
    ).scalar()


class Estate:
    """The identities at one root node as one import writes them: found
    if the node already holds them, created once if not, observed once
    per import. The counts are what the import's audit line reports."""

    def __init__(
        self, db: Session, import_row: Import, provider: ProviderInstance, node: ScopeNode,
    ) -> None:
        self.db = db
        self.import_row = import_row
        self.provider = provider
        self.node = node
        self.identities: dict[str, Identity] = {
            identity.external_id: identity
            for identity in db.execute(
                select(Identity).where(Identity.scope_node_id == node.id)
            ).scalars()
        }
        self.new_count = 0
        self.observations = 0
        self._observed: set[int] = set()

    def get_or_create(
        self, external_id: str, name: str, provider_type: str, kind: IdentityKind,
        home: Home = Home.this_directory, origin: str | None = None,
    ) -> Identity:
        identity = self.identities.get(external_id)
        if identity is None:
            identity = Identity(
                provider_id=self.provider.id, scope_node_id=self.node.id,
                external_id=external_id, provider_type=provider_type, kind=kind,
                home=home, origin=origin, first_display_name=name[:255], provisional=False,
            )
            self.db.add(identity)
            self.db.flush()
            self.identities[external_id] = identity
            self.new_count += 1
        return identity

    def observed(self, identity: Identity) -> bool:
        """Whether this import has observed the identity yet."""
        return identity.id in self._observed

    def observe(
        self, identity: Identity, display_name: str, provider_ref: str, **fields: object,
    ) -> bool:
        """One observation per identity per import. Both halves matter:
        an identity observed only by the import that created it drops
        out of every later view, and one observed twice by one import
        breaks the row that makes "once per import" true. Returns
        whether this call wrote it."""
        if identity.id in self._observed:
            return False
        self._observed.add(identity.id)
        self.db.add(IdentityObservation(
            import_id=self.import_row.id, identity_id=identity.id,
            display_name=display_name[:255], provider_ref=provider_ref[:2048], **fields,
        ))
        self.observations += 1
        return True
