"""Every table, in one import, for the migrations and the tests.

Each part owns its own models module; this module exists so that
Base.metadata knows every table and so a caller who needs several can
import them from one place.
"""

from manifest_identity.api.models import IntegrationToken
from manifest_identity.authorize.models import (
    Authorization,
    AuthorizationStatus,
    AuthorizedRelationship,
    EntryPath,
    GovernanceRecord,
)
from manifest_identity.core.db import Base
from manifest_identity.core.models import (
    GLOBAL_NODE_EXTERNAL_ID,
    AuditEvent,
    AuthSession,
    Partition,
    Provider,
    RoleBinding,
    ScopeNode,
    Setting,
    User,
    utcnow,
)
from manifest_identity.decide.models import (
    Alert,
    AlertDelivery,
    Campaign,
    CampaignItem,
    CampaignTrigger,
)
from manifest_identity.observe.models import (
    Credential,
    CredentialKind,
    Grant,
    GrantMode,
    Home,
    Identity,
    IdentityKind,
    IdentityObservation,
    Import,
    Membership,
    ObservedRelationship,
    ProviderInstance,
    RoleDefinition,
)

__all__ = [
    "GLOBAL_NODE_EXTERNAL_ID", "Alert", "AlertDelivery", "AuditEvent",
    "Authorization", "AuthorizationStatus", "AuthorizedRelationship",
    "AuthSession", "Base",
    "Campaign", "CampaignItem", "CampaignTrigger", "Credential",
    "CredentialKind",
    "EntryPath", "GovernanceRecord", "Grant", "GrantMode", "Home", "Identity",
    "IdentityKind", "IdentityObservation", "Import", "IntegrationToken",
    "Membership", "ObservedRelationship", "Partition", "Provider",
    "ProviderInstance", "RoleBinding", "RoleDefinition", "ScopeNode", "Setting",
    "User", "utcnow",
]
