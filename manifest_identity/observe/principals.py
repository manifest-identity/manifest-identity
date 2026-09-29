"""Who a trust policy actually names.

A role's trust policy is the door into that role, and until this existed
the importer recorded the door without recording who holds a key: one
relationship row per role, with the principal left as the words "trust
policy". That is enough to say a role is assumable and not enough to
answer the question a review asks, which is by whom.

So the document is read into one principal per row. The shapes a
provider writes are few and awkward, and each says something different
about the boundary being crossed:

    {"AWS": "arn:aws:iam::111:user/deploy"}   a principal in some account
    {"AWS": "arn:aws:iam::111:root"}          every principal in an account
    {"Federated": "arn:...:saml-provider/Okta"} an identity provider
    {"Federated": "token.actions.github..."}  a workload identity provider
    {"Service": "ec2.amazonaws.com"}          the provider's own service
    {"AWS": "*"} or "*"                       anyone at all

Only statements that allow are read. A deny statement narrows a door
rather than opening one, and reading it as a principal would invent
access that does not exist.

Nothing here decides whether a trust is wrong. It reads what the
document says, and the finding classes and the delta judge it.
"""

from __future__ import annotations

from dataclasses import dataclass

# What kind of boundary the principal sits across. Stored on the
# relationship row as from_kind.
AWS = "aws"
FEDERATED = "federated"
SERVICE = "service"
CANONICAL = "canonical"
WILDCARD = "wildcard"

# The relationship's own kind: a federation crosses into an identity
# provider, everything else is a trust.
KIND_TRUST = "trust"
KIND_FEDERATION = "federation"


@dataclass(frozen=True)
class Principal:
    kind: str
    from_kind: str
    ref: str


def _statements(document: object) -> list[dict[str, object]]:
    if not isinstance(document, dict):
        return []
    raw = document.get("Statement")
    if isinstance(raw, dict):
        return [raw]
    if isinstance(raw, list):
        return [item for item in raw if isinstance(item, dict)]
    return []


def _values(raw: object) -> list[str]:
    if isinstance(raw, str):
        return [raw]
    if isinstance(raw, list):
        return [item for item in raw if isinstance(item, str)]
    return []


def principals(document: object) -> list[Principal]:
    """Every principal a trust policy allows, in the order written, with
    duplicates removed and the account-wide and wildcard forms kept as
    themselves rather than expanded."""
    found: list[Principal] = []
    seen: set[tuple[str, str]] = set()

    def add(kind: str, from_kind: str, ref: str) -> None:
        ref = ref.strip()[:2048]
        if not ref or (from_kind, ref) in seen:
            return
        seen.add((from_kind, ref))
        found.append(Principal(kind=kind, from_kind=from_kind, ref=ref))

    for statement in _statements(document):
        if str(statement.get("Effect", "")).lower() != "allow":
            continue
        raw = statement.get("Principal")
        if raw == "*":
            add(KIND_TRUST, WILDCARD, "*")
            continue
        if not isinstance(raw, dict):
            continue
        for value in _values(raw.get("AWS")):
            if value == "*":
                add(KIND_TRUST, WILDCARD, "*")
            else:
                add(KIND_TRUST, AWS, value)
        for value in _values(raw.get("Federated")):
            add(KIND_FEDERATION, FEDERATED, value)
        for value in _values(raw.get("Service")):
            add(KIND_TRUST, SERVICE, value)
        for value in _values(raw.get("CanonicalUser")):
            add(KIND_TRUST, CANONICAL, value)
    return found


def account_of(reference: str) -> str | None:
    """The account an ARN belongs to, or nothing when the string is not
    an ARN, which is the case for a service or an issuer URL."""
    parts = reference.split(":")
    if len(parts) > 5 and parts[0] == "arn" and parts[4]:
        return parts[4]
    return None


def is_external(reference: str, account: str) -> bool:
    """Whether a principal sits outside the account being imported. An
    ARN in another account is external; a string that is not an ARN
    belongs to a provider or an issuer and is handled by its own kind."""
    found = account_of(reference)
    return found is not None and found != account


def display_name(reference: str) -> str:
    """A short label for a principal: the last path segment of an ARN,
    the whole string otherwise, which is what a page has room for."""
    if "/" in reference:
        return reference.rsplit("/", 1)[-1][:255]
    if reference.startswith("arn:") and reference.endswith(":root"):
        account = account_of(reference)
        return f"account {account}" if account else reference[:255]
    return reference[:255]
