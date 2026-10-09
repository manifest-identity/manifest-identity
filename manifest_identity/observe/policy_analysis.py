"""Reading what a policy document can actually do.

Judgment lives here, so the limits are stated first. This reads grants,
not effective permissions: explicit denies are noted but not evaluated
against the allows they narrow, conditions are noted but not
interpreted, and privilege reachable by assuming another role is not
computed at all (the chaining limitation, recorded as an accepted risk
and inherited from the prior art). The consequence is one-directional
and stated wherever a finding is shown: this reading can overstate a
grant that a deny or a condition narrows, and it understates any
privilege reached through a chain.

Detection is capability-shaped rather than name-shaped: a policy named
ReadOnly that can rewrite its own default version is admin, and a
policy named FullAdminLegacy that grants three read actions is not.
The escalation combinations are the published taxonomy credited in
ACKNOWLEDGEMENTS.md.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# One of these alone lets a principal grant itself more privilege.
SELF_ESCALATION = {
    "iam:createpolicyversion": "rewrite an attached policy's default version",
    "iam:setdefaultpolicyversion": "switch an attached policy to a stronger version",
    "iam:attachuserpolicy": "attach an administrator policy to itself",
    "iam:attachrolepolicy": "attach an administrator policy to a role",
    "iam:attachgrouppolicy": "attach an administrator policy to its group",
    "iam:putuserpolicy": "write itself an inline administrator policy",
    "iam:putrolepolicy": "write a role an inline administrator policy",
    "iam:putgrouppolicy": "write its group an inline administrator policy",
    "iam:addusertogroup": "add itself to an administrator group",
    "iam:createaccesskey": "mint credentials for a stronger principal",
    "iam:createloginprofile": "set a console password on a stronger principal",
    "iam:updateloginprofile": "reset a console password on a stronger principal",
    "iam:updateassumerolepolicy": "make a stronger role assumable by itself",
}

# Passing a role into a compute service runs code as that role, so
# either half alone is ordinary and the pair is an escalation path.
# noqa on the next line: the checker reads "PASS" in the name as a
# credential; this is the provider's action string for passing a role.
PASS_ROLE = "iam:passrole"  # noqa: S105
COMPUTE_LAUNCH = {
    "ec2:runinstances": "launch an instance running as a passed role",
    "lambda:createfunction": "create a function running as a passed role",
    "cloudformation:createstack": "create a stack acting as a passed role",
    "glue:createdevendpoint": "create an endpoint running as a passed role",
    "sagemaker:createnotebookinstance": "create a notebook running as a passed role",
    "datapipeline:createpipeline": "create a pipeline running as a passed role",
}

# A wildcard over read operations and a wildcard over every operation
# are not the same finding. Treating them alike is how a tool earns the
# reputation that gets it muted, so the reading distinguishes them.
READ_VERBS = ("get", "list", "describe", "head", "view", "search", "read",
              "query", "scan", "select", "batchget", "lookup", "retrieve")

IAM_MUTATING_PREFIXES = ("iam:create", "iam:delete", "iam:put", "iam:attach",
                         "iam:detach", "iam:update", "iam:add", "iam:remove",
                         "iam:set", "iam:tag", "iam:untag")


@dataclass
class PolicyReading:
    """What one policy document grants, in capability terms."""

    admin_equivalent: bool = False
    wildcard_action: bool = False
    wildcard_write: bool = False
    wildcard_resource: bool = False
    iam_mutating: bool = False
    escalation: list[str] = field(default_factory=list)
    negated_allow: bool = False
    conditioned: bool = False
    has_deny: bool = False

    @property
    def privileged(self) -> bool:
        return bool(
            self.admin_equivalent
            or self.escalation
            or self.iam_mutating
            or (self.wildcard_write and self.wildcard_resource)
            or self.negated_allow
        )

    def merge(self, other: PolicyReading) -> PolicyReading:
        return PolicyReading(
            admin_equivalent=self.admin_equivalent or other.admin_equivalent,
            wildcard_action=self.wildcard_action or other.wildcard_action,
            wildcard_write=self.wildcard_write or other.wildcard_write,
            wildcard_resource=self.wildcard_resource or other.wildcard_resource,
            iam_mutating=self.iam_mutating or other.iam_mutating,
            escalation=sorted(set(self.escalation) | set(other.escalation)),
            negated_allow=self.negated_allow or other.negated_allow,
            conditioned=self.conditioned or other.conditioned,
            has_deny=self.has_deny or other.has_deny,
        )


def _as_list(value: object) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, str)]
    return []


def _pattern(action: str) -> re.Pattern[str]:
    """IAM wildcards are * and ?; everything else is literal."""
    escaped = re.escape(action.lower())
    return re.compile("^" + escaped.replace(r"\*", ".*").replace(r"\?", ".") + "$")


def _grants(patterns: list[str], action: str) -> bool:
    return any(_pattern(p).match(action) for p in patterns)


CAPABILITY_KIND = "capabilities"


def capability_document(
    provider: str, level: str, scope: str, *,
    administers: bool, changes_access: bool, writes: bool, reads: bool,
    actions: list[str] | None = None,
) -> dict[str, object]:
    """A definition's contents for a provider whose roles are fixed
    levels rather than documents of actions. It says what the level
    can do in the reading's own terms, so the finding engine reads it
    the way it reads a policy and never learns the provider's words.
    A provider whose roles do enumerate what they allow (a cluster
    role's verbs on resources) lists them as actions, so a changed
    definition can name what it gained the way a policy can (1.7)."""
    document: dict[str, object] = {
        "kind": CAPABILITY_KIND, "provider": provider, "level": level, "scope": scope,
        "administers": administers, "changes_access": changes_access,
        "writes": writes, "reads": reads,
    }
    if actions is not None:
        document["actions"] = sorted(set(actions))
    return document


def read_policy(document: object) -> PolicyReading:  # noqa: C901
    """Read one policy document. Malformed input reads as granting
    nothing, never as an exception: these documents are untrusted
    file content, and the parsers upstream already bound them."""
    reading = PolicyReading()
    if not isinstance(document, dict):
        return reading
    if document.get("kind") == CAPABILITY_KIND:
        # A capability document says outright what a policy document
        # has to be read for. Administering a scope is administrator
        # equivalence at that scope; changing access is the mutating
        # capability. Writing and reading carry no finding of their
        # own, the same as a policy that writes one service.
        reading.admin_equivalent = document.get("administers") is True
        reading.iam_mutating = document.get("changes_access") is True
        return reading
    statements = document.get("Statement")
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list):
        return reading

    for statement in statements:
        if not isinstance(statement, dict):
            continue
        effect = statement.get("Effect")
        if not isinstance(effect, str):
            continue
        if effect.lower() == "deny":
            reading.has_deny = True
            continue
        if effect.lower() != "allow":
            continue

        actions = _as_list(statement.get("Action"))
        not_actions = _as_list(statement.get("NotAction"))
        resources = _as_list(statement.get("Resource"))
        not_resources = _as_list(statement.get("NotResource"))
        if statement.get("Condition"):
            reading.conditioned = True

        # An allow written as "everything except" grants whatever the
        # provider adds tomorrow, which is why it reads as broad here.
        if not_actions or not_resources:
            reading.negated_allow = True

        wildcard_resource = "*" in resources or bool(not_resources)
        if wildcard_resource:
            reading.wildcard_resource = True
        for action in actions:
            if "*" not in action:
                continue
            reading.wildcard_action = True
            operation = action.split(":", 1)[1] if ":" in action else action
            if operation.startswith("*") or not operation.lower().startswith(
                READ_VERBS
            ):
                reading.wildcard_write = True

        if "*" in actions and wildcard_resource:
            reading.admin_equivalent = True
        if _grants(actions, "iam:createuser") and _grants(actions, "iam:attachuserpolicy"):
            reading.admin_equivalent = True

        # Two shapes reach the same capability: the action names a
        # mutating operation outright, or a wildcard pattern covers one.
        # Probing only the wildcard shape missed every literal action,
        # which is how most real policies are written.
        for action in actions:
            lowered = action.lower()
            if any(
                lowered.startswith(prefix) or _pattern(action).match(prefix + "x")
                for prefix in IAM_MUTATING_PREFIXES
            ):
                reading.iam_mutating = True
                break

        for action, description in SELF_ESCALATION.items():
            if _grants(actions, action):
                reading.escalation.append(description)

        if _grants(actions, PASS_ROLE):
            for action, description in COMPUTE_LAUNCH.items():
                if _grants(actions, action):
                    reading.escalation.append(description)

    reading.escalation = sorted(set(reading.escalation))
    return reading


@dataclass
class TrustReading:
    """Who may assume a role, from its trust policy."""

    public: bool = False
    cross_account: list[str] = field(default_factory=list)
    federated: list[str] = field(default_factory=list)
    services: list[str] = field(default_factory=list)
    conditioned: bool = False


def read_trust_policy(document: object, own_account: str) -> TrustReading:  # noqa: C901
    reading = TrustReading()
    if not isinstance(document, dict):
        return reading
    statements = document.get("Statement")
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list):
        return reading

    account = re.compile(r"arn:[^:]*:iam::(\d{12}):")
    for statement in statements:
        if not isinstance(statement, dict):
            continue
        effect = statement.get("Effect")
        if not isinstance(effect, str) or effect.lower() != "allow":
            continue
        if statement.get("Condition"):
            reading.conditioned = True
        principal = statement.get("Principal")
        if principal == "*":
            reading.public = True
            continue
        if not isinstance(principal, dict):
            continue
        for entry in _as_list(principal.get("AWS")):
            if entry == "*":
                reading.public = True
                continue
            match = account.match(entry)
            if match and match.group(1) != own_account:
                reading.cross_account.append(match.group(1))
            elif not match and entry.isdigit() and entry != own_account:
                reading.cross_account.append(entry)
        reading.federated.extend(_as_list(principal.get("Federated")))
        reading.services.extend(_as_list(principal.get("Service")))

    reading.cross_account = sorted(set(reading.cross_account))
    reading.federated = sorted(set(reading.federated))
    reading.services = sorted(set(reading.services))
    return reading


# Naming what changed between two versions of one definition.
#
# The delta already says a role changed after it was authorized. That
# sentence tells a reviewer to look and not what to look at, and a
# reviewer who has to open two JSON documents to find out will approve
# the change unread. So the two versions are compared here in the same
# capability terms the reading above uses, and the finding names the
# actions that arrived, the actions that left, and any line the new
# version crossed that the old one did not.
#
# The limits are the reading's limits. Actions are compared as the
# patterns the document wrote, lowercased, so "s3:*" arriving is named
# as "s3:*" and not expanded. A version written as everything-except
# cannot be enumerated, and is named as such rather than as nothing.

# How many actions a finding names before it says "and N more". A
# policy can list hundreds, and a finding that lists hundreds is one
# nobody reads.
NAMED_ACTIONS = 12

EVERYTHING_EXCEPT = "everything except: "


def allowed_actions(document: object) -> frozenset[str]:
    """The action patterns a document allows, as it wrote them. An
    allow written with NotAction becomes one token that says so, since
    what it grants is everything the provider will ever add."""
    found: set[str] = set()
    if not isinstance(document, dict):
        return frozenset()
    if document.get("kind") == CAPABILITY_KIND:
        # A capability document that enumerates what it allows names
        # those as its actions; one that only states a level has none
        # to name, and a change between two levels reads as a change
        # of level rather than of actions.
        listed = document.get("actions")
        return frozenset(
            str(a).lower() for a in listed
        ) if isinstance(listed, list) else frozenset()
    statements = document.get("Statement")
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list):
        return frozenset()
    for statement in statements:
        if not isinstance(statement, dict):
            continue
        effect = statement.get("Effect")
        if not isinstance(effect, str) or effect.lower() != "allow":
            continue
        for action in _as_list(statement.get("Action")):
            found.add(action.lower())
        not_actions = _as_list(statement.get("NotAction"))
        if not_actions:
            found.add(EVERYTHING_EXCEPT + ", ".join(sorted(a.lower() for a in not_actions)))
    return frozenset(found)


@dataclass
class ChangeReading:
    """What one version of a definition has that the other did not."""

    added: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    # Lines the new version crosses that the old one did not, in the
    # words the privilege findings already use.
    crossed: list[str] = field(default_factory=list)
    # Set when one side's document was never observed, so the change
    # cannot be described and the finding says so instead of guessing.
    undescribable: str | None = None

    @property
    def material(self) -> bool:
        """Whether the change grants anything it did not before. A
        version that only removes is still a change worth a look, and
        it is not the same finding as one that widens."""
        return bool(self.added or self.crossed)

    def as_text(self) -> str:
        if self.undescribable:
            return self.undescribable
        parts: list[str] = []
        if self.added:
            parts.append("added " + _named(self.added))
        if self.removed:
            parts.append("removed " + _named(self.removed))
        if self.crossed:
            parts.append("now " + "; now ".join(self.crossed))
        return ", ".join(parts) if parts else "the documents differ only in wording"


def _named(actions: list[str]) -> str:
    shown = actions[:NAMED_ACTIONS]
    rest = len(actions) - len(shown)
    text = ", ".join(shown)
    return text + (f", and {rest} more" if rest > 0 else "")


def _crossings(before: PolicyReading, after: PolicyReading) -> list[str]:
    crossed: list[str] = []
    if after.admin_equivalent and not before.admin_equivalent:
        crossed.append("administrator-equivalent")
    if after.wildcard_write and after.wildcard_resource and not (
        before.wildcard_write and before.wildcard_resource
    ):
        crossed.append("a write wildcard on every resource")
    if after.iam_mutating and not before.iam_mutating:
        crossed.append("able to change access controls")
    if after.negated_allow and not before.negated_allow:
        crossed.append("an allow written as everything except")
    for description in after.escalation:
        if description not in before.escalation:
            crossed.append("able to " + description)
    return crossed


def describe_change(before: object, after: object) -> ChangeReading:
    """Compare two versions of one definition. Either side may be
    missing, which happens when a version was authorized by hash and
    its document was never observed; that is said rather than read as
    an empty policy, because an empty policy would make every action
    in the other version look newly added."""
    if not isinstance(before, dict) and not isinstance(after, dict):
        return ChangeReading(
            undescribable="neither version's document was observed, so the "
            "change cannot be described"
        )
    if not isinstance(before, dict):
        return ChangeReading(
            undescribable="the authorized version's document was never "
            "observed, so what changed cannot be described"
        )
    if not isinstance(after, dict):
        return ChangeReading(
            undescribable="the current version's document was not observed, "
            "so what changed cannot be described"
        )
    was, now = allowed_actions(before), allowed_actions(after)
    return ChangeReading(
        added=sorted(now - was),
        removed=sorted(was - now),
        crossed=_crossings(read_policy(before), read_policy(after)),
    )
