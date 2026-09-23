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


def read_policy(document: object) -> PolicyReading:
    """Read one policy document. Malformed input reads as granting
    nothing, never as an exception: these documents are untrusted
    file content, and the parsers upstream already bound them."""
    reading = PolicyReading()
    if not isinstance(document, dict):
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


def read_trust_policy(document: object, own_account: str) -> TrustReading:
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
