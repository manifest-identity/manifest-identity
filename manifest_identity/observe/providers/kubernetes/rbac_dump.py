"""The Kubernetes role-based access control dump parser.

The file is the cluster's own answer to one command:

    kubectl get roles,clusterroles,rolebindings,clusterrolebindings,serviceaccounts -A -o json

which is a List whose items carry the API's own objects (field
semantics verified against the Kubernetes reference documentation at
build time, September 29, 2026): a Role or ClusterRole holds rules of
apiGroups, resources, and verbs, additive with no deny and with "*" as
a wildcard; a RoleBinding or ClusterRoleBinding holds subjects of kind
User, Group, or ServiceAccount and one roleRef; a ServiceAccount is an
object with a namespace, a name, and the uid the cluster never reuses.
A RoleBinding may reference a ClusterRole, which grants that role
inside the binding's namespace only.

The file does not name the cluster. Nothing in the API's objects does,
so the cluster's name arrives beside the file as a form field, the
one thing about this source the content cannot say.

Held to the contract the other parsers set: bounded, in memory,
verified against its own claims, and no error ever repeats file
content. The vocabulary ends here; the importer turns these into the
neutral rows.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime

MAX_FILE_BYTES = 50 * 1024 * 1024
MAX_ENTITIES = 100_000
MAX_NAME_CHARS = 253  # the API's own limit for a name

RBAC_KINDS = frozenset({"Role", "ClusterRole", "RoleBinding", "ClusterRoleBinding"})
SUBJECT_KINDS = frozenset({"User", "Group", "ServiceAccount"})
# The verbs the API defines. A verb outside this list is refused,
# because a misspelled verb in a file is a file that was edited.
VERBS = frozenset({
    "get", "list", "watch", "create", "update", "patch", "delete", "deletecollection",
    "bind", "escalate", "impersonate", "use", "approve", "sign", "*",
})


class ParseError(ValueError):
    """File-level rejection; messages carry rules and names of our own
    contract, never values from the file."""


@dataclass
class ParsedRule:
    api_groups: list[str]
    resources: list[str]
    verbs: list[str]
    resource_names: list[str] = field(default_factory=list)
    non_resource_urls: list[str] = field(default_factory=list)


@dataclass
class ParsedRole:
    kind: str  # Role or ClusterRole
    name: str
    namespace: str | None
    uid: str | None
    created: datetime | None
    rules: list[ParsedRule]
    aggregated: bool


@dataclass
class ParsedSubject:
    kind: str  # User, Group, ServiceAccount
    name: str
    namespace: str | None


@dataclass
class ParsedBinding:
    kind: str  # RoleBinding or ClusterRoleBinding
    name: str
    namespace: str | None
    uid: str | None
    role_kind: str  # Role or ClusterRole
    role_name: str
    subjects: list[ParsedSubject]


@dataclass
class ParsedServiceAccount:
    name: str
    namespace: str
    uid: str | None
    created: datetime | None


@dataclass
class ParsedDump:
    roles: list[ParsedRole] = field(default_factory=list)
    bindings: list[ParsedBinding] = field(default_factory=list)
    service_accounts: list[ParsedServiceAccount] = field(default_factory=list)
    skipped: int = 0


def _name(raw: object, where: str) -> str:
    if not isinstance(raw, str) or not raw or len(raw) > MAX_NAME_CHARS:
        raise ParseError(f"{where}: name is missing or longer than {MAX_NAME_CHARS}")
    if any(ord(c) < 33 for c in raw):
        raise ParseError(f"{where}: name carries whitespace or a control character")
    return raw


def _optional_name(raw: object, where: str) -> str | None:
    return None if raw is None else _name(raw, where)


def _time(raw: object, where: str) -> datetime | None:
    if raw is None:
        return None
    if not isinstance(raw, str):
        raise ParseError(f"{where}: a timestamp must be a string")
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ParseError(f"{where}: a timestamp is not ISO 8601") from exc
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _strings(raw: object, where: str) -> list[str]:
    if raw is None:
        return []
    if not isinstance(raw, list) or not all(isinstance(x, str) for x in raw):
        raise ParseError(f"{where}: must be a list of strings")
    if len(raw) > MAX_ENTITIES:
        raise ParseError(f"{where}: more than {MAX_ENTITIES} entries")
    return raw


def _record(raw: object, where: str) -> dict[str, object]:
    if not isinstance(raw, dict):
        raise ParseError(f"{where}: each entry must be an object")
    return raw


def _metadata(item: dict[str, object], where: str) -> dict[str, object]:
    metadata = item.get("metadata")
    if not isinstance(metadata, dict):
        raise ParseError(f"{where}: metadata is missing")
    return metadata


def _rules(raw: object, where: str) -> list[ParsedRule]:
    rules: list[ParsedRule] = []
    for index, r_raw in enumerate(_strings_or_records(raw, f"{where}.rules")):
        r_where = f"{where}.rules[{index}]"
        rule = _record(r_raw, r_where)
        verbs = _strings(rule.get("verbs"), r_where)
        unknown = [v for v in verbs if v not in VERBS]
        if unknown:
            raise ParseError(f"{r_where}: a verb is not one the API defines")
        rules.append(ParsedRule(
            api_groups=_strings(rule.get("apiGroups"), r_where),
            resources=_strings(rule.get("resources"), r_where),
            verbs=verbs,
            resource_names=_strings(rule.get("resourceNames"), r_where),
            non_resource_urls=_strings(rule.get("nonResourceURLs"), r_where),
        ))
    return rules


def _strings_or_records(raw: object, where: str) -> list[object]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise ParseError(f"{where}: must be a list")
    if len(raw) > MAX_ENTITIES:
        raise ParseError(f"{where}: more than {MAX_ENTITIES} entries")
    return raw


def parse_rbac_dump(data: bytes) -> ParsedDump:
    if len(data) > MAX_FILE_BYTES:
        raise ParseError(f"file exceeds {MAX_FILE_BYTES} bytes")
    try:
        document = json.loads(data)
    except ValueError as exc:
        raise ParseError("file is not valid JSON") from exc
    if not isinstance(document, dict) or document.get("kind") != "List":
        raise ParseError("file must be a kubectl List")
    items = _strings_or_records(document.get("items"), "items")
    dump = ParsedDump()

    for index, raw in enumerate(items):
        where = f"items[{index}]"
        item = _record(raw, where)
        kind = item.get("kind")
        metadata = _metadata(item, where)
        name = _name(metadata.get("name"), where)
        namespace = _optional_name(metadata.get("namespace"), f"{where}.namespace")
        uid = _optional_name(metadata.get("uid"), f"{where}.uid")
        created = _time(metadata.get("creationTimestamp"), where)

        if kind in ("Role", "ClusterRole"):
            if kind == "Role" and namespace is None:
                raise ParseError(f"{where}: a Role must carry a namespace")
            dump.roles.append(ParsedRole(
                kind=str(kind), name=name,
                namespace=namespace if kind == "Role" else None,
                uid=uid, created=created,
                rules=_rules(item.get("rules"), where),
                aggregated=isinstance(item.get("aggregationRule"), dict),
            ))
        elif kind in ("RoleBinding", "ClusterRoleBinding"):
            if kind == "RoleBinding" and namespace is None:
                raise ParseError(f"{where}: a RoleBinding must carry a namespace")
            role_ref = _record(item.get("roleRef"), f"{where}.roleRef")
            role_kind = role_ref.get("kind")
            if role_kind not in ("Role", "ClusterRole"):
                raise ParseError(f"{where}.roleRef: kind is not Role or ClusterRole")
            if kind == "ClusterRoleBinding" and role_kind == "Role":
                raise ParseError(f"{where}.roleRef: a ClusterRoleBinding cannot bind a Role")
            subjects: list[ParsedSubject] = []
            for s_index, s_raw in enumerate(_strings_or_records(item.get("subjects"), where)):
                s_where = f"{where}.subjects[{s_index}]"
                subject = _record(s_raw, s_where)
                s_kind = subject.get("kind")
                if s_kind not in SUBJECT_KINDS:
                    raise ParseError(f"{s_where}: kind is not User, Group, or ServiceAccount")
                s_namespace = _optional_name(subject.get("namespace"), f"{s_where}.namespace")
                if s_kind == "ServiceAccount" and s_namespace is None:
                    raise ParseError(f"{s_where}: a ServiceAccount subject needs a namespace")
                subjects.append(ParsedSubject(
                    kind=str(s_kind), name=_name(subject.get("name"), s_where),
                    namespace=s_namespace if s_kind == "ServiceAccount" else None,
                ))
            dump.bindings.append(ParsedBinding(
                kind=str(kind), name=name,
                namespace=namespace if kind == "RoleBinding" else None,
                uid=uid, role_kind=str(role_kind),
                role_name=_name(role_ref.get("name"), f"{where}.roleRef"),
                subjects=subjects,
            ))
        elif kind == "ServiceAccount":
            if namespace is None:
                raise ParseError(f"{where}: a ServiceAccount must carry a namespace")
            dump.service_accounts.append(ParsedServiceAccount(
                name=name, namespace=namespace, uid=uid, created=created,
            ))
        else:
            # Anything else in the list is not access and is counted, not
            # read: a person who dumped every object gets a number back.
            dump.skipped += 1

    _verify(dump)
    return dump


def _verify(dump: ParsedDump) -> None:
    """The file against its own claims. A binding may reference a role
    the file does not hold, which the API allows and which the importer
    records as a definition with no contents; but one name for two
    objects of the same kind in the same namespace is a file that was
    edited."""
    seen: set[tuple[str, str | None, str]] = set()
    for role in dump.roles:
        key = (role.kind, role.namespace, role.name)
        if key in seen:
            raise ParseError("a role name appears twice in one namespace")
        seen.add(key)
    for binding in dump.bindings:
        key = (binding.kind, binding.namespace, binding.name)
        if key in seen:
            raise ParseError("a binding name appears twice in one namespace")
        seen.add(key)
    accounts = {(sa.namespace, sa.name) for sa in dump.service_accounts}
    if len(accounts) < len(dump.service_accounts):
        raise ParseError("a service account appears twice in one namespace")
