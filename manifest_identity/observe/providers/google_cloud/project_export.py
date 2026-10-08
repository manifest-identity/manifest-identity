"""The Google Cloud project export parser.

Google Cloud answers in pieces, each a gcloud command's own JSON, so
the file is one document that holds those pieces verbatim under a key
each. The shape is this product's; the pieces are the provider's
(field names read from the gcloud reference on September 29, 2026; the
key list's fields are re-verified against a live command when a real
project is first read):

    project           gcloud projects describe PROJECT_ID --format=json
                      (projectId, projectNumber)
    policy            gcloud projects get-iam-policy PROJECT_ID --format=json
                      (bindings of role to members, each with an
                      optional condition; etag; version)
    service_accounts  gcloud iam service-accounts list --format=json
                      (email, uniqueId, displayName, disabled)
    keys              per account, gcloud iam service-accounts keys list
                      --iam-account EMAIL --format=json, keyed by email
                      (name, keyType USER_MANAGED or SYSTEM_MANAGED,
                      validAfterTime, validBeforeTime, disabled)
    role_definitions  optional, gcloud iam roles describe for any role
                      whose permissions should be read (name, title,
                      includedPermissions)
    activity          optional, the last authentication per service
                      account from the activity analyzer
                      (gcloud policy-intelligence query-activity
                      --activity-type serviceAccountLastAuthentication),
                      keyed by email

A member is written the way the policy writes it: user:, serviceAccount:,
group:, domain:, the two public forms allUsers and allAuthenticatedUsers,
the deleted: prefix a policy keeps for a principal that no longer
exists, and the principal:// and principalSet:// forms of workload
identity federation. The vocabulary ends here.

Held to the contract the other parsers set: bounded, in memory,
verified against its own claims, and no error ever repeats file
content.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime

from manifest_identity.observe.providers import parsing
from manifest_identity.observe.providers.parsing import ParseError

MAX_FILE_BYTES = 25 * 1024 * 1024
MAX_ENTITIES = 50_000
MAX_TEXT_CHARS = 1024

MEMBER_PREFIXES = ("user", "serviceAccount", "group", "domain", "deleted", "principal",
                   "principalSet")
PUBLIC_MEMBERS = frozenset({"allUsers", "allAuthenticatedUsers"})
KEY_TYPES = frozenset({"USER_MANAGED", "SYSTEM_MANAGED"})

_PROJECT_ID = re.compile(r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$")
_ROLE = re.compile(r"^(roles/[A-Za-z0-9._]+|(projects|organizations)/[^/]+/roles/[A-Za-z0-9._]+)$")
_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+$")


_LIMITS = parsing.Limits(max_entries=MAX_ENTITIES, max_text=MAX_TEXT_CHARS)
_list = _LIMITS.read_list
_text = _LIMITS.read_text
_record = parsing.read_record
_time = parsing.read_time


@dataclass
class ParsedMember:
    text: str      # as the policy wrote it
    kind: str      # user, serviceAccount, group, domain, public, deleted, federated
    name: str      # the part after the prefix, or the whole for a public form


@dataclass
class ParsedBinding:
    role: str
    members: list[ParsedMember]
    condition_title: str | None


@dataclass
class ParsedKey:
    id: str
    user_managed: bool
    valid_after: datetime | None
    valid_before: datetime | None
    disabled: bool


@dataclass
class ParsedServiceAccount:
    email: str
    unique_id: str
    display_name: str
    disabled: bool
    keys: list[ParsedKey] = field(default_factory=list)
    last_authenticated: datetime | None = None


@dataclass
class ParsedRoleDefinition:
    name: str
    title: str
    permissions: list[str]


@dataclass
class ParsedProject:
    project_id: str
    project_number: str
    bindings: list[ParsedBinding] = field(default_factory=list)
    service_accounts: list[ParsedServiceAccount] = field(default_factory=list)
    role_definitions: list[ParsedRoleDefinition] = field(default_factory=list)
    skipped: int = 0


def parse_member(text: str, where: str) -> ParsedMember:
    if text in PUBLIC_MEMBERS:
        return ParsedMember(text=text, kind="public", name=text)
    if text.startswith("principal://") or text.startswith("principalSet://"):
        return ParsedMember(text=text, kind="federated", name=text.split("//", 1)[1])
    prefix, separator, name = text.partition(":")
    if not separator or prefix not in MEMBER_PREFIXES or not name:
        raise ParseError(f"{where}: a member is not written the way a policy writes one")
    if prefix == "deleted":
        # deleted:user:someone@example.test?uid=123: the principal is
        # gone and the binding is not.
        return ParsedMember(text=text, kind="deleted", name=name)
    if prefix in ("user", "serviceAccount", "group") and not _EMAIL.match(name):
        raise ParseError(f"{where}: a {prefix} member must be an address")
    return ParsedMember(text=text, kind=prefix, name=name)


def parse_project_export(data: bytes) -> ParsedProject:
    if len(data) > MAX_FILE_BYTES:
        raise ParseError(f"file exceeds {MAX_FILE_BYTES} bytes")
    try:
        document = json.loads(data)
    except ValueError as exc:
        raise ParseError("file is not valid JSON") from exc
    if not isinstance(document, dict):
        raise ParseError("file must be a JSON object")

    project = _record(document.get("project"), "project")
    project_id = _text(project.get("projectId"), "project")
    if not _PROJECT_ID.match(project_id):
        raise ParseError("project: projectId is not a project identifier")
    number = project.get("projectNumber")
    if not isinstance(number, str | int) or isinstance(number, bool) or not str(number).isdigit():
        raise ParseError("project: projectNumber must be digits")
    parsed = ParsedProject(project_id=project_id, project_number=str(number))

    policy = _record(document.get("policy"), "policy")
    for index, raw in enumerate(_list(policy.get("bindings"), "policy.bindings")):
        where = f"policy.bindings[{index}]"
        binding = _record(raw, where)
        role = _text(binding.get("role"), where)
        if not _ROLE.match(role):
            raise ParseError(f"{where}: role is not a role name")
        condition = binding.get("condition")
        title = None
        if condition is not None:
            title = _text(_record(condition, f"{where}.condition").get("title"), where, "")
        members = [
            parse_member(_text(m, f"{where}.members[{m_index}]"), f"{where}.members[{m_index}]")
            for m_index, m in enumerate(_list(binding.get("members"), f"{where}.members"))
        ]
        parsed.bindings.append(ParsedBinding(role=role, members=members, condition_title=title))

    # Absent is fine; present and not an object is not, and an empty
    # list is not an object: the test that found this read one as "no
    # keys" and the parser said nothing.
    keys_by_email = document.get("keys")
    if keys_by_email is None:
        keys_by_email = {}
    if not isinstance(keys_by_email, dict):
        raise ParseError("keys: must be an object keyed by account address")
    activity = document.get("activity")
    if activity is None:
        activity = {}
    if not isinstance(activity, dict):
        raise ParseError("activity: must be an object keyed by account address")
    for index, raw in enumerate(_list(document.get("service_accounts"), "service_accounts")):
        where = f"service_accounts[{index}]"
        account = _record(raw, where)
        email = _text(account.get("email"), where)
        if not _EMAIL.match(email):
            raise ParseError(f"{where}: email is not an address")
        unique_id = account.get("uniqueId")
        if not isinstance(unique_id, str) or not unique_id.isdigit():
            raise ParseError(f"{where}: uniqueId must be digits")
        keys: list[ParsedKey] = []
        for k_index, k_raw in enumerate(_list(keys_by_email.get(email), f"keys[{email}]")):
            k_where = f"keys[{index}][{k_index}]"
            key = _record(k_raw, k_where)
            name = _text(key.get("name"), k_where)
            key_type = key.get("keyType", "USER_MANAGED")
            if key_type not in KEY_TYPES:
                raise ParseError(f"{k_where}: keyType is not USER_MANAGED or SYSTEM_MANAGED")
            keys.append(ParsedKey(
                id=name.rsplit("/", 1)[-1],
                user_managed=key_type == "USER_MANAGED",
                valid_after=_time(key.get("validAfterTime"), k_where),
                valid_before=_time(key.get("validBeforeTime"), k_where),
                disabled=bool(key.get("disabled", False)),
            ))
        parsed.service_accounts.append(ParsedServiceAccount(
            email=email, unique_id=unique_id,
            display_name=_text(account.get("displayName"), where, email),
            disabled=bool(account.get("disabled", False)),
            keys=keys,
            last_authenticated=_time(activity.get(email), f"activity[{index}]"),
        ))

    for index, raw in enumerate(_list(document.get("role_definitions"), "role_definitions")):
        where = f"role_definitions[{index}]"
        definition = _record(raw, where)
        name = _text(definition.get("name"), where)
        if not _ROLE.match(name):
            raise ParseError(f"{where}: name is not a role name")
        permissions = _list(definition.get("includedPermissions"), f"{where}.includedPermissions")
        if not all(isinstance(p, str) and "." in p for p in permissions):
            raise ParseError(f"{where}: a permission is not written as service.resource.verb")
        parsed.role_definitions.append(ParsedRoleDefinition(
            name=name, title=_text(definition.get("title"), where, name),
            permissions=[str(p) for p in permissions],
        ))

    _verify(parsed)
    return parsed


def _verify(parsed: ParsedProject) -> None:
    emails = [a.email for a in parsed.service_accounts]
    if len(set(emails)) < len(emails):
        raise ParseError("a service account appears twice")
    ids = [a.unique_id for a in parsed.service_accounts]
    if len(set(ids)) < len(ids):
        raise ParseError("a service account identifier appears twice")
    names = [d.name for d in parsed.role_definitions]
    if len(set(names)) < len(names):
        raise ParseError("a role definition appears twice")
