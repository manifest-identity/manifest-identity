"""The account authorization details parser.

The second untrusted surface, held to the same contract as the first:
bounded, in memory, verified against its own claims, and no error ever
repeats file content. Field semantics verified against the provider's
documentation at build time, August 18, 2026: policy documents arrive
URL-encoded and are decoded before parsing; a user's GroupList holds
group names resolved against GroupDetailList in the same file;
AWS-managed policy ARNs carry the literal account "aws" and are exempt
from the one-account check; and a true IsTruncated flag means the
export is an incomplete snapshot and is rejected whole (D-030).
"""

import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from urllib.parse import unquote

MAX_FILE_BYTES = 25 * 1024 * 1024
MAX_ENTITIES = 50_000
MAX_DOCUMENT_BYTES = 200 * 1024
MAX_NAME_CHARS = 255

_ARN_ACCOUNT = re.compile(r"^arn:[^:]*:iam::(\d{12}|aws):")


class ParseError(ValueError):
    """File-level rejection; messages carry rules and names of our own
    contract, never values from the file."""


@dataclass
class ParsedUser:
    name: str
    arn: str
    user_id: str
    created: datetime | None
    group_names: list[str]
    attached_policies: list[dict[str, str]]
    inline_policy_names: list[str]
    tags: dict[str, str]
    inline_documents: list[dict[str, object]]


@dataclass
class ParsedRole:
    name: str
    arn: str
    role_id: str
    created: datetime | None
    trust_policy: dict[str, object] | None
    last_used: datetime | None
    last_used_region: str | None
    attached_policies: list[dict[str, str]]
    inline_policy_names: list[str]
    tags: dict[str, str]
    inline_documents: list[dict[str, object]]


@dataclass
class ParsedGroup:
    name: str
    arn: str
    group_id: str
    attached_policies: list[dict[str, str]]
    inline_policy_names: list[str]
    inline_documents: list[dict[str, object]]


@dataclass
class ParsedPolicy:
    name: str
    arn: str
    aws_managed: bool
    document: dict[str, object] | None


@dataclass
class ParsedDetails:
    account_id: str
    users: list[ParsedUser] = field(default_factory=list)
    roles: list[ParsedRole] = field(default_factory=list)
    groups: list[ParsedGroup] = field(default_factory=list)
    policies: list[ParsedPolicy] = field(default_factory=list)
    skipped: int = 0


def _time(raw: object) -> datetime | None:
    if not isinstance(raw, str) or not raw:
        return None
    parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp lacks a timezone")
    return parsed.astimezone(UTC)


def _document(raw: object) -> dict[str, object] | None:
    """Policy documents arrive URL-encoded; decode bounded, parse, and
    require an object at the top."""
    if raw is None:
        return None
    if isinstance(raw, dict):
        return raw  # some exporters pre-decode; accept the honest form
    if not isinstance(raw, str):
        raise ValueError("document is neither text nor object")
    if len(raw) > MAX_DOCUMENT_BYTES:
        raise ValueError("document exceeds the size bound")
    decoded = unquote(raw)
    parsed = json.loads(decoded)
    if not isinstance(parsed, dict):
        raise ValueError("document is not an object")
    return parsed


def _attached(raw: object) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    if isinstance(raw, list):
        for item in raw:
            if isinstance(item, dict):
                name = item.get("PolicyName")
                arn = item.get("PolicyArn")
                if isinstance(name, str) and isinstance(arn, str):
                    out.append(
                        {"name": name[:MAX_NAME_CHARS], "arn": arn[:2048]}
                    )
    return out


def _inline_names(raw: object) -> list[str]:
    out: list[str] = []
    if isinstance(raw, list):
        for item in raw:
            if isinstance(item, dict) and isinstance(item.get("PolicyName"), str):
                out.append(item["PolicyName"][:MAX_NAME_CHARS])
    return out


def _inline_documents(raw: object) -> list[dict[str, object]]:
    """Inline policies with their documents: the classic place privilege
    hides, so names alone were never going to be enough (D-033)."""
    out: list[dict[str, object]] = []
    if isinstance(raw, list):
        for item in raw:
            if isinstance(item, dict) and isinstance(item.get("PolicyName"), str):
                try:
                    document = _document(item.get("PolicyDocument"))
                except ValueError:
                    document = None
                out.append({
                    "name": item["PolicyName"][:MAX_NAME_CHARS],
                    "document": document,
                })
    return out


def _tags(raw: object) -> dict[str, str]:
    out: dict[str, str] = {}
    if isinstance(raw, list):
        for item in raw:
            if isinstance(item, dict):
                key, value = item.get("Key"), item.get("Value")
                if isinstance(key, str) and isinstance(value, str):
                    out[key[:128]] = value[:256]
    return out


def _account_of(arn: object, report: ParsedDetails) -> str | None:
    """Returns the account, enforcing the one-account claim; the
    literal account "aws" (provider-managed policies) is exempt."""
    if not isinstance(arn, str):
        return None
    match = _ARN_ACCOUNT.match(arn)
    if match is None:
        return None
    account = match.group(1)
    if account == "aws":
        return account
    if report.account_id == "":
        report.account_id = account
    elif account != report.account_id:
        raise ParseError("file mixes accounts")
    return account


def parse_authorization_details(data: bytes) -> ParsedDetails:
    if len(data) > MAX_FILE_BYTES:
        raise ParseError("file exceeds the size bound")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ParseError("file is not valid UTF-8") from exc
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ParseError("file is not parseable as JSON") from exc
    if not isinstance(payload, dict):
        raise ParseError("top level is not an object")
    if payload.get("IsTruncated") is True:
        raise ParseError(
            "export is truncated and therefore an incomplete snapshot; "
            "re-export with pagination completed"
        )
    def detail_list(key: str) -> list[object]:
        value = payload.get(key)
        if value is None:
            return []
        if not isinstance(value, list):
            # A malformed claim, found by the fuzz suite on its first
            # run: a truthy non-list here crashed iteration.
            raise ParseError(f"{key} is not a list")
        return value

    users_raw = detail_list("UserDetailList")
    roles_raw = detail_list("RoleDetailList")
    groups_raw = detail_list("GroupDetailList")
    policies_raw = detail_list("Policies")
    if not any([users_raw, roles_raw, groups_raw, policies_raw]):
        raise ParseError("file contains none of the expected detail lists")
    total = len(users_raw) + len(roles_raw) + len(groups_raw) + len(policies_raw)
    if total > MAX_ENTITIES:
        raise ParseError("file exceeds the entity bound")

    report = ParsedDetails(account_id="")

    for raw in users_raw:
        if not isinstance(raw, dict):
            report.skipped += 1
            continue
        try:
            name, arn, user_id = raw.get("UserName"), raw.get("Arn"), raw.get("UserId")
            if not (
                isinstance(name, str) and name
                and isinstance(user_id, str) and user_id
                and _account_of(arn, report)
            ):
                report.skipped += 1
                continue
            report.users.append(
                ParsedUser(
                    name=name[:MAX_NAME_CHARS],
                    arn=str(arn)[:2048],
                    user_id=user_id[:128],
                    created=_time(raw.get("CreateDate")),
                    group_names=[
                        g[:MAX_NAME_CHARS]
                        for g in raw.get("GroupList") or []
                        if isinstance(g, str)
                    ],
                    attached_policies=_attached(raw.get("AttachedManagedPolicies")),
                    inline_policy_names=_inline_names(raw.get("UserPolicyList")),
                    tags=_tags(raw.get("Tags")),
                    inline_documents=_inline_documents(raw.get("UserPolicyList")),
                )
            )
        except ParseError:
            raise
        except ValueError:
            report.skipped += 1

    for raw in roles_raw:
        if not isinstance(raw, dict):
            report.skipped += 1
            continue
        try:
            name, arn, role_id = raw.get("RoleName"), raw.get("Arn"), raw.get("RoleId")
            if not (
                isinstance(name, str) and name
                and isinstance(role_id, str) and role_id
                and _account_of(arn, report)
            ):
                report.skipped += 1
                continue
            last_used_raw = raw.get("RoleLastUsed") or {}
            region = last_used_raw.get("Region") if isinstance(last_used_raw, dict) else None
            report.roles.append(
                ParsedRole(
                    name=name[:MAX_NAME_CHARS],
                    arn=str(arn)[:2048],
                    role_id=role_id[:128],
                    created=_time(raw.get("CreateDate")),
                    trust_policy=_document(raw.get("AssumeRolePolicyDocument")),
                    last_used=_time(
                        last_used_raw.get("LastUsedDate")
                        if isinstance(last_used_raw, dict)
                        else None
                    ),
                    last_used_region=(
                        region[:64] if isinstance(region, str) else None
                    ),
                    attached_policies=_attached(raw.get("AttachedManagedPolicies")),
                    inline_policy_names=_inline_names(raw.get("RolePolicyList")),
                    tags=_tags(raw.get("Tags")),
                    inline_documents=_inline_documents(raw.get("RolePolicyList")),
                )
            )
        except ParseError:
            raise
        except ValueError:
            report.skipped += 1

    for raw in groups_raw:
        if not isinstance(raw, dict):
            report.skipped += 1
            continue
        try:
            name, arn, group_id = raw.get("GroupName"), raw.get("Arn"), raw.get("GroupId")
            if not (
                isinstance(name, str) and name
                and isinstance(group_id, str) and group_id
                and _account_of(arn, report)
            ):
                report.skipped += 1
                continue
            report.groups.append(
                ParsedGroup(
                    name=name[:MAX_NAME_CHARS],
                    arn=str(arn)[:2048],
                    group_id=group_id[:128],
                    attached_policies=_attached(raw.get("AttachedManagedPolicies")),
                    inline_policy_names=_inline_names(raw.get("GroupPolicyList")),
                    inline_documents=_inline_documents(raw.get("GroupPolicyList")),
                )
            )
        except ParseError:
            raise
        except ValueError:
            report.skipped += 1

    for raw in policies_raw:
        if not isinstance(raw, dict):
            report.skipped += 1
            continue
        try:
            name, arn = raw.get("PolicyName"), raw.get("Arn")
            if not (isinstance(name, str) and name and isinstance(arn, str)):
                report.skipped += 1
                continue
            account = _account_of(arn, report)
            if account is None:
                report.skipped += 1
                continue
            document = None
            for version in raw.get("PolicyVersionList") or []:
                if isinstance(version, dict) and version.get("IsDefaultVersion"):
                    document = _document(version.get("Document"))
                    break
            report.policies.append(
                ParsedPolicy(
                    name=name[:MAX_NAME_CHARS],
                    arn=arn[:2048],
                    aws_managed=account == "aws",
                    document=document,
                )
            )
        except ParseError:
            raise
        except ValueError:
            report.skipped += 1

    if report.account_id == "":
        raise ParseError("file contains no usable rows")
    return report
