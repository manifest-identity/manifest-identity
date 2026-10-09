"""The SharpHound collection parser: the second door into a domain.

SharpHound, the BloodHound collector, writes one JSON file per object
type and zips them together. Each file is an object with two keys:
`data`, the objects, and `meta`, which names the `type` (users,
groups, computers, domains, and others this parser ignores), the
collection `methods`, a `count`, and the format `version`. Every
object carries `ObjectIdentifier` (the security identifier, which the
collector prefixes with the domain's name for the well-known
identifiers under S-1-5-32), `Properties` (name as NAME@DOMAIN, domain,
domainsid, distinguishedname, enabled, whencreated, pwdlastset,
lastlogontimestamp as seconds since the epoch with -1 or 0 for never,
admincount, serviceprincipalnames, pwdneverexpires, description,
operatingsystem), and `Aces`, one control right each: PrincipalSID,
PrincipalType, RightName, IsInherited. A group carries `Members`
(ObjectIdentifier, ObjectType) and a domain carries `Trusts`
(TargetDomainName, TargetDomainSid, TrustDirection, TrustType,
IsTransitive). Shape read from the collector's own fixtures in the
BloodHound repository (version 6) on September 29, 2026; versions 5
and 6 are accepted. The `count` is not enforced, because the
collector's own fixtures carry a count of zero over a full list.

What this door adds over the cmdlet document is the control rights,
which are the can-obtain mode for a directory: a principal that owns
a privileged group, or can write its membership, can obtain what the
group holds without being a member, and a review that reads only the
membership never sees it.

Two forms are read: the zip the collector writes, and one JSON object
whose keys users, groups, computers, and domains each hold that file's
object, for anyone who unpacked the zip first. A loose single file is
refused by name, because one file is one object type and an import of
users alone would make every group vanish from the next view.

Held to the contract the other parsers set: bounded, in memory,
verified against its own claims, and no error ever repeats file
content.
"""

from __future__ import annotations

import io
import json
import re
import zipfile
from datetime import UTC, datetime

from manifest_identity.observe.providers.active_directory.directory_export import (
    MAX_ENTITIES,
    MAX_FILE_BYTES,
    ParsedAccount,
    ParsedAce,
    ParsedDomain,
    ParsedGroup,
    ParsedTrust,
    _list,
    _optional_text,
    _strings,
    _text,
    verify,
)
from manifest_identity.observe.providers.parsing import (
    ParseError,
)
from manifest_identity.observe.providers.parsing import (
    read_choice as _choice,
)
from manifest_identity.observe.providers.parsing import (
    read_record as _record,
)

MAX_MEMBER_BYTES = 200 * 1024 * 1024
MAX_UNPACKED_BYTES = 400 * 1024 * 1024
VERSIONS = frozenset({5, 6})
TYPES = ("domains", "users", "groups", "computers")
MEMBER_TYPES = frozenset({"User", "Group", "Computer", "Base"})
TRUST_DIRECTIONS = frozenset({"Inbound", "Outbound", "Bidirectional", "Disabled"})

_SID = re.compile(r"^S-1-\d+(?:-\d+){1,15}$")
_PREFIXED = re.compile(r"^[A-Za-z0-9.-]+-(S-1-5-32-\d+)$")


def _sid(raw: object, where: str) -> str:
    """A SharpHound identifier: the SID, or the domain name prefixed
    to a well-known SID, which is stripped so the two doors name the
    same object the same way."""
    if isinstance(raw, str):
        prefixed = _PREFIXED.match(raw)
        if prefixed:
            return prefixed.group(1)
        if _SID.match(raw):
            return raw
    raise ParseError(f"{where}: identifier is not a security identifier")


def _epoch(raw: object, where: str) -> datetime | None:
    if raw is None:
        return None
    if isinstance(raw, bool) or not isinstance(raw, int | float):
        raise ParseError(f"{where}: a timestamp must be seconds since the epoch")
    if raw <= 0:
        return None
    try:
        return datetime.fromtimestamp(raw, tz=UTC)
    except (OverflowError, OSError, ValueError) as exc:
        raise ParseError(f"{where}: a timestamp is out of range") from exc


def _flag(raw: object, where: str) -> bool:
    if raw is None:
        return False
    if isinstance(raw, bool):
        return raw
    raise ParseError(f"{where}: a flag must be true or false")


def _name_parts(raw: object, where: str) -> tuple[str, str]:
    """NAME@DOMAIN as the collector writes it, split once."""
    name = _text(raw, where)
    account, sep, domain = name.rpartition("@")
    if not sep or not account or not domain:
        raise ParseError(f"{where}: name is not written as NAME@DOMAIN")
    return account, domain.lower()


def _file(raw: object, kind: str) -> list[dict[str, object]]:
    document = _record(raw, kind)
    meta = _record(document.get("meta"), f"{kind}.meta")
    if meta.get("type") != kind:
        raise ParseError(f"{kind}: the file's meta names another object type")
    if meta.get("version") not in VERSIONS:
        raise ParseError(f"{kind}: the format version is not one this parser reads")
    return [_record(o, f"{kind}[{i}]") for i, o in enumerate(_list(document.get("data"), kind))]


def _aces(raw: object, where: str, target: str) -> list[ParsedAce]:
    out = []
    for index, entry in enumerate(_list(raw, where)):
        ace = _record(entry, f"{where}[{index}]")
        out.append(ParsedAce(
            target_sid=target,
            principal_sid=_sid(ace.get("PrincipalSID"), f"{where}[{index}]"),
            principal_type=_text(ace.get("PrincipalType"), f"{where}[{index}]", "Base"),
            right=_text(ace.get("RightName"), f"{where}[{index}]"),
            inherited=_flag(ace.get("IsInherited"), f"{where}[{index}].IsInherited"),
        ))
    return out


def _account(obj: dict[str, object], where: str, computer: bool) -> ParsedAccount:
    props = _record(obj.get("Properties"), f"{where}.Properties")
    if computer:
        # A computer is named HOST.DOMAIN; its account name is the host
        # with the dollar sign the directory appends.
        host = _text(props.get("name"), where)
        sam = _text(props.get("samaccountname"), where, host.split(".")[0] + "$")
    else:
        account, _domain = _name_parts(props.get("name"), where)
        sam = _text(props.get("samaccountname"), where, account)
    return ParsedAccount(
        sid=_sid(obj.get("ObjectIdentifier"), where),
        sam_account_name=sam,
        distinguished_name=_text(props.get("distinguishedname"), where),
        enabled=_flag(props.get("enabled"), f"{where}.enabled") if "enabled" in props else True,
        password_last_set=_epoch(props.get("pwdlastset"), where),
        last_logon=_epoch(props.get("lastlogontimestamp"), where),
        created=_epoch(props.get("whencreated"), where),
        admin_count=_flag(props.get("admincount"), f"{where}.admincount"),
        service_principal_names=_strings(
            props.get("serviceprincipalnames"), f"{where}.serviceprincipalnames",
        ),
        password_never_expires=_flag(props.get("pwdneverexpires"), f"{where}.pwdneverexpires"),
        description=_optional_text(props.get("description"), where),
        operating_system=(
            _optional_text(props.get("operatingsystem"), where) if computer else None
        ),
    )


def _read_zip(data: bytes) -> dict[str, object]:
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise ParseError("file is not a zip the collector wrote") from exc
    joined: dict[str, object] = {}
    unpacked = 0
    with archive:
        for info in archive.infolist():
            kind = next((k for k in TYPES if info.filename.lower().endswith(f"{k}.json")), None)
            if kind is None:
                continue
            if info.file_size > MAX_MEMBER_BYTES:
                raise ParseError(f"a member exceeds {MAX_MEMBER_BYTES} bytes unpacked")
            unpacked += info.file_size
            if unpacked > MAX_UNPACKED_BYTES:
                raise ParseError(f"the archive exceeds {MAX_UNPACKED_BYTES} bytes unpacked")
            raw = archive.read(info)
            if len(raw) > MAX_MEMBER_BYTES:
                raise ParseError(f"a member exceeds {MAX_MEMBER_BYTES} bytes unpacked")
            try:
                joined[kind] = json.loads(raw.decode("utf-8-sig"))
            except ValueError as exc:
                raise ParseError("a member is not valid JSON") from exc
    return joined


def parse_collection(data: bytes) -> ParsedDomain:  # noqa: C901
    if len(data) > MAX_FILE_BYTES:
        raise ParseError(f"file exceeds {MAX_FILE_BYTES} bytes")
    if data[:2] == b"PK":
        joined = _read_zip(data)
    else:
        try:
            loaded = json.loads(data.decode("utf-8-sig"))
        except ValueError as exc:
            raise ParseError("file is not valid JSON") from exc
        if not isinstance(loaded, dict):
            raise ParseError("file must be a JSON object")
        if "meta" in loaded and "data" in loaded:
            raise ParseError(
                "one collector file is one object type; import the zip the collector "
                "wrote, or the files joined under one object"
            )
        joined = loaded
    if "users" not in joined or "groups" not in joined:
        raise ParseError("the collection must carry users and groups")

    domains = _file(joined.get("domains"), "domains") if "domains" in joined else []
    users = _file(joined["users"], "users")
    groups = _file(joined["groups"], "groups")
    computers = _file(joined["computers"], "computers") if "computers" in joined else []

    # The domain: from domains.json when present, else from the first
    # user's own domainsid and domain, which every object carries.
    if domains:
        head = domains[0]
        props = _record(head.get("Properties"), "domains[0].Properties")
        sid = _sid(head.get("ObjectIdentifier"), "domains[0]")
        dns_root = _text(props.get("name"), "domains[0]").lower()
    elif users:
        props = _record(users[0].get("Properties"), "users[0].Properties")
        sid = _sid(props.get("domainsid"), "users[0]")
        dns_root = _text(props.get("domain"), "users[0]").lower()
    else:
        raise ParseError("the collection names no domain and lists no user")
    parsed = ParsedDomain(sid=sid, dns_root=dns_root, netbios_name=dns_root.split(".")[0])

    for index, obj in enumerate(users):
        where = f"users[{index}]"
        account = _account(obj, where, computer=False)
        parsed.users.append(account)
        parsed.aces += _aces(obj.get("Aces"), f"{where}.Aces", account.sid)

    for index, obj in enumerate(groups):
        where = f"groups[{index}]"
        props = _record(obj.get("Properties"), f"{where}.Properties")
        group_name, _domain = _name_parts(props.get("name"), where)
        members = []
        for m_index, raw in enumerate(_list(obj.get("Members"), f"{where}.Members")):
            member = _record(raw, f"{where}.Members[{m_index}]")
            _choice(member.get("ObjectType", "Base"), MEMBER_TYPES,
                    f"{where}.Members[{m_index}]", "ObjectType")
            members.append(_sid(member.get("ObjectIdentifier"), f"{where}.Members[{m_index}]"))
        group_sid = _sid(obj.get("ObjectIdentifier"), where)
        parsed.groups.append(ParsedGroup(
            sid=group_sid,
            sam_account_name=_text(props.get("samaccountname"), where, group_name),
            distinguished_name=_text(props.get("distinguishedname"), where),
            scope="Global", category="Security", member_sids=members,
            admin_count=_flag(props.get("admincount"), f"{where}.admincount"),
        ))
        parsed.aces += _aces(obj.get("Aces"), f"{where}.Aces", group_sid)

    for index, obj in enumerate(computers):
        where = f"computers[{index}]"
        parsed.computers.append(_account(obj, where, computer=True))

    for index, obj in enumerate(domains):
        where = f"domains[{index}]"
        parsed.aces += _aces(obj.get("Aces"), f"{where}.Aces", parsed.sid)
        for t_index, raw in enumerate(_list(obj.get("Trusts"), f"{where}.Trusts")):
            trust = _record(raw, f"{where}.Trusts[{t_index}]")
            parsed.trusts.append(ParsedTrust(
                name=_text(trust.get("TargetDomainName"), f"{where}.Trusts[{t_index}]").lower(),
                direction=_choice(trust.get("TrustDirection"), TRUST_DIRECTIONS,
                                  f"{where}.Trusts[{t_index}]", "TrustDirection"),
                trust_type=_text(trust.get("TrustType"), f"{where}.Trusts[{t_index}]", "Forest"),
                forest_transitive=_flag(trust.get("IsTransitive"),
                                        f"{where}.Trusts[{t_index}].IsTransitive"),
            ))

    if len(parsed.aces) > MAX_ENTITIES:
        raise ParseError(f"more than {MAX_ENTITIES} control rights")
    verify(parsed)
    return parsed
