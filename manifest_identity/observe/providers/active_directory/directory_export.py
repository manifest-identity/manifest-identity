"""The Active Directory domain export parser.

The directory ships no export of who holds what, so the file is one
document assembled from the ActiveDirectory module's own cmdlets, each
list under a key naming the read it came from (property names as the
module writes them, read from the Get-ADUser reference on September
29, 2026; the default set is DistinguishedName, Enabled, GivenName,
Name, ObjectClass, ObjectGUID, SamAccountName, SID, Surname, and
UserPrincipalName, and every other property is asked for by name):

    domain     Get-ADDomain: DNSRoot, NetBIOSName, DomainSID
    users      Get-ADUser -Filter * -Properties Enabled,PasswordLastSet,
               LastLogonDate,whenCreated,adminCount,ServicePrincipalNames,
               PasswordNeverExpires,Description
    groups     Get-ADGroup -Filter *, each with Members as the SIDs of
               Get-ADGroupMember (not recursive, so a nested group is a
               member and the hop is kept)
    computers  Get-ADComputer -Filter * -Properties Enabled,
               PasswordLastSet,LastLogonDate,whenCreated,OperatingSystem
    trusts     optional, Get-ADTrust -Filter *: Name, Direction,
               TrustType, ForestTransitive

The assembling script is in the parser's documentation. Two forms of
the same value are accepted because the two PowerShell generations
serialize them differently: a security identifier is the string or the
object whose Value is the string, and a date is ISO 8601 or the older
"/Date(milliseconds)/" form. The vocabulary ends here.

Held to the contract the other parsers set: bounded, in memory,
verified against its own claims, and no error ever repeats file
content.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime

from manifest_identity.observe.providers import parsing
from manifest_identity.observe.providers.parsing import ParseError, read_document, read_time

MAX_FILE_BYTES = 50 * 1024 * 1024
MAX_ENTITIES = 100_000
MAX_TEXT_CHARS = 1024

GROUP_SCOPES = frozenset({"DomainLocal", "Global", "Universal"})
GROUP_CATEGORIES = frozenset({"Security", "Distribution"})
TRUST_DIRECTIONS = frozenset({"Inbound", "Outbound", "BiDirectional", "Disabled"})

# A security identifier as the directory writes one: the revision, the
# authority, and the sub-authorities. The domain part is what a domain
# never reuses and what every member reference names.
_SID = re.compile(r"^S-1-\d+(?:-\d+){1,15}$")
_DOMAIN_SID = re.compile(r"^S-1-5-21(?:-\d+){3}$")
_OLD_DATE = re.compile(r"^/Date\((-?\d+)\)/$")
_DNS_NAME = re.compile(r"^[a-z0-9][a-z0-9.-]*$")


_LIMITS = parsing.Limits(max_entries=MAX_ENTITIES, max_text=MAX_TEXT_CHARS)
_list = _LIMITS.read_list
_text = _LIMITS.read_text
_strings = _LIMITS.read_strings
_choice = parsing.read_choice
_record = parsing.read_record


@dataclass
class ParsedAccount:
    """A user or a computer: the fields a review reads."""

    sid: str
    sam_account_name: str
    distinguished_name: str
    enabled: bool
    password_last_set: datetime | None
    last_logon: datetime | None
    created: datetime | None
    admin_count: bool
    service_principal_names: list[str]
    password_never_expires: bool
    description: str | None
    operating_system: str | None = None  # computers only


@dataclass
class ParsedGroup:
    sid: str
    sam_account_name: str
    distinguished_name: str
    scope: str
    category: str
    member_sids: list[str]
    admin_count: bool = False


@dataclass
class ParsedTrust:
    name: str
    direction: str
    trust_type: str
    forest_transitive: bool


@dataclass
class ParsedAce:
    """One control right a principal holds over an object, as the
    SharpHound collector writes it; the cmdlet document carries none."""

    target_sid: str
    principal_sid: str
    principal_type: str
    right: str
    inherited: bool


@dataclass
class ParsedDomain:
    sid: str
    dns_root: str
    netbios_name: str
    users: list[ParsedAccount] = field(default_factory=list)
    groups: list[ParsedGroup] = field(default_factory=list)
    computers: list[ParsedAccount] = field(default_factory=list)
    trusts: list[ParsedTrust] = field(default_factory=list)
    aces: list[ParsedAce] = field(default_factory=list)
    skipped: int = 0


def _time(raw: object, where: str) -> datetime | None:
    if isinstance(raw, dict):
        # Windows PowerShell 5.1 writes a DateTime as an object with a
        # value under DateTime or value; the string inside is what counts.
        raw = raw.get("DateTime", raw.get("value"))
    if isinstance(raw, str):
        old = _OLD_DATE.match(raw)
        if old:
            return datetime.fromtimestamp(int(old.group(1)) / 1000, tz=UTC)
    return read_time(raw, where)


def _sid(raw: object, where: str) -> str:
    if isinstance(raw, dict):
        raw = raw.get("Value")
    if not isinstance(raw, str) or not _SID.match(raw):
        raise ParseError(f"{where}: identifier is not a security identifier")
    return raw


def _optional_text(raw: object, where: str) -> str | None:
    if raw is None or raw == "":
        return None
    return _text(raw, where)


def _flag(raw: object, where: str, default: bool) -> bool:
    if raw is None:
        return default
    if isinstance(raw, bool):
        return raw
    # adminCount arrives as the integer the attribute holds.
    if isinstance(raw, int):
        return raw != 0
    raise ParseError(f"{where}: a flag must be true or false")


def _account(row: dict[str, object], where: str, computer: bool) -> ParsedAccount:
    spns = _strings(row.get("ServicePrincipalNames"), f"{where}.ServicePrincipalNames")
    return ParsedAccount(
        sid=_sid(row.get("SID"), where),
        sam_account_name=_text(row.get("SamAccountName"), where),
        distinguished_name=_text(row.get("DistinguishedName"), where),
        enabled=_flag(row.get("Enabled"), f"{where}.Enabled", True),
        password_last_set=_time(row.get("PasswordLastSet"), where),
        last_logon=_time(row.get("LastLogonDate"), where),
        created=_time(row.get("whenCreated"), where),
        admin_count=_flag(row.get("adminCount"), f"{where}.adminCount", False),
        service_principal_names=spns,
        password_never_expires=_flag(
            row.get("PasswordNeverExpires"), f"{where}.PasswordNeverExpires", False,
        ),
        description=_optional_text(row.get("Description"), where),
        operating_system=(
            _optional_text(row.get("OperatingSystem"), where) if computer else None
        ),
    )


def parse_domain_export(data: bytes) -> ParsedDomain:
    document = read_document(data, MAX_FILE_BYTES)

    domain = _record(document.get("domain"), "domain")
    dns_root = _text(domain.get("DNSRoot"), "domain").lower()
    if not _DNS_NAME.match(dns_root):
        raise ParseError("domain: DNSRoot is not a domain name")
    sid = _sid(domain.get("DomainSID"), "domain")
    if not _DOMAIN_SID.match(sid):
        raise ParseError("domain: DomainSID is not a domain's identifier")
    parsed = ParsedDomain(
        sid=sid, dns_root=dns_root,
        netbios_name=_text(domain.get("NetBIOSName"), "domain", dns_root.split(".")[0]),
    )

    for index, raw in enumerate(_list(document.get("users"), "users")):
        where = f"users[{index}]"
        parsed.users.append(_account(_record(raw, where), where, computer=False))

    for index, raw in enumerate(_list(document.get("groups"), "groups")):
        where = f"groups[{index}]"
        row = _record(raw, where)
        members = [
            _sid(m, f"{where}.Members[{m_index}]")
            for m_index, m in enumerate(_list(row.get("Members"), f"{where}.Members"))
        ]
        parsed.groups.append(ParsedGroup(
            sid=_sid(row.get("SID"), where),
            sam_account_name=_text(row.get("SamAccountName"), where),
            distinguished_name=_text(row.get("DistinguishedName"), where),
            scope=_choice(row.get("GroupScope", "Global"), GROUP_SCOPES, where, "GroupScope"),
            category=_choice(
                row.get("GroupCategory", "Security"), GROUP_CATEGORIES, where, "GroupCategory",
            ),
            member_sids=members,
            admin_count=_flag(row.get("adminCount"), f"{where}.adminCount", False),
        ))

    for index, raw in enumerate(_list(document.get("computers"), "computers")):
        where = f"computers[{index}]"
        parsed.computers.append(_account(_record(raw, where), where, computer=True))

    for index, raw in enumerate(_list(document.get("trusts"), "trusts")):
        where = f"trusts[{index}]"
        row = _record(raw, where)
        name = _text(row.get("Name"), where).lower()
        if not _DNS_NAME.match(name):
            raise ParseError(f"{where}: Name is not a domain name")
        parsed.trusts.append(ParsedTrust(
            name=name,
            direction=_choice(row.get("Direction"), TRUST_DIRECTIONS, where, "Direction"),
            trust_type=_text(row.get("TrustType"), where, "Uplevel"),
            forest_transitive=_flag(
                row.get("ForestTransitive"), f"{where}.ForestTransitive", False,
            ),
        ))

    verify(parsed)
    return parsed


def verify(parsed: ParsedDomain) -> None:
    """The claims a document makes about itself, checked: one entry per
    identifier, every identifier from the domain it says it is or from
    a well-known authority, and every account and group name unique,
    because a name is what a person reads and two of them is a trap."""
    sids = [a.sid for a in parsed.users] + [g.sid for g in parsed.groups] + [
        c.sid for c in parsed.computers
    ]
    if len(set(sids)) < len(sids):
        raise ParseError("an identifier appears twice")
    for value in sids:
        if not (value.startswith(parsed.sid + "-") or value.startswith("S-1-5-32-")):
            raise ParseError("an object's identifier is from a domain the file does not describe")
    names = [a.sam_account_name.lower() for a in parsed.users] + [
        g.sam_account_name.lower() for g in parsed.groups
    ] + [c.sam_account_name.lower() for c in parsed.computers]
    if len(set(names)) < len(names):
        raise ParseError("an account name appears twice")
    for computer in parsed.computers:
        if not computer.sam_account_name.endswith("$"):
            raise ParseError(
                "a computer's account name does not end the way the directory writes one"
            )
    for ace in parsed.aces:
        if ace.target_sid not in set(sids) and ace.target_sid != parsed.sid:
            raise ParseError("a control right names an object the file does not list")
