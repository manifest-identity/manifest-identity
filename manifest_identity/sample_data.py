"""The synthetic account: every archetype the rules can find.

Deterministic by construction. There is no randomness and no reference
to the current time: three fixed snapshot generations a month apart,
and every date literal. That matters twice over. The derivation engine
measures staleness against the snapshot's capture time rather than the
wall clock (D-006), so fixed dates stay meaningful forever, and a
deterministic generator can be checked against its committed output,
which is what keeps the shipped files from drifting away from the code
that makes them.

Credential-shaped strings are impossible here by construction rather
than by review: the file formats carry no key material, and every
identifier is a provider-shaped identifier, never a secret. The secret
scanner runs over the committed output at commit time and in the
pipeline, which is the mechanism; the invariant test is the belt.

Run it: python -m manifest_identity.sample_data [directory] [--scale N]

The scale mode adds N synthetic identities to the same three
generations, two thirds services and one third people, with archetypal
variation derived from each identity's index, so a thousand-identity
account is as deterministic as the nineteen-identity one. The
committed sample stays the curated small set; scaled sets are for
load work and ship as release artifacts, never commits.
"""

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import quote

ACCOUNT = "555555555555"

# Three generations, a month apart. Far enough that the minimum
# observation age releases and staleness is measurable.
GENERATIONS = (
    datetime(2026, 6, 1, tzinfo=UTC),
    datetime(2026, 7, 1, tzinfo=UTC),
    datetime(2026, 8, 1, tzinfo=UTC),
)

CREDENTIAL_HEADER = (
    "user,arn,user_creation_time,password_enabled,password_last_used,"
    "password_last_changed,password_next_rotation,mfa_active,"
    "access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date,"
    "access_key_1_last_used_region,access_key_1_last_used_service,"
    "access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date,"
    "access_key_2_last_used_region,access_key_2_last_used_service,"
    "cert_1_active,cert_1_last_rotated,cert_2_active,cert_2_last_rotated"
)


def _stamp(when: datetime | None) -> str:
    return when.strftime("%Y-%m-%dT%H:%M:%S+00:00") if when else "N/A"


def _document(*statements: dict[str, object]) -> str:
    """Policy documents arrive URL-encoded from the provider, so the
    sample carries them that way too: a fixture that is easier to parse
    than the real thing tests a parser nobody has."""
    return quote(json.dumps({"Version": "2012-10-17", "Statement": list(statements)}))


def _allow(action: object, resource: object = "*", **extra: object) -> dict[str, object]:
    return {"Effect": "Allow", "Action": action, "Resource": resource, **extra}


@dataclass
class Person:
    """One principal, with everything both file formats need."""

    name: str
    uid: str
    created: datetime
    why: str  # the archetype this exists to produce
    password: bool = False
    mfa: bool = False
    password_used: datetime | None = None
    key1: bool = False
    key1_rotated: datetime | None = None
    key1_used: datetime | None = None
    key2: bool = False
    key2_rotated: datetime | None = None
    cert1: bool = False
    groups: list[str] = field(default_factory=list)
    inline: list[tuple[str, str]] = field(default_factory=list)
    attached: list[tuple[str, str]] = field(default_factory=list)
    tags: dict[str, str] = field(default_factory=dict)
    root: bool = False


@dataclass
class Role:
    name: str
    uid: str
    created: datetime
    why: str
    trust: str
    attached: list[tuple[str, str]] = field(default_factory=list)
    inline: list[tuple[str, str]] = field(default_factory=list)
    last_used: datetime | None = None
    tags: dict[str, str] = field(default_factory=dict)


@dataclass
class Group:
    name: str
    uid: str
    why: str
    attached: list[tuple[str, str]] = field(default_factory=list)
    inline: list[tuple[str, str]] = field(default_factory=list)


ADMIN_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"
READONLY_ARN = "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"
MANAGED = {
    ADMIN_ARN: ("AdministratorAccess", _document(_allow("*"))),
    READONLY_ARN: (
        "AmazonS3ReadOnlyAccess",
        _document(_allow(["s3:Get*", "s3:List*"], "*")),
    ),
}


def people(generation: int) -> list[Person]:
    """The population at one generation. Differences between
    generations are the point: an identity that stops being used, a
    name that comes back under a new identifier, a group that gains a
    member."""
    d = datetime
    everyone = [
        Person(
            name="<root_account>", uid="555555555555", root=True,
            created=d(2019, 3, 11, tzinfo=UTC),
            why="root use is the finding that has no benign reading",
            password=True, mfa=True,
            # Used once, in the second generation, and never again.
            password_used=d(2026, 6, 14, tzinfo=UTC) if generation >= 1 else None,
        ),
        Person(
            name="ops-console", uid="AIDASAMPLEOPSCONSOLE",
            created=d(2024, 2, 1, tzinfo=UTC),
            why="a console password with no second factor",
            password=True, mfa=False,
            password_used=d(2026, 7, 20, tzinfo=UTC) if generation >= 2 else None,
            tags={"owner": "platform-team"},
        ),
        Person(
            name="dev-lisa", uid="AIDASAMPLEDEVLISA000",
            created=d(2023, 9, 12, tzinfo=UTC),
            why="a person holding access keys: human use of a non-human credential",
            password=True, mfa=True,
            password_used=d(2026, 7, 29, tzinfo=UTC),
            key1=True, key1_rotated=d(2026, 1, 10, tzinfo=UTC),
            key1_used=d(2026, 7, 30, tzinfo=UTC),
            tags={"owner": "app-team"},
        ),
        Person(
            name="legacy-backup", uid="AIDASAMPLELEGACYBACK",
            created=d(2021, 4, 5, tzinfo=UTC),
            why="an old key on an identity nobody has used",
            key1=True, key1_rotated=d(2021, 4, 5, tzinfo=UTC),
            tags={"owner": "storage-team"},
        ),
        Person(
            name="ci-deployer", uid="AIDASAMPLECIDEPLOYER",
            created=d(2023, 1, 15, tzinfo=UTC),
            why="administrator privilege inherited through a group",
            key1=True, key1_rotated=d(2026, 3, 1, tzinfo=UTC),
            key1_used=d(2026, 7, 28, tzinfo=UTC),
            groups=["automation"], tags={"owner": "platform-team"},
        ),
        Person(
            name="vendor-sync", uid="AIDASAMPLEVENDORSYNC",
            created=d(2022, 9, 9, tzinfo=UTC),
            why="two live keys, no owner, and admin through a group",
            key1=True, key1_rotated=d(2026, 5, 1, tzinfo=UTC),
            key1_used=d(2026, 7, 30, tzinfo=UTC),
            key2=True, key2_rotated=d(2024, 1, 1, tzinfo=UTC),
            groups=["automation"],
        ),
        Person(
            name="data-pipeline", uid="AIDASAMPLEDATAPIPELI",
            created=d(2023, 6, 1, tzinfo=UTC),
            why="a shadow admin: two ordinary permissions that combine",
            key1=True, key1_rotated=d(2026, 4, 1, tzinfo=UTC),
            key1_used=d(2026, 7, 25, tzinfo=UTC),
            inline=[("pipeline-runner", _document(
                _allow(["iam:PassRole", "ec2:RunInstances"])))],
            tags={"owner": "data-team"},
        ),
        Person(
            name="report-reader", uid="AIDASAMPLEREPORTREAD",
            created=d(2025, 2, 2, tzinfo=UTC),
            why="broad read access, which is a notice and not a warning",
            key1=True, key1_rotated=d(2026, 6, 15, tzinfo=UTC),
            key1_used=d(2026, 7, 29, tzinfo=UTC),
            attached=[("AmazonS3ReadOnlyAccess", READONLY_ARN)],
            tags={"owner": "finance"},
        ),
        Person(
            name="cert-holder", uid="AIDASAMPLECERTHOLDER",
            created=d(2020, 8, 8, tzinfo=UTC),
            why="a signing certificate most estates forgot they hold",
            cert1=True, key1=True,
            key1_rotated=d(2026, 2, 1, tzinfo=UTC),
            key1_used=d(2026, 7, 1, tzinfo=UTC),
            tags={"owner": "integrations"},
        ),
        Person(
            name="iam-helper", uid="AIDASAMPLEIAMHELPER0",
            created=d(2024, 11, 1, tzinfo=UTC),
            why="edits access controls without being an administrator",
            key1=True, key1_rotated=d(2026, 6, 1, tzinfo=UTC),
            key1_used=d(2026, 7, 27, tzinfo=UTC),
            inline=[("user-tidier", _document(
                _allow(["iam:UpdateUser", "iam:TagUser"],
                       f"arn:aws:iam::{ACCOUNT}:user/*")))],
            tags={"owner": "platform-team"},
        ),
        Person(
            name="wide-writer", uid="AIDASAMPLEWIDEWRITER",
            created=d(2024, 5, 5, tzinfo=UTC),
            why="a wildcard that can change things, on every resource",
            key1=True, key1_rotated=d(2026, 5, 20, tzinfo=UTC),
            key1_used=d(2026, 7, 26, tzinfo=UTC),
            inline=[("bucket-owner", _document(_allow("s3:*", "*")))],
            tags={"owner": "data-team"},
        ),
        Person(
            name="except-all", uid="AIDASAMPLEEXCEPTALL0",
            created=d(2025, 7, 7, tzinfo=UTC),
            why="an allow written as everything except a short list",
            key1=True, key1_rotated=d(2026, 6, 30, tzinfo=UTC),
            key1_used=d(2026, 7, 31, tzinfo=UTC),
            inline=[("almost-everything", _document(
                {"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"}))],
            tags={"owner": "platform-team"},
        ),
    ]

    if generation >= 2:
        everyone.append(Person(
            name="new-joiner", uid="AIDASAMPLENEWJOINER0",
            created=d(2026, 7, 10, tzinfo=UTC),
            why="joins the administrator group late, so membership "
                "drift has something to report",
            key1=True, key1_rotated=d(2026, 7, 10, tzinfo=UTC),
            key1_used=d(2026, 7, 29, tzinfo=UTC),
            groups=["automation"], tags={"owner": "platform-team"},
        ))

    # The resurrection: the same display name under a different
    # immutable identifier, appearing only in the last generation.
    if generation < 2:
        everyone.append(Person(
            name="phoenix", uid="AIDASAMPLEPHOENIXOLD",
            created=d(2022, 1, 1, tzinfo=UTC),
            why="deleted between generations, then recreated",
            key1=True, key1_rotated=d(2022, 1, 1, tzinfo=UTC),
            tags={"owner": "platform-team"},
        ))
    else:
        everyone.append(Person(
            name="phoenix", uid="AIDASAMPLEPHOENIXNEW",
            created=d(2026, 7, 20, tzinfo=UTC),
            why="the recreated principal, which inherits nothing",
            key1=True, key1_rotated=d(2026, 7, 20, tzinfo=UTC),
            tags={"owner": "platform-team"},
        ))
    return everyone


def roles() -> list[Role]:
    service = _document({
        "Effect": "Allow",
        "Principal": {"Service": "ec2.amazonaws.com"},
        "Action": "sts:AssumeRole",
    })
    public = _document({
        "Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole",
    })
    partner = _document({
        "Effect": "Allow",
        "Principal": {"AWS": "arn:aws:iam::999999999999:root"},
        "Action": "sts:AssumeRole",
    })
    vendor = _document({
        "Effect": "Allow",
        "Principal": {"AWS": "arn:aws:iam::999999999999:root"},
        "Action": "sts:AssumeRole",
        "Condition": {"StringEquals": {"sts:ExternalId": "a-shared-value"}},
    })
    return [
        Role(name="app-runtime", uid="AROASAMPLEAPPRUNTIME",
             created=datetime(2024, 1, 1, tzinfo=UTC),
             why="ordinary furniture, and it must stay quiet",
             trust=service, attached=[("AmazonS3ReadOnlyAccess", READONLY_ARN)],
             last_used=datetime(2026, 7, 30, tzinfo=UTC),
             tags={"owner": "platform-team"}),
        Role(name="partner-legacy", uid="AROASAMPLEPARTNERLEG",
             created=datetime(2019, 6, 1, tzinfo=UTC),
             why="assumable by anyone, with nothing narrowing it",
             trust=public),
        Role(name="partner-open", uid="AROASAMPLEPARTNEROPE",
             created=datetime(2023, 3, 1, tzinfo=UTC),
             why="another account, with no condition",
             trust=partner, tags={"owner": "partnerships"}),
        Role(name="vendor-audit", uid="AROASAMPLEVENDORAUDI",
             created=datetime(2024, 3, 1, tzinfo=UTC),
             why="another account with an external identifier: the "
                 "documented pattern, and only a notice",
             trust=vendor, tags={"owner": "security"},
             last_used=datetime(2026, 7, 15, tzinfo=UTC)),
    ]


def groups() -> list[Group]:
    return [
        Group(name="automation", uid="AGPASAMPLEAUTOMATION",
              why="a standing administrator grant with no owner",
              attached=[("AdministratorAccess", ADMIN_ARN)]),
        Group(name="break-glass", uid="AGPASAMPLEBREAKGLASS",
              why="privilege waiting for its first member",
              inline=[("emergency-access", _document(_allow("*")))]),
        Group(name="readers", uid="AGPASAMPLEREADERS000",
              why="an ordinary group, which must produce nothing",
              attached=[("AmazonS3ReadOnlyAccess", READONLY_ARN)]),
    ]


def membership(generation: int) -> dict[str, list[str]]:
    """Who is in which group, per generation; the third generation
    gains a member so the drift finding has something to see."""
    automation = ["ci-deployer", "vendor-sync"]
    if generation >= 2:
        # A late arrival rather than an existing principal: adding an
        # identity that carries its own archetype would mask it, since
        # administrator privilege subsumes the narrower findings.
        automation = [*automation, "new-joiner"]
    return {"automation": automation, "break-glass": [], "readers": ["report-reader"]}


BULK_EPOCH = datetime(2025, 1, 1, tzinfo=UTC)


def bulk_people(generation: int, scale: int) -> list[Person]:
    """The scaled population: index-derived, never random. Every
    variation is a modulus of the index, so the same index is the same
    identity forever, and the archetypes the curated set demonstrates
    reappear at scale in fixed proportions: unowned every 11th,
    long-idle every 13th, keyless people and passworded services never,
    because the person-or-service split is the point of the bulk."""
    captured = GENERATIONS[generation]
    out: list[Person] = []
    for i in range(scale):
        human = i % 3 == 0
        created = BULK_EPOCH + timedelta(days=(i * 7) % 400)
        idle = i % 13 == 0
        last_used = created if idle else captured - timedelta(days=(i % 9) + 1)
        tags = {} if i % 11 == 0 else {"owner": f"team-{i % 12:02d}"}
        member_of: list[str] = []
        if i % 29 == 0:
            member_of = ["automation"]
        elif i % 5 == 0:
            member_of = ["readers"]
        if human:
            out.append(Person(
                name=f"person-{i:05d}",
                uid=f"AIDAB{i:016d}",
                created=created,
                why="bulk person: password and a second factor",
                password=True,
                password_used=last_used,
                mfa=i % 7 != 0,
                tags=tags,
                groups=member_of,
            ))
        else:
            out.append(Person(
                name=f"svc-{i:05d}",
                uid=f"AIDAS{i:016d}",
                created=created,
                why="bulk service: keys only, nobody to offboard it",
                key1=True,
                key1_rotated=created,
                key1_used=last_used,
                tags=tags,
                groups=member_of,
            ))
    return out


def credential_report(generation: int, scale: int = 0) -> str:
    rows = [CREDENTIAL_HEADER]
    for person in people(generation) + bulk_people(generation, scale):
        arn = (
            f"arn:aws:iam::{ACCOUNT}:root" if person.root
            else f"arn:aws:iam::{ACCOUNT}:user/{person.name}"
        )
        password_fields = (
            "not_supported,not_supported" if person.root
            else f"{_stamp(person.created)},N/A"
        )
        rows.append(
            f"{person.name},{arn},{_stamp(person.created)},"
            f"{'TRUE' if person.password else 'FALSE'},"
            f"{_stamp(person.password_used) if person.password else 'N/A'},"
            f"{password_fields},"
            f"{'TRUE' if person.mfa else 'FALSE'},"
            f"{'TRUE' if person.key1 else 'FALSE'},"
            f"{_stamp(person.key1_rotated)},{_stamp(person.key1_used)},"
            f"{'us-west-2' if person.key1_used else 'N/A'},"
            f"{'s3' if person.key1_used else 'N/A'},"
            f"{'TRUE' if person.key2 else 'FALSE'},"
            f"{_stamp(person.key2_rotated)},N/A,N/A,N/A,"
            f"{'TRUE' if person.cert1 else 'FALSE'},"
            f"{_stamp(person.created) if person.cert1 else 'N/A'},FALSE,N/A"
        )
    return "\n".join(rows) + "\n"


def authorization_details(generation: int, scale: int = 0) -> str:
    roster = people(generation) + bulk_people(generation, scale)
    members = membership(generation)
    for person in bulk_people(generation, scale):
        for group in person.groups:
            members.setdefault(group, []).append(person.name)
    in_groups = {
        person.name: [g for g, names in members.items() if person.name in names]
        for person in roster
    }
    payload: dict[str, object] = {
        "UserDetailList": [
            {
                "UserName": p.name,
                "UserId": p.uid,
                "Arn": f"arn:aws:iam::{ACCOUNT}:user/{p.name}",
                "CreateDate": _stamp(p.created),
                "GroupList": in_groups.get(p.name, []),
                "AttachedManagedPolicies": [
                    {"PolicyName": name, "PolicyArn": arn} for name, arn in p.attached
                ],
                "UserPolicyList": [
                    {"PolicyName": name, "PolicyDocument": document}
                    for name, document in p.inline
                ],
                "Tags": [{"Key": k, "Value": v} for k, v in p.tags.items()],
            }
            for p in roster
            if not p.root  # the root account has no authorization detail entry
        ],
        "RoleDetailList": [
            {
                "RoleName": r.name,
                "RoleId": r.uid,
                "Arn": f"arn:aws:iam::{ACCOUNT}:role/{r.name}",
                "CreateDate": _stamp(r.created),
                "AssumeRolePolicyDocument": r.trust,
                "AttachedManagedPolicies": [
                    {"PolicyName": name, "PolicyArn": arn} for name, arn in r.attached
                ],
                "RolePolicyList": [
                    {"PolicyName": name, "PolicyDocument": document}
                    for name, document in r.inline
                ],
                "RoleLastUsed": (
                    {"LastUsedDate": _stamp(r.last_used), "Region": "us-west-2"}
                    if r.last_used else {}
                ),
                "Tags": [{"Key": k, "Value": v} for k, v in r.tags.items()],
            }
            for r in roles()
        ],
        "GroupDetailList": [
            {
                "GroupName": g.name,
                "GroupId": g.uid,
                "Arn": f"arn:aws:iam::{ACCOUNT}:group/{g.name}",
                "AttachedManagedPolicies": [
                    {"PolicyName": name, "PolicyArn": arn} for name, arn in g.attached
                ],
                "GroupPolicyList": [
                    {"PolicyName": name, "PolicyDocument": document}
                    for name, document in g.inline
                ],
            }
            for g in groups()
        ],
        "Policies": [
            {
                "PolicyName": name,
                "Arn": arn,
                "PolicyVersionList": [
                    {"IsDefaultVersion": True, "Document": document, "VersionId": "v1"}
                ],
            }
            for arn, (name, document) in MANAGED.items()
        ],
        "IsTruncated": False,
    }
    return json.dumps(payload, indent=2) + "\n"


def authorizations_template() -> str:
    """The template for the file door, generated rather than written,
    so its columns come from the shipped mapping itself (D-074) and
    the two cannot drift. Its rows name identities from the sample
    account above, so a reader can import it after the observed files
    and watch the record fill."""
    from manifest_identity.authorize.csv_import import DEFAULT_FIELDS

    columns = [
        column
        for spec in DEFAULT_FIELDS.values()
        if (column := spec.get("column")) is not None
    ]
    everyone = {person.name: person.uid for person in people(len(GENERATIONS) - 1)}
    rows = [
        {
            "identity_id": everyone["report-reader"],
            "role": "arn:aws:iam::aws:policy/ReadOnlyAccess",
            "mode": "standing",
            "path": "",
            "owner_kind": "team",
            "owner": "platform-team",
            "justification": "reads the audit bucket for the nightly report",
            "reference": "CHG-1041",
            "control": "AC-6",
            "valid_from": "2026-09-01",
            "valid_until": "2027-08-31",
        },
        {
            "identity_id": everyone["data-pipeline"],
            "role": "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess",
            "mode": "standing",
            "path": "membership:operations",
            "owner_kind": "individual",
            "owner": "dana.okafor",
            "secondary_owner_kind": "team",
            "secondary_owner": "platform-team",
            "justification": "moves the nightly extract while the rewrite lands",
            "reference": "CHG-1042",
            "control": "AC-2",
            "valid_from": "2026-09-01",
            "valid_until": "2027-02-28",
        },
    ]
    lines = [",".join(columns)]
    for row in rows:
        lines.append(",".join(str(row.get(column, "")) for column in columns))
    return "\n".join(lines) + "\n"


def file_set(scale: int = 0) -> dict[str, str]:
    """Every sample file, by name, deterministic and complete. A zero
    scale is the committed curated set, byte for byte; any other scale
    adds that many bulk identities to every generation."""
    out: dict[str, str] = {}
    for generation, captured in enumerate(GENERATIONS):
        day = captured.strftime("%Y-%m-%d")
        out[f"{day}-credential-report.csv"] = credential_report(generation, scale)
        out[f"{day}-authorization-details.json"] = authorization_details(
            generation, scale
        )
    out["authorizations-template.csv"] = authorizations_template()
    return out


def write(directory: Path, scale: int = 0) -> list[Path]:
    directory.mkdir(parents=True, exist_ok=True)
    written = []
    for name, content in file_set(scale).items():
        path = directory / name
        path.write_text(content)
        written.append(path)
    return written


def capture_times() -> list[str]:
    return [when.isoformat() for when in GENERATIONS]


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "directory", nargs="?", default="sample-data",
        help="where to write the files",
    )
    parser.add_argument(
        "--scale", type=int, default=0,
        help="bulk identities to add per generation (0 keeps the curated set)",
    )
    arguments = parser.parse_args()
    for path in write(Path(arguments.directory), arguments.scale):
        print(path)
