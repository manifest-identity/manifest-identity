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
            # In the third generation this policy quietly gains the power
            # to delete users. Nobody re-authorized it, which is the
            # change 1.7 exists to name.
            inline=[("user-tidier", _document(
                _allow(
                    ["iam:UpdateUser", "iam:TagUser"]
                    + (["iam:DeleteUser"] if generation >= 2 else []),
                    f"arn:aws:iam::{ACCOUNT}:user/*",
                )))],
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


def observed_template() -> str:
    """The template for the observed side's file door (1.11), generated
    rather than written for the same reason as the other one: the
    header is the shipped mapping's own column names, so the documented
    file imports clean through it. The rows are a directory nobody
    runs, with the three shapes a row can take: a standing hold, a hold
    through a group with the hop written, and an eligible one."""
    header = (
        "provider,account,identity_id,identity_name,identity_type,identity_kind,"
        "role,role_name,mode,path"
    )
    rows = [
        "active_directory,corp,S-1-5-21-100,sample.person,user,person,"
        "Domain Admins,Domain Admins,standing,",
        "active_directory,corp,S-1-5-21-101,svc-nightly,user,service,"
        "Backup Operators,Backup Operators,standing,membership:backup-team",
        "active_directory,corp,S-1-5-21-102,sample.oncall,user,person,"
        "Domain Admins,Domain Admins,eligible,",
    ]
    return "\n".join([header, *rows]) + "\n"


# The Kubernetes cluster: the third provider's estate (1.14b), a kubectl
# List of the objects the parser reads, generated with the same rule
# that every archetype the engine can find there exists once.

CLUSTER = "sample-cluster"


def _k8s(kind: str, name: str, namespace: str | None, uid: str, created: str,
         **body: object) -> dict[str, object]:
    metadata: dict[str, object] = {"name": name, "uid": uid, "creationTimestamp": created}
    if namespace:
        metadata["namespace"] = namespace
    item: dict[str, object] = {
        "apiVersion": "v1" if kind == "ServiceAccount" else "rbac.authorization.k8s.io/v1",
        "kind": kind, "metadata": metadata,
    }
    item.update(body)
    return item


def _rule(
    verbs: list[str], resources: list[str], groups: list[str] | None = None,
) -> dict[str, object]:
    return {"apiGroups": groups if groups is not None else [""], "resources": resources,
            "verbs": verbs}


def _subject(kind: str, name: str, namespace: str | None = None) -> dict[str, object]:
    subject: dict[str, object] = {"kind": kind, "name": name}
    if kind == "ServiceAccount":
        subject["namespace"] = namespace
    else:
        subject["apiGroup"] = "rbac.authorization.k8s.io"
    return subject


def kubernetes_rbac(generation: int) -> str:
    """The cluster's dump at one generation. The secrets reader gains
    every verb in the second month, so a changed custom role names
    what it gained; a contractor is bound to admin in the third, so the
    delta has a new door to report."""
    d = "2025-01-15T00:00:00Z"
    secrets_verbs = ["get", "list"] if generation == 0 else ["*"]
    items: list[dict[str, object]] = [
        # The four roles the API ships, as the API writes them.
        _k8s("ClusterRole", "cluster-admin", None, "cr-0001", d,
             rules=[_rule(["*"], ["*"], ["*"]), {"nonResourceURLs": ["*"], "verbs": ["*"]}]),
        _k8s("ClusterRole", "admin", None, "cr-0002", d, rules=[
            _rule(["*"], ["pods", "services", "configmaps", "secrets"]),
            _rule(["get", "list", "watch", "create", "update", "patch", "delete"],
                  ["roles", "rolebindings"], ["rbac.authorization.k8s.io"]),
        ]),
        _k8s("ClusterRole", "edit", None, "cr-0003", d, rules=[
            _rule(["*"], ["pods", "services", "configmaps", "secrets"]),
        ]),
        _k8s("ClusterRole", "view", None, "cr-0004", d, rules=[
            _rule(["get", "list", "watch"], ["pods", "services", "configmaps"]),
        ]),
        # Customer roles: a secrets reader that grows, and a role that
        # can hand out roles, which is privilege escalation by name.
        _k8s("ClusterRole", "secrets-reader", None, "cr-0101", d,
             rules=[_rule(secrets_verbs, ["secrets"])]),
        _k8s("ClusterRole", "rbac-editor", None, "cr-0102", d, rules=[
            _rule(["create", "update", "bind", "escalate"],
                  ["clusterrolebindings", "clusterroles"], ["rbac.authorization.k8s.io"]),
        ]),
        _k8s("Role", "config-reader", "payments", "r-0201", d,
             rules=[_rule(["get", "list"], ["configmaps"])]),
        # Service accounts.
        _k8s("ServiceAccount", "deployer", "kube-system", "sa-0301", d),
        _k8s("ServiceAccount", "api", "payments", "sa-0302", d),
        _k8s("ServiceAccount", "default", "payments", "sa-0303", d),
        _k8s("ServiceAccount", "prometheus", "monitoring", "sa-0304", d),
        _k8s("ServiceAccount", "rbac-bot", "ci", "sa-0305", d),
        # Bindings.
        _k8s("ClusterRoleBinding", "cluster-admin", None, "crb-0401", d,
             roleRef={"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole",
                      "name": "cluster-admin"},
             subjects=[_subject("Group", "system:masters"), _subject("User", "ops-lead"),
                       _subject("ServiceAccount", "deployer", "kube-system")]),
        _k8s("ClusterRoleBinding", "rbac-bot", None, "crb-0402", d,
             roleRef={"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole",
                      "name": "rbac-editor"},
             subjects=[_subject("ServiceAccount", "rbac-bot", "ci")]),
        _k8s("ClusterRoleBinding", "secrets-audit", None, "crb-0403", d,
             roleRef={"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole",
                      "name": "secrets-reader"},
             subjects=[_subject("User", "audit-tool")]),
        _k8s("ClusterRoleBinding", "monitoring-view", None, "crb-0404", d,
             roleRef={"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole",
                      "name": "view"},
             subjects=[_subject("Group", "system:serviceaccounts:monitoring")]),
        _k8s("RoleBinding", "config", "payments", "rb-0501", d,
             roleRef={"apiGroup": "rbac.authorization.k8s.io", "kind": "Role",
                      "name": "config-reader"},
             subjects=[_subject("ServiceAccount", "api", "payments")]),
        _k8s("RoleBinding", "editors", "payments", "rb-0502", d,
             roleRef={"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole",
                      "name": "edit"},
             subjects=[_subject("User", "dev-nadia"), _subject("Group", "payments-team")]),
    ]
    if generation >= 2:
        items.append(_k8s(
            "RoleBinding", "contractor", "payments", "rb-0503", "2026-07-20T00:00:00Z",
            roleRef={"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole",
                     "name": "admin"},
            subjects=[_subject("User", "new-contractor")],
        ))
    return json.dumps({"kind": "List", "apiVersion": "v1", "items": items}, indent=2) + "\n"


# The Google Cloud project: the fourth provider's estate (1.14c), the
# document the parser reads, assembled from gcloud's own answers.

PROJECT = "sample-project"
PROJECT_NUMBER = "123456789012"
_SA_DOMAIN = f"{PROJECT}.iam.gserviceaccount.com"


def _key(key_id: str, after: str, before: str | None = None,
         key_type: str = "USER_MANAGED") -> dict[str, object]:
    return {
        "name": f"projects/{PROJECT}/serviceAccounts/x/keys/{key_id}",
        "keyType": key_type, "keyAlgorithm": "KEY_ALG_RSA_2048",
        "validAfterTime": after,
        "validBeforeTime": before or "9999-12-31T23:59:59Z",
    }


def google_cloud_project(generation: int) -> str:
    """The project at one generation. A deleted principal's binding
    survives it from the second month; the custom deployer role gains
    the permission that sets policy in the third."""
    ci = f"ci@{_SA_DOMAIN}"
    legacy = f"legacy@{_SA_DOMAIN}"
    deploy = f"deploy@{_SA_DOMAIN}"
    compute = f"{PROJECT_NUMBER}-compute@developer.gserviceaccount.com"
    editors = ["serviceAccount:" + ci, "group:developers@example.test",
               "serviceAccount:" + compute]
    if generation >= 1:
        editors.append("deleted:user:former@example.test?uid=100000000000000000001")
    deployer_permissions = [
        "compute.instances.create", "compute.instances.delete", "compute.instances.get",
        "compute.instances.list", "iam.serviceAccounts.actAs",
    ]
    if generation >= 2:
        deployer_permissions.append("resourcemanager.projects.setIamPolicy")
    used = _stamp(datetime(2026, 5, 27, tzinfo=UTC) + timedelta(days=30 * generation))
    document = {
        "project": {"projectId": PROJECT, "projectNumber": PROJECT_NUMBER,
                    "lifecycleState": "ACTIVE"},
        "policy": {
            "bindings": [
                {"role": "roles/owner", "members": ["user:sam@example.test"]},
                {"role": "roles/editor", "members": editors},
                {"role": "roles/viewer", "members": ["group:auditors@example.test"]},
                {"role": "roles/iam.serviceAccountKeyAdmin",
                 "members": ["serviceAccount:" + legacy]},
                {"role": "roles/storage.objectViewer", "members": ["allUsers"]},
                {"role": f"projects/{PROJECT}/roles/deployer",
                 "members": ["serviceAccount:" + deploy],
                 "condition": {"title": "weekdays", "expression":
                               "request.time.getDayOfWeek('UTC') < 6"}},
            ],
            "etag": "BwX0sample=",
            "version": 3,
        },
        "service_accounts": [
            {"email": ci, "uniqueId": "100000000000000000010",
             "displayName": "continuous integration", "disabled": False},
            {"email": legacy, "uniqueId": "100000000000000000020",
             "displayName": "legacy sync", "disabled": False},
            {"email": deploy, "uniqueId": "100000000000000000030",
             "displayName": "deployer", "disabled": False},
            {"email": compute, "uniqueId": "100000000000000000040",
             "displayName": "Compute Engine default service account", "disabled": False},
        ],
        "keys": {
            ci: [_key("a1", "2026-03-01T00:00:00Z")],
            legacy: [_key("b1", "2023-02-01T00:00:00Z"), _key("b2", "2024-06-01T00:00:00Z")],
            deploy: [_key("c0", "2026-01-01T00:00:00Z", key_type="SYSTEM_MANAGED")],
            compute: [],
        },
        "role_definitions": [
            {"name": f"projects/{PROJECT}/roles/deployer", "title": "Deployer",
             "includedPermissions": deployer_permissions, "stage": "GA"},
        ],
        "activity": {ci: used, deploy: used, compute: used},
    }
    return json.dumps(document, indent=2) + "\n"


# The Azure and Entra tenant: the fifth provider's estate (1.14d), the
# document the parser reads, assembled from Graph's objects and the
# command line's output.

TENANT = "aaaaaaaa-0000-4000-8000-000000000001"
SUBSCRIPTION = "11111111-2222-3333-4444-555555555555"
_ROLE_PREFIX = f"/subscriptions/{SUBSCRIPTION}/providers/Microsoft.Authorization/roleDefinitions/"
AZURE_OWNER = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
AZURE_CONTRIBUTOR = "b24988ac-6180-42a0-ab88-20f7382dd24c"
AZURE_READER = "acdd72a7-3385-48ef-bd42-f606fba81ae7"
AZURE_USER_ACCESS = "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9"
GLOBAL_ADMINISTRATOR = "62e90394-69f5-4237-9190-012177145e10"
USER_ADMINISTRATOR = "fe930be7-5e62-47db-91af-98c3a49a38b1"
GLOBAL_READER = "f2ef992c-3afb-46b9-b7cf-a126ee74c451"


def _oid(kind: str, number: int) -> str:
    """An invented object identifier in GUID form."""
    return f"{kind}-0000-4000-8000-{number:012d}"


def _member(kind: str, oid: str) -> dict[str, str]:
    return {"@odata.type": f"#microsoft.graph.{kind}", "id": oid}


def _assignment(principal: str, name: str | None, principal_type: str, role: str,
                role_name: str, scope: str) -> dict[str, object]:
    return {"principalId": principal, "principalName": name, "principalType": principal_type,
            "roleDefinitionId": _ROLE_PREFIX + role, "roleDefinitionName": role_name,
            "scope": scope}


def azure_tenant(generation: int) -> str:
    """The tenant at one generation. The guest's Contributor becomes
    Owner in the second month; a member gains User Access Administrator
    at the subscription in the third."""
    sam, rita, mike, guest, dormant = (_oid("11111111", n) for n in (1, 2, 3, 4, 5))
    pipeline, legacy, webapp = (_oid("22222222", n) for n in (1, 2, 3))
    admins, developers, engineering = (_oid("33333333", n) for n in (1, 2, 3))
    signed = _stamp(datetime(2026, 5, 29, tzinfo=UTC) + timedelta(days=30 * generation))
    sub = f"/subscriptions/{SUBSCRIPTION}"
    guest_role = (AZURE_CONTRIBUTOR, "Contributor") if generation == 0 else (AZURE_OWNER, "Owner")
    assignments = [
        _assignment(admins, "cloud-admins", "Group", AZURE_OWNER, "Owner", sub),
        _assignment(pipeline, "deploy-pipeline", "ServicePrincipal", AZURE_CONTRIBUTOR,
                    "Contributor", sub),
        _assignment(webapp, "webapp-identity", "ServicePrincipal", AZURE_READER, "Reader", sub),
        _assignment(guest, "contractor_partner.test#EXT#@sample.onmicrosoft.com", "User",
                    guest_role[0], guest_role[1], f"{sub}/resourceGroups/app"),
        _assignment(legacy, "legacy-integration", "ServicePrincipal", AZURE_OWNER, "Owner",
                    f"{sub}/resourceGroups/legacy"),
        _assignment(developers, "developers", "Group", AZURE_CONTRIBUTOR, "Contributor",
                    f"{sub}/resourceGroups/app"),
        # An assignment the directory no longer explains: the principal
        # was deleted after it was made.
        _assignment(_oid("44444444", 1), None, "User", AZURE_READER, "Reader", sub),
    ]
    if generation >= 2:
        assignments.append(_assignment(
            mike, "mike@example.test", "User", AZURE_USER_ACCESS, "User Access Administrator",
            sub,
        ))
    document = {
        "tenant": {"id": TENANT, "displayName": "Sample Tenant", "cloud": "AzureCloud"},
        "users": [
            {"id": sam, "userPrincipalName": "sam@example.test", "displayName": "Sam Owner",
             "accountEnabled": True, "userType": "Member",
             "createdDateTime": "2021-04-02T00:00:00Z",
             "signInActivity": {"lastSignInDateTime": signed}, "mfa_registered": True},
            {"id": rita, "userPrincipalName": "rita@example.test", "displayName": "Rita Ops",
             "accountEnabled": True, "userType": "Member",
             "createdDateTime": "2022-08-19T00:00:00Z",
             "signInActivity": {"lastSignInDateTime": signed}, "mfa_registered": True},
            {"id": mike, "userPrincipalName": "mike@example.test", "displayName": "Legacy Mike",
             "accountEnabled": True, "userType": "Member",
             "createdDateTime": "2019-11-03T00:00:00Z",
             "signInActivity": {"lastSignInDateTime": "2025-11-20T00:00:00Z"},
             "mfa_registered": False},
            {"id": guest,
             "userPrincipalName": "contractor_partner.test#EXT#@sample.onmicrosoft.com",
             "displayName": "Contractor Lee", "accountEnabled": True, "userType": "Guest",
             "createdDateTime": "2026-02-10T00:00:00Z",
             "signInActivity": {"lastSignInDateTime": signed}},
            {"id": dormant, "userPrincipalName": "former@example.test",
             "displayName": "Former Employee", "accountEnabled": False, "userType": "Member",
             "createdDateTime": "2020-01-06T00:00:00Z",
             "signInActivity": {"lastSignInDateTime": "2025-06-01T00:00:00Z"},
             "mfa_registered": True},
        ],
        "groups": [
            {"id": admins, "displayName": "cloud-admins", "securityEnabled": True,
             "members": [_member("user", sam), _member("user", rita)]},
            {"id": developers, "displayName": "developers", "securityEnabled": True,
             "members": [_member("user", mike), _member("group", engineering)]},
            {"id": engineering, "displayName": "engineering", "securityEnabled": True,
             "members": [_member("user", rita)]},
        ],
        "service_principals": [
            {"id": pipeline, "appId": _oid("55555555", 1), "displayName": "deploy-pipeline",
             "servicePrincipalType": "Application", "accountEnabled": True,
             "passwordCredentials": [
                 {"keyId": _oid("66666666", 1), "startDateTime": "2026-03-01T00:00:00Z",
                  "endDateTime": "2026-12-01T00:00:00Z", "displayName": "ci"}],
             "keyCredentials": []},
            {"id": legacy, "appId": _oid("55555555", 2), "displayName": "legacy-integration",
             "servicePrincipalType": "Application", "accountEnabled": True,
             "passwordCredentials": [
                 {"keyId": _oid("66666666", 2), "startDateTime": "2023-01-15T00:00:00Z",
                  "endDateTime": "2025-01-15T00:00:00Z", "displayName": "old"},
                 {"keyId": _oid("66666666", 3), "startDateTime": "2024-11-01T00:00:00Z",
                  "endDateTime": "2027-11-01T00:00:00Z", "displayName": "current"}],
             "keyCredentials": [
                 {"keyId": _oid("66666666", 4), "startDateTime": "2025-05-01T00:00:00Z",
                  "endDateTime": "2027-05-01T00:00:00Z", "type": "AsymmetricX509Cert",
                  "usage": "Verify"}]},
            {"id": webapp, "appId": _oid("55555555", 3), "displayName": "webapp-identity",
             "servicePrincipalType": "ManagedIdentity", "accountEnabled": True,
             "passwordCredentials": [], "keyCredentials": []},
        ],
        "directory_roles": [
            {"id": _oid("77777777", 1), "roleTemplateId": GLOBAL_ADMINISTRATOR,
             "displayName": "Global Administrator", "members": [_member("user", sam)]},
            {"id": _oid("77777777", 2), "roleTemplateId": USER_ADMINISTRATOR,
             "displayName": "User Administrator", "members": [_member("user", rita)]},
            {"id": _oid("77777777", 3), "roleTemplateId": GLOBAL_READER,
             "displayName": "Global Reader",
             "members": [_member("servicePrincipal", pipeline)]},
        ],
        "role_eligibilities": [
            {"principalId": rita, "roleDefinitionId": GLOBAL_ADMINISTRATOR,
             "directoryScopeId": "/", "startDateTime": "2026-01-10T00:00:00Z",
             "endDateTime": "2027-01-10T00:00:00Z", "memberType": "Direct"},
        ],
        "subscriptions": [
            {"id": SUBSCRIPTION, "displayName": "Production", "role_assignments": assignments},
        ],
    }
    return json.dumps(document, indent=2) + "\n"


# One sample table per provider the table door reads and no parser
# reads yet (1.14a): what a recipe under recipes/ produces from that
# provider's own export, so a person can import each provider the day
# they meet the product. Every identifier is invented.

TEMPLATE_HEADER = (
    "provider,account,identity_id,identity_name,identity_type,identity_kind,"
    "role,role_name,mode,path"
)

PROVIDER_TABLES: dict[str, list[str]] = {
    "kubernetes": [
        "kubernetes,sample-cluster,user:ops-lead,ops-lead,user,unknown,"
        "clusterrole:cluster-admin,cluster-admin,standing,",
        "kubernetes,sample-cluster,group:system:masters,system:masters,group,group,"
        "clusterrole:cluster-admin,cluster-admin,standing,",
        "kubernetes,sample-cluster,serviceaccount:kube-system/deployer,deployer,"
        "serviceaccount,service,clusterrole:cluster-admin,cluster-admin,standing,",
        "kubernetes,sample-cluster,serviceaccount:payments/api,api,serviceaccount,service,"
        "role:payments/config-reader,config-reader,standing,",
        "kubernetes,sample-cluster,user:dev-nadia,dev-nadia,user,unknown,"
        "clusterrole:edit,edit,standing,",
        "kubernetes,sample-cluster,group:platform-team,platform-team,group,group,"
        "clusterrole:admin,admin,standing,",
    ],
    "gcp": [
        "gcp,sample-project,user:sam@example.test,sam@example.test,user,person,"
        "roles/owner,roles/owner,standing,",
        "gcp,sample-project,serviceAccount:ci@sample-project.iam.gserviceaccount.com,"
        "ci@sample-project.iam.gserviceaccount.com,serviceAccount,service,"
        "roles/editor,roles/editor,standing,",
        "gcp,sample-project,group:data-readers@example.test,data-readers@example.test,"
        "group,group,roles/bigquery.dataViewer,roles/bigquery.dataViewer,standing,",
        "gcp,sample-project,serviceAccount:legacy@sample-project.iam.gserviceaccount.com,"
        "legacy@sample-project.iam.gserviceaccount.com,serviceAccount,service,"
        "roles/iam.serviceAccountKeyAdmin,roles/iam.serviceAccountKeyAdmin,standing,",
        "gcp,sample-project,allUsers,allUsers,allUsers,external,"
        "roles/storage.objectViewer,roles/storage.objectViewer,standing,",
    ],
    "azure": [
        "azure,11111111-2222-3333-4444-555555555555,a1b2c3d4-0000-0000-0000-000000000001,"
        "sam@example.test,user,person,"
        "/subscriptions/11111111-2222-3333-4444-555555555555/providers/"
        "Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635,"
        "Owner,standing,",
        "azure,11111111-2222-3333-4444-555555555555,a1b2c3d4-0000-0000-0000-000000000002,"
        "deploy-pipeline,serviceprincipal,service,"
        "/subscriptions/11111111-2222-3333-4444-555555555555/providers/"
        "Microsoft.Authorization/roleDefinitions/b24988ac-6180-42a0-ab88-20f7382dd24c,"
        "Contributor,standing,",
        "azure,11111111-2222-3333-4444-555555555555,a1b2c3d4-0000-0000-0000-000000000003,"
        "cloud-readers,group,group,"
        "/subscriptions/11111111-2222-3333-4444-555555555555/providers/"
        "Microsoft.Authorization/roleDefinitions/acdd72a7-3385-48ef-bd42-f606fba81ae7,"
        "Reader,standing,",
        "azure,11111111-2222-3333-4444-555555555555,a1b2c3d4-0000-0000-0000-000000000004,"
        "contractor@partner.test,user,person,"
        "/subscriptions/11111111-2222-3333-4444-555555555555/providers/"
        "Microsoft.Authorization/roleDefinitions/18d7d88d-d35e-4fb5-a5c3-7773c20a72d9,"
        "User Access Administrator,standing,",
    ],
    "okta": [
        "okta,sample-org,00u0000000000000sam,sam@example.test,user,person,"
        "SUPER_ADMIN,Super Organization Administrator,standing,",
        "okta,sample-org,00u0000000000000rita,rita@example.test,user,person,"
        "ORG_ADMIN,Organization Administrator,standing,membership:group",
        "okta,sample-org,00u0000000000000help,helpdesk@example.test,user,person,"
        "HELP_DESK_ADMIN,Help Desk Administrator,standing,",
        "okta,sample-org,00u0000000000000audit,auditor@example.test,user,person,"
        "READ_ONLY_ADMIN,Read Only Administrator,standing,",
    ],
    "active_directory": [
        "active_directory,corp,S-1-5-21-1000-1,sam.owner,user,person,"
        "Domain Admins,Domain Admins,standing,",
        "active_directory,corp,S-1-5-21-1000-2,svc-backup,user,service,"
        "Backup Operators,Backup Operators,standing,",
        "active_directory,corp,S-1-5-21-1000-3,helpdesk-tier1,group,group,"
        "Account Operators,Account Operators,standing,",
        "active_directory,corp,S-1-5-21-1000-4,legacy.mike,user,person,"
        "Domain Admins,Domain Admins,standing,membership:infra-admins",
    ],
    "database": [
        "database,prod-db,16384,app_writer,role,unknown,app_rw,app_rw,standing,",
        "database,prod-db,16385,reporting,role,unknown,app_ro,app_ro,standing,",
        "database,prod-db,16386,dba_sam,role,unknown,superuser,superuser,standing,",
        "database,prod-db,16387,migrations,role,unknown,superuser,superuser,standing,",
    ],
}


def provider_table(provider: str) -> str:
    return "\n".join([TEMPLATE_HEADER, *PROVIDER_TABLES[provider]]) + "\n"


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


# The GitHub organization: the second provider's estate, generated the
# same way, with the same rule that every archetype the engine can find
# there exists once. Every login and id is invented; nothing here is
# anyone's real organization.

ORGANIZATION = "sample-org"


@dataclass
class Member:
    login: str
    id: int
    why: str
    role: str = "member"
    two_factor: bool = True
    created: datetime | None = None
    last_active: datetime | None = None


def members(generation: int) -> list[Member]:
    d = datetime
    everyone = [
        Member(login="sam-owner", id=1001, role="owner", created=d(2021, 4, 2, tzinfo=UTC),
               why="an organization owner: administrator equivalence by role",
               last_active=d(2026, 5, 30, tzinfo=UTC) + timedelta(days=30 * generation)),
        Member(login="rita-ops", id=1002, role="owner", created=d(2022, 8, 19, tzinfo=UTC),
               why="an owner without a second factor until the third month",
               two_factor=generation >= 2,
               last_active=d(2026, 5, 28, tzinfo=UTC) + timedelta(days=30 * generation)),
        Member(login="dev-amir", id=1003, created=d(2023, 1, 9, tzinfo=UTC),
               why="an ordinary developer, who must stay quiet",
               last_active=d(2026, 5, 31, tzinfo=UTC) + timedelta(days=30 * generation)),
        Member(login="dev-chen", id=1004, created=d(2023, 6, 14, tzinfo=UTC),
               why="joins the platform team in the third month: membership drift",
               last_active=d(2026, 5, 29, tzinfo=UTC) + timedelta(days=30 * generation)),
        Member(login="legacy-mike", id=1005, created=d(2019, 11, 3, tzinfo=UTC),
               why="no second factor and no activity: the account nobody uses",
               two_factor=False, last_active=d(2025, 11, 20, tzinfo=UTC)),
        Member(login="release-bot", id=1006, created=d(2024, 2, 27, tzinfo=UTC),
               why="a machine account holding a token and a repository grant",
               last_active=d(2026, 5, 31, tzinfo=UTC) + timedelta(days=30 * generation)),
    ]
    if generation >= 1:
        everyone.append(Member(
            login="new-dev", id=1007, created=d(2026, 6, 10, tzinfo=UTC),
            why="a late arrival, so the second month differs from the first",
            last_active=d(2026, 6, 28, tzinfo=UTC) + timedelta(days=30 * (generation - 1)),
        ))
    return everyone


def teams(generation: int) -> list[dict[str, object]]:
    platform = ["sam-owner", "rita-ops"]
    if generation >= 2:
        platform = [*platform, "dev-chen"]
    developers = ["dev-amir", "dev-chen"]
    frontend = ["new-dev"] if generation >= 1 else []
    return [
        {"slug": "platform", "id": 301, "name": "platform", "parent": None,
         "members": platform,
         "repositories": [{"name": "infra", "permission": "admin"},
                          {"name": "api", "permission": "maintain"}]},
        {"slug": "developers", "id": 302, "name": "developers", "parent": None,
         "members": developers,
         "repositories": [{"name": "api", "permission": "write"},
                          {"name": "website", "permission": "write"}]},
        {"slug": "frontend", "id": 305, "name": "frontend", "parent": "developers",
         "members": frontend,
         "repositories": [{"name": "website", "permission": "write"}]},
        # Privilege waiting for its first member.
        {"slug": "incident-commanders", "id": 303, "name": "incident-commanders",
         "parent": None, "members": [],
         "repositories": [{"name": "api", "permission": "admin"},
                          {"name": "infra", "permission": "admin"},
                          {"name": "website", "permission": "admin"}]},
        {"slug": "auditors", "id": 304, "name": "auditors", "parent": None,
         "members": ["legacy-mike"],
         "repositories": [{"name": "api", "permission": "read"},
                          {"name": "infra", "permission": "read"}]},
    ]


def repositories(generation: int) -> list[dict[str, object]]:
    # The contractor's grant grows from write to admin in the second
    # month, which is what a delta exists to notice.
    contractor = "write" if generation == 0 else "admin"
    return [
        {"name": "api", "id": 401, "visibility": "private",
         "collaborators": [{"login": "release-bot", "permission": "write"}],
         "deploy_keys": []},
        {"name": "infra", "id": 402, "visibility": "private",
         "collaborators": [],
         "deploy_keys": [{"id": 501, "title": "terraform-runner", "read_only": False,
                          "created_at": "2024-01-15T00:00:00+00:00",
                          "last_used": _stamp(
                              datetime(2026, 5, 28, tzinfo=UTC)
                              + timedelta(days=30 * generation))}]},
        {"name": "website", "id": 403, "visibility": "public",
         "collaborators": [{"login": "contractor-lee", "permission": contractor}],
         "deploy_keys": [{"id": 502, "title": "pages-deploy", "read_only": True,
                          "created_at": "2026-05-02T00:00:00+00:00",
                          "last_used": None}]},
    ]


def installations() -> list[dict[str, object]]:
    return [
        {"id": 601, "app_slug": "ci-runner", "app_id": 71,
         "permissions": {"contents": "write", "checks": "write", "metadata": "read"},
         "repository_selection": "all", "created_at": "2025-03-04T00:00:00+00:00"},
        # An app that can change who holds what is an administrator.
        {"id": 602, "app_slug": "org-admin-tool", "app_id": 72,
         "permissions": {"administration": "write", "members": "write", "metadata": "read"},
         "repository_selection": "all", "created_at": "2025-09-18T00:00:00+00:00"},
    ]


def tokens(generation: int) -> list[dict[str, object]]:
    used = datetime(2026, 5, 27, tzinfo=UTC) + timedelta(days=30 * generation)
    return [
        {"id": 701, "owner": "rita-ops", "created_at": "2026-03-01T00:00:00+00:00",
         "expires_at": "2026-09-01T00:00:00+00:00", "last_used_at": _stamp(used),
         "token_expired": False},
        {"id": 702, "owner": "release-bot", "created_at": "2025-12-01T00:00:00+00:00",
         "expires_at": "2026-12-01T00:00:00+00:00", "last_used_at": _stamp(used),
         "token_expired": False},
        {"id": 703, "owner": "legacy-mike", "created_at": "2025-01-01T00:00:00+00:00",
         "expires_at": "2026-01-01T00:00:00+00:00", "last_used_at": None,
         "token_expired": True},
    ]


def github_organization(generation: int) -> str:
    """The organization export at one generation, in the shape the
    parser documents."""
    document = {
        "organization": {"login": ORGANIZATION, "id": 9001},
        "members": [
            {"login": m.login, "id": m.id, "type": "User", "role": m.role,
             "two_factor_enabled": m.two_factor,
             "created_at": _stamp(m.created) if m.created else None,
             "last_active_at": _stamp(m.last_active) if m.last_active else None}
            for m in members(generation)
        ],
        "outside_collaborators": [{"login": "contractor-lee", "id": 2001, "type": "User"}],
        "teams": teams(generation),
        "repositories": repositories(generation),
        "installations": installations(),
        "tokens": tokens(generation),
    }
    return json.dumps(document, indent=2) + "\n"


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
        out[f"{day}-github-organization.json"] = github_organization(generation)
        out[f"{day}-kubernetes-rbac.json"] = kubernetes_rbac(generation)
        out[f"{day}-google-cloud.json"] = google_cloud_project(generation)
        out[f"{day}-azure-tenant.json"] = azure_tenant(generation)
    out["authorizations-template.csv"] = authorizations_template()
    out["observed-template.csv"] = observed_template()
    for provider in PROVIDER_TABLES:
        out[f"observed-{provider.replace('_', '-')}.csv"] = provider_table(provider)
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
