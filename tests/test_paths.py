"""Access paths (1.6): how privilege actually reaches an identity.

Two halves, and they fail differently. Reading a trust policy is a
parsing problem, so it is tested against the shapes a provider writes,
including the ones that name nobody. Expanding paths is a derivation
problem, so it is tested against an estate imported through the real
endpoint, because the thing worth proving is that a user who holds
nothing directly still shows the administrator policy it can reach
through a group or by assuming a role.

The case that matters most is the assumable role: privilege reached
that way is privilege the identity can take whenever it likes, without
asking anyone, and it appears nowhere in that identity's own grants.
"""

import json
from urllib.parse import quote

from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from manifest_identity.core.roles import Role
from manifest_identity.models import Grant, Identity, Import, ObservedRelationship
from manifest_identity.observe import paths, principals
from tests.conftest import ROLE_USERS, auth_header, login, make_user

ACCOUNT = "123456789012"
OTHER = "999999999999"
ADMIN_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"
ADMIN_DOCUMENT = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
}


def trust(*statements: dict[str, object]) -> str:
    return quote(json.dumps({"Version": "2012-10-17", "Statement": list(statements)}))


def allow(principal: object) -> dict[str, object]:
    return {"Effect": "Allow", "Action": "sts:AssumeRole", "Principal": principal}


def user_entry(
    name: str, uid: str, groups: list[str] | None = None, *, admin: bool = False
) -> dict[str, object]:
    entry: dict[str, object] = {
        "UserName": name,
        "UserId": uid,
        "Arn": f"arn:aws:iam::{ACCOUNT}:user/{name}",
        "CreateDate": "2025-01-01T00:00:00Z",
        "GroupList": groups or [],
    }
    if admin:
        entry["AttachedManagedPolicies"] = [
            {"PolicyName": "AdministratorAccess", "PolicyArn": ADMIN_ARN}
        ]
    return entry


def role_entry(name: str, rid: str, document: str) -> dict[str, object]:
    return {
        "RoleName": name,
        "RoleId": rid,
        "Arn": f"arn:aws:iam::{ACCOUNT}:role/{name}",
        "CreateDate": "2024-06-01T00:00:00Z",
        "AssumeRolePolicyDocument": document,
        "AttachedManagedPolicies": [
            {"PolicyName": "AdministratorAccess", "PolicyArn": ADMIN_ARN}
        ],
    }


def group_entry(name: str, gid: str) -> dict[str, object]:
    return {
        "GroupName": name,
        "GroupId": gid,
        "Arn": f"arn:aws:iam::{ACCOUNT}:group/{name}",
        "AttachedManagedPolicies": [
            {"PolicyName": "AdministratorAccess", "PolicyArn": ADMIN_ARN}
        ],
    }


def import_estate(client: TestClient, db: Session, payload: dict[str, object]) -> str:
    make_user(db, Role.administrator)
    token = login(client, ROLE_USERS[Role.administrator])
    payload.setdefault(
        "Policies",
        [
            {
                "PolicyName": "AdministratorAccess",
                "Arn": ADMIN_ARN,
                "PolicyVersionList": [
                    {"IsDefaultVersion": True, "Document": ADMIN_DOCUMENT}
                ],
            }
        ],
    )
    payload.setdefault("AccountId", ACCOUNT)
    response = client.post(
        "/imports/authorization-details",
        headers=auth_header(token),
        files={"file": ("d.json", json.dumps(payload).encode(), "application/json")},
        data={"captured_at": "2026-08-01T00:00:00+00:00"},
    )
    assert response.status_code == 201, response.text
    return token


def identity_named(db: Session, external_id: str) -> Identity:
    return db.execute(
        select(Identity).where(Identity.external_id == external_id)
    ).scalar_one()


def latest_import(db: Session) -> int:
    return db.execute(
        select(Import.id).order_by(Import.id.desc()).limit(1)
    ).scalar_one()


def reached_by(db: Session, external_id: str) -> list[paths.AccessPath]:
    return paths.for_identity(
        db, import_id=latest_import(db), identity=identity_named(db, external_id)
    )


# What a trust policy names, read from the shapes providers write.


def test_one_principal_per_named_entry() -> None:
    document = {
        "Statement": [
            allow(
                {
                    "AWS": [
                        f"arn:aws:iam::{OTHER}:user/deploy",
                        f"arn:aws:iam::{OTHER}:root",
                    ]
                }
            ),
            allow({"Service": "ec2.amazonaws.com"}),
            allow({"Federated": f"arn:aws:iam::{ACCOUNT}:saml-provider/Okta"}),
        ]
    }
    found = principals.principals(document)
    assert [(p.from_kind, p.ref) for p in found] == [
        (principals.AWS, f"arn:aws:iam::{OTHER}:user/deploy"),
        (principals.AWS, f"arn:aws:iam::{OTHER}:root"),
        (principals.SERVICE, "ec2.amazonaws.com"),
        (principals.FEDERATED, f"arn:aws:iam::{ACCOUNT}:saml-provider/Okta"),
    ]
    federation = next(p for p in found if p.from_kind == principals.FEDERATED)
    assert federation.kind == principals.KIND_FEDERATION


def test_a_deny_statement_names_nobody() -> None:
    """A deny narrows a door rather than opening one, and reading it as
    a principal would invent access that does not exist."""
    document = {
        "Statement": [
            {"Effect": "Deny", "Principal": {"AWS": f"arn:aws:iam::{OTHER}:root"}}
        ]
    }
    assert principals.principals(document) == []


def test_both_wildcard_forms_are_recorded_as_wildcard() -> None:
    for document in (
        {"Statement": [allow("*")]},
        {"Statement": [allow({"AWS": "*"})]},
    ):
        found = principals.principals(document)
        assert [p.from_kind for p in found] == [principals.WILDCARD]


def test_a_principal_named_twice_is_recorded_once() -> None:
    reference = f"arn:aws:iam::{OTHER}:root"
    document = {"Statement": [allow({"AWS": reference}), allow({"AWS": reference})]}
    assert len(principals.principals(document)) == 1


def test_nothing_is_read_from_a_document_that_is_not_one() -> None:
    for document in (None, "", [], {"Statement": "nonsense"}):
        assert principals.principals(document) == []


# What the importer writes when it reads those principals.


def test_one_row_per_principal_and_a_guest_for_the_external_account(
    client: TestClient, db: Session
) -> None:
    import_estate(
        client,
        db,
        {
            "RoleDetailList": [
                role_entry(
                    "deploy",
                    "AROADEPLOY0000000001",
                    trust(
                        allow({"AWS": f"arn:aws:iam::{OTHER}:root"}),
                        allow({"Service": "ec2.amazonaws.com"}),
                        allow("*"),
                    ),
                )
            ],
        },
    )
    rows = list(db.execute(select(ObservedRelationship)).scalars())
    assert sorted(row.from_kind for row in rows) == [
        principals.AWS,
        principals.SERVICE,
        principals.WILDCARD,
    ]
    # The external account becomes an identity, because a guest that can
    # assume a role here is a thing somebody has to own.
    guest = identity_named(db, f"arn:aws:iam::{OTHER}:root")
    assert guest.home == "other_tenant"
    assert guest.home_ref == OTHER
    assert guest.first_display_name == f"account {OTHER}"
    # A service principal and a wildcard name nobody to govern.
    for reference in ("ec2.amazonaws.com", "*"):
        assert (
            db.execute(
                select(Identity).where(Identity.external_id == reference)
            ).scalar_one_or_none()
            is None
        )


def test_a_federated_principal_is_a_federation_and_an_identity_provider(
    client: TestClient, db: Session
) -> None:
    issuer = f"arn:aws:iam::{ACCOUNT}:saml-provider/Okta"
    import_estate(
        client,
        db,
        {
            "RoleDetailList": [
                role_entry(
                    "federated",
                    "AROAFED00000000000001",
                    trust(allow({"Federated": issuer})),
                )
            ],
        },
    )
    row = db.execute(select(ObservedRelationship)).scalar_one()
    assert row.kind == principals.KIND_FEDERATION
    assert identity_named(db, issuer).home == "identity_provider"


# What an identity can actually reach, derived and never stored.


def test_a_direct_grant_is_held_now(client: TestClient, db: Session) -> None:
    import_estate(
        client,
        db,
        {"UserDetailList": [user_entry("holder", "AIDAHOLDER00000000001", admin=True)]},
    )
    found = reached_by(db, "AIDAHOLDER00000000001")
    assert len(found) == 1
    assert found[0].holds_now
    assert found[0].through == paths.VIA_DIRECT


def test_a_group_puts_a_membership_hop_in_the_path(
    client: TestClient, db: Session
) -> None:
    """The user holds nothing of its own, and the inventory has to show
    the administrator policy anyway."""
    import_estate(
        client,
        db,
        {
            "UserDetailList": [
                user_entry("member", "AIDAMEMBER00000000001", ["platform"])
            ],
            "GroupDetailList": [group_entry("platform", "AGPAPLATFORM000000001")],
        },
    )
    found = reached_by(db, "AIDAMEMBER00000000001")
    assert len(found) == 1
    assert found[0].holds_now
    assert found[0].through == paths.VIA_MEMBERSHIP
    assert [hop.via for hop in found[0].hops] == [
        paths.VIA_MEMBERSHIP,
        paths.VIA_DIRECT,
    ]
    assert found[0].hops[0].ref == "platform"


def test_an_assumable_role_is_access_the_identity_can_obtain(
    client: TestClient, db: Session
) -> None:
    """The heart of the subphase. This privilege appears nowhere in the
    user's own grants, and the user can take it at will."""
    import_estate(
        client,
        db,
        {
            "UserDetailList": [user_entry("caller", "AIDACALLER00000000001")],
            "RoleDetailList": [
                role_entry(
                    "admin-role",
                    "AROAADMIN00000000001",
                    trust(allow({"AWS": f"arn:aws:iam::{ACCOUNT}:user/caller"})),
                )
            ],
        },
    )
    found = reached_by(db, "AIDACALLER00000000001")
    holds_now, can_obtain = paths.split(found)
    assert holds_now == []
    assert len(can_obtain) == 1
    assert can_obtain[0].mode == "eligible"
    assert can_obtain[0].through == paths.VIA_TRUST
    assert can_obtain[0].hops[0].ref == "admin-role"


def test_an_account_wide_principal_reaches_every_identity_in_it(
    client: TestClient, db: Session
) -> None:
    import_estate(
        client,
        db,
        {
            "UserDetailList": [user_entry("anyone", "AIDAANYONE00000000001")],
            "RoleDetailList": [
                role_entry(
                    "shared",
                    "AROASHARED0000000001",
                    trust(allow({"AWS": f"arn:aws:iam::{ACCOUNT}:root"})),
                )
            ],
        },
    )
    assert [path.through for path in reached_by(db, "AIDAANYONE00000000001")] == [
        paths.VIA_TRUST
    ]


def test_a_chain_of_trust_is_followed_and_bounded(
    client: TestClient, db: Session
) -> None:
    """A role may trust a role. The walk follows it, and a cycle stops
    at the bound instead of running forever."""
    cycle = trust(
        allow({"AWS": f"arn:aws:iam::{ACCOUNT}:user/climber"}),
        allow({"AWS": f"arn:aws:iam::{ACCOUNT}:role/step-two"}),
    )
    second = trust(allow({"AWS": f"arn:aws:iam::{ACCOUNT}:role/step-one"}))
    import_estate(
        client,
        db,
        {
            "UserDetailList": [user_entry("climber", "AIDACLIMBER0000000001")],
            "RoleDetailList": [
                role_entry("step-one", "AROASTEPONE000000001", cycle),
                role_entry("step-two", "AROASTEPTWO000000001", second),
            ],
        },
    )
    found = reached_by(db, "AIDACLIMBER0000000001")
    assert {path.hops[-2].ref for path in found} == {"step-one", "step-two"}
    assert all(not path.holds_now for path in found)
    # Two hops is the bound, so no path is longer than trust, trust, and
    # the direct hop at the end.
    assert max(len(path.hops) for path in found) == 3


def test_a_wildcard_trust_is_not_a_path_for_anybody(
    client: TestClient, db: Session
) -> None:
    """Anyone at all is a finding, and turning it into a path for every
    identity would bury the real ones."""
    import_estate(
        client,
        db,
        {
            "UserDetailList": [user_entry("bystander", "AIDABYSTANDER00000001")],
            "RoleDetailList": [
                role_entry("open", "AROAOPEN000000000001", trust(allow("*")))
            ],
        },
    )
    assert reached_by(db, "AIDABYSTANDER00000001") == []


def test_nothing_is_written_by_asking(client: TestClient, db: Session) -> None:
    """The product's rule: nothing derived is stored."""
    import_estate(
        client,
        db,
        {
            "UserDetailList": [
                user_entry("reader", "AIDAREADER00000000001", ["platform"])
            ],
            "GroupDetailList": [group_entry("platform", "AGPAPLATFORM000000001")],
        },
    )
    before = len(list(db.execute(select(Grant)).scalars()))
    reached_by(db, "AIDAREADER00000000001")
    reached_by(db, "AIDAREADER00000000001")
    assert len(list(db.execute(select(Grant)).scalars())) == before
