"""The seventh provider: an Active Directory domain on the neutral
tables, through two doors (D-083, D-084).

The cmdlet document and the collector's zip arrive as one parsed
domain, so one importer reads both and the assertions read the result
through the same routes: a user with a password, a service account
that carries a Kerberos key beside it, a computer that is a workload,
a group that reaches the domain's built-in privilege to its members
through every level of nesting, a foreign principal from another
domain on the record as external, a trust as a relationship, and, from
the second door alone, a control right as access the principal can
obtain without being a member.
"""

import io
import json
import zipfile

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from manifest_identity.compare import delta
from manifest_identity.core.roles import Role
from manifest_identity.models import Credential, Grant, Identity, ObservedRelationship, ScopeNode
from manifest_identity.observe import policy_analysis
from manifest_identity.observe.active_directory_importer import (
    group_capabilities,
    organizational_units,
)
from manifest_identity.observe.providers.active_directory import (
    directory_export as export,
)
from manifest_identity.observe.providers.active_directory import (
    sharphound_collection as collection,
)
from manifest_identity.sample_data import DOMAIN_SID, GENERATIONS, PARTNER_SID, file_set
from tests.conftest import ROLE_USERS, auth_header, login, make_user


def operator(client: TestClient, db: Session) -> str:
    make_user(db, Role.operator)
    return login(client, ROLE_USERS[Role.operator])


def import_generation(
    client: TestClient, token: str, generation: int, door: str = "active-directory"
) -> tuple[int, dict]:
    captured = GENERATIONS[generation]
    name = f"{captured.strftime('%Y-%m-%d')}-{door}.json"
    response = client.post(
        f"/imports/{door}",
        headers=auth_header(token),
        files={"file": (name, file_set()[name].encode(), "application/json")},
        data={"captured_at": captured.isoformat()},
    )
    return response.status_code, response.json()


def import_all(client: TestClient, token: str, door: str = "active-directory") -> None:
    for generation in range(len(GENERATIONS)):
        status, body = import_generation(client, token, generation, door)
        assert status == 201, body


def inventory(client: TestClient, token: str) -> dict[str, dict]:
    rows = client.get("/identities?limit=500", headers=auth_header(token)).json()["rows"]
    return {row["display_name"]: row for row in rows}


def detail(client: TestClient, token: str, identity_id: int) -> dict:
    return client.get(f"/identities/{identity_id}", headers=auth_header(token)).json()


def named(db: Session, name: str) -> Identity:
    return db.execute(select(Identity).where(Identity.first_display_name == name)).scalar_one()


# The parsers.

SID = "S-1-5-21-1-2-3"
USER = f"{SID}-1104"
GROUP = f"{SID}-512"


def minimal(**overrides: object) -> bytes:
    document: dict[str, object] = {
        "domain": {"DNSRoot": "acme.test", "NetBIOSName": "ACME", "DomainSID": SID},
        "users": [{"SID": USER, "SamAccountName": "alice",
                   "DistinguishedName": "CN=alice,OU=People,DC=acme,DC=test"}],
        "groups": [{"SID": GROUP, "SamAccountName": "Domain Admins",
                    "DistinguishedName": "CN=Domain Admins,CN=Users,DC=acme,DC=test",
                    "Members": [USER]}],
    }
    document.update(overrides)
    return json.dumps(document).encode()


def test_the_parser_reads_both_powershell_generations() -> None:
    parsed = export.parse_domain_export(minimal(
        users=[{"SID": {"Value": USER}, "SamAccountName": "alice",
                "DistinguishedName": "CN=alice,DC=acme,DC=test",
                "PasswordLastSet": "/Date(1700000000000)/", "LastLogonDate": "2026-01-02T03:04:05Z",
                "adminCount": 1, "Enabled": False}],
    ))
    user = parsed.users[0]
    assert user.sid == USER and user.enabled is False and user.admin_count is True
    assert user.password_last_set is not None and user.password_last_set.year == 2023
    assert user.last_logon is not None and user.last_logon.year == 2026
    assert parsed.netbios_name == "ACME"


@pytest.mark.parametrize(
    ("overrides", "rule"),
    [
        ({"domain": {"DNSRoot": "acme.test", "DomainSID": "S-1-5-32-544"}},
         "not a domain's identifier"),
        ({"users": [{"SID": "S-1-5-21-9-9-9-1", "SamAccountName": "bob",
                     "DistinguishedName": "CN=bob,DC=x"}]}, "domain the file does not describe"),
        ({"computers": [{"SID": f"{SID}-1300", "SamAccountName": "host",
                         "DistinguishedName": "CN=host,DC=x"}]}, "does not end the way"),
        ({"groups": [{"SID": GROUP, "SamAccountName": "alice",
                      "DistinguishedName": "CN=g,DC=x"}]}, "account name appears twice"),
        ({"groups": [{"SID": GROUP, "SamAccountName": "g", "DistinguishedName": "CN=g,DC=x",
                      "GroupScope": "Galactic"}]}, "GroupScope is not one"),
    ],
)
def test_a_document_that_breaks_the_directorys_rules_is_refused_without_echo(
    overrides: dict[str, object], rule: str
) -> None:
    with pytest.raises(export.ParseError) as caught:
        export.parse_domain_export(minimal(**overrides))
    message = str(caught.value)
    assert rule in message
    for value in ("S-1-5-21-9-9-9-1", "Galactic", "bob", "host"):
        assert value not in message


def test_organizational_units_read_outermost_first() -> None:
    assert organizational_units("CN=alice,OU=Interns,OU=People,DC=acme,DC=test") == [
        "People", "Interns",
    ]
    assert organizational_units("CN=Domain Admins,CN=Users,DC=acme,DC=test") == []
    assert organizational_units(r"CN=Smith\, Jane,OU=People,DC=acme,DC=test") == ["People"]


def sharphound_zip(generation: int = 0) -> bytes:
    """The collector's own form: one file per type, zipped."""
    day = GENERATIONS[generation].strftime("%Y-%m-%d")
    joined = json.loads(file_set()[f"{day}-sharphound.json"])
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for kind, document in joined.items():
            archive.writestr(f"20260601120000_{kind}.json", json.dumps(document))
        archive.writestr("20260601120000_gpos.json", json.dumps({"data": [], "meta": {}}))
    return buffer.getvalue()


def test_the_collectors_zip_and_the_joined_object_parse_the_same() -> None:
    from_zip = collection.parse_collection(sharphound_zip())
    from_json = collection.parse_collection(
        file_set()[f"{GENERATIONS[0].strftime('%Y-%m-%d')}-sharphound.json"].encode()
    )
    assert [u.sid for u in from_zip.users] == [u.sid for u in from_json.users]
    assert len(from_zip.aces) == len(from_json.aces) > 0
    assert from_zip.sid == DOMAIN_SID
    administrators = next(g for g in from_zip.groups if g.sam_account_name == "Administrators")
    assert administrators.sid == "S-1-5-32-544", "the domain prefix on a well-known SID is stripped"


@pytest.mark.parametrize(
    ("data", "rule"),
    [
        (json.dumps({"data": [], "meta": {"type": "users", "version": 6}}).encode(),
         "import the zip"),
        (json.dumps({"users": {"data": [], "meta": {"type": "users", "version": 6}}}).encode(),
         "must carry users and groups"),
        (json.dumps({"users": {"data": [], "meta": {"type": "groups", "version": 6}},
                     "groups": {"data": [], "meta": {"type": "groups", "version": 6}}}).encode(),
         "names another object type"),
        (json.dumps({"users": {"data": [], "meta": {"type": "users", "version": 2}},
                     "groups": {"data": [], "meta": {"type": "groups", "version": 6}}}).encode(),
         "format version"),
        (b"PK\x03\x04not really", "not a zip"),
    ],
)
def test_a_collection_that_is_not_one_is_refused_by_name(data: bytes, rule: str) -> None:
    with pytest.raises(collection.ParseError) as caught:
        collection.parse_collection(data)
    assert rule in str(caught.value)


# The capabilities.


def test_the_built_in_groups_read_from_the_table() -> None:
    assert group_capabilities(f"{SID}-512", "Domain Admins")["administers"] is True
    backup = group_capabilities("S-1-5-32-551", "Backup Operators")
    assert backup is not None
    assert backup["changes_access"] is True and backup["administers"] is False
    assert policy_analysis.read_policy(backup).iam_mutating
    printers = group_capabilities("S-1-5-32-550", "Print Operators")
    assert printers is not None
    assert printers["writes"] is True and printers["changes_access"] is False
    dns = group_capabilities(f"{SID}-1500", "DnsAdmins")
    assert dns is not None and dns["changes_access"] is True, "matched by name"
    assert group_capabilities(f"{SID}-1201", "engineering") is None


# The importer, first door.


def test_the_domain_becomes_the_neutral_rows(client: TestClient, db: Session) -> None:
    token = operator(client, db)
    status, body = import_generation(client, token, 0)
    assert status == 201, body
    assert body["account"] == "corp.example.test"
    rows = inventory(client, token)
    assert rows["sam.owner"]["identity_type"] == "user"
    assert rows["DC01$"]["identity_type"] == "computer"
    assert "Domain Admins" not in rows, "a group stays out of the inventory"
    groups = {g["name"]: g for g in client.get("/groups", headers=auth_header(token)).json()}
    assert groups["Domain Admins"]["privileged"] is True
    assert groups["Administrators"]["members"] == 3, "the nested group and its members, flattened"
    units = db.execute(
        select(ScopeNode.display_name).where(ScopeNode.kind == "organizational_unit")
    ).scalars().all()
    assert {"People", "Disabled", "Service Accounts", "Domain Controllers", "Servers"} <= set(units)


def test_credentials_follow_the_accounts_shape(client: TestClient, db: Session) -> None:
    token = operator(client, db)
    import_generation(client, token, 0)

    def credentials(name: str) -> list[Credential]:
        return db.execute(
            select(Credential).where(Credential.identity_id == named(db, name).id)
        ).scalars().all()

    sam = credentials("sam.owner")
    assert [c.kind for c in sam] == ["password"] and sam[0].active is True
    service = {c.kind: c for c in credentials("svc-backup")}
    assert set(service) == {"password", "kerberos_key"}
    assert service["kerberos_key"].external_id.startswith("MSSQLSvc/")
    assert detail(client, token, named(db, "svc-backup").id)["kind"] == "mixed"
    former = credentials("former.employee")
    assert former[0].active is False, "a disabled account's password is not live"
    machine = credentials("DC01$")
    assert [c.kind for c in machine] == ["kerberos_key"]
    assert detail(client, token, named(db, "DC01$").id)["kind"] == "service"


def test_nesting_reaches_the_members_with_the_holding_group_named(
    client: TestClient, db: Session
) -> None:
    token = operator(client, db)
    import_generation(client, token, 1)
    mike = detail(client, token, named(db, "legacy.mike").id)
    held = {(h["role"], tuple(x["ref"] for x in h["path"])) for h in mike["holds_now"]}
    assert ("Account Operators", ("Account Operators",)) in held, "through the outer group"
    sam = detail(client, token, named(db, "sam.owner").id)
    roles = {h["role"] for h in sam["holds_now"]}
    assert {"Domain Admins", "Administrators"} <= roles
    nestings = db.execute(
        select(ObservedRelationship).where(ObservedRelationship.kind == "group_nesting")
    ).scalars().all()
    assert {n.from_ref for n in nestings} == {"Domain Admins", "helpdesk"}


def test_a_foreign_principal_and_a_trust_are_on_the_record(
    client: TestClient, db: Session
) -> None:
    token = operator(client, db)
    import_generation(client, token, 2)
    foreign = named(db, f"{PARTNER_SID}-1500")
    assert foreign.kind == "external" and foreign.home == "other_tenant"
    assert "Administrators" in {
        h["role"] for h in detail(client, token, foreign.id)["holds_now"]
    }
    trust = db.execute(
        select(ObservedRelationship).where(ObservedRelationship.kind == "trust")
    ).scalar_one()
    assert trust.from_ref == "partner.example.test" and trust.document["direction"] == "Inbound"


def test_the_same_snapshot_twice_is_a_conflict_and_the_wrong_door_says_so(
    client: TestClient, db: Session
) -> None:
    token = operator(client, db)
    assert import_generation(client, token, 0)[0] == 201
    status, body = import_generation(client, token, 0)
    assert status == 409 and "already imported" in body["detail"]
    name = f"{GENERATIONS[0].strftime('%Y-%m-%d')}-active-directory.json"
    response = client.post(
        "/imports/sharphound",
        headers=auth_header(token),
        files={"file": (name, file_set()[name].encode(), "application/json")},
        data={"captured_at": GENERATIONS[0].isoformat()},
    )
    assert response.status_code == 422
    assert "shaped like an Active Directory domain export" in response.json()["detail"]
    response = client.post(
        "/imports/active-directory",
        headers=auth_header(token),
        files={"file": ("c.zip", sharphound_zip(), "application/zip")},
        data={"captured_at": GENERATIONS[0].isoformat()},
    )
    assert response.status_code == 422
    assert "shaped like a SharpHound collection" in response.json()["detail"]


# The second door.


def test_the_collector_adds_what_a_principal_can_obtain(client: TestClient, db: Session) -> None:
    token = operator(client, db)
    response = client.post(
        "/imports/sharphound",
        headers=auth_header(token),
        files={"file": ("c.zip", sharphound_zip(1), "application/zip")},
        data={"captured_at": GENERATIONS[1].isoformat()},
    )
    assert response.status_code == 201, response.json()
    mike = detail(client, token, named(db, "legacy.mike").id)
    obtainable = {(h["role"], h["mode"]) for h in mike["can_obtain"]}
    assert ("Domain Admins", "eligible") in obtainable, "through the help desk's AddMember right"
    assert "Domain Admins" not in {h["role"] for h in mike["holds_now"]}
    sync = detail(client, token, named(db, "sync.svc").id)
    assert {h["role"] for h in sync["can_obtain"]} == {"control of corp.example.test"}
    assert sync["holds_now"] == []
    rights = db.execute(
        select(Grant).where(Grant.source_kind == "control_right")
    ).scalars().all()
    assert all(not g.source_ref.startswith("WriteDacl") for g in rights), "inherited: not written"
    assert not any(
        g.identity_id == named(db, "Domain Admins").id for g in rights
    ), "a group that holds a definition standing is not written as able to obtain it"


def test_both_doors_land_on_one_estate(client: TestClient, db: Session) -> None:
    token = operator(client, db)
    import_all(client, token)
    import_all(client, token, "sharphound")
    domains = db.execute(select(ScopeNode).where(ScopeNode.kind == "domain")).scalars().all()
    assert len(domains) == 1
    assert len(db.execute(
        select(Identity).where(Identity.first_display_name == "sam.owner")
    ).scalars().all()) == 1, "the same identifier is the same identity through either door"


# The findings and the delta.


def test_the_sample_domain_produces_the_findings_it_was_built_for(
    client: TestClient, db: Session
) -> None:
    token = operator(client, db)
    import_all(client, token)
    rows = inventory(client, token)

    def codes(name: str) -> set[str]:
        return {f["code"] for f in detail(client, token, rows[name]["id"])["findings"]}

    assert "admin_equivalent" in codes("sam.owner")
    assert "admin_equivalent" in codes("nadia.dev"), "a domain administrator from the third month"
    assert {"iam_mutating", "unused_identity"} <= codes("legacy.mike")
    assert "iam_mutating" in codes("svc-backup"), "a backup operator can take every key"
    former = rows["former.employee"]
    assert former["critical"] == 0 and former["warning"] == 0, "disabled is quiet"
    reader = rows["audit.reader"]
    assert reader["critical"] == 0, "a remote management user reads"


def test_the_delta_names_what_nobody_authorized(client: TestClient, db: Session) -> None:
    token = operator(client, db)
    import_all(client, token, "sharphound")
    nadia = named(db, "nadia.dev")
    held = {f.role for f in delta.for_identity(db, nadia) if f.kind == delta.HELD_NOT_AUTHORIZED}
    assert f"ad:group:{DOMAIN_SID}-512" in held
    mike = named(db, "legacy.mike")
    kinds = {f.kind for f in delta.for_identity(db, mike)}
    assert delta.ELIGIBLE_NOT_AUTHORIZED in kinds, "the help desk's right, through the group"
