"""The audit trail is tamper-evident (issue 39).

Every row hashes its content and the previous row's hash; a row
altered or removed by an actor with owner access breaks every hash
after it, and the walk names the first bad row. The evidence export
carries the chain head, so a copy held outside the database anchors
the trail against alteration after the export.
"""

import sys

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from manifest_identity.core import audit, verify_chain
from manifest_identity.core.roles import Role
from manifest_identity.models import AuditEvent
from manifest_identity.sample_data import GENERATIONS, file_set
from tests.conftest import auth_header, login, make_user


def _write(db: Session, n: int) -> None:
    for i in range(n):
        audit.record(db, actor_username="tester", action="probe", target=f"t{i}")
    db.commit()


def test_rows_chain_and_an_intact_trail_verifies(client: TestClient, db: Session) -> None:
    _write(db, 3)
    rows = list(db.execute(select(AuditEvent).order_by(AuditEvent.id)).scalars())
    assert rows[0].prev_hash == audit.GENESIS
    assert rows[1].prev_hash == rows[0].row_hash
    assert rows[2].prev_hash == rows[1].row_hash
    result = audit.verify(db)
    assert result.ok and result.first_bad_id is None
    assert result.head == rows[-1].row_hash


def test_an_altered_row_is_detected_and_named(client: TestClient, db: Session) -> None:
    _write(db, 3)
    middle = db.execute(select(AuditEvent).order_by(AuditEvent.id)).scalars().all()[1]
    # Tamper the way an owner would: straight SQL, past the ORM and
    # past the application role that cannot delete or alter rows.
    db.execute(text("UPDATE audit_events SET detail = 'rewritten' WHERE id = :id"),
               {"id": middle.id})
    db.commit()
    db.expire_all()
    result = audit.verify(db)
    assert not result.ok and result.first_bad_id == middle.id


def test_a_removed_row_is_detected_by_the_row_after_it(client: TestClient, db: Session) -> None:
    _write(db, 3)
    rows = db.execute(select(AuditEvent).order_by(AuditEvent.id)).scalars().all()
    db.execute(text("DELETE FROM audit_events WHERE id = :id"), {"id": rows[1].id})
    db.commit()
    db.expire_all()
    result = audit.verify(db)
    assert not result.ok and result.first_bad_id == rows[2].id


def test_the_evidence_export_anchors_the_chain_head(client: TestClient, db: Session) -> None:
    token = login(client, make_user(db, Role.administrator))
    files = file_set()
    day = GENERATIONS[-1].strftime("%Y-%m-%d")
    for route, name in (("credential-report", f"{day}-credential-report.csv"),
                        ("authorization-details", f"{day}-authorization-details.json")):
        imported = client.post(f"/imports/{route}",
                               files={"file": (name, files[name].encode(), "text/plain")},
                               data={"captured_at": GENERATIONS[-1].isoformat()},
                               headers=auth_header(token))
        assert imported.status_code == 201, imported.text
    created = client.post(
        "/campaigns",
        json={"name": "anchor", "scope": "everything", "due_at": "2026-12-31T00:00:00+00:00"},
        headers=auth_header(token),
    )
    assert created.status_code == 201, created.text
    export = client.get(f"/campaigns/{created.json()['id']}/evidence",
                        headers=auth_header(token)).json()
    assert export["audit_chain_head"] == audit.chain_head(db)
    assert len(export["audit_chain_head"]) == 64
    # Each export records itself first (D-089), so each file anchors the
    # head as it stood after its own disclosure.
    csv_body = client.get(f"/campaigns/{created.json()['id']}/evidence.csv",
                          headers=auth_header(token)).text
    assert "audit_chain_head," + audit.chain_head(db) in csv_body


def _verify(monkeypatch: pytest.MonkeyPatch, *args: str) -> int:
    """Run the offline verifier the way an operator does, by its command line."""
    monkeypatch.setattr(sys, "argv", ["verify_chain", *args])
    return verify_chain.main()


def test_the_verifier_passes_an_intact_trail_and_its_own_head(
    client: TestClient, db: Session, monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _write(db, 3)
    rows = audit.verify(db).rows
    assert _verify(monkeypatch) == 0
    assert f"audit chain intact, {rows} rows" in capsys.readouterr().out
    assert _verify(monkeypatch, "--anchor", audit.chain_head(db)) == 0
    assert "intact through the anchor" in capsys.readouterr().out


def test_the_verifier_refuses_an_anchor_the_trail_does_not_reach(
    client: TestClient, db: Session, monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The anchor is a head copied out in an evidence export; a trail
    that no longer reaches it was altered after the export."""
    _write(db, 2)
    assert _verify(monkeypatch, "--anchor", "0" * 64) == 1
    assert "does not reach the anchored head" in capsys.readouterr().err


def test_the_verifier_fails_a_tampered_trail_and_names_the_row(
    client: TestClient, db: Session, monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _write(db, 3)
    middle = db.execute(select(AuditEvent).order_by(AuditEvent.id)).scalars().all()[1]
    db.execute(text("UPDATE audit_events SET detail = 'rewritten' WHERE id = :id"),
               {"id": middle.id})
    db.commit()
    db.expire_all()
    assert _verify(monkeypatch) == 1
    assert f"audit chain broken at row {middle.id}" in capsys.readouterr().err

