"""Alerts and their deliveries (1.9): who was told, and did it arrive.

The two rules under test are the ones a mail server would tempt
somebody to break. A delivery that fails is recorded as failed and
never breaks the action that raised the alert, because an outage must
not stop an authorization from being written. And the recipient list is
bounded and deduplicated, because an alert that fans out to hundreds of
people has told nobody.

Everything else is the record: an authorization written or revoked
raises an alert with the administrators and the owner as recipients,
and the route reads it back with every delivery beside it.
"""

import json

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from manifest_identity.core import events
from manifest_identity.core.roles import Role
from manifest_identity.decide import alerts
from manifest_identity.models import Alert, AlertDelivery, Identity
from tests.conftest import ROLE_USERS, auth_header, login, make_user
from tests.test_governance import admin_policy, user_entry

ADMIN_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"


class FailingDeliverer:
    channel = "broken"

    def deliver(self, alert: Alert, recipient: str) -> str:
        raise ConnectionError("the mail server is down")


def seed(client: TestClient, db: Session) -> tuple[str, Identity]:
    make_user(db, Role.administrator)
    token = login(client, ROLE_USERS[Role.administrator])
    payload = {
        "UserDetailList": [user_entry("told", "AIDAALERT000000000001", privileged=True)],
        "Policies": [admin_policy()],
    }
    response = client.post(
        "/imports/authorization-details",
        headers=auth_header(token),
        files={"file": ("d.json", json.dumps(payload).encode(), "application/json")},
        data={"captured_at": "2026-08-01T00:00:00+00:00"},
    )
    assert response.status_code == 201, response.text
    identity = db.execute(
        select(Identity).where(Identity.external_id == "AIDAALERT000000000001")
    ).scalar_one()
    return token, identity


def authorize(client: TestClient, token: str, identity_id: int) -> dict[str, object]:
    response = client.post(
        f"/identities/{identity_id}/authorizations",
        headers=auth_header(token),
        json={
            "role_definition_external_id": ADMIN_ARN,
            "path": [{"via": "direct", "ref": "", "mode": "active"}],
            "owner_kind": "team",
            "owner_ref": "platform-team",
            "justification": "the platform team administers this account",
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def alerts_of(db: Session, kind: str) -> list[Alert]:
    return list(db.execute(select(Alert).where(Alert.event_kind == kind)).scalars())


def deliveries_of(db: Session, alert: Alert) -> list[AlertDelivery]:
    return list(
        db.execute(select(AlertDelivery).where(AlertDelivery.alert_id == alert.id)).scalars()
    )


def test_writing_an_authorization_tells_the_administrators_and_the_owner(
    client: TestClient, db: Session
) -> None:
    token, identity = seed(client, db)
    authorize(client, token, identity.id)
    raised = alerts_of(db, alerts.AUTHORIZATION_WRITTEN)
    assert len(raised) == 1
    recipients = {d.recipient for d in deliveries_of(db, raised[0])}
    assert ROLE_USERS[Role.administrator] in recipients
    assert "platform-team" in recipients
    assert all(d.result == alerts.RESULT_RECORDED for d in deliveries_of(db, raised[0]))
    assert all(d.channel == alerts.CHANNEL_RECORD for d in deliveries_of(db, raised[0]))


def test_revoking_an_authorization_raises_its_own_alert(
    client: TestClient, db: Session
) -> None:
    token, identity = seed(client, db)
    written = authorize(client, token, identity.id)
    response = client.post(
        f"/authorizations/{written['id']}/revoke",
        headers=auth_header(token),
        json={"reason": "the team no longer administers this account"},
    )
    assert response.status_code == 201, response.text
    raised = alerts_of(db, alerts.AUTHORIZATION_REVOKED)
    assert len(raised) == 1
    assert "no longer administers" in (raised[0].detail or "")


def test_a_failed_delivery_is_recorded_as_failed_and_the_action_still_lands(
    client: TestClient, db: Session
) -> None:
    """The mail server is down. The authorization is still written, the
    alert is still raised, and every delivery says it failed and why."""
    token, identity = seed(client, db)
    alerts.set_deliverer(FailingDeliverer())
    try:
        written = authorize(client, token, identity.id)
    finally:
        alerts.set_deliverer(alerts.RecordingDeliverer())
    assert written["status"] == "authorized"
    raised = alerts_of(db, alerts.AUTHORIZATION_WRITTEN)
    assert len(raised) == 1
    rows = deliveries_of(db, raised[0])
    assert rows, "the alert reached nobody and recorded nothing"
    assert all(row.result == alerts.RESULT_FAILED for row in rows)
    assert all("mail server is down" in (row.detail or "") for row in rows)
    assert all(row.channel == "broken" for row in rows)


def test_recipients_are_deduplicated_and_bounded(client: TestClient, db: Session) -> None:
    make_user(db, Role.administrator)
    administrator = ROLE_USERS[Role.administrator]
    crowd = [f"person-{n:03d}" for n in range(50)]
    recipients = alerts.recipients_for(db, administrator, "owner", "owner", *crowd)
    assert recipients[0] == administrator
    assert recipients.count(administrator) == 1
    assert recipients.count("owner") == 1
    assert len(recipients) == alerts.MAX_RECIPIENTS


def test_an_unknown_event_kind_is_refused(client: TestClient, db: Session) -> None:
    """The vocabulary is closed on purpose: a page filters by it."""
    try:
        alerts.raise_alert(
            db, event_kind="something_happened", subject_kind="identity",
            subject_ref="1", detail=None, recipients=[],
        )
    except ValueError as refusal:
        assert "not an event kind" in str(refusal)
    else:
        raise AssertionError("an unknown event kind was accepted")


def test_the_route_reads_alerts_newest_first_with_their_deliveries(
    client: TestClient, db: Session
) -> None:
    token, identity = seed(client, db)
    written = authorize(client, token, identity.id)
    client.post(
        f"/authorizations/{written['id']}/revoke",
        headers=auth_header(token),
        json={"reason": "reading it back"},
    )
    body = client.get("/alerts", headers=auth_header(token)).json()
    assert [row["event_kind"] for row in body[:2]] == [
        alerts.AUTHORIZATION_REVOKED, alerts.AUTHORIZATION_WRITTEN
    ]
    assert body[0]["deliveries"], "the route dropped the deliveries"
    assert {d["result"] for d in body[0]["deliveries"]} == {alerts.RESULT_RECORDED}


def test_a_reviewer_may_read_alerts(client: TestClient, db: Session) -> None:
    seed(client, db)
    make_user(db, Role.reviewer)
    reviewer = login(client, ROLE_USERS[Role.reviewer])
    assert client.get("/alerts", headers=auth_header(reviewer)).status_code == 200


def test_an_announcement_nothing_answers_is_refused_not_dropped(
    monkeypatch: pytest.MonkeyPatch, db: Session,
) -> None:
    """D-096: a dropped announcement is an alert that never fired."""


    monkeypatch.setattr(events, "_listeners", {})
    with pytest.raises(RuntimeError, match="nothing listens"):
        events.announce(db, events.AuthorizationChange(
            kind="authorization_written", authorization_id=1, summary="s", owners=(None, None),
        ))


def test_registering_a_listener_twice_keeps_one(monkeypatch: pytest.MonkeyPatch) -> None:


    monkeypatch.setattr(events, "_listeners", {})
    events.listen("authorization_written", alerts._on_authorization_change)
    events.listen("authorization_written", alerts._on_authorization_change)
    assert len(events._listeners["authorization_written"]) == 1

