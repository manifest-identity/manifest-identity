"""Rejected input never comes back (D-089): every door that accepts a
file is sent one carrying a marker string in a shape it rejects, and
the marker reaches no response, no audit record, and no log line,
because rejected input can carry a live credential."""

import logging

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from manifest_identity.core.roles import Role
from manifest_identity.models import AuditEvent
from tests.conftest import ROLE_USERS, auth_header, login, make_user
from tests.test_matrix import CALL_PLANS

MARKER = "AKIAMARKER0000REJECT"
DOORS = sorted(k for k, plan in CALL_PLANS.items() if k.startswith("POST ") and "files" in plan[2])
BAD = [
    ("json", ('{"' + MARKER + '": [1, 2,').encode()),
    ("csv", ("a,b\n" + MARKER + ',"unterminated\n').encode()),
    ("binary", b"\x00\xff" + MARKER.encode() + b"\xfe"),
]


def test_there_are_doors_to_test() -> None:
    assert len(DOORS) >= 9, DOORS


@pytest.mark.parametrize("door", DOORS)
@pytest.mark.parametrize("shape", [b[0] for b in BAD])
def test_a_rejected_file_never_comes_back(
    client: TestClient, db: Session, caplog: pytest.LogCaptureFixture, door: str, shape: str
) -> None:
    make_user(db, Role.administrator)
    token = login(client, ROLE_USERS[Role.administrator])
    method, path, kwargs = CALL_PLANS[door]
    name, _, kind = kwargs["files"]["file"]
    content = dict(BAD)[shape]
    call = {**kwargs, "files": {"file": (name, content, kind)}}
    with caplog.at_level(logging.DEBUG):
        response = getattr(client, method)(path, headers=auth_header(token), **call)
    assert response.status_code >= 400, f"{door} accepted a {shape} file it should refuse"
    assert MARKER not in response.text
    assert MARKER not in caplog.text
    assert not db.execute(
        select(AuditEvent).where(
            or_(AuditEvent.detail.contains(MARKER), AuditEvent.target.contains(MARKER))
        )
    ).first()
