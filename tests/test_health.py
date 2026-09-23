"""The two health routes: liveness unconditional, readiness truthful."""

import pytest
from fastapi.testclient import TestClient

from manifest_identity import main as main_module


def test_liveness_is_ok(client: TestClient) -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_readiness_ok_with_a_database(client: TestClient) -> None:
    response = client.get("/health/database")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_readiness_reports_unavailable(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(main_module, "database_reachable", lambda: False)
    response = client.get("/health/database")
    assert response.status_code == 503
    # No failure detail in the body, only availability.
    assert response.json() == {"status": "unavailable"}
