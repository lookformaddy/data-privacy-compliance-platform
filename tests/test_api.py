"""FastAPI suite — auto-skipped when FastAPI/httpx are not installed."""

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient  # noqa: E402

from privacy_platform.api import app  # noqa: E402

assert app is not None
client = TestClient(app)


def test_scan_endpoint_classifies_email_column():
    response = client.post("/scan", json={
        "records": [{"email": "a@example.com"}, {"email": "b@example.com"}],
    })
    assert response.status_code == 200
    columns = {c["field"]: c for c in response.json()["columns"]}
    assert columns["email"]["category"] == "email"


def test_consent_grant_then_check_roundtrip():
    grant = client.post("/consent/grant", json={
        "subject_id": "cust-api", "purpose": "marketing", "fields": ["email"],
    })
    assert grant.status_code == 200
    check = client.post("/consent/check", json={
        "subject_id": "cust-api", "purpose": "marketing", "field": "email",
    })
    assert check.json()["allowed"] is True


def test_audit_verify_endpoint_reports_intact_chain():
    response = client.get("/audit/verify")
    assert response.status_code == 200
    assert response.json()["intact"] is True
