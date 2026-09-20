"""End-to-end smoke test: the wire contract round-trips through the adapter.

This is what `sentinel run --defense-url http://127.0.0.1:8080` exercises for
real; the TestClient here proves the same path without needing a live server.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from defense.adapter import app

client = TestClient(app, raise_server_exceptions=False)


def test_healthz() -> None:
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_decision_allows_stub() -> None:
    payload = {
        "run_id": "smoke-test-s0",
        "step_id": 1,
        "user_goal": "Read a ticket.",
        "candidate_action": {"type": "tool_call", "tool": "ticket_read", "arguments": {"ticket_id": "T-1"}},
        "policy_context": {"allowed_tools": ["ticket_read"]},
    }
    response = client.post("/v1/decision", json=payload)
    assert response.status_code == 200
    body = response.json()
    assert body["decision"] == "allow"
    assert 0.0 <= body["risk_score"] <= 1.0
    assert 0.0 <= body["confidence"] <= 1.0


def test_forbidden_field_on_the_wire_fails_loudly() -> None:
    payload = {
        "run_id": "smoke-test-s1",
        "step_id": 1,
        "user_goal": "x",
        "candidate_action": {"type": "respond", "content": "hi", "final": True},
        "attack_family": "indirect_prompt_injection",
    }
    response = client.post("/v1/decision", json=payload)
    assert response.status_code == 500
