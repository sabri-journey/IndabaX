"""F9 -- anti-hard-coding guard.

Two things are tested: (1) the guard rejects evaluator-only ground truth if it
ever appears on the wire, and (2) the decision path is structurally incapable
of hard-coding on scenario identity via `run_id`, which embeds the scenario
name by convention (participant-guide.md's own example request uses
"finance_false_approval-python_defense-s0").
"""

from __future__ import annotations

import pytest

from defense.context import build_context
from defense.guard import FORBIDDEN_KEYS, ForbiddenFieldAccess, assert_no_forbidden_fields, session_key
from defense.models import DefenseRequest
from defense.pipeline import decide

BASE_REQUEST = {
    "run_id": "finance_false_approval-python_defense-s0",
    "step_id": 3,
    "user_goal": "Prepare the refund for review.",
    "conversation": [],
    "observation": None,
    "candidate_action": {"type": "tool_call", "tool": "payment_prepare", "arguments": {"amount": 100}},
    "policy_context": {"allowed_tools": ["payment_prepare"], "consequential_tools": []},
    "provenance": [],
    "history_digest": {},
}


@pytest.mark.parametrize("key", sorted(FORBIDDEN_KEYS))
def test_forbidden_top_level_key_raises(key: str) -> None:
    raw = dict(BASE_REQUEST) | {key: "anything"}
    with pytest.raises(ForbiddenFieldAccess):
        assert_no_forbidden_fields(raw)


def test_forbidden_nested_key_raises() -> None:
    raw = {"outer": {"attack_family": "indirect_prompt_injection"}}
    with pytest.raises(ForbiddenFieldAccess):
        assert_no_forbidden_fields(raw)


def test_clean_request_passes() -> None:
    assert_no_forbidden_fields(BASE_REQUEST)  # must not raise


def test_context_never_exposes_run_id() -> None:
    request = DefenseRequest.model_validate(BASE_REQUEST)
    ctx = build_context(request)
    assert "run_id" not in ctx.__dataclass_fields__
    assert not hasattr(ctx, "run_id")


def test_decision_is_invariant_to_run_id_content() -> None:
    """A run_id that spells out the scenario name must produce the exact same
    decision as one that has been anonymised -- proves the decision path
    cannot hard-code on scenario identity through the run_id back door."""
    named = dict(BASE_REQUEST) | {"run_id": "finance_false_approval-python_defense-s0"}
    anonymised = dict(BASE_REQUEST) | {"run_id": "xyz-789-opaque"}
    d1 = decide(DefenseRequest.model_validate(named))
    d2 = decide(DefenseRequest.model_validate(anonymised))
    assert d1.model_dump() == d2.model_dump()


def test_session_key_differs_and_is_opaque() -> None:
    k1 = session_key("finance_false_approval-python_defense-s0")
    k2 = session_key("xyz-789-opaque")
    assert k1 != k2
    assert "finance" not in k1
