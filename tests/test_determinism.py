"""Build brief SS1.4: same input -> byte-identical decision, every time."""

from __future__ import annotations

import json

from defense.models import DefenseRequest
from defense.pipeline import decide

REQUEST = {
    "run_id": "r1",
    "step_id": 1,
    "user_goal": "Read the ticket and summarise it.",
    "conversation": [],
    "observation": None,
    "candidate_action": {"type": "tool_call", "tool": "ticket_read", "arguments": {"ticket_id": "T-1"}},
    "policy_context": {"allowed_tools": ["ticket_read"], "consequential_tools": []},
    "provenance": [],
    "history_digest": {},
}


def test_repeated_calls_are_byte_identical() -> None:
    request = DefenseRequest.model_validate(REQUEST)
    outputs = [json.dumps(decide(request).model_dump(), sort_keys=True) for _ in range(5)]
    assert len(set(outputs)) == 1
