"""Action digest: determinism/whitespace-canonicalisation, and (when the
starter kit is on disk) byte-for-byte equality with the harness's own
sentinel.core.actions.CandidateAction.digest() -- see digest.py's docstring
for why a mismatch here would be a serious, silent correctness bug."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from defense.digest import action_digest
from defense.models import CandidateAction


def test_digest_is_deterministic() -> None:
    action = CandidateAction(type="tool_call", tool="payment_confirm", arguments={"payment_id": "PAY-0001"})
    assert action_digest(action) == action_digest(action)


def test_digest_ignores_argument_order() -> None:
    a = CandidateAction(type="tool_call", tool="payment_prepare", arguments={"amount": 100, "account_id": "ACC-1"})
    b = CandidateAction(type="tool_call", tool="payment_prepare", arguments={"account_id": "ACC-1", "amount": 100})
    assert action_digest(a) == action_digest(b)


def test_digest_canonicalises_whitespace_in_strings() -> None:
    a = CandidateAction(type="tool_call", tool="case_note_create", arguments={"text": "hello   world"})
    b = CandidateAction(type="tool_call", tool="case_note_create", arguments={"text": "hello world"})
    assert action_digest(a) == action_digest(b)


def test_digest_differs_for_different_arguments() -> None:
    a = CandidateAction(type="tool_call", tool="payment_confirm", arguments={"payment_id": "PAY-0001"})
    b = CandidateAction(type="tool_call", tool="payment_confirm", arguments={"payment_id": "PAY-0002"})
    assert action_digest(a) != action_digest(b)


def test_digest_covers_confirmation_for() -> None:
    target = CandidateAction(type="tool_call", tool="payment_confirm", arguments={"payment_id": "PAY-0001"})
    wrapper = CandidateAction(type="request_confirmation", confirmation_for=target)
    other_target = CandidateAction(type="tool_call", tool="payment_confirm", arguments={"payment_id": "PAY-0002"})
    other_wrapper = CandidateAction(type="request_confirmation", confirmation_for=other_target)
    assert action_digest(wrapper) != action_digest(other_wrapper)


STARTER_KIT_SRC = Path.home() / "Sentinel_Starter_Kit" / "src"


def test_matches_simulator_digest_algorithm() -> None:
    if not STARTER_KIT_SRC.is_dir():
        pytest.skip("starter kit not found on disk; skipping cross-check")
    if str(STARTER_KIT_SRC) not in sys.path:
        sys.path.insert(0, str(STARTER_KIT_SRC))
    try:
        from sentinel.core.actions import ActionType, CandidateAction as SimCandidateAction
    except Exception as exc:  # pragma: no cover - environment-dependent
        pytest.skip(f"starter kit present but not importable ({exc})")

    ours = CandidateAction(
        type="tool_call", tool="payment_execute", arguments={"payment_id": "PAY-0001", "amount": 1250.0}
    )
    theirs = SimCandidateAction(
        type=ActionType.TOOL_CALL, tool="payment_execute", arguments={"payment_id": "PAY-0001", "amount": 1250.0}
    )
    assert action_digest(ours) == theirs.digest()
