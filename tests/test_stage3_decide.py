"""Stage 3 -- decision arbitration decision table."""

from __future__ import annotations

from defense.context import DecisionContext
from defense.models import CandidateAction, HistoryDigest
from defense.stage1_bayes import BayesResult
from defense.stage2_policy import Finding, PolicyVerdict
from defense.stage3_decide import arbitrate

NO_BAYES = BayesResult(risk=0.0, confidence=0.5)


def _tool_call_ctx() -> DecisionContext:
    action = CandidateAction(type="tool_call", tool="payment_confirm", arguments={"payment_id": "PAY-0001"})
    return DecisionContext(
        session_key="s1",
        step_id=1,
        user_goal="g",
        conversation=(),
        observation=None,
        candidate_action=action,
        policy_context={},
        provenance=(),
        history_digest=HistoryDigest(),
    )


def _request_confirmation_ctx() -> DecisionContext:
    target = CandidateAction(type="tool_call", tool="payment_confirm", arguments={"payment_id": "PAY-0001"})
    wrapper = CandidateAction(type="request_confirmation", confirmation_for=target)
    return DecisionContext(
        session_key="s1",
        step_id=1,
        user_goal="g",
        conversation=(),
        observation=None,
        candidate_action=wrapper,
        policy_context={},
        provenance=(),
        history_digest=HistoryDigest(),
    )


def test_no_findings_allows() -> None:
    decision = arbitrate(_tool_call_ctx(), PolicyVerdict(findings=()), NO_BAYES)
    assert decision.decision == "allow"


def test_hard_critical_finding_blocks() -> None:
    finding = Finding("R1", "tool_permission", "critical", "TOOL_NOT_REQUIRED_FOR_GOAL", "msg")
    decision = arbitrate(_tool_call_ctx(), PolicyVerdict(findings=(finding,)), NO_BAYES)
    assert decision.decision == "block"
    assert decision.risk_score >= 0.9


def test_hard_low_severity_finding_escalates_not_blocks() -> None:
    finding = Finding("R1", "sensitive_sink", "low", "SOME_CODE", "msg")
    decision = arbitrate(_tool_call_ctx(), PolicyVerdict(findings=(finding,)), NO_BAYES)
    assert decision.decision == "escalate"


def test_confirmation_only_on_tool_call_escalates() -> None:
    finding = Finding("GEN-CONSEQUENTIAL-APPROVAL", "consequential_approval", "critical", "MISSING_CONFIRMATION", "msg")
    decision = arbitrate(_tool_call_ctx(), PolicyVerdict(findings=(finding,)), NO_BAYES)
    assert decision.decision == "escalate"


def test_confirmation_only_on_request_confirmation_wrapper_allows() -> None:
    """Allowing the wrapper is what makes the harness ask the simulated
    human for the target action -- mirrors the shipped `provenance`
    baseline's handling of this action shape."""
    finding = Finding("GEN-CONSEQUENTIAL-APPROVAL", "consequential_approval", "critical", "MISSING_CONFIRMATION", "msg")
    decision = arbitrate(_request_confirmation_ctx(), PolicyVerdict(findings=(finding,)), NO_BAYES)
    assert decision.decision == "allow"
    assert "CONFIRMATION_REQUESTED" in decision.reason_codes


def test_mixed_hard_and_confirmation_findings_blocks() -> None:
    hard = Finding("GEN-INSTRUCTION-MIRRORS-UNTRUSTED", "instruction_mirrors_untrusted", "high", "UNTRUSTED_INSTRUCTION_SOURCE", "msg")
    confirm = Finding("GEN-CONSEQUENTIAL-APPROVAL", "consequential_approval", "critical", "MISSING_CONFIRMATION", "msg")
    decision = arbitrate(_tool_call_ctx(), PolicyVerdict(findings=(hard, confirm)), NO_BAYES)
    assert decision.decision == "block"


def test_reason_codes_are_valid_upper_snake_case() -> None:
    import re

    finding = Finding("R1", "tool_permission", "critical", "TOOL_NOT_REQUIRED_FOR_GOAL", "msg")
    decision = arbitrate(_tool_call_ctx(), PolicyVerdict(findings=(finding,)), NO_BAYES)
    for code in decision.reason_codes:
        assert re.fullmatch(r"[A-Z][A-Z0-9_]{1,63}", code), code
