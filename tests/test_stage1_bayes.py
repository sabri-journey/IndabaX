"""Stage 1 -- sequential Bayesian monitor: decay, hysteresis, and the two
weak/strong-signal calibration properties the config is built around."""

from __future__ import annotations

from defense.context import DecisionContext
from defense.models import CandidateAction, HistoryDigest, ProvenanceRecord
from defense.models import Provenance as WireProvenance
from defense.session_store import SessionState
from defense.stage1_bayes import cached_likelihoods, cached_thresholds, update
from defense.stage2_policy import Finding, PolicyVerdict

CONFIG = cached_thresholds()


def _ctx(*, provenance_records: tuple = ()) -> DecisionContext:
    action = CandidateAction(type="tool_call", tool="payment_confirm", arguments={"payment_id": "PAY-0001"})
    return DecisionContext(
        session_key="s1",
        step_id=1,
        user_goal="g",
        conversation=(),
        observation=None,
        candidate_action=action,
        policy_context={},
        provenance=provenance_records,
        history_digest=HistoryDigest(),
    )


def _untrusted_provenance_record() -> ProvenanceRecord:
    return ProvenanceRecord(
        id="p1",
        provenance=WireProvenance(
            source_type="email",
            source_id="EM-1",
            trust_level="untrusted_external",
            origin_actor="vendor",
            retrieved_via="email_read",
            sensitivity="internal",
        ),
    )


def _finding(reason_code: str, kind: str = "provenance_condition", severity: str = "high") -> Finding:
    return Finding(rule_id="R1", kind=kind, severity=severity, reason_code=reason_code, message="m")


def test_config_loads_with_expected_shape() -> None:
    likelihoods = cached_likelihoods()
    assert len(likelihoods) >= 8
    assert all(spec.likelihood_ratio > 1.0 for spec in likelihoods)
    assert CONFIG.decay_factor < 1.0
    assert CONFIG.hysteresis_consecutive_steps >= 1


def test_no_evidence_stays_near_prior() -> None:
    session = SessionState(session_key="s1")
    ctx = _ctx()
    result = update(ctx, session, PolicyVerdict())
    assert abs(result.risk - CONFIG.prior_p_compromised) < 0.02
    assert not result.hysteresis_met


def test_weak_untrusted_content_signal_alone_does_not_approach_threshold() -> None:
    session = SessionState(session_key="s1")
    ctx = _ctx(provenance_records=(_untrusted_provenance_record(),))
    result = update(ctx, session, PolicyVerdict())
    assert result.risk < 0.3
    assert not result.hysteresis_met


def test_strong_signal_requires_multiple_steps_to_meet_hysteresis() -> None:
    """A single strong-evidence step is not enough by itself -- both the
    threshold crossing AND N consecutive crossings are required."""
    session = SessionState(session_key="s1")
    ctx = _ctx()
    policy = PolicyVerdict(findings=(_finding("UNTRUSTED_INSTRUCTION_SOURCE"),))

    first = update(ctx, session, policy)
    assert not first.hysteresis_met, "one step alone must not satisfy hysteresis"

    results = [first]
    for _ in range(5):
        results.append(update(ctx, session, policy))
        if results[-1].hysteresis_met:
            break

    assert any(r.hysteresis_met for r in results), "sustained strong evidence should eventually meet hysteresis"
    met_index = next(i for i, r in enumerate(results) if r.hysteresis_met)
    assert met_index >= CONFIG.hysteresis_consecutive_steps - 1


def test_decay_lets_risk_fall_after_evidence_stops() -> None:
    session = SessionState(session_key="s1")
    ctx = _ctx()
    policy_hot = PolicyVerdict(findings=(_finding("UNTRUSTED_INSTRUCTION_SOURCE"),))
    for _ in range(4):
        update(ctx, session, policy_hot)
    peak = update(ctx, session, policy_hot).risk

    policy_clean = PolicyVerdict()
    risk = peak
    for _ in range(15):
        risk = update(ctx, session, policy_clean).risk

    assert risk < peak, "risk must decay back down once evidence stops arriving"


def test_hysteresis_streak_resets_on_a_clean_step() -> None:
    session = SessionState(session_key="s1")
    ctx = _ctx()
    hot = PolicyVerdict(findings=(_finding("UNTRUSTED_INSTRUCTION_SOURCE"),))
    clean = PolicyVerdict()

    update(ctx, session, hot)
    r2 = update(ctx, session, hot)
    assert r2.risk >= CONFIG.escalate_risk_threshold  # crossed once

    update(ctx, session, clean)  # streak-breaking step
    assert session.extra["bayes"]["streak"] == 0
