"""Stage 3 -- decision arbitration (v2: policy + rewrite catalogue + Bayes/hysteresis).

Decision table:
  - no stage-2 findings on THIS action, but stage
    1's posterior has cleared (risk, confidence)
    for `hysteresis_consecutive_steps` in a row,
    AND the action is consequential-or-sink (UER
    guard, F3)                                     -> ESCALATE
    (SEQ_RISK_ACCUMULATION: a per-action review
    would have allowed this; the session-level
    posterior is what catches a fragmented/
    multi-step/adaptive attack)
  - no findings and no hysteresis-confirmed
    session risk                                    -> ALLOW
  - any "hard" finding (not just missing
    approval -- see stage2_policy.CONFIRMATION_KINDS)
    at severity high/critical, AND a rewrite in
    config/rewrites.yaml fully addresses every
    current finding                                 -> REWRITE (F2: "rewrite
                                                        is our highest-value
                                                        lever for Precision;
                                                        treat BLOCK as a last
                                                        resort")
  - ... same, but no rewrite fully addresses it     -> BLOCK
  - only confirmation-kind findings remain, and
    the candidate action is a plain tool_call       -> ESCALATE (this is what
                                                        makes the harness ask
                                                        the simulated human)
  - only confirmation-kind findings remain, and
    the candidate action is itself a
    request_confirmation wrapper                    -> ALLOW (allowing the
                                                        wrapper is what makes
                                                        the harness ask the
                                                        simulated human for
                                                        *that* action; mirrors
                                                        the shipped `provenance`
                                                        baseline's handling of
                                                        this action shape)
  - only low/medium hard findings remain            -> ESCALATE (never
                                                        silently allow a real
                                                        finding, but don't
                                                        block on weak
                                                        evidence either)

In every branch where stage 2 *did* find something, `bayes.risk` only nudges
the reported `risk_score` upward (`max(severity_risk, bayes.risk)`) -- the
decision *kind* is still driven by the deterministic policy findings. The
Bayesian signal only drives the decision kind by itself in the first branch
above, precisely because that is the one case a per-action policy review
cannot cover at all.
"""

from __future__ import annotations

from defense.capabilities import default_registry
from defense.context import DecisionContext
from defense.models import DefenseDecision
from defense.provenance import target_action
from defense.rewrites import propose_rewrite
from defense.stage1_bayes import BayesResult, cached_thresholds
from defense.stage2_policy import PolicyVerdict

SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}
SEVERITY_RISK = {"low": 0.35, "medium": 0.55, "high": 0.8, "critical": 0.95}
REWRITE_RISK_CAP = 0.6
MAX_REASON_CODES = 16
MAX_EXPLANATION_CHARS = 500


def _reason_codes(findings) -> list[str]:
    return sorted({f.reason_code for f in findings})[:MAX_REASON_CODES]


def _explanation(findings) -> str | None:
    if not findings:
        return None
    text = "; ".join(f"{f.rule_id}: {f.message}" for f in findings)
    return text[:MAX_EXPLANATION_CHARS]


def _is_consequential_or_sink(ctx: DecisionContext) -> bool:
    target = target_action(ctx.candidate_action)
    if target.type != "tool_call" or target.tool is None:
        return False
    registry = default_registry()
    if target.tool not in registry:
        return False
    capability = registry.get(target.tool)
    return capability.is_consequential(target.arguments) or capability.sink


def arbitrate(ctx: DecisionContext, policy: PolicyVerdict, bayes: BayesResult) -> DefenseDecision:
    if not policy.findings:
        config = cached_thresholds()
        if bayes.hysteresis_met and (
            not config.bayes_escalation_requires_consequential_or_sink or _is_consequential_or_sink(ctx)
        ):
            return DefenseDecision(
                decision="escalate",
                risk_score=bayes.risk,
                confidence=bayes.confidence,
                reason_codes=["SEQ_RISK_ACCUMULATION", *bayes.reason_codes][:MAX_REASON_CODES],
                explanation="accumulated session risk crossed threshold across multiple steps; "
                "no single action triggered a policy rule",
            )
        return DefenseDecision(
            decision="allow",
            risk_score=round(bayes.risk, 4),
            confidence=max(bayes.confidence, 0.6),
            reason_codes=["POLICY_CLEAN"],
            explanation=None,
        )

    hard = policy.hard_findings
    confirmation_only = policy.confirmation_findings

    if hard:
        worst = max((f.severity for f in hard), key=lambda s: SEVERITY_RANK[s])
        risk = max(SEVERITY_RISK[worst], bayes.risk)
        if SEVERITY_RANK[worst] >= SEVERITY_RANK["high"]:
            rewrite = propose_rewrite(ctx, policy.findings)
            if rewrite is not None:
                return DefenseDecision(
                    decision="rewrite",
                    risk_score=round(min(risk, REWRITE_RISK_CAP), 4),
                    confidence=0.75,
                    reason_codes=_reason_codes(hard),
                    explanation=(f"{rewrite.rewrite_id}: {rewrite.removed}. " + (_explanation(hard) or ""))[
                        :MAX_EXPLANATION_CHARS
                    ],
                    rewritten_action=rewrite.rewritten,
                    metadata={"rewrite_id": rewrite.rewrite_id, "removed": rewrite.removed},
                )
            return DefenseDecision(
                decision="block",
                risk_score=round(risk, 4),
                confidence=0.8,
                reason_codes=_reason_codes(hard),
                explanation=_explanation(hard),
            )
        # low/medium hard findings only: real evidence, but not strong enough
        # to block outright -- escalate rather than silently allow.
        return DefenseDecision(
            decision="escalate",
            risk_score=round(risk, 4),
            confidence=0.6,
            reason_codes=_reason_codes(hard),
            explanation=_explanation(hard),
        )

    # Only confirmation-kind findings remain (consequential_approval /
    # forced_confirmation): the action is otherwise clean, it just has no
    # recorded human approval yet.
    risk = max(0.5, bayes.risk)
    if ctx.candidate_action.type == "request_confirmation":
        return DefenseDecision(
            decision="allow",
            risk_score=round(risk, 4),
            confidence=0.7,
            reason_codes=["CONFIRMATION_REQUESTED", *_reason_codes(confirmation_only)],
            explanation=_explanation(confirmation_only),
        )
    return DefenseDecision(
        decision="escalate",
        risk_score=round(risk, 4),
        confidence=0.7,
        reason_codes=_reason_codes(confirmation_only),
        explanation=_explanation(confirmation_only),
    )
