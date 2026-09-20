"""Wires stage0 -> stage2 -> stage1 -> stage3 into one decision call.

This is the only function `adapter.py` calls into the decision path with. It
takes the wire-level `DefenseRequest` and immediately narrows it to
`DecisionContext` (see context.py) -- nothing past that point can see the raw
run_id, so the anti-hard-coding guard (F9) holds structurally, not just by
convention.

Session state (state_machine's tool-call log, and from build step 6 the
Bayesian posterior) is looked up here, once, by `ctx.session_key` -- an HTTP
defense is called stateless per step, so this is the one place that bridges
across calls for the same run (see session_store.py).

Every stage here checks `ablation.py`'s environment-variable toggles (F6) so
`scripts/run_ablation.py` can disable a whole component for a real,
end-to-end `sentinel eval` run without touching this module.

`decide_with_trace` additionally returns `TraceExtras` -- everything the
observability layer (F7, build step 8) wants beyond the wire-level
`DefenseDecision` (per-rule findings, raw-vs-visible text diffs, the
Bayesian internals) -- never part of the decision itself, purely for the
trace. `decide` is the thin wrapper the wire contract and the test suite
use; it is not a separate code path, so there is no risk of the two
diverging.
"""

from __future__ import annotations

from dataclasses import dataclass

from defense import ablation
from defense.context import DecisionContext, build_context
from defense.models import DefenseDecision, DefenseRequest
from defense.session_store import default_store
from defense.stage0_normalise import normalise
from defense.stage1_bayes import BayesResult
from defense.stage1_bayes import update as bayes_update
from defense.stage2_policy import evaluate as policy_evaluate
from defense.stage3_decide import arbitrate

FLAT_BAYES = BayesResult(risk=0.0, confidence=0.5)


@dataclass(frozen=True)
class TraceExtras:
    findings: tuple[dict, ...]
    normalisation_signals: tuple[str, ...]
    hidden_text_diffs: tuple[dict, ...]
    bayes_risk: float
    bayes_confidence: float
    bayes_reason_codes: tuple[str, ...]
    hysteresis_met: bool


def _hidden_text_diffs(raw_ctx: DecisionContext, normalised_ctx: DecisionContext) -> tuple[dict, ...]:
    diffs = []
    for raw_item, visible_item in zip(raw_ctx.conversation, normalised_ctx.conversation, strict=True):
        if raw_item.content != visible_item.content:
            diffs.append(
                {
                    "role": raw_item.role,
                    "kind": raw_item.kind,
                    "raw": raw_item.content,
                    "visible": visible_item.content,
                }
            )
    return tuple(diffs)


def decide_with_trace(request: DefenseRequest) -> tuple[DefenseDecision, TraceExtras]:
    raw_ctx = build_context(request)
    ctx = normalise(raw_ctx) if ablation.normalisation_enabled() else raw_ctx
    session = default_store().get_or_create(ctx.session_key)
    policy = policy_evaluate(ctx, session)
    bayes = bayes_update(ctx, session, policy) if ablation.bayes_enabled() else FLAT_BAYES
    decision = arbitrate(ctx, policy, bayes)

    extras = TraceExtras(
        findings=tuple(
            {
                "rule_id": f.rule_id,
                "kind": f.kind,
                "severity": f.severity,
                "reason_code": f.reason_code,
                "message": f.message,
            }
            for f in policy.findings
        ),
        normalisation_signals=ctx.normalisation_signals,
        hidden_text_diffs=_hidden_text_diffs(raw_ctx, ctx) if ablation.normalisation_enabled() else (),
        bayes_risk=bayes.risk,
        bayes_confidence=bayes.confidence,
        bayes_reason_codes=bayes.reason_codes,
        hysteresis_met=bayes.hysteresis_met,
    )
    return decision, extras


def decide(request: DefenseRequest) -> DefenseDecision:
    decision, _extras = decide_with_trace(request)
    return decision
