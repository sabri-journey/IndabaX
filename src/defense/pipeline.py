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
"""

from __future__ import annotations

from defense import ablation
from defense.context import build_context
from defense.models import DefenseDecision, DefenseRequest
from defense.session_store import default_store
from defense.stage0_normalise import normalise
from defense.stage1_bayes import BayesResult
from defense.stage1_bayes import update as bayes_update
from defense.stage2_policy import evaluate as policy_evaluate
from defense.stage3_decide import arbitrate

FLAT_BAYES = BayesResult(risk=0.0, confidence=0.5)


def decide(request: DefenseRequest) -> DefenseDecision:
    ctx = build_context(request)
    if ablation.normalisation_enabled():
        ctx = normalise(ctx)
    session = default_store().get_or_create(ctx.session_key)
    policy = policy_evaluate(ctx, session)
    bayes = bayes_update(ctx, session, policy) if ablation.bayes_enabled() else FLAT_BAYES
    return arbitrate(ctx, policy, bayes)
