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
"""

from __future__ import annotations

from defense.context import build_context
from defense.models import DefenseDecision, DefenseRequest
from defense.session_store import default_store
from defense.stage0_normalise import normalise
from defense.stage1_bayes import update as bayes_update
from defense.stage2_policy import evaluate as policy_evaluate
from defense.stage3_decide import arbitrate


def decide(request: DefenseRequest) -> DefenseDecision:
    ctx = build_context(request)
    ctx = normalise(ctx)
    session = default_store().get_or_create(ctx.session_key)
    policy = policy_evaluate(ctx, session)
    bayes = bayes_update(ctx, session, policy)
    return arbitrate(ctx, policy, bayes)
