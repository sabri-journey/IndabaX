"""Wires stage0 -> stage1 -> stage2 -> stage3 into one decision call.

This is the only function `adapter.py` calls into the decision path with. It
takes the wire-level `DefenseRequest` and immediately narrows it to
`DecisionContext` (see context.py) -- nothing past that point can see the raw
run_id, so the anti-hard-coding guard (F9) holds structurally, not just by
convention.
"""

from __future__ import annotations

from defense.context import build_context
from defense.models import DefenseDecision, DefenseRequest
from defense.stage0_normalise import normalise
from defense.stage1_bayes import update as bayes_update
from defense.stage2_policy import evaluate as policy_evaluate
from defense.stage3_decide import arbitrate


def decide(request: DefenseRequest) -> DefenseDecision:
    ctx = build_context(request)
    ctx = normalise(ctx)
    policy = policy_evaluate(ctx)
    bayes = bayes_update(ctx)
    return arbitrate(ctx, policy, bayes)
