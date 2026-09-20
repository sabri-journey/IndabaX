"""Stage 3 -- decision arbitration.

TODO (build step 6): combine `PolicyVerdict` + `BayesResult` + irreversibility
(config/capabilities.yaml, F1) into one of ALLOW/BLOCK/ESCALATE/REWRITE via an
explicit, documented decision table (not scattered ifs), preferring
rewrite > escalate > block whenever a rewrite genuinely removes the hazard
(config/rewrites.yaml, F2).

Currently a stub that allows everything, purely to prove the wire contract
end-to-end (`sentinel run --defense-url ...`) before any real decision logic
lands.
"""

from __future__ import annotations

from defense.context import DecisionContext
from defense.models import DefenseDecision
from defense.stage1_bayes import BayesResult
from defense.stage2_policy import PolicyVerdict


def arbitrate(ctx: DecisionContext, policy: PolicyVerdict, bayes: BayesResult) -> DefenseDecision:
    """Stub: allow everything. Build steps 4-6 replace this with the real table."""
    return DefenseDecision(
        decision="allow",
        risk_score=bayes.risk,
        confidence=bayes.confidence,
        reason_codes=["PIPELINE_STUB"],
        explanation="stub pipeline: stage0-3 rule/bayes logic not yet implemented, allowing by default",
    )
