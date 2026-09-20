"""Stage 1 -- sequential Bayesian monitor over session risk.

TODO (build step 6): maintain a posterior over `session_is_compromised`, keyed
by `DecisionContext.session_key` (never the raw run_id -- see guard.py),
updated per observation and per candidate action using likelihood ratios
declared in config/likelihoods.yaml. Must include decay so an old, resolved
suspicion doesn't poison a long benign session. `history_digest` in the wire
contract only ever reflects the current turn (verified against
agent/reference.py in the simulator: `_turn_provenance` resets per turn), so
this stage's own persistent session store is what actually gives us
cross-turn/adaptive-attack coverage -- it is not redundant with anything the
simulator already computes for us.

Currently a flat, uninformative posterior so the pipeline is wired end-to-end
before any real logic lands.
"""

from __future__ import annotations

from dataclasses import dataclass

from defense.context import DecisionContext


@dataclass(frozen=True)
class BayesResult:
    risk: float
    confidence: float
    reason_codes: tuple[str, ...] = ()


def update(ctx: DecisionContext) -> BayesResult:
    """No-op until build step 6: flat, uninformative posterior."""
    return BayesResult(risk=0.0, confidence=0.5)
