"""Stage 2 -- deterministic Progent-style policy engine.

TODO (build step 4): per-tool/per-argument rules loaded from
config/rules/{enterprise,finance,soc}.yaml, forbid evaluated before allow,
default-deny on consequential tools (config/capabilities.yaml, F1), plus the
two conditions that are the core of our thesis:
  - provenance condition: a critical argument must trace to a source at or
    above a required trust level;
  - process-state condition: consequential actions require the state machine
    (fed only from the event log) to show the right predecessor/approval.

Currently a no-op (no rule ever fires) so the pipeline is wired end-to-end
before any real logic lands.
"""

from __future__ import annotations

from dataclasses import dataclass

from defense.context import DecisionContext


@dataclass(frozen=True)
class PolicyVerdict:
    blocked: bool = False
    escalate: bool = False
    rule_ids: tuple[str, ...] = ()
    reason_codes: tuple[str, ...] = ()


def evaluate(ctx: DecisionContext) -> PolicyVerdict:
    """No-op until build step 4: no rule ever fires."""
    return PolicyVerdict()
