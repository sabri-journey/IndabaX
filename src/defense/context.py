"""The only view of a request that decision-path code (stage0..stage3) may see.

Built once, in `build_context`, from the raw wire request. It deliberately has
no `run_id` field -- see guard.py -- so it is structurally impossible for any
downstream stage to branch on scenario identity via the run id, even by
accident. If a future stage needs "was this session seen before", it takes
`session_key`, never the raw string.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from defense.guard import session_key
from defense.models import CandidateAction, ConversationItem, DefenseRequest, HistoryDigest, ObservationView, ProvenanceRecord


@dataclass(frozen=True)
class DecisionContext:
    session_key: str
    step_id: int
    user_goal: str
    conversation: tuple[ConversationItem, ...]
    observation: ObservationView | None
    candidate_action: CandidateAction
    policy_context: dict[str, Any]
    provenance: tuple[ProvenanceRecord, ...]
    history_digest: HistoryDigest
    provenance_by_id: dict[str, ProvenanceRecord] = field(default_factory=dict)


def build_context(request: DefenseRequest) -> DecisionContext:
    provenance_by_id = {record.id: record for record in request.provenance}
    return DecisionContext(
        session_key=session_key(request.run_id),
        step_id=request.step_id,
        user_goal=request.user_goal,
        conversation=tuple(request.conversation),
        observation=request.observation,
        candidate_action=request.candidate_action,
        policy_context=dict(request.policy_context),
        provenance=tuple(request.provenance),
        history_digest=request.history_digest,
        provenance_by_id=provenance_by_id,
    )
