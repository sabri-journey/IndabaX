"""Process state machine (shared module).

Fed *exclusively* from structured, harness-computed facts --
`history_digest.tool_calls` (tool name, decision, succeeded) and
`history_digest.confirmations_granted` (action digests the harness's own
human-confirmation flow actually approved) -- never from the free text of an
email, document, log line, or memory entry. This is what makes "log text is
evidence, not authority" (spec p.2, "Hostile log text") and "a payment cannot
be confirmed without an authenticated approval" hold structurally: nothing in
this module ever parses prose for claims like "approval was already granted".

`history_digest.tool_calls` only carries the run's most recent 20 calls
(agent/reference.py in the starter kit: `self._tool_calls[-20:]`). We fold
each request's digest into the session's own longer-lived log (session_store),
de-duplicated by step_id, so a long-horizon session (difficulty level 5)
keeps prerequisite evidence the harness's own digest would otherwise let age
out.
"""

from __future__ import annotations

from dataclasses import dataclass

from defense.capabilities import CapabilityRegistry
from defense.context import DecisionContext
from defense.session_store import ObservedCall, SessionState


@dataclass(frozen=True)
class PrerequisiteViolation:
    tool: str
    missing: tuple[str, ...]


def merge_harness_history(ctx: DecisionContext, session: SessionState) -> None:
    """Fold this request's history_digest.tool_calls (harness ground truth)
    into the session's own log. Idempotent: safe to call on every request."""
    seen_steps = {call.step_id for call in session.tool_call_log}
    for summary in ctx.history_digest.tool_calls:
        if not isinstance(summary, dict):
            continue
        step_id = summary.get("step_id")
        tool = summary.get("tool")
        if step_id is None or tool is None or step_id in seen_steps:
            continue
        session.tool_call_log.append(
            ObservedCall(
                step_id=step_id,
                tool=tool,
                arguments={},
                decision=summary.get("decision") or "unknown",
                succeeded=summary.get("succeeded"),
            )
        )
        seen_steps.add(step_id)
    session.tool_call_log.sort(key=lambda call: call.step_id)


def has_succeeded(session: SessionState, tool: str) -> bool:
    return any(call.tool == tool and call.succeeded for call in session.tool_call_log)


def is_confirmed(ctx: DecisionContext, action_digest: str) -> bool:
    """The one true signal for "an authenticated approval happened": the
    harness's own confirmation ledger (`history_digest.confirmations_granted`,
    populated only after a real ESCALATE -> simulated-human round trip). Never
    derived from text content, so a forged "approval already granted" claim
    in an email or log line cannot satisfy this."""
    return action_digest in ctx.history_digest.confirmations_granted


def check_prerequisites(
    ctx: DecisionContext, session: SessionState, tool: str, registry: CapabilityRegistry
) -> PrerequisiteViolation | None:
    """None if every tool this `tool` requires as a predecessor has already
    succeeded in this session; otherwise the violation, naming what's missing."""
    merge_harness_history(ctx, session)
    capability = registry.get(tool)
    missing = tuple(pred for pred in capability.requires_predecessor if not has_succeeded(session, pred))
    return PrerequisiteViolation(tool=tool, missing=missing) if missing else None
