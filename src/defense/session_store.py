"""Per-run session state, shared by the provenance registry, the state
machine, and (from build step 6) the Bayesian monitor.

Keyed exclusively by `DecisionContext.session_key` -- the opaque hash from
guard.py, never the raw run_id. An HTTP defense is called stateless per step
(see docs/BUILD_PROMPT.md SS1, "session state" note in FIXLOG's build-step-2
entry), so anything that needs to reason across steps or turns has to
persist here explicitly; nothing here is inferred from request content.

In-memory, single-process. Good enough for local evaluation and the demo
video; note this as a known limitation in SAFETY.md if the service is ever
run with multiple workers (each worker would keep a separate session store).
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ObservedCall:
    step_id: int
    tool: str
    arguments: dict[str, Any]
    decision: str  # "allow" | "block" | "escalate" | "rewrite"
    succeeded: bool | None = None


@dataclass
class SessionState:
    session_key: str
    created_at: float = field(default_factory=time.monotonic)
    last_seen: float = field(default_factory=time.monotonic)
    tool_call_log: list[ObservedCall] = field(default_factory=list)
    # Free-form scratch space for other modules (e.g. the Bayesian monitor's
    # posterior). Keyed by module name so unrelated modules can't collide.
    extra: dict[str, Any] = field(default_factory=dict)


class SessionStore:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._sessions: dict[str, SessionState] = {}

    def get_or_create(self, session_key: str) -> SessionState:
        with self._lock:
            state = self._sessions.get(session_key)
            if state is None:
                state = SessionState(session_key=session_key)
                self._sessions[session_key] = state
            state.last_seen = time.monotonic()
            return state

    def record_call(self, session_key: str, step_id: int, tool: str, arguments: dict[str, Any], decision: str) -> None:
        state = self.get_or_create(session_key)
        with self._lock:
            state.tool_call_log.append(ObservedCall(step_id, tool, dict(arguments), decision))

    def evict_older_than(self, seconds: float) -> None:
        """Housekeeping for a long-lived process; not called automatically."""
        cutoff = time.monotonic() - seconds
        with self._lock:
            stale = [key for key, state in self._sessions.items() if state.last_seen < cutoff]
            for key in stale:
                del self._sessions[key]

    def clear(self) -> None:
        """Test-only: reset all sessions."""
        with self._lock:
            self._sessions.clear()


_STORE: SessionStore | None = None


def default_store() -> SessionStore:
    global _STORE
    if _STORE is None:
        _STORE = SessionStore()
    return _STORE
