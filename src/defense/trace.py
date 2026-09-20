"""Append-only JSONL trace -- the substrate for the observability layer (F7).

Written by the adapter after a decision is made. Deliberately takes the raw
`run_id` as a parameter for human legibility in the dashboard/video (a judge
watching the video needs to see which scenario is playing) -- but this module
is a *sink*, never a source, for decision logic: nothing here feeds back into
`pipeline.decide`. The decision path itself only ever sees
`DecisionContext.session_key` (see guard.py, context.py).
"""

from __future__ import annotations

import json
import threading
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_LOCK = threading.Lock()
DEFAULT_TRACE_DIR = Path(__file__).resolve().parents[2] / "traces"


def append(
    *,
    run_id: str,
    session_key: str,
    step_id: int,
    candidate_action: dict[str, Any],
    decision: dict[str, Any],
    latency_ms: float | None = None,
    trace_dir: Path = DEFAULT_TRACE_DIR,
) -> None:
    trace_dir.mkdir(parents=True, exist_ok=True)
    path = trace_dir / f"{session_key}.jsonl"
    record = {
        "ts": datetime.now(UTC).isoformat(),
        "run_id": run_id,
        "session_key": session_key,
        "step_id": step_id,
        "candidate_action": candidate_action,
        "decision": decision,
        "latency_ms": latency_ms,
        "degraded": bool(decision.get("metadata", {}).get("degraded", False)),
    }
    line = json.dumps(record, sort_keys=True, separators=(",", ":"))
    with _LOCK, path.open("a", encoding="utf-8") as fh:
        fh.write(line + "\n")


def timer() -> Any:
    """Small helper: `start = time.perf_counter()` ... `latency_ms = elapsed_ms(start)`."""
    return time.perf_counter()


def elapsed_ms(start: float) -> float:
    return (time.perf_counter() - start) * 1000
