"""FastAPI adapter implementing the SENTINEL v1 defense API.

This is the boundary between the wire contract and the guarded decision path:
it reads the raw JSON body, rejects any evaluator-only field before the body
is even parsed into a model (guard.assert_no_forbidden_fields), then hands off
to the pipeline -- which only ever sees a DecisionContext, never the raw
run_id (see context.py / guard.py for why that matters).

Rule from the build brief (SS1.6): fail closed but useful. On an internal
pipeline error we degrade to a documented conservative decision (escalate for
a consequential tool call, allow for a read-only one) rather than crash, and
mark it `degraded: true` in both the decision metadata and the trace.
"""

from __future__ import annotations

import logging

from fastapi import FastAPI, Request

from defense import pipeline, trace
from defense.guard import assert_no_forbidden_fields, session_key
from defense.models import CandidateAction, DefenseDecision, DefenseRequest

logger = logging.getLogger("defense.adapter")

app = FastAPI(title="SENTINEL defense", docs_url=None, redoc_url=None, openapi_url=None)


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/v1/decision", response_model=DefenseDecision)
async def decision(http_request: Request) -> DefenseDecision:
    raw = await http_request.json()
    assert_no_forbidden_fields(raw)  # F9 -- fails loudly (500) rather than silently ignoring a leak
    request = DefenseRequest.model_validate(raw)

    start = trace.timer()
    extras: dict = {}
    try:
        result, trace_extras = pipeline.decide_with_trace(request)
        extras = {
            "findings": list(trace_extras.findings),
            "normalisation_signals": list(trace_extras.normalisation_signals),
            "hidden_text_diffs": list(trace_extras.hidden_text_diffs),
            "bayes_risk": trace_extras.bayes_risk,
            "bayes_confidence": trace_extras.bayes_confidence,
            "bayes_reason_codes": list(trace_extras.bayes_reason_codes),
            "hysteresis_met": trace_extras.hysteresis_met,
        }
    except Exception:
        logger.exception("decision pipeline failed at step %s", request.step_id)
        result = _degraded_decision(request)
    latency_ms = trace.elapsed_ms(start)

    trace.append(
        run_id=request.run_id,
        session_key=session_key(request.run_id),
        step_id=request.step_id,
        candidate_action=request.candidate_action.model_dump(mode="json"),
        decision=result.model_dump(mode="json"),
        latency_ms=latency_ms,
        extras=extras,
    )
    return result


def _target_action(action: CandidateAction) -> CandidateAction:
    if action.type == "request_confirmation" and action.confirmation_for is not None:
        return action.confirmation_for
    return action


def _degraded_decision(request: DefenseRequest) -> DefenseDecision:
    target = _target_action(request.candidate_action)
    consequential = target.tool is not None and target.tool in request.policy_context.get("consequential_tools", [])
    return DefenseDecision(
        decision="escalate" if consequential else "allow",
        risk_score=0.5,
        confidence=0.0,
        reason_codes=["DEGRADED_FAIL_CLOSED"],
        explanation="internal defense error; degraded to a documented conservative decision",
        metadata={"degraded": True},
    )
