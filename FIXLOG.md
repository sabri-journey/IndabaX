# FIXLOG

Tracks what changed against our original four-stage design, and why, against
the fixes (F1–F9) identified in `docs/BUILD_PROMPT.md`.

## Build step 2 — skeleton, adapter, trace schema, anti-hard-coding guard

Problem in original design: the plan described a provenance registry, secret
detector, and process state machine as things we'd build from scratch,
without first checking what the simulator already hands the defense on the
wire.

What I implemented:
- `src/defense/models.py` — self-contained copy of the SENTINEL v1 wire
  schema (lenient request, strict response), independent of the simulator
  package so the defense runs standalone.
- `src/defense/guard.py` + `context.py` (F9) — `assert_no_forbidden_fields`
  scans the raw JSON body for evaluator-only keys before parsing (defense in
  depth; the schema never defines these, so this should never fire against the
  real simulator). More importantly: `build_context` replaces the raw
  `run_id` with an opaque `session_key` (sha256, truncated) before anything in
  stage0–3 ever sees it. `run_id` embeds the scenario name by convention
  (`"finance_false_approval-python_defense-s0"` in the participant guide's own
  example request) — without this, a defense could hard-code on scenario
  identity via `run_id` string matching without ever touching a field
  literally named `scenario_id`.
- `src/defense/pipeline.py` — wires stage0 → stage2 → stage1 → stage3;
  currently all four stages are stubs (stage3 returns `ALLOW` for everything)
  so the wire contract is proven end-to-end before any real decision logic
  lands.
- `src/defense/trace.py` — JSONL trace substrate for the observability layer
  (F7), keyed by `session_key`. Takes `run_id` as a parameter for human
  legibility in the dashboard/video only; it is a sink, not a source, for
  decision logic.
- `src/defense/adapter.py` — FastAPI service (`GET /healthz`,
  `POST /v1/decision`). Implements the fail-closed-but-useful rule (build
  brief §1.6): on an internal pipeline exception, degrades to `ESCALATE` for a
  consequential candidate action or `ALLOW` for a read-only one, and marks
  `metadata.degraded = true` in both the decision and the trace, instead of
  crashing.

Files touched: `src/defense/{__init__,models,guard,context,stage0_normalise,
stage1_bayes,stage2_policy,stage3_decide,pipeline,trace,adapter}.py`,
`tests/{test_no_scenario_leak,test_determinism,test_adapter_smoke}.py`,
`pytest.ini`, `requirements.txt`, `Dockerfile`, `README.md`.

Evidence: `pytest` — all tests pass (guard, determinism, adapter smoke,
including the run_id-invariance test). End-to-end verified against the
starter kit with `sentinel run --defense-url http://127.0.0.1:8080 --defense
... --model mock` — see console output in the step-2 status report.

Residual risk: stage0–3 are stubs; nothing has been evaluated against
`sentinel eval public` yet — ASR/BTU/etc. are all trivial (allow-everything)
until build steps 4–6 land.

<!-- Further entries (F1-F8) appended as each build step lands. -->
