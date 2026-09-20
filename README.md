# SENTINEL defense — IndabaX Tunisia 2026

A security layer between the Qwen3-8B reference agent and its tools, built for
the SENTINEL challenge (submission deadline 22/09 23:59). Runs as an HTTP
service implementing the SENTINEL v1 defense API (`POST /v1/decision`,
`GET /healthz`) and is invoked from the starter kit with:

```bash
uv run sentinel run --scenario <scenario.yaml> --defense-url http://127.0.0.1:8080 --model mock
uv run sentinel run --scenario <scenario.yaml> --defense-url http://127.0.0.1:8080 --model qwen3-8b
```

## Status

Build step 2 (skeleton) is in place: wire contract, the anti-hard-coding guard,
the JSONL trace substrate, and an end-to-end stub that `ALLOW`s everything.

Build step 3 (shared modules) is in place: the capability registry
(`config/capabilities.yaml` + `capabilities.py`, all 25 tools across the three
domains, cross-checked against the starter kit's own tool definitions when
available), the provenance/taint registry (`provenance.py`), the
encoding-aware secret/canary detector (`secrets.py`), the process state
machine (`state_machine.py`), the shared session store (`session_store.py`),
and the canonical action digest (`digest.py`, cross-checked byte-for-byte
against the harness's own algorithm). 66 tests pass, including 10 that
cross-validate against the actual starter kit source on disk.

Stage 0–3 decision logic itself (normalisation, Bayesian monitor, policy
engine, arbitration) does not yet *use* these modules — see the `TODO`
docstring in each `src/defense/stageN_*.py` and `FIXLOG.md` for progress
against the build plan. `stage3_decide.arbitrate` still allows everything.

## Architecture

Four stages in series, fed by shared modules, sitting behind one FastAPI
adapter (`src/defense/adapter.py`):

```
DefenseRequest (wire)
  -> guard.assert_no_forbidden_fields   (F9, fails loudly on evaluator-only fields)
  -> context.build_context              (narrows to DecisionContext; drops raw run_id)
  -> stage0_normalise.normalise         (visible-text extraction, hidden-content signal)
  -> stage2_policy.evaluate             (Progent-style per-tool/per-arg rules)
  -> stage1_bayes.update                (sequential session-risk posterior)
  -> stage3_decide.arbitrate            (policy + bayes + irreversibility -> ALLOW/BLOCK/ESCALATE/REWRITE)
  -> trace.append                       (JSONL, keyed by session_key, for the observability layer)
```

## Why there's a `guard.py` and a `context.py`

SENTINEL disqualifies any decision derived from a scenario id, filename, or an
organizer-provided expected outcome (see the starter kit's
`docs/threat-model.md` and `docs/participant-guide.md`). The wire schema never
defines such a field — but `run_id` embeds the scenario name by convention
(the participant guide's own example request is
`"run_id": "finance_false_approval-python_defense-s0"`). `context.build_context`
strips `run_id` down to an opaque `session_key` before anything in `stage0`–`stage3`
runs, so hard-coding on scenario identity through that back door is
structurally impossible, not just discouraged by convention. `tests/test_no_scenario_leak.py`
proves it: two requests identical except for `run_id` content produce
byte-identical decisions.

## Running locally

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
PYTHONPATH=src uvicorn defense.adapter:app --port 8080
```

## Tests

```bash
pip install -r requirements.txt
pytest
```

## Repository layout

See `docs/BUILD_PROMPT.md` §4 for the target layout; `FIXLOG.md` tracks what
changed against our original four-stage design and why, per fix (F1–F9).
