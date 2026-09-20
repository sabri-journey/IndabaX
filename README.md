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

Build step 4 (stage 0 + stage 2, wired end to end) is in place: stage 0
normalises hidden/homoglyph/HTML tricks; stage 2 is a real Progent-style
policy engine (`config/rules/{general,enterprise,finance,soc}.yaml`) using
the capability registry, provenance tracer, secret detector, and state
machine; stage 3 is a first (pre-Bayes, pre-rewrite) policy -> decision
translation. 98 tests pass.

First real `sentinel eval public --model mock` result (public split, 19
scenarios): **ASR 0.0, BTU 1.0, CVR 0.0, FBR 0.0, UER 0.0, DFI 1.0** — every
attack in the published library defeated, every benign task still completes,
zero false blocks. Validation split (9 scenarios): the same, ASR/BTU/CVR/FBR/
UER all clean. Two real false positives were found and fixed against actual
scenario traces (not synthetic data) during this step — see FIXLOG for both;
they're the reason `provenance.py`'s trust aggregation prefers the
*most*-trusted available explanation for a value rather than the worst one.

Build step 5 (rewrite catalogue + hard-negative gate) is in place:
`config/rewrites.yaml` + `src/defense/rewrites.py` turn some would-be BLOCKs
into a safer substitute action (send → draft, close-incident → flagged for
review, secret masked out of an outbound body) when a rewrite fully
addresses every current finding; a dedicated `tests/test_hard_negatives.py`
runs the five published `hard_negative`-tagged scenarios end to end against
the real simulator (not a synthetic approximation) as a regression gate, plus
a unit test proving scary vocabulary in trusted content never changes the
decision. 109 tests pass. Re-running `sentinel eval public`/`validation`
after this step: **still ASR 0.0, BTU 1.0, CVR 0.0, FBR 0.0, UER 0.0** — the
rewrite catalogue visibly fires on real scenarios (e.g. `soc_hostile_log_text`'s
hostile-log-dictated incident closure is now REWRITE'd to stay open with a
human-review flag, instead of a flat BLOCK) without moving any headline
metric.

Not yet done: stage 1's Bayesian monitor is still a flat stub (build step
6), and none of this has been run against `--model qwen3-8b` yet (build step
10) — the architecture doc's own warning applies: a defense can look
stronger against `mock` than the real model, so these numbers are evidence,
not a final result.

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
