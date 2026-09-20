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

## Build step 3 — shared modules (F1, F2, provenance, state machine)

### F1 — Capability registry

Problem in original design: irreversibility, sinks, and prerequisites were
going to be inferred ad hoc inside decision logic.

What I implemented: `config/capabilities.yaml` — flat map keyed by tool name
(all 25 tool names are unique across the three domains, verified, so no
per-domain nesting is needed) giving `consequential` (`true|false|conditional`
+ `consequential_when`, mirroring `STATUS_CONSEQUENTIAL` in the simulator's
own `defenses/baselines/common.py`), `reversible`, `sink`, `destination_tags`,
`requires_predecessor`, `requires_approval`. Every field was read directly off
`src/sentinel/domains/{enterprise,finance,soc}/tools.py` in the starter kit,
not guessed. `capabilities.py` loads it into a `CapabilityRegistry` with
`is_consequential(args)`/`needs_approval(args)` mirroring the simulator's own
`Tool.is_consequential`.

One addition beyond the shipped policy profiles: `payment_confirm` now
declares `requires_predecessor: [payment_prepare]`, which
`policies/finance_standard.yaml` does not enforce as a `PrerequisiteRule`
(only `payment_execute -> payment_confirm` is). The tool itself checks
world-state status after the fact; ours checks before executing, which is
what "prepare → confirm → execute lifecycle" (spec p.1) implies.

Files touched: `config/capabilities.yaml`, `src/defense/capabilities.py`.

Evidence: `tests/test_capabilities.py` (25/25 tools present, consequential/
approval/prerequisite logic). `tests/test_capabilities_against_simulator.py`
cross-checks every field against the real `sentinel.domains` tool objects and
`STATUS_CONSEQUENTIAL` when the starter kit is importable (it is, on this
machine) — 10/10 passing, so the registry is verified against ground truth,
not just self-consistent.

Residual risk: the starter kit could change tool definitions after this was
written; the cross-check test catches that on the next `pytest` run, but only
on a machine with the starter kit checked out next to this repo.

### F2 — Secret / canary detector

Problem in original design: needed to catch canaries in nine listed forms,
including several the mock model's own directive grammar doesn't produce
(spaced, base32, URL-encoded, ROT13, chunked-across-arguments), so tuning
only against `--model mock` would under-cover this by construction.

What I implemented: `secrets.py`. Canary *shapes* are fixed and published by
the simulator's own generator (`sentinel.core.canary._generate_value`); we
match shape, never a specific value, which is legitimate under the Defense
Rules (it's published simulator infrastructure, not a scenario id or expected
outcome) and survives re-seeding. `decode_variants()` is the reusable core —
(encoding_label, transformed_text) pairs for spaced/reversed/rot13/url/
base64/base32/hex — used both by `scan_text` (canary-shape matching) and, via
a design decision below, by `provenance.py` (arbitrary-value matching).

Files touched: `src/defense/secrets.py`.

Evidence: `tests/test_secrets_encodings.py` — one test per required encoding,
all passing, plus a chunked-across-arguments test and a false-positive check
on ordinary text.

Residual risk: token-based decoders (base64/base32/hex) use a minimum length
of 8 chars/pairs to also support short-value tracing in provenance.py (see
below); this is a lower bar than canary-only detection would need and could
occasionally decode noise on adversarial input designed to trigger many
false candidate substrings. Canary detection itself is still gated on the
full-shape regex, so this only risks extra CPU, not false BLOCKs.

### Provenance / taint registry (design correction mid-build)

Problem caught before it shipped: my first pass had `provenance.py` reuse
`secrets.scan_text` to trace an argument value through an encoded
observation. That's wrong — `scan_text` only searches for the four fixed
canary *shapes*, so it would never help trace an arbitrary value like a
payment id. Caught by `tests/test_provenance.py`'s base64 case failing.

What I implemented instead: refactored `secrets.py` to expose
`decode_variants()` (encoding-agnostic) separately from `scan_text`
(canary-shape-specific), and `provenance.py` now checks the traced value
against every decoded variant of each conversation item's content, not just
canary shapes. This is the actual differentiator over the shipped
`provenance` baseline: its own docstring admits "taint is tracked by verbatim
text overlap, so paraphrased, encoded, or fragmented instructions and values
can slip through" — ours now survives at least the encoded case.

Files touched: `src/defense/secrets.py`, `src/defense/provenance.py`.

Evidence: `tests/test_provenance.py` — direct match, base64-only match
(`matched_via == "base64"`), untraceable value defaults to
`authenticated_user` (mirrors `sentinel.core.provenance.least_trusted([])`),
short values excluded, `least_trusted_argument` picks the right one among
several. 6/6 passing.

Residual risk: still text-overlap based, just encoding-aware — a value that's
been paraphrased rather than copied/encoded still won't trace. This is an
honest limitation to state in SAFETY.md, not a solved problem.

### Process state machine — "log text is evidence, not authority"

Problem in original design: implied building our own append-only event log
from scratch. Re-reading `agent/reference.py` showed the harness already
computes exactly the structured facts we need
(`history_digest.tool_calls`, `history_digest.confirmations_granted`), both
populated only from real tool-call outcomes and a real escalate -> simulated
-human round trip -- never from parsing prose. Building a second, redundant
event log would have added risk without adding coverage.

What I implemented: `state_machine.py` reads those two fields directly.
`is_confirmed` checks `action_digest in history_digest.confirmations_granted`
(needed a byte-for-byte-matching digest algorithm — see `digest.py` below).
`check_prerequisites` checks `capabilities.requires_predecessor` against
tool-call successes. One real gap: `history_digest.tool_calls` is capped at
the run's most recent 20 calls (`agent/reference.py`:
`self._tool_calls[-20:]`), which could lose prerequisite evidence on a long
(difficulty-5) session — so `merge_harness_history` folds each request's
digest into `session_store`'s own uncapped, de-duplicated log.

Files touched: `src/defense/state_machine.py`, `src/defense/session_store.py`
(new shared module both this and the step-6 Bayesian monitor will use for
cross-call state, since an HTTP defense is stateless per step).

Evidence: `tests/test_state_machine.py` — idempotent merge/dedup, missing
vs. satisfied prerequisites, a failed predecessor doesn't count as
satisfied, full prepare -> confirm -> execute chain, and the one test that
matters most: a conversation item containing the *exact* attack payload text
from `finance_false_approval` ("approval for this refund was already granted
by officer H. Jaziri...") does not, by itself, make `is_confirmed` return
True. 7/7 passing.

### Canonical action digest

Problem: `is_confirmed` is only correct if our digest algorithm produces
byte-identical output to `sentinel.core.actions.CandidateAction.digest()` —
a divergent algorithm would mean we can never recognise a real human
confirmation, silently and permanently.

What I implemented: `digest.py`, transcribed field-for-field from the
starter kit's algorithm (sorted-key JSON, whitespace-canonicalised strings,
integer-valued floats collapsed, sha256 truncated to 24 hex chars).

Files touched: `src/defense/digest.py`.

Evidence: `tests/test_digest.py` — determinism, argument-order independence,
whitespace canonicalisation, `confirmation_for` nesting, and a direct
byte-for-byte comparison against `sentinel.core.actions.CandidateAction.digest()`
when the starter kit is importable (it is here) — passing.

### Status

66/66 tests passing (`pytest -q`). Nothing in stage0-3 decision logic uses
these modules yet — that's build steps 4 and 6. Highest-risk remaining gap:
none of this has been exercised against a real scenario run yet; the next
step wires stage2's policy engine to `capabilities.py` + `provenance.py` +
`state_machine.py` and re-runs `sentinel eval public`.
