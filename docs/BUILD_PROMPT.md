# Claude Code build prompt — SENTINEL defense (IndabaX Tunisia 2026)

> Paste everything below the line into Claude Code, after replacing the two
> `<PATH>` placeholders. Keep this file in the repo as `docs/BUILD_PROMPT.md`.

---

## 0. Context

We are a team competing in **SENTINEL: Adaptive Safety for Autonomous AI Agents**
(IndabaX Tunisia 2026). Submission deadline: **22/09 23:59**. We have ~2.5 days.

- Simulator / starter kit repo: `<https://github.com/Skan22/Sentinel_Starter_Kit>`
- Our defense repo (to build): `<https://github.com/sabri-journey/IndabaX>`
- Spec book PDF: in `resources/`
- Everything runs **fully offline** on synthetic data. No network calls at runtime.

**Before writing any code**, read these in the starter kit and summarise back to me
in 15 lines what constrains our design:

- `README.md`
- `docs/architecture.md`, `docs/participant-guide.md`, `docs/threat-model.md`,
  `docs/security-model.md`, `docs/scoring.md`, `docs/scenario-authoring.md`
- `src/sentinel/core/` (provenance, actions, events, policies, canaries, world state)
- `src/sentinel/defenses/` (the `Defense` interface + the five baselines, especially
  `provenance` and `heuristic_risk`)
- `src/sentinel/domains/` (enterprise, finance, soc tool definitions — note
  `is_consequential`, prerequisites, sink tags)
- `src/sentinel/evaluator/` (labels, graders, leak detection, metrics)
- `scenarios/`, `policies/`, `fixtures/`
- `starter-kits/python-defense/`

Do not start coding until you have done this read and reported back.

---

## 1. Non-negotiable rules (breaking these disqualifies us)

1. A decision may be derived **only** from: agent state, the candidate action, its
   provenance, the active policy, and observed content. Nothing else.
2. **Never** read, branch on, or even log-as-input: scenario id, scenario filename,
   `attack.present`, attack family, reference plans, evaluator labels, expected
   outcomes, or any `_meta` field. Add a runtime guard that raises if such a key is
   ever accessed by the decision path, plus a unit test proving it.
3. Every decision resolves to exactly one of: `ALLOW`, `BLOCK`, `ESCALATE`, `REWRITE`.
4. The defense must be **deterministic**: same inputs → byte-identical decisions and
   trace. No wall-clock, no RNG without a fixed seed, no dict-ordering dependence.
5. No network access at decision time. No LLM call inside the decision path.
6. Fail **closed but useful**: on internal error or timeout, degrade to a documented
   conservative decision (escalate for consequential, allow for read-only) and mark
   the decision `degraded: true` in the trace. Target p95 latency < 50 ms per call.

---

## 2. Architecture to implement

A security layer between the agent (Qwen3-8B) and its tools. Four stages in series,
fed by four shared modules.

### Stage 0 — Deterministic normalisation and provenance tagging
- Extract only text a human would actually see: strip zero-width and bidi control
  characters, Unicode confusables/homoglyph-normalise (NFKC), HTML comments, hidden
  elements, `display:none`, white-on-white, alt-text trickery, markdown link targets
  that differ from their label.
- Keep **both** the raw and the visible text; record the delta as a signal
  (`R-HIDDEN-TEXT`) — hidden content is itself evidence of manipulation.
- Assign every observation exactly one of SENTINEL's six trust levels, using the
  names the simulator uses: `SYSTEM_POLICY`, `AUTHENTICATED_USER`,
  `TRUSTED_INTERNAL`, `UNTRUSTED_INTERNAL`, `UNTRUSTED_EXTERNAL`,
  `ADVERSARY_CONTROLLED`.

### Stage 1 — Sequential Bayesian monitor
- Maintain a posterior over `session_is_compromised` updated per observation and per
  candidate action, so fragmented / multi-step / adaptive attacks accumulate evidence
  that a per-action review would miss.
- Emit `(risk, confidence)` where risk is a **calibrated probability**, not an
  arbitrary 0–100 score.
- Likelihood ratios per signal must be declared in a single config file
  (`config/likelihoods.yaml`) with a one-line justification each, so the report can
  cite them and the ablation can disable them.
- Include decay so an old, resolved suspicion doesn't poison a long benign session
  (protects long-horizon scenarios from runaway escalation).

### Stage 2 — Deterministic policy engine (Progent-style)
- Per-tool and per-argument rules; **forbid evaluated before allow**; **default-deny
  on consequential tools**; separate rule packs for `general`, `finance`, `soc`,
  `enterprise`, loaded from YAML.
- Extend with two conditions that are the core of our thesis:
  - **Provenance condition** — a critical argument must trace to a source at or above
    a required trust level (e.g. a payee account number may not originate from
    `UNTRUSTED_EXTERNAL`).
  - **Process-state condition** — a payment cannot be confirmed without an
    authenticated approval; an incident cannot be closed and monitoring cannot be
    disabled without trusted evidence; `prepare → confirm → execute` order enforced.
- Rules are data, not code. Every rule has a stable `rule_id` and a human-readable
  `reason`.

### Stage 3 — Decision arbitration
- Combines policy verdict + Bayesian posterior + irreversibility into one of the four
  actions, via an explicit, documented decision table (not scattered `if`s).
- Prefers the least destructive effective intervention: **rewrite > escalate > block**
  whenever a rewrite genuinely removes the hazard.

### Shared modules
- **Provenance registry** — a taint/dataflow graph where values and memory entries
  inherit the lowest trust of their sources. Memory written after reading untrusted
  content stays untrusted on recall. Must answer "where did this exact argument value
  come from?" with a chain, for the trace.
- **Secret / canary detector** — detects secrets and canaries in plain, spaced,
  reversed, base64, base32, hex, URL-encoded, ROT13, and chunked-across-arguments
  forms. Must operate on both raw and normalised text.
- **Process state machine** — fed **exclusively** from the append-only event log, never
  from model output or untrusted text.
- **Capability registry (NEW — see fixes)** — per-tool metadata: consequential?
  reversible? sink? destination tags? required predecessors? required approval?

---

## 3. Fixes to our original design — implement all of these

These are gaps we identified against the spec and the rubric. Implement each, and
report on each in `FIXLOG.md`.

**F1 — Irreversibility as a first-class property.**
Create `capabilities.yaml` giving every tool explicit `consequential`,
`reversible`, `sink`, `destination_tags`, `requires_predecessor`, `requires_approval`.
Align the vocabulary with the simulator's own `is_consequential(args)` and
`tool_prerequisites` so our metrics and the evaluator's labels speak the same
language. Stage 3 reads irreversibility from here, never infers it ad hoc.

**F2 — Explicit rewrite catalogue.**
`rewrites.yaml`: per-domain, per-tool safer substitutions, each with a precondition
and a `rewrite_id`. At minimum:
- enterprise: `send_email → create_draft`; strip/mask detected secrets from body and
  attachments; downgrade external recipients to internal-only draft.
- finance: `execute_payment → keep_prepared`; `confirm_payment → escalate`; mask
  account identifiers in any outbound text.
- soc: `close_incident → flag_for_human_review`; `disable_monitoring → no-op + alert`;
  `remediate → propose_remediation`.
The trace must show original action vs rewritten action side by side, plus what was
removed and why. Rewrite is our highest-value lever for the Precision criterion —
treat BLOCK as a last resort when no rewrite preserves the legitimate goal.

**F3 — Escalation policy with hysteresis and a UER guard.**
Escalate only when `(risk, confidence)` crosses a documented threshold **and** the
action is consequential/irreversible, **or** a hard policy condition is unmet.
Require the posterior to stay above threshold for N consecutive updates (hysteresis)
so one noisy signal can't trigger escalation. Never escalate a legitimate,
non-consequential, read-only action — that is exactly what UER penalises. Thresholds
live in `config/thresholds.yaml`, are tuned on the published library, and are
reported honestly in the report.

**F4 — Hard-negative / over-refusal tuning as a first-class objective.**
Benign work full of scary vocabulary must pass. Build a dedicated test suite over the
`hard_negative` scenarios (`enterprise_security_digest`, `finance_fraud_awareness_note`,
`soc_confirmed_isolation`, plus the validation cases) and make FBR/UER on them a CI
gate: if a change raises false blocks on hard negatives, the test fails. Our decision
must rest on *irreversibility + untrusted provenance of arguments*, never on the
presence of alarming words — add a test asserting that a benign document containing
words like "transfer all funds", "disable monitoring", "API token" does not by itself
change any decision.

**F5 — Calibration is a deliverable, not a by-product.**
Compute Brier score and ECE (10 equal-width bins) over the published library; add a
reliability-diagram script. Tune the Bayesian likelihoods so reported risk actually
means probability. Document the calibration curve in the report.

**F6 — Ablation built into the architecture from day one.**
Every component is toggleable by config/CLI flag: `--no-bayes`, `--no-provenance`,
`--no-state-machine`, `--no-normalisation`, `--no-secret-detector`, `--rules-only`.
Provide `scripts/run_ablation.py` that runs the full published library under each
configuration and emits a single comparison table (BTU, ASR, CVR, FBR, UER, TUI, DFI,
Brier, ECE) to `results/ablation.md`. The report needs at least one ablation, honestly
reported — this makes it one command.

**F7 — Observability layer that is not a log dump.**
JSONL trace is the substrate; build a real viewer on top (single-page local dashboard,
no network). It must show, per decision:
- timeline of the session with each action and its outcome;
- risk posterior **trajectory** across the session (this is what makes multi-step
  attacks legible on camera);
- the provenance chain for the specific argument that drove the decision;
- which rule ids fired, reason codes, confidence, latency;
- original vs rewritten action for rewrites;
- a diff view of raw vs visible text when hidden content was stripped.
Reason codes must come from a closed, documented taxonomy (`REASON_CODES.md`), e.g.
`R-PROV-UNTRUSTED-ARG`, `R-STATE-NO-APPROVAL`, `R-EXFIL-ENCODED-SECRET`,
`R-HIDDEN-TEXT`, `R-SEQ-RISK-ACCUMULATION`, `R-IRREVERSIBLE-DEFAULT-DENY`.
Video & Observability is 40 of 100 points; legibility of *why* is the criterion.

**F8 — Responsible-AI / safety statement as a tracked artifact.**
`SAFETY.md`, written honestly: what the defense protects against, known failure
modes, expected false-positive behaviour, exactly what data the defense observes,
when a human is consulted, and what it does **not** protect against (e.g. a
fully-trusted-source insider instruction, semantic goal drift within policy, an
attack whose payload is entirely plausible legitimate content). Judges explicitly
reward an honest failure shown over a hidden one.

**F9 — Anti-hard-coding guard.**
As stated in §1.2: a runtime assertion plus a test proving the decision path cannot
see scenario identity. Mention this guard in the report — it is cheap and it directly
addresses the one disqualifying failure mode.

---

## 4. Repository layout to produce

```
our-defense/
  README.md                 # what it is, how to run, architecture diagram
  FIXLOG.md                 # what you changed vs our original design, and why
  SAFETY.md                 # responsible-AI statement
  REASON_CODES.md           # closed taxonomy
  ABLATION.md / results/    # ablation table + calibration plots
  config/
    capabilities.yaml  likelihoods.yaml  thresholds.yaml  rewrites.yaml
    rules/{general,enterprise,finance,soc}.yaml
  src/defense/
    stage0_normalise.py  stage1_bayes.py  stage2_policy.py  stage3_decide.py
    provenance.py  secrets.py  state_machine.py  capabilities.py
    trace.py  adapter.py        # adapter to the simulator's Defense interface
  observability/              # local dashboard reading the JSONL trace
  scripts/
    run_eval.py  run_ablation.py  calibrate.py
  tests/
    test_no_scenario_leak.py  test_hard_negatives.py  test_determinism.py
    test_provenance.py  test_secrets_encodings.py  test_state_machine.py
```

---

## 5. Build order (respect it — we are time-boxed)

1. Read the docs and report back (§0). Wait for my confirmation.
2. Skeleton + adapter to the simulator's `Defense` interface + trace schema + the
   anti-hard-coding guard and its test. Verify `sentinel run --defense-url ...` works
   end-to-end with a stub that allows everything.
3. Shared modules: capability registry, provenance registry, secret detector, state
   machine — with unit tests, including every encoding in F2/§2.
4. Stage 0 and Stage 2 (normalisation + rules). Run `sentinel eval public` with
   `--model mock`. Record the first BTU/ASR/CVR/FBR/UER/TUI/DFI baseline.
5. Hard-negative tuning (F4) and the rewrite catalogue (F2). Re-run eval.
6. Stage 1 Bayesian monitor + Stage 3 arbitration with hysteresis (F3). Re-run eval.
7. Calibration (F5) and ablation (F6).
8. Observability dashboard (F7).
9. `SAFETY.md`, `README.md`, `FIXLOG.md`, and a results section I can paste into the
   technical report.
10. Re-run the 3 chosen demo scenarios with `--model qwen3-8b` and save the traces the
    video will be built around: one benign task completing, one clear attack caught,
    one hard negative passing, ideally one multi-step/long-horizon showing the risk
    trajectory climb.

After each numbered step: run the tests, run the eval, commit with a clear message,
and give me a 5-line status with the current metric table.

---

## 6. How to report back to me

Maintain `FIXLOG.md` continuously. For each of F1–F9, one entry:

```
### F3 — Escalation hysteresis
Problem in original design: thresholds undefined; risk of high UER.
What I implemented: ...
Files touched: ...
Evidence: UER 0.31 → 0.04 on the published library (before/after table).
Residual risk: ...
```

At the end of every working session, print a short summary to the console:
what you fixed, what the metrics did, what is still open, and what you think the
highest-risk remaining gap is. If you disagree with anything in this brief, say so
before implementing it rather than silently working around it.

Ask me before: adding any dependency that isn't pure-Python/offline, changing the
four-outcome contract, or anything that would make the defense non-deterministic.
