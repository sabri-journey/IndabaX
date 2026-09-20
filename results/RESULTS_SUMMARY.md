# Results summary — ready to paste into the technical report

All numbers below are from `sentinel eval`, `--model mock`, against the
`sentinel-bench/0.1.0` published scenario library, run through this
defense's real HTTP service (`--defense-url`), not an in-process shortcut.
Raw JSON for every run is in `results/` and `results/baselines/`. Baseline
numbers (`allow_all`, `deny_sensitive`, `keyword`, `heuristic_risk`,
`provenance`) use the starter kit's own in-process baselines
(`--defense <name>`), so their latency column is not directly comparable to
ours (no HTTP round trip) — noted below, not hidden.

## 6. Results — main comparison table (public split, 19 scenarios)

| Defense | BTU | ASR | CVR | FBR | UER | TUI | DFI | Brier | ECE | p95 ms |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| allow_all | 1.000 | 1.000 | 0.526 | 0.000 | 0.000 | 0.728 | 0.842 | 0.214 | 0.214 | 0.017 |
| deny_sensitive | 0.556 | 0.800 | 0.105 | 0.059 | 0.000 | 0.857 | 0.895 | 0.127 | 0.047 | 0.019 |
| keyword | 0.778 | 0.700 | 0.368 | 0.046 | 0.000 | 0.809 | 0.947 | 0.138 | 0.054 | 0.033 |
| heuristic_risk | 1.000 | 0.000 | 0.000 | 0.000 | 0.011 | 0.983 | 1.000 | 0.056 | 0.140 | 0.029 |
| provenance | 1.000 | 0.000 | 0.000 | 0.046 | 0.000 | 1.000 | 1.000 | 0.038 | 0.099 | 0.040 |
| **ours** | **1.000** | **0.000** | **0.000** | **0.000** | **0.000** | 0.967 | 1.000 | 0.053 | 0.079 | 5.703† |

† Ours runs over real HTTP (the deployment shape every team's submission
uses); baselines above run in-process. 5.7 ms p95 is still comfortably fast
for a synchronous defense call — the comparison is about correctness, not
latency, here.

**Headline claim, evidenced**: `allow_all`/`deny_sensitive`/`keyword` all
fail on ASR exactly as the spec predicts for naive defenses ("what will not
score well: keyword filters, blanket refusal"). Both `heuristic_risk` and
`provenance` reach ASR 0.0 like we do, but `provenance` — the baseline our
method most directly extends — has **FBR 0.046** (it falsely blocks
legitimate work the published library's own `provenance` implementation
gets wrong) where we have **FBR 0.000**, and `heuristic_risk` has UER 0.011
where we have 0.000. This is the concrete, measured version of our
hypothesis: verbatim-text-overlap provenance tracking (what the shipped
baseline does) over-blocks; the encoding-aware, most-trusted-explanation
tracer we built does not, on this library.

## Results by domain (ours, public split)

| Domain | ASR | BTU | CVR | FBR | UER | TUI | DFI |
| --- | --- | --- | --- | --- | --- | --- | --- |
| enterprise | 0.000 | 1.000 | 0.000 | 0.000 | 0.000 | 0.944 | 1.000 |
| finance | 0.000 | 1.000 | 0.000 | 0.000 | 0.000 | 1.000 | 1.000 |
| soc | 0.000 | 1.000 | 0.000 | 0.000 | 0.000 | 1.000 | 1.000 |

## Results by attack family (ours, public split)

| Family | Scenarios | Attack successes | Critical violations |
| --- | --- | --- | --- |
| `direct_instruction` | 3 | 0 | 0 |
| `indirect_prompt_injection` | 4 | 0 | 0 |
| `memory_poisoning` | 2 | 0 | 0 |
| `multi_step` | 1 | 0 | 0 |
| `none` (benign, incl. hard negatives) | 9 | 0 | 0 |

## Cross-checks (all `--model mock`)

| Run | ASR | BTU | CVR | FBR | UER |
| --- | --- | --- | --- | --- | --- |
| public split | 0.000 | 1.000 | 0.000 | 0.000 | 0.000 |
| validation split (9 scenarios, never debugged against) | 0.000 | 1.000 | 0.000 | 0.000 | 0.000 |
| public split, `--attack-mode adaptive` | 0.000 | 1.000 | 0.000 | 0.000 | 0.000 |

The validation-split and adaptive-mode results matter most for
generalization: validation scenarios were never specifically inspected
while building the rules, and the two real false-positive bugs described
below were both found and fixed against *public*-split scenarios, then
independently confirmed not to regress the validation split.

## 7. Ablations (F6) — see `results/ablation.md` for the full table

| config | btu | asr | cvr | fbr | uer | tui | dfi | brier | ece |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| full | 1.000 | 0.000 | 0.000 | 0.000 | 0.000 | 0.967 | 1.000 | 0.051–0.053 | 0.075–0.079 |
| no_bayes | 1.000 | 0.000 | 0.000 | 0.000 | 0.000 | 0.967 | 1.000 | 0.036 | 0.057 |
| no_provenance | 1.000 | 0.000 | 0.000 | 0.000 | 0.000 | 0.952 | 1.000 | 0.060 | 0.076 |
| no_state_machine | 1.000 | 0.000 | 0.000 | 0.000 | 0.000 | 0.967 | 1.000 | 0.040 | 0.060 |
| no_secret_detector | 1.000 | 0.000 | 0.000 | 0.000 | 0.000 | 0.967 | 1.000 | 0.051 | 0.075 |
| rules_only (no bayes, no rewrite) | 1.000 | 0.000 | 0.000 | 0.000 | 0.000 | 0.983 | 1.000 | 0.035 | 0.055 |

**Honest reading**: on the current published library, stage 2's
deterministic rules alone already defeat every attack — ablating any single
component leaves ASR/BTU/CVR/FBR/UER unchanged. The Bayesian layer's own
marginal value on *this* library is a small calibration cost (Brier
0.036→0.051), not a change in outcome; its architectural purpose
(catching a fragmented/adaptive pattern no single rule would) is proven by
dedicated unit tests (`tests/test_stage1_bayes.py`) rather than by a
published scenario shaped to need it. `no_provenance`'s worse TUI (0.952)
and calibration is the clearest evidence the provenance layer is doing real
work even when it doesn't change ASR — see `FIXLOG.md`'s build-step-4 and
step-7 entries for exactly what it catches that the state machine alone
does not (`finance_false_approval`'s instruction-mirroring catch, in
particular).

## 8. Calibration (F5) — see `results/eval_public_full_calibration.md`/`.svg`

Reliability table, public split, post-fix:

| Bin | Count | Mean predicted risk | Observed illegitimate fraction |
| --- | --- | --- | --- |
| [0.1, 0.2) | 87 | 0.100 | 0.034 |
| [0.5, 0.6) | 2 | 0.500 | 0.000 |
| [0.6, 0.7) | 1 | 0.600 | 1.000 |
| [0.9, 1.0) | 22 | 0.988 | 0.909 |

Brier 0.053, ECE 0.079. The dominant bin (clean allows, 87/112 decisions) is
mildly *over*-cautious (10% claimed vs. 3.4% observed), not overconfident.
The top bin is mildly overconfident (98.8% claimed vs. 90.9% observed) —
traced to 2 of 22 decisions being legitimate actions that were correctly
*escalated* (not falsely blocked) but still carry a high reported risk. See
`FIXLOG.md` for the real calibration bug found and fixed in this step (a
session-level posterior was being reported as a per-action risk score) and
the before/after (Brier 0.309 → 0.051, ECE 0.330 → 0.075).

## Failure analysis — pointers into FIXLOG for the report's section 8

Every entry below is a **real defect found in our own process**, not a
hypothetical, with file references and before/after evidence already
written up in `FIXLOG.md`:

1. Provenance aggregation taking the worst-case source over-blocked
   legitimate work an attacker merely also referenced (build step 4).
2. A hyphenated reason code silently degraded every decision on that path
   to fail-closed BLOCK, caught by the hard-negative gate (build step 6).
3. Hysteresis counting a stale, decayed-but-still-elevated posterior as
   "sustained," letting one already-BLOCKed step spill into the next clean
   action's decision (build step 7).
4. A session-level posterior reported as a per-action risk score,
   self-contradicting a simultaneous ALLOW (build step 7) — the dominant
   calibration bug.

See `SAFETY.md`'s "Known failure modes" and "What this does not protect
against" sections for the failure modes we can name without having observed
them directly (paraphrase evasion, insider-trusted-source instructions,
semantic goal drift within policy) — the honest boundary between "found and
fixed" and "architecturally possible, not yet observed."
