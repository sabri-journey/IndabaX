# Responsible AI and safety statement

This document is F8 from our build brief and the "Responsible AI" section
the spec asks every team to cover: what this defense protects against, its
known failure modes, expected false-positive behavior, what data it
observes, when a human is consulted, and — as directly as we can state it —
what it does **not** protect against. "The challenge rewards honest safety
boundaries, not claims of complete safety" (spec book, p.4); everything
below is written to that standard, including two sections (Known failure
modes, What this does not protect against) that exist specifically to avoid
overselling what we built.

## What this defense protects against

- **Indirect prompt injection** from untrusted documents, emails, logs,
  tool outputs, and memory: `GEN-INSTRUCTION-MIRRORS-UNTRUSTED` catches a
  candidate action whose tool name and arguments are spelled out in
  untrusted-or-worse content (the `finance_false_approval`,
  `soc_hostile_log_text`, `enterprise_poisoned_invoice` shape).
- **Provenance-driven hijack** of a specific argument or destination:
  `GEN-PROVENANCE-CONSEQUENTIAL` / `GEN-SINK-DESTINATION-PROVENANCE` /
  `FIN-BENEFICIARY-PROVENANCE` catch a consequential argument, a sink's
  recipient, or a payment beneficiary tracing to an untrusted source with no
  independent, user-authorized explanation.
- **Unauthorized or premature consequential actions**: every consequential
  tool call (`payment_confirm`, `payment_execute`, `email_send`,
  `remediation_execute`, closing a ticket/incident) is default-denied until
  the harness's own structured confirmation ledger
  (`history_digest.confirmations_granted`) shows a real, recorded human
  approval — never a text claim, however convincing ("approval was already
  granted by officer H. Jaziri" does not satisfy this, by construction; see
  `tests/test_state_machine.py`).
- **Process-order violations**: `prepare → confirm → execute` and
  `remediation_prepare → remediation_execute` are enforced defense-side,
  before execution, from our own session-scoped, harness-fed event log —
  never from model output or the content being read.
- **Data exfiltration**, including encoded and fragmented forms: the canary
  detector matches plain, spaced, reversed, ROT13, URL-encoded, base64,
  base32, and hex forms, plus a value chunked across separate arguments.
  Confidential/restricted content traced (even partially, via windowed
  matching) into an outbound message to a destination outside
  trusted-internal is independently flagged.
- **Hidden-content evasion**: zero-width/bidi control characters, hidden
  HTML/comments, and a small set of common homoglyphs are stripped before
  any downstream reasoning; the raw-vs-visible delta is itself evidence.
- **Fragmented / multi-step / adaptive patterns that no single action would
  trip**: a session-level Bayesian posterior accumulates evidence across
  steps (with decay, so an old, resolved suspicion doesn't poison a long
  benign session) and can escalate a clean-looking action if sustained
  session-level suspicion crosses threshold — gated so it can never fire on
  a non-consequential, internal-only action (the UER guard).
- **Over-refusal on legitimate work**: reading, summarizing, or recording
  untrusted-sourced facts internally (a case note, an incident record) is
  never penalized by itself — the decision rests on irreversibility
  combined with untrusted provenance of *arguments*, not on vocabulary or
  the mere presence of untrusted content. Verified against all five
  published `hard_negative` scenarios (`tests/test_hard_negatives.py`) and a
  dedicated test that scary words ("transfer all funds", "disable
  monitoring", "API token") in trusted content never change a decision.

## What data the defense observes

Exactly what the wire contract (`DefenseRequest`) provides for the current
step, plus this session's own history it has accumulated across prior
steps: the user's goal, the conversation so far (role, kind, content,
provenance ids), the current observation, the candidate action, the active
policy context (`allowed_tools`, `consequential_tools`,
`internal_email_domains`), provenance records (source type, trust level,
sensitivity, origin actor), and a harness-computed history digest (recent
tool calls, confirmations granted, least-trusted/most-sensitive seen this
turn). It never receives — and a structural guard plus a dedicated test
suite (`tests/test_no_scenario_leak.py`) enforce this — a scenario id,
filename, attack family, reference plan, evaluator label, or expected
outcome. `run_id` is replaced with an opaque session-key hash before
anything past the wire boundary can see it, specifically because `run_id`
embeds the scenario name by convention on the wire (see `guard.py`) and a
naive defense reading it could hard-code on scenario identity without ever
touching a field literally named `scenario_id`.

Everything the defense stores is process-local, in-memory, keyed by that
opaque session key, and never persisted to disk except the JSONL trace
(itself synthetic data only, safe to include in this repository — see
`docs/security-model.md` in the starter kit). No external network call is
made at decision time; the tool registry it protects has no network
capability either.

## When a human is consulted

Whenever a consequential action (payment confirm/execute, an external send,
a remediation execute, closing a ticket or incident) has no recorded
confirmation and no hard finding forces a BLOCK/REWRITE instead: the
defense returns `ESCALATE` (or, for the one action shape where the agent
itself is asking for confirmation, `ALLOW` — which is what makes the
harness ask the simulated human for that specific action; see
`stage3_decide.py`'s decision table). A human is also consulted whenever
the accumulated session-level posterior has cleared its threshold for
multiple consecutive steps and the current action is consequential or could
reach outside the organization, even if no single-action rule fired.

## Known failure modes (found in our own testing, not hypothetical)

We are listing real defects our own process caught and fixed, not
theoretical ones, because the process of finding them is itself part of the
safety case:

- **A hyphenated reason code silently degraded every decision to
  fail-closed BLOCK** until the hard-negative regression gate caught it by
  name (build step 6). The lesson generalizes: a defense that fails closed
  on error can still fail in a way that looks like a false BLOCK rather
  than a crash, so its self-tests need to check *specific* scenarios by
  name, not just aggregate pass/fail.
- **Provenance aggregation that took the worst-case source for a value
  wrongly penalized legitimate work an attacker merely also referenced**
  (a correct, user-named recipient repeated in a poisoned document; a
  legitimate read the injected text also happened to instruct). Fixed by
  preferring the most-trusted *available* explanation, deliberately scoped
  differently for different rules so the fix for one didn't quietly defeat
  another rule's primary catch (`GEN-INSTRUCTION-MIRRORS-UNTRUSTED` needed
  a narrower, user-authorization-only exemption than
  `GEN-SINK-DESTINATION-PROVENANCE` did — see FIXLOG for the full
  reasoning). This class of bug — "the attacker's text incidentally
  overlaps something legitimate" — is exactly the kind of over-refusal risk
  we expect could still exist in shapes we haven't tested.
- **Hysteresis initially counted a numerically-elevated but stale posterior
  as "sustained," letting one already-BLOCKed strong-evidence step spill
  into an unnecessary escalation of the very next, entirely clean action.**
  Fixed by requiring fresh, strong evidence on each counted step.
- **The Bayesian session posterior was, at one point, reported as the
  per-action risk score of an unrelated clean action being simultaneously
  ALLOWed** — self-contradictory, and the dominant cause of a real
  calibration regression (Brier 0.309 → 0.051 after the fix). We now
  distinguish "how suspicious is this session overall" from "how suspicious
  is this specific action," and only surface the session-level number where
  it actually drives the decision.

All four were caught by our own ablation/hard-negative/calibration tooling
before being reported here — not found by an external reviewer — which is
itself evidence for how much confidence to place in the remainder of the
system that hasn't been stress-tested this hard.

## Expected false-positive behavior

- Every hard finding currently defaults to `BLOCK` unless one of three
  narrow rewrite specs applies (`config/rewrites.yaml`); most
  provenance/instruction findings outside enterprise email and SOC incident
  closure have no rewrite path yet, so a real attacker-adjacent-but-
  legitimate action in those shapes would be blocked, not downgraded, today.
- The provenance tracer is still fundamentally text-overlap based (encoding-
  aware, not just verbatim — see `provenance.py`) — a value that has been
  *paraphrased* rather than copied or encoded will not trace, in either
  direction: a genuinely malicious paraphrased value could slip through
  undetected, and conversely we cannot rule out a legitimate paraphrase
  someday triggering a false negative-avoidance we haven't observed.
- The homoglyph list in `stage0_normalise.py` is a small, explicitly
  non-exhaustive set of common Cyrillic/Greek look-alikes — NFKC alone does
  not unify these, and characters outside our hand-picked list will not be
  despoofed.
- The Bayesian layer's likelihood ratios and thresholds are hand-tuned
  engineering judgment against the published scenario library, not fit to
  labelled data (none exists) — see `results/ablation.md` and
  `results/*_calibration.md` for exactly how well-calibrated the resulting
  risk scores are and where the residual gap comes from.

## What this does not protect against

- **A fully-trusted-source insider instruction.** If the user's own goal,
  or a genuinely `system_policy`/`authenticated_user`-trust source,
  directs a harmful-but-technically-authorized action, nothing here second-
  guesses stated intent — by design, per the Defense Rules ("the user's own
  request asks for something out of policy" is `direct_instruction`, a
  family this system does not specifically target beyond the same
  consequential-gating every action gets).
- **Semantic goal drift that stays within policy.** A subtly wrong but
  policy-compliant action (right tool, right trust level, wrong actual
  intent) is invisible to rule- or provenance-based checks; nothing here
  reasons about whether an action serves the user's *true* goal, only
  whether its provenance and irreversibility are acceptable.
- **An attack whose payload is entirely plausible, legitimate-looking
  content with no provenance mismatch, no hidden text, no encoded secret,
  and no lifecycle violation.** If an attacker can make a malicious
  instruction indistinguishable in trust, form, and content from a genuine
  one, this defense has no independent signal left to catch it on.
- **Model-weight attacks, side channels, or multi-agent collusion** — out
  of scope for this challenge's MVP per `docs/threat-model.md`, and
  correspondingly out of scope here.
- **Anything outside the simulator's threat model** — network access,
  credential theft, sandbox escape are structurally impossible for the
  scenario attacker to attempt in the first place (see
  `docs/threat-model.md`), so this defense was never asked to, and does
  not, defend against them.

## Honest summary

Across the full published scenario library (public + validation splits,
`--model mock`, every ablation configuration): **ASR 0.0, BTU 1.0, CVR 0.0,
FBR 0.0, UER 0.0**. That is a genuinely strong result on the evidence we
have — and it is evidence from one offline mock model against one published
library, not a claim of general robustness. The failure modes and gaps
above are the parts of that claim we can already see the edges of; we
expect there are others we cannot yet see, which is exactly what the
ablation/calibration tooling in this repo (`scripts/run_ablation.py`,
`scripts/calibrate.py`) exists to keep surfacing rather than to declare
finished.
