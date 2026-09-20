# Observability layer (F7)

`index.html` is a single, self-contained, offline trace viewer — no server,
no build step, no external resources (fonts, CDNs, JS libraries). Open it
directly in a browser (`file://` works) and load a trace produced by
`src/defense/trace.py` (`traces/<session_key>.jsonl`, or any renamed copy —
e.g. `results/demo_traces/*.jsonl`).

It renders, per decision (not just a log dump):

- a summary bar (step count, allow/block/escalate/rewrite counts, average
  latency);
- a risk-trajectory chart across the session, points colour-coded by
  decision kind;
- a timeline, one row per step, colour-coded by decision, with reason-code
  chips visible without expanding;
- on expand: the explanation, every stage-2 rule that fired (rule id,
  severity, reason code, the provenance chain or message that triggered
  it), original-vs-rewritten action side by side for `rewrite` decisions,
  raw-vs-visible text side by side wherever stage 0 stripped hidden
  content, and the stage-1 Bayesian internals (posterior risk, confidence,
  which signals fired, whether hysteresis was met).

All of this comes from the `extras` object `trace.append()` now writes
alongside the wire-level decision (`src/defense/pipeline.py`'s
`decide_with_trace`) — purely for observability; nothing in `extras` feeds
back into the decision path.

## Verification

Every field escapes attacker-controllable content consistently (the whole
point of this page is to safely render adversarial payloads). Visually
confirmed with real generated traces via headless Chrome
(`google-chrome --headless --screenshot=...`) against
`enterprise_poisoned_invoice` (BLOCK, with the rules-fired panel and
provenance chain visible) and `soc_hostile_log_text` (REWRITE, with the
original-vs-rewritten side-by-side and the risk trajectory spike/decay both
visible on the chart) -- not just static code review. Screenshots in
`screenshots/`. `?trace=<path>` and `&expand=all` (see `index.html`) make
this kind of scripted screenshot straightforward to reproduce.
