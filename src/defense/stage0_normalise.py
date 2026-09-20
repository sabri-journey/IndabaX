"""Stage 0 -- deterministic normalisation and provenance tagging.

Trust-level assignment itself is already done by the simulator: every
observation in `DefenseRequest.provenance` arrives with a `trust_level`. This
stage's job is what the simulator does NOT do for us: extract only the text a
human would actually see (strip zero-width/bidi control characters, NFKC-
normalise confusables, strip HTML comments/hidden elements/white-on-white/
mismatched markdown link targets) and record the raw-vs-visible delta as
evidence (`R-HIDDEN-TEXT`) for stage 1/2.

TODO (build step 4): implement the above. Currently a no-op so the pipeline is
wired end-to-end before any real logic lands.
"""

from __future__ import annotations

from defense.context import DecisionContext


def normalise(ctx: DecisionContext) -> DecisionContext:
    """No-op until build step 4. Returns ctx unchanged."""
    return ctx
