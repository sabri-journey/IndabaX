"""Stage 0 -- deterministic normalisation and provenance tagging.

Trust-level assignment is already done by the simulator: every observation
in `DefenseRequest.provenance` arrives with a `trust_level`. This stage's job
is what the simulator does NOT do for us: extract only the text a human
would actually see (strip zero-width/bidi control characters, despoof a
small set of common homoglyphs, strip HTML comments/hidden elements,
flag markdown links whose label and target disagree) and record the
raw-vs-visible delta as evidence (`R-HIDDEN-TEXT`) for stage 2.

IMPORTANT: this stage never mutates `ctx.candidate_action`. The action's
`arguments`/`content` must stay byte-identical to what the agent actually
proposed -- `digest.action_digest` and the harness's own
`history_digest.confirmations_granted` depend on exact equality, and a
normalised copy would silently and permanently break every confirmation
check (see digest.py's docstring for the failure mode). Only
`ctx.conversation` and `ctx.observation` -- read-only observational text --
are replaced with their visible form; a separate, non-mutating helper is
provided for text-analysis of the candidate action itself.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, replace

from defense.context import DecisionContext
from defense.models import CandidateAction

ZERO_WIDTH = "​‌‍⁠﻿᠎"
BIDI_CONTROLS = "".join(chr(c) for c in range(0x202A, 0x202F)) + "".join(chr(c) for c in range(0x2066, 0x206A))
_STRIP_CHARS_RE = re.compile(f"[{re.escape(ZERO_WIDTH + BIDI_CONTROLS)}]")

_HTML_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)
_HIDDEN_TAG_RE = re.compile(
    r"<(\w+)\b[^>]*\b(?:hidden\b|display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0)[^>]*>.*?</\1\s*>",
    re.IGNORECASE | re.DOTALL,
)
_ANY_TAG_RE = re.compile(r"<[^>]+>")
_MD_LINK_RE = re.compile(r"\[([^\]]+)\]\(([^)]+)\)")
_HIDDEN_TEXT_DELTA_THRESHOLD = 4  # ignore trivial whitespace-collapse noise

# A small, non-exhaustive set of common look-alike characters used in
# homoglyph attacks (Cyrillic/Greek letters that read as Latin). NFKC alone
# does not unify these -- they are different Unicode blocks, not
# compatibility-equivalent. Documented as a known limitation in SAFETY.md,
# not claimed as complete confusable-character coverage.
HOMOGLYPHS = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c",
    "у": "y", "х": "x", "і": "i", "ј": "j", "һ": "h",
    "Α": "A", "Β": "B", "Ε": "E", "Ι": "I", "Κ": "K",
    "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T",
    "Υ": "Y", "Χ": "X",
}  # fmt: skip


@dataclass(frozen=True)
class NormalisedText:
    raw: str
    visible: str
    signals: tuple[str, ...]

    @property
    def hidden(self) -> bool:
        return "R-HIDDEN-TEXT" in self.signals


def _strip_hidden_html(text: str) -> str:
    text = _HTML_COMMENT_RE.sub(" ", text)
    text = _HIDDEN_TAG_RE.sub(" ", text)
    return text


def _has_mismatched_link(text: str) -> bool:
    for label, target in _MD_LINK_RE.findall(text):
        label_domain = re.search(r"([a-z0-9-]+\.[a-z]{2,})", label, re.IGNORECASE)
        target_domain = re.search(r"://([a-z0-9.-]+)", target, re.IGNORECASE)
        if label_domain and target_domain and label_domain.group(1).lower() not in target_domain.group(1).lower():
            return True
    return False


def normalise_text(raw: str | None) -> NormalisedText:
    if not raw:
        return NormalisedText(raw=raw or "", visible=raw or "", signals=())

    signals: list[str] = []

    despoofed = "".join(HOMOGLYPHS.get(ch, ch) for ch in raw)
    nfkc = unicodedata.normalize("NFKC", despoofed)
    if nfkc != raw:
        signals.append("R-CONFUSABLE-CHARS")

    stripped_controls = _STRIP_CHARS_RE.sub("", nfkc)
    if len(stripped_controls) != len(nfkc):
        signals.append("R-INVISIBLE-CHARS")

    no_hidden_html = _strip_hidden_html(stripped_controls)
    if no_hidden_html != stripped_controls:
        signals.append("R-HIDDEN-HTML")

    if _has_mismatched_link(raw):
        signals.append("R-MISMATCHED-LINK")

    # Strip remaining ordinary tags for the *visible* rendering (their text
    # content stays, only markup goes) -- keeps stage 2's text matching
    # working on prose rather than markup.
    visible = " ".join(_ANY_TAG_RE.sub(" ", no_hidden_html).split())
    raw_collapsed = " ".join(raw.split())
    if len(raw_collapsed) - len(visible) > _HIDDEN_TEXT_DELTA_THRESHOLD:
        signals.append("R-HIDDEN-TEXT")

    return NormalisedText(raw=raw, visible=visible, signals=tuple(signals))


def normalise(ctx: DecisionContext) -> DecisionContext:
    """Replaces each conversation/observation item's content with its visible
    form and records hidden-content signals in `ctx.normalisation_signals`.
    Does NOT touch `ctx.candidate_action` -- see module docstring."""
    normalised_items = []
    all_signals: list[str] = []
    for item in ctx.conversation:
        result = normalise_text(item.content)
        all_signals.extend(result.signals)
        normalised_items.append(item.model_copy(update={"content": result.visible}))

    observation = ctx.observation
    if observation is not None:
        result = normalise_text(observation.content)
        all_signals.extend(result.signals)
        observation = observation.model_copy(update={"content": result.visible})

    return replace(
        ctx,
        conversation=tuple(normalised_items),
        observation=observation,
        normalisation_signals=tuple(all_signals),
    )


def normalise_candidate_action_text(action: CandidateAction) -> NormalisedText:
    """Text-analysis-only normalised form of the candidate action's own
    text payload (content + argument values), for stage 2 checks that need
    to reason about what the action itself says. Never used to replace
    `ctx.candidate_action` -- see module docstring."""
    parts: list[str] = []
    if action.content:
        parts.append(action.content)
    parts.extend(str(v) for v in action.arguments.values() if v is not None)
    return normalise_text("\n".join(parts))
