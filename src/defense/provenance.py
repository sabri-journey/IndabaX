"""Provenance registry (shared module): answers "where did this exact
argument value come from?" with a chain, for both stage 2's provenance
condition and the observability trace (F7).

The wire contract gives us provenance *per observation* (DefenseRequest.provenance,
keyed by id, attached to conversation items), not per argument -- there is no
field saying "this tool-call argument was copied from provenance record X".
The shipped `provenance` baseline in the starter kit approximates this with
raw substring/sliding-window text overlap (defenses/baselines/provenance.py),
which its own docstring admits paraphrased, encoded, or fragmented values can
defeat. This module is our actual differentiator: it normalises before
comparing (case, whitespace) and additionally decodes candidate values through
the same encodings secrets.py knows about, so a value that only matches after
base64/hex/reverse/rot13 decoding is still traced to its source instead of
silently passing as "no known origin".

Untrusted does not mean untraceable -- most looked-up values (case ids,
document ids the user asked for) genuinely come from AUTHENTICATED_USER and
should trace there. An argument value that appears nowhere in the visible
conversation defaults to AUTHENTICATED_USER (mirrors
sentinel.core.provenance.least_trusted([]) in the starter kit: an empty
evidence set is treated as authenticated user input, not maximum suspicion --
otherwise every literal the agent invents, like a fixed limit=5, would look
"untraceable" and get flagged).
"""

from __future__ import annotations

from dataclasses import dataclass

from defense.context import DecisionContext
from defense.models import ConversationItem, Provenance, ProvenanceRecord
from defense.secrets import decode_variants

TRUST_RANK = {
    "system_policy": 0,
    "authenticated_user": 1,
    "trusted_internal": 2,
    "untrusted_internal": 3,
    "untrusted_external": 4,
    "adversary_controlled": 5,
}

SENSITIVITY_RANK = {"public": 0, "internal": 1, "confidential": 2, "restricted": 3}

MIN_TRACE_LENGTH = 4


def _squash(text: str) -> str:
    return " ".join(text.split()).casefold()


@dataclass(frozen=True)
class TaintLink:
    conversation_role: str
    conversation_kind: str
    provenance: Provenance
    matched_via: str  # "direct" | encoding name from secrets.py | "untraced"


@dataclass(frozen=True)
class TaintChain:
    value: str
    links: tuple[TaintLink, ...]

    @property
    def trust_level(self) -> str:
        if not self.links:
            return "authenticated_user"
        return max((link.provenance.trust_level for link in self.links), key=lambda t: TRUST_RANK[t])

    @property
    def sensitivity(self) -> str:
        if not self.links:
            return "public"
        return max((link.provenance.sensitivity for link in self.links), key=lambda s: SENSITIVITY_RANK[s])

    @property
    def is_untrusted(self) -> bool:
        return TRUST_RANK[self.trust_level] >= TRUST_RANK["untrusted_internal"]

    def describe(self) -> str:
        if not self.links:
            return f"{self.value!r}: no traceable source, treated as authenticated_user"
        parts = [f"{link.provenance.source_type}:{link.provenance.source_id} ({link.matched_via})" for link in self.links]
        return f"{self.value!r} <- " + " | ".join(parts)


def trace_value(
    value: str, conversation: tuple[ConversationItem, ...], provenance_by_id: dict[str, ProvenanceRecord]
) -> TaintChain:
    if not isinstance(value, str) or len(value) < MIN_TRACE_LENGTH:
        return TaintChain(value=str(value), links=())

    links: list[TaintLink] = []
    squashed_value = _squash(value)

    for item in conversation:
        item_provs = [provenance_by_id[pid].provenance for pid in item.provenance_ids if pid in provenance_by_id]
        if not item_provs:
            continue

        # Encoding-aware: check the value against every decoded variant of the
        # item's content (plain, spaced, reversed, rot13, url, base64, base32,
        # hex -- see secrets.decode_variants), not just a raw substring check,
        # so a value that only matches after decoding is still traced instead
        # of silently passing as "no known origin". "direct" is just the
        # "plain" variant under a name that reads better in the trace.
        matched_via: str | None = None
        for encoding, variant_text in decode_variants(item.content):
            if squashed_value in _squash(variant_text):
                matched_via = "direct" if encoding == "plain" else encoding
                break

        if matched_via is not None:
            for prov in item_provs:
                links.append(TaintLink(item.role, item.kind, prov, matched_via))

    return TaintChain(value=value, links=tuple(links))


def trace_action_arguments(ctx: DecisionContext) -> dict[str, TaintChain]:
    """Trace every string argument of ctx.candidate_action (and, for
    request_confirmation, its target) back to the conversation."""
    action = ctx.candidate_action
    target = action.confirmation_for if action.type == "request_confirmation" and action.confirmation_for else action
    chains: dict[str, TaintChain] = {}
    for name, arg_value in target.arguments.items():
        if isinstance(arg_value, str):
            chains[name] = trace_value(arg_value, ctx.conversation, ctx.provenance_by_id)
    if target.content:
        chains["content"] = trace_value(target.content, ctx.conversation, ctx.provenance_by_id)
    return chains


def least_trusted_argument(chains: dict[str, TaintChain]) -> tuple[str, TaintChain] | None:
    """The (argument_name, chain) whose traced trust level is lowest (i.e.
    least trustworthy) -- the one stage 2's provenance condition should
    reason about first. None if there are no string/content arguments."""
    if not chains:
        return None
    return max(chains.items(), key=lambda kv: TRUST_RANK[kv[1].trust_level])
