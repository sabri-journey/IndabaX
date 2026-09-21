"""Rewrite catalogue (F2): per-domain, per-tool safer substitutions.

"Rewrite is our highest-value lever for the Precision criterion -- treat
BLOCK as a last resort when no rewrite genuinely removes the hazard" (build
brief). stage3_decide tries this before defaulting a hard finding to BLOCK.

A rewrite is only proposed when it would address EVERY current finding, not
just some (see _fully_addressed) -- a rewrite that silences one finding
while leaving an unrelated one unaddressed is not "removing the hazard",
it's hiding half of it.

Every substitute-tool rewrite must still land on a tool this scenario's
policy_context.allowed_tools actually lists: the harness's own
`_valid_rewrite` only checks the target tool exists in the global registry,
but PolicyEngine.check_attempt independently flags a tool outside
allowed_tools afterwards -- a rewrite that isn't in allowed_tools would trade
a defense-side BLOCK for an evaluator-side policy violation, which is worse,
not better (see config/rewrites.yaml's own docstring for the two build-brief
items deliberately left out because no mechanically valid rewrite exists).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from defense.capabilities import default_registry
from defense.context import DecisionContext
from defense.models import CandidateAction
from defense.provenance import target_action
from defense.secrets import mask, scan_values
from defense.stage2_policy import Finding

DEFAULT_REWRITES_PATH = Path(__file__).resolve().parents[2] / "config" / "rewrites.yaml"


@dataclass(frozen=True)
class RewriteSpec:
    id: str
    kind: str
    description: str = ""
    applies_to: Any = None
    from_tool: str | None = None
    to_tool: str | None = None
    tool: str | None = None
    from_status_argument: str = "status"
    from_status_values: tuple[str, ...] = ()
    to_status: str | None = None
    append_note: str = ""
    triggers_on_reason_codes: tuple[str, ...] = ()


@dataclass(frozen=True)
class RewriteResult:
    rewrite_id: str
    kind: str
    original: CandidateAction
    rewritten: CandidateAction
    reason_codes: tuple[str, ...]
    removed: str


def load_rewrites(path: Path = DEFAULT_REWRITES_PATH) -> list[RewriteSpec]:
    raw = yaml.safe_load(path.read_text())
    specs: list[RewriteSpec] = []
    for entry in raw.get("rewrites", []):
        specs.append(
            RewriteSpec(
                id=entry["id"],
                kind=entry["kind"],
                description=entry.get("description", ""),
                applies_to=entry.get("applies_to"),
                from_tool=entry.get("from_tool"),
                to_tool=entry.get("to_tool"),
                tool=entry.get("tool"),
                from_status_argument=entry.get("from_status_argument", "status"),
                from_status_values=tuple(entry.get("from_status_values", [])),
                to_status=entry.get("to_status"),
                append_note=entry.get("append_note", ""),
                triggers_on_reason_codes=tuple(entry.get("triggers_on_reason_codes", [])),
            )
        )
    return specs


_REWRITES: list[RewriteSpec] | None = None


def cached_default_rewrites() -> list[RewriteSpec]:
    global _REWRITES
    if _REWRITES is None:
        _REWRITES = load_rewrites()
    return _REWRITES


def _fully_addressed(spec: RewriteSpec, findings: tuple[Finding, ...]) -> bool:
    if not findings:
        return False
    return all(f.reason_code in spec.triggers_on_reason_codes for f in findings)


def _tool_allowed(tool: str, policy_context: dict[str, Any]) -> bool:
    return tool in policy_context.get("allowed_tools", [])


def _matches_sink(tool: str) -> bool:
    registry = default_registry()
    return tool in registry and registry.get(tool).sink


def _outbound_values(target: CandidateAction) -> list[str]:
    values = [str(v) for v in target.arguments.values() if isinstance(v, str)]
    if target.content:
        values.append(target.content)
    return values


def _try_mask_secret(spec: RewriteSpec, target: CandidateAction, findings: tuple[Finding, ...]) -> RewriteResult | None:
    if not target.tool or not _matches_sink(target.tool):
        return None
    hits = scan_values(_outbound_values(target))
    plain_hits = [h for h in hits if h.encoding == "plain"]
    if not plain_hits:
        return None
    new_arguments = {k: (mask(v, plain_hits) if isinstance(v, str) else v) for k, v in target.arguments.items()}
    rewritten = CandidateAction(type="tool_call", tool=target.tool, arguments=new_arguments)
    if rewritten.arguments == target.arguments:
        return None
    return RewriteResult(
        rewrite_id=spec.id,
        kind=spec.kind,
        original=target,
        rewritten=rewritten,
        reason_codes=tuple(sorted({f.reason_code for f in findings})),
        removed=f"masked {len(plain_hits)} secret value(s) from outbound text",
    )


def _try_mask_secret_response(
    spec: RewriteSpec, target: CandidateAction, findings: tuple[Finding, ...]
) -> RewriteResult | None:
    """Response-channel mirror of _try_mask_secret (build step 10): a
    `respond` action has no tool/arguments, so the sink-scoped rewrite above
    never applies to it. Masks a detected canary/secret out of the response
    content itself and lets the (now-safe) answer still reach the user,
    instead of blocking a reply whose SHAPE was the reference-plan-correct
    answer to a legitimate question -- exactly the same "action is right,
    content is the problem" case the sink version already handles.

    Deliberately does NOT attempt to mask SENSITIVE_IN_RESPONSE findings:
    unlike a canary/secret (an exact, known value scan_values can locate and
    redact), a sensitive_response finding only says "this traces to
    confidential/restricted content" via a windowed hash match, with no
    single literal substring safe to remove -- the same reason
    GEN-SENSITIVE-TO-UNTRUSTED-SINK has no masking rewrite either."""
    if target.type != "respond" or not target.content:
        return None
    hits = scan_values([target.content])
    plain_hits = [h for h in hits if h.encoding == "plain"]
    if not plain_hits:
        return None
    new_content = mask(target.content, plain_hits)
    if new_content == target.content:
        return None
    rewritten = CandidateAction(type="respond", content=new_content, final=target.final)
    return RewriteResult(
        rewrite_id=spec.id,
        kind=spec.kind,
        original=target,
        rewritten=rewritten,
        reason_codes=tuple(sorted({f.reason_code for f in findings})),
        removed=f"masked {len(plain_hits)} secret value(s) from response text",
    )


def _try_substitute_tool(
    spec: RewriteSpec, target: CandidateAction, findings: tuple[Finding, ...], policy_context: dict[str, Any]
) -> RewriteResult | None:
    if target.tool != spec.from_tool or not spec.to_tool:
        return None
    if not _tool_allowed(spec.to_tool, policy_context):
        return None
    rewritten = CandidateAction(type="tool_call", tool=spec.to_tool, arguments=dict(target.arguments))
    return RewriteResult(
        rewrite_id=spec.id,
        kind=spec.kind,
        original=target,
        rewritten=rewritten,
        reason_codes=tuple(sorted({f.reason_code for f in findings})),
        removed=f"{spec.from_tool} -> {spec.to_tool}",
    )


def _try_downgrade_status(spec: RewriteSpec, target: CandidateAction, findings: tuple[Finding, ...]) -> RewriteResult | None:
    if target.tool != spec.tool:
        return None
    if target.arguments.get(spec.from_status_argument) not in spec.from_status_values:
        return None
    new_arguments = dict(target.arguments)
    new_arguments[spec.from_status_argument] = spec.to_status
    original_note = str(new_arguments.get("note") or "")
    new_arguments["note"] = (original_note + " " + spec.append_note).strip()
    rewritten = CandidateAction(type="tool_call", tool=target.tool, arguments=new_arguments)
    return RewriteResult(
        rewrite_id=spec.id,
        kind=spec.kind,
        original=target,
        rewritten=rewritten,
        reason_codes=tuple(sorted({f.reason_code for f in findings})),
        removed=f"{spec.from_status_argument}={spec.from_status_values} -> {spec.to_status}",
    )


def propose_rewrite(ctx: DecisionContext, findings: tuple[Finding, ...]) -> RewriteResult | None:
    target = target_action(ctx.candidate_action)
    # Every other rewrite kind (substitute_tool, downgrade_status) genuinely
    # needs a tool_call to retarget; mask_secret_response is the one
    # exception (build step 10) -- a `respond` action has no tool at all, so
    # it can't be excluded by the same blanket check the other kinds need.
    if target.type not in ("tool_call", "respond") or (target.type == "tool_call" and target.tool is None):
        return None

    for spec in cached_default_rewrites():
        if not _fully_addressed(spec, findings):
            continue

        result: RewriteResult | None = None
        if spec.kind == "mask_secret":
            result = _try_mask_secret(spec, target, findings)
        elif spec.kind == "mask_secret_response":
            result = _try_mask_secret_response(spec, target, findings)
        elif spec.kind == "substitute_tool":
            result = _try_substitute_tool(spec, target, findings, ctx.policy_context)
        elif spec.kind == "downgrade_status":
            result = _try_downgrade_status(spec, target, findings)

        if result is not None:
            return result

    return None
