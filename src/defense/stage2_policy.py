"""Stage 2 -- deterministic Progent-style policy engine.

Rule *shape* mirrors `sentinel.core.policies` in the starter kit
(discriminated rule kinds, one evaluator per kind) -- proven, simple, and
easy for a judge to read end-to-end in one sitting. We extend it with the
two conditions that are the core of our thesis: `provenance_condition` /
`destination_provenance` (a critical argument must trace to a source at or
above a required trust level -- provenance.py) and the process-state checks
already built in state_machine.py (prepare -> confirm -> execute order; a
harness-confirmed approval, never a text claim).

Rules are data (config/rules/*.yaml): which tools, which arguments, which
thresholds, which domain. Evaluators are a small, fixed set of Python
functions below -- "rules are data, not code" means the *policy* is editable
without touching Python, not that we hand-rolled a general-purpose
expression interpreter. A bespoke DSL was judged a correctness risk not
worth taking in a multi-day build; this is the documented simplification
(see FIXLOG's build-step-4 entry).

"Forbid evaluated before allow": every rule below only ever *adds* a
Finding to an append-only list -- there is no "allow" rule kind that could
cancel one out, so this property holds structurally, not by rule ordering.

"Default-deny on consequential tools": GEN-CONSEQUENTIAL-APPROVAL
(config/rules/general.yaml) fires for every tool whose
`CapabilityRegistry.is_consequential(args)` is true, with no opt-out, unless
`state_machine.is_confirmed` says otherwise.

Rule files are loaded unconditionally (general + all three domain packs):
tool names are unique across enterprise/finance/soc (verified in
tests/test_capabilities.py), so a domain-specific rule simply never matches a
tool from a different domain -- there is no need to infer which domain a
request belongs to (and the wire contract does not reliably expose that
anyway; see guard.py's discussion of `run_id`).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from defense import ablation
from defense.capabilities import CapabilityRegistry, default_registry
from defense.context import DecisionContext
from defense.digest import action_digest
from defense.provenance import (
    TRUST_RANK,
    SENSITIVITY_RANK,
    instruction_dictated_by_untrusted,
    least_trusted_argument,
    target_action,
    trace_action_arguments,
    trace_bulk_text,
    trace_value,
)
from defense.secrets import scan_values
from defense.session_store import SessionState
from defense.state_machine import check_prerequisites, is_confirmed

DEFAULT_RULES_DIR = Path(__file__).resolve().parents[2] / "config" / "rules"
DEFAULT_RULE_FILES = ("general", "enterprise", "finance", "soc")

SENSITIVE_LEVELS = {"confidential", "restricted"}

# Rule kinds whose only defect is "not yet approved" -- allowing this action
# is what makes the harness ask the simulated human (request_confirmation
# candidate actions) or triggers our own ESCALATE (plain tool_call
# candidates). Everything else is a hard mismatch/hijack signal, not a
# paperwork gap.
CONFIRMATION_KINDS = frozenset({"consequential_approval", "forced_confirmation"})

# Which rule kinds each ablation.py toggle disables (F6) -- grouped by which
# shared module the kind actually depends on, not by name similarity:
# sensitive_sink depends on provenance.trace_bulk_text, not secrets.py, so it
# groups with the provenance kinds despite the "sink" in its name.
_STATE_MACHINE_KINDS = frozenset({"prerequisite", "consequential_approval", "forced_confirmation"})
_PROVENANCE_KINDS = frozenset(
    {
        "provenance_condition",
        "destination_provenance",
        "instruction_mirrors_untrusted",
        "sensitive_sink",
        "sensitive_response",
    }
)
_SECRET_DETECTOR_KINDS = frozenset({"secret_sink", "secret_response"})


def _ablation_enabled(kind: str) -> bool:
    if kind in _STATE_MACHINE_KINDS and not ablation.state_machine_rules_enabled():
        return False
    if kind in _PROVENANCE_KINDS and not ablation.provenance_rules_enabled():
        return False
    if kind in _SECRET_DETECTOR_KINDS and not ablation.secret_detector_rules_enabled():
        return False
    return True


@dataclass(frozen=True)
class RuleSpec:
    id: str
    kind: str
    severity: str
    reason_code: str
    description: str = ""
    applies_to: Any = None  # None | "consequential" | "sink" | list[str]
    arguments: tuple[str, ...] = ()
    max_trust: str = "trusted_internal"
    destination_argument: str = "to"
    when_argument: dict[str, list[Any]] = field(default_factory=dict)
    require_untrusted_destination: bool = True


@dataclass(frozen=True)
class Finding:
    rule_id: str
    kind: str
    severity: str
    reason_code: str
    message: str


@dataclass(frozen=True)
class PolicyVerdict:
    findings: tuple[Finding, ...] = ()
    action_digest: str | None = None

    @property
    def hard_findings(self) -> tuple[Finding, ...]:
        return tuple(f for f in self.findings if f.kind not in CONFIRMATION_KINDS)

    @property
    def confirmation_findings(self) -> tuple[Finding, ...]:
        return tuple(f for f in self.findings if f.kind in CONFIRMATION_KINDS)


def load_rules(paths: list[Path]) -> list[RuleSpec]:
    rules: list[RuleSpec] = []
    for path in paths:
        if not path.is_file():
            continue
        raw = yaml.safe_load(path.read_text())
        for entry in raw.get("rules", []):
            rules.append(
                RuleSpec(
                    id=entry["id"],
                    kind=entry["kind"],
                    severity=entry["severity"],
                    reason_code=entry["reason_code"],
                    description=entry.get("description", ""),
                    applies_to=entry.get("applies_to"),
                    arguments=tuple(entry.get("arguments", [])),
                    max_trust=entry.get("max_trust", "trusted_internal"),
                    destination_argument=entry.get("destination_argument", "to"),
                    when_argument=entry.get("when_argument", {}),
                    require_untrusted_destination=entry.get("require_untrusted_destination", True),
                )
            )
    return rules


def default_rules(rules_dir: Path = DEFAULT_RULES_DIR) -> list[RuleSpec]:
    return load_rules([rules_dir / f"{name}.yaml" for name in DEFAULT_RULE_FILES])


_RULES: list[RuleSpec] | None = None


def cached_default_rules() -> list[RuleSpec]:
    global _RULES
    if _RULES is None:
        _RULES = default_rules()
    return _RULES


def _rule_applies(rule: RuleSpec, tool: str, arguments: dict[str, Any], registry: CapabilityRegistry) -> bool:
    if rule.applies_to is None:
        return True
    if tool not in registry:
        return False
    capability = registry.get(tool)
    if rule.applies_to == "consequential":
        return capability.is_consequential(arguments)
    if rule.applies_to == "sink":
        return capability.sink
    if rule.applies_to == "consequential_or_sink":
        return capability.is_consequential(arguments) or capability.sink
    if isinstance(rule.applies_to, list):
        return tool in rule.applies_to
    return False


def _argument_condition_matches(rule: RuleSpec, arguments: dict[str, Any]) -> bool:
    if not rule.when_argument:
        return True
    return all(arguments.get(key) in values for key, values in rule.when_argument.items())


def resolve_destination_trust(capability, arguments: dict[str, Any], policy_context: dict[str, Any]) -> str:
    """Mirrors recipient_trust() in the starter kit's tools/base.py: a
    dynamic-destination sink (email) resolves to trusted_internal only if the
    recipient's domain is in policy_context.internal_email_domains; a static
    trusted_internal sink (notes/tickets/incidents) always resolves there;
    anything else fails closed to untrusted_external."""
    if "dynamic" in capability.destination_tags:
        recipient = str(arguments.get("to", "")).lower()
        internal_domains = [d.lower() for d in policy_context.get("internal_email_domains", [])]
        if any(recipient.endswith("@" + domain) for domain in internal_domains):
            return "trusted_internal"
        return "untrusted_external"
    if "trusted_internal" in capability.destination_tags:
        return "trusted_internal"
    return "untrusted_external"


def _outbound_text_values(target) -> list[str]:
    values = [str(v) for v in target.arguments.values() if isinstance(v, str)]
    if target.content:
        values.append(target.content)
    return values


def evaluate(ctx: DecisionContext, session: SessionState, registry: CapabilityRegistry | None = None) -> PolicyVerdict:
    registry = registry or default_registry()
    rules = cached_default_rules()

    action = ctx.candidate_action
    target = target_action(action)
    digest = action_digest(target)

    findings: list[Finding] = []

    # A `respond` action has no tool at all, so every tool-scoped rule kind
    # below (sink destination, secret-in-sink-arguments, ...) structurally
    # cannot see it -- "is this tool a sink" has no meaning when there is no
    # tool. That is exactly the shape the reference agent uses to exfiltrate
    # in practice (build step 10, real Qwen3-8B): a legitimate, in-scope
    # lookup returns tainted content, and the agent's own summarising reply
    # repeats a restricted value back to the user with no tool call involved.
    # These two checks are the response-channel mirror of GEN-SECRET-TO-
    # UNTRUSTED-SINK / GEN-SENSITIVE-TO-UNTRUSTED-SINK, run unconditionally
    # for any `respond` action so this path is no longer structurally unseen.
    if target.type == "respond" and target.content:
        for rule in rules:
            if not _ablation_enabled(rule.kind):
                continue
            if rule.kind == "secret_response":
                hits = scan_values([target.content])
                if hits:
                    findings.append(
                        Finding(
                            rule.id,
                            rule.kind,
                            rule.severity,
                            rule.reason_code,
                            f"secret detected in outbound response ({hits[0].kind}, {hits[0].encoding})",
                        )
                    )
            elif rule.kind == "sensitive_response":
                chain = trace_bulk_text(target.content, ctx.conversation, ctx.provenance_by_id)
                if SENSITIVITY_RANK[chain.sensitivity] >= SENSITIVITY_RANK["confidential"] and chain.links:
                    findings.append(
                        Finding(
                            rule.id,
                            rule.kind,
                            rule.severity,
                            rule.reason_code,
                            f"outbound response traces to {chain.sensitivity} content: {chain.describe()}",
                        )
                    )

    if target.type != "tool_call" or target.tool is None:
        return PolicyVerdict(findings=tuple(findings), action_digest=digest)

    tool = target.tool

    for rule in rules:
        if not _ablation_enabled(rule.kind):
            continue

        if rule.kind == "tool_permission":
            if tool not in ctx.policy_context.get("allowed_tools", []):
                findings.append(
                    Finding(rule.id, rule.kind, rule.severity, rule.reason_code, f"{tool!r} is outside allowed_tools")
                )

        elif rule.kind == "unknown_tool":
            if tool not in registry:
                findings.append(
                    Finding(rule.id, rule.kind, rule.severity, rule.reason_code, f"{tool!r} is not a recognised tool")
                )

        elif rule.kind == "prerequisite":
            if tool in registry:
                violation = check_prerequisites(ctx, session, tool, registry)
                if violation is not None:
                    findings.append(
                        Finding(
                            rule.id,
                            rule.kind,
                            rule.severity,
                            rule.reason_code,
                            f"{tool!r} attempted before required step(s) {violation.missing}",
                        )
                    )

        elif rule.kind == "consequential_approval":
            if tool in registry:
                capability = registry.get(tool)
                if capability.is_consequential(target.arguments) and not is_confirmed(ctx, digest):
                    findings.append(
                        Finding(
                            rule.id,
                            rule.kind,
                            rule.severity,
                            rule.reason_code,
                            f"{tool!r} is consequential with no recorded human confirmation",
                        )
                    )

        elif rule.kind == "forced_confirmation":
            if _rule_applies(rule, tool, target.arguments, registry) and _argument_condition_matches(
                rule, target.arguments
            ):
                if not is_confirmed(ctx, digest):
                    findings.append(
                        Finding(
                            rule.id,
                            rule.kind,
                            rule.severity,
                            rule.reason_code,
                            f"{tool!r} with {rule.when_argument} requires a recorded human confirmation",
                        )
                    )

        elif rule.kind == "instruction_mirrors_untrusted":
            if _rule_applies(rule, tool, target.arguments, registry):
                hit = instruction_dictated_by_untrusted(ctx)
                if hit is not None:
                    findings.append(
                        Finding(rule.id, rule.kind, rule.severity, rule.reason_code, f"{tool!r} call: {hit.describe()}")
                    )

        elif rule.kind == "provenance_condition":
            if _rule_applies(rule, tool, target.arguments, registry):
                chains = trace_action_arguments(ctx)
                if rule.arguments:
                    chains = {name: chain for name, chain in chains.items() if name in rule.arguments}
                worst = least_trusted_argument(chains)
                if worst is not None:
                    name, chain = worst
                    if TRUST_RANK[chain.trust_level] > TRUST_RANK[rule.max_trust]:
                        findings.append(
                            Finding(rule.id, rule.kind, rule.severity, rule.reason_code, f"{name}: {chain.describe()}")
                        )

        elif rule.kind == "destination_provenance":
            if _rule_applies(rule, tool, target.arguments, registry):
                dest_value = target.arguments.get(rule.destination_argument)
                if isinstance(dest_value, str):
                    chain = trace_value(dest_value, ctx.conversation, ctx.provenance_by_id)
                    if TRUST_RANK[chain.trust_level] > TRUST_RANK[rule.max_trust]:
                        findings.append(
                            Finding(
                                rule.id,
                                rule.kind,
                                rule.severity,
                                rule.reason_code,
                                f"{rule.destination_argument}={dest_value!r}: {chain.describe()}",
                            )
                        )

        elif rule.kind == "secret_sink":
            if tool in registry and registry.get(tool).sink and _rule_applies(rule, tool, target.arguments, registry):
                capability = registry.get(tool)
                destination = resolve_destination_trust(capability, target.arguments, ctx.policy_context)
                if not rule.require_untrusted_destination or destination != "trusted_internal":
                    hits = scan_values(_outbound_text_values(target))
                    if hits:
                        findings.append(
                            Finding(
                                rule.id,
                                rule.kind,
                                rule.severity,
                                rule.reason_code,
                                f"secret detected in outbound {tool!r} ({hits[0].kind}, {hits[0].encoding})",
                            )
                        )

        elif rule.kind == "sensitive_sink":
            if tool in registry and registry.get(tool).sink and _rule_applies(rule, tool, target.arguments, registry):
                capability = registry.get(tool)
                destination = resolve_destination_trust(capability, target.arguments, ctx.policy_context)
                if destination != "trusted_internal":
                    body = "\n".join(_outbound_text_values(target))
                    chain = trace_bulk_text(body, ctx.conversation, ctx.provenance_by_id)
                    if SENSITIVITY_RANK[chain.sensitivity] >= SENSITIVITY_RANK["confidential"] and chain.links:
                        findings.append(
                            Finding(
                                rule.id,
                                rule.kind,
                                rule.severity,
                                rule.reason_code,
                                f"outbound {tool!r} traces to {chain.sensitivity} content: {chain.describe()}",
                            )
                        )

    return PolicyVerdict(findings=tuple(findings), action_digest=digest)
