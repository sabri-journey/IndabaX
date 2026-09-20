"""Anti-hard-coding guard (F9).

SENTINEL disqualifies any decision derived from a scenario id, filename, or an
organizer-provided expected outcome, however correct it looks
(docs/threat-model.md -> "Defender assumptions"; docs/participant-guide.md ->
"Defense Rules"). The wire schema (`models.DefenseRequest`) never defines fields
like scenario id, attack family, or reference plan, so in normal operation
nothing forbidden should ever arrive. Two things still make this worth enforcing
in code rather than trusting convention:

1. `run_id` embeds the scenario id by construction. The participant guide's own
   example request uses `"run_id": "finance_false_approval-python_defense-s0"`.
   Naive code that pattern-matches on `run_id` (e.g. `"finance" in run_id`) would
   be hard-coding on scenario identity through the back door, even though it
   never touches a field literally named "scenario_id". We remove this
   possibility structurally: everything downstream of `build_context` only ever
   sees an opaque `session_key`, never the raw `run_id` string.
2. A misconfigured runner, a future schema change, or a bug elsewhere could leak
   an evaluator-only field onto the wire. We scan the raw JSON body -- before
   Pydantic silently drops unknown keys -- and fail loudly instead of silently
   ignoring it, so a leak is caught in CI rather than discovered by a judge.
"""

from __future__ import annotations

import hashlib
from typing import Any

FORBIDDEN_KEYS = {
    "scenario_id",
    "scenario",
    "filename",
    "attack",
    "attack_present",
    "attack_family",
    "difficulty",
    "reference_plan",
    "expected_outcome",
    "labels",
    "label",
    "success_conditions",
    "security_properties",
    "match_keys",
    "_meta",
}


class ForbiddenFieldAccess(RuntimeError):
    """Raised when the raw request carries an evaluator-only field."""


def assert_no_forbidden_fields(raw: Any, path: str = "$") -> None:
    """Recursively reject evaluator-only ground truth in a pre-validation request body.

    Defense in depth: the wire schema never defines these fields, so this should
    never fire in normal operation against the real simulator. It exists to fail
    loudly rather than silently drop the field if one ever leaks onto the wire.
    """
    if isinstance(raw, dict):
        for key, value in raw.items():
            if key.lower() in FORBIDDEN_KEYS:
                raise ForbiddenFieldAccess(
                    f"{path}.{key} is evaluator-only ground truth and must not reach the decision path"
                )
            assert_no_forbidden_fields(value, f"{path}.{key}")
    elif isinstance(raw, list):
        for index, item in enumerate(raw):
            assert_no_forbidden_fields(item, f"{path}[{index}]")


def session_key(run_id: str) -> str:
    """Opaque, non-reversible stand-in for run_id.

    Decision logic may use this only as an equality-comparable session handle
    (e.g. a dict key for Bayesian session state) -- never for substring/pattern
    matching, since the whole point is that it carries none of the scenario-name
    information the raw run_id does.
    """
    return hashlib.sha256(run_id.encode("utf-8")).hexdigest()[:16]
