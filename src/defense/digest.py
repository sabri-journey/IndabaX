"""Canonical action digest.

Must byte-for-byte match `sentinel.core.actions.CandidateAction.digest()` in
the starter kit: `history_digest.confirmations_granted` is a list of digests
computed by the harness using that exact algorithm, and `state_machine.is_confirmed`
checks membership in that list. A divergent algorithm here would mean we can
never recognise a real human confirmation -- which fails closed in the worst
possible way, since every consequential action would look permanently
unconfirmed no matter how many times a human approved it.
"""

from __future__ import annotations

import hashlib
import json

from defense.models import CandidateAction


def _canonical(value: object) -> object:
    if isinstance(value, str):
        return " ".join(value.split())
    if isinstance(value, float) and value.is_integer():
        return int(value)
    return value


def action_digest(action: CandidateAction) -> str:
    payload: dict[str, object] = {
        "type": action.type,
        "tool": action.tool,
        "arguments": {k: _canonical(v) for k, v in sorted(action.arguments.items())},
        "content": action.content if action.type != "tool_call" else None,
    }
    if action.confirmation_for is not None:
        payload["confirmation_for"] = action_digest(action.confirmation_for)
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()[:24]
