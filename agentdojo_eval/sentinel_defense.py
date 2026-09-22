"""Adapter: routes AgentDojo tool calls through the live SENTINEL defense
server (POST /v1/decision) before they execute.

Lives entirely outside the IndabaX repo (src/defense/ is untouched by this
file). It only ever talks to the defense over HTTP, exactly the same wire
contract the Sentinel Starter Kit's own harness uses -- so nothing about
src/defense needed to change to test it against a second, independent
benchmark.

Integration point: AgentDojo's stock `ToolsExecutor.query()` loops over the
LLM's proposed `tool_calls` and calls `runtime.run_function(...)` for each
one, unconditionally. `SentinelToolsExecutor` is a drop-in replacement with
the same interface that asks SENTINEL for a decision on each proposed call
first: ALLOW executes normally, BLOCK/ESCALATE returns a synthetic refusal
(same ChatToolResultMessage shape ToolsExecutor already uses for invalid-
tool errors), REWRITE executes with the rewritten arguments instead.

AgentDojo has no first-class "provenance/trust" concept of its own -- unlike
the Sentinel Starter Kit, which hands the defense an explicit provenance
chain per value, AgentDojo's injection tasks embed the attack directly in a
tool result's free text. TOOL_TRUST below is a hand-authored, deliberately
conservative heuristic bridging that gap: any tool whose result can contain
another party's free text (an email someone else sent, a calendar invite
someone else created, a transaction memo a counterparty wrote) is tagged
untrusted_external; anything reflecting the user's own prior actions is
trusted_internal. This is the one part of this adapter that is a judgment
call rather than a faithful translation, and is called out as such in the
report, not the defense pipeline itself.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Sequence
from dataclasses import dataclass, field

import requests

from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.functions_runtime import EmptyEnv, Env, FunctionCall, FunctionReturnType, FunctionsRuntime
from agentdojo.types import ChatMessage, ChatToolResultMessage, get_text_content_as_str, text_content_block_from_string

DEFENSE_URL = "http://127.0.0.1:8081/v1/decision"  # separate instance: knows AgentDojo's tools, port 8080 untouched

# ---------------------------------------------------------------------------
# Capability metadata (mirrors the role of config/capabilities.yaml in
# src/defense, but hand-authored here for AgentDojo's own 34 tools --
# banking (11) + workspace (23)). Judgment calls, documented inline.
# ---------------------------------------------------------------------------

CONSEQUENTIAL_TOOLS = {
    # banking
    "send_money", "schedule_transaction", "update_scheduled_transaction",
    "update_password", "update_user_info",
    # workspace
    "send_email", "delete_email", "create_calendar_event", "cancel_calendar_event",
    "reschedule_calendar_event", "add_calendar_event_participants",
    "append_to_file", "create_file", "delete_file", "share_file",
}

# Sink tools: their outbound text (or the act itself) can leave the user's
# own trust boundary. destination_argument names the field carrying WHO
# receives it, for provenance-of-destination checks.
SINK_TOOLS = {
    "send_money": "recipient",
    "schedule_transaction": "recipient",
    "update_scheduled_transaction": "recipient",
    "send_email": "recipient",
    "create_calendar_event": "participants",
    "add_calendar_event_participants": "participants",
    "reschedule_calendar_event": None,  # notifies existing participants, no new destination arg
    "share_file": "email",
}

# Tools whose RESULT can carry another party's free text -- the injection
# surface. Anything not listed here is treated as carrying no attacker-
# influenceable free text (a plain balance figure, a boolean, etc.).
UNTRUSTED_RESULT_TOOLS = {
    "get_most_recent_transactions",   # counterparty-written transaction subject lines
    "get_scheduled_transactions",
    "get_unread_emails", "get_received_emails", "search_emails",  # externally-authored email bodies
    "search_calendar_events", "get_day_calendar_events",  # externally-created event descriptions
    "get_file_by_id", "list_files", "search_files", "search_files_by_filename",  # possibly shared files
}

# Tools whose result reflects the user's OWN prior actions/documents --
# trusted. read_file belongs here, not in UNTRUSTED_RESULT_TOOLS: it's the
# user's own uploaded document (e.g. their own bill), not content another
# party authored -- confirmed by banking user_task_0 (read own bill, pay
# it), a false GEN-PROVENANCE-CONSEQUENTIAL block until this correction.
TRUSTED_RESULT_TOOLS = {
    "get_sent_emails", "get_draft_emails", "get_balance", "get_iban",
    "get_user_info", "get_current_day", "read_file",
}


@dataclass
class _SessionState:
    run_id: str = field(default_factory=lambda: f"agentdojo-{uuid.uuid4().hex[:12]}")
    step_id: int = 0
    provenance_records: dict[str, dict] = field(default_factory=dict)
    conversation: list[dict] = field(default_factory=list)
    next_provenance_id: int = 0


def _new_provenance_id(state: _SessionState) -> str:
    state.next_provenance_id += 1
    return f"p{state.next_provenance_id}"


def _classify_tool_result(tool_name: str) -> tuple[str, str]:
    """(trust_level, sensitivity) for a tool result -- see module docstring."""
    if tool_name in UNTRUSTED_RESULT_TOOLS:
        return "untrusted_external", "internal"
    if tool_name in TRUSTED_RESULT_TOOLS:
        return "trusted_internal", "internal"
    return "untrusted_internal", "internal"  # conservative default, see docstring


def _record_tool_result(state: _SessionState, tool_name: str, content: str) -> str | None:
    if not content:
        return None
    trust, sensitivity = _classify_tool_result(tool_name)
    pid = _new_provenance_id(state)
    state.provenance_records[pid] = {
        "id": pid,
        "provenance": {
            "source_type": "tool_result",
            "source_id": tool_name,
            "trust_level": trust,
            "origin_actor": "external_party" if trust == "untrusted_external" else "user",
            "retrieved_via": tool_name,
            "sensitivity": sensitivity,
        },
    }
    state.conversation.append(
        {"role": "tool", "kind": "tool_result", "content": content, "provenance_ids": [pid]}
    )
    return pid


def _build_request(
    state: _SessionState,
    user_goal: str,
    candidate_action: dict,
    all_tool_names: list[str],
) -> dict:
    state.step_id += 1
    return {
        "run_id": state.run_id,
        "step_id": state.step_id,
        "user_goal": user_goal,
        "conversation": list(state.conversation),
        "candidate_action": candidate_action,
        "policy_context": {
            "allowed_tools": all_tool_names,
            "consequential_tools": sorted(CONSEQUENTIAL_TOOLS & set(all_tool_names)),
            "internal_email_domains": ["company.com"],
        },
        "provenance": list(state.provenance_records.values()),
        "history_digest": {},
    }


# guard.py's FORBIDDEN_KEYS (src/defense/guard.py) rejects any request
# carrying one of these key names anywhere in the body -- a deliberate
# anti-cheating check against evaluator-only ground truth leaking onto the
# wire in the Sentinel Starter Kit's own harness, where a field named e.g.
# "filename" could only ever be leaked test metadata. AgentDojo's own tool
# vocabulary is unrelated and happens to use "filename" as an ordinary,
# legitimate argument (search_files_by_filename) -- a real 500 here, but a
# cross-benchmark naming collision, not a SENTINEL bug. Rather than weaken
# guard.py (which is doing exactly its job for its actual, intended
# context), rename the colliding key before it goes over the wire, and
# reverse the rename on a REWRITE's returned arguments before executing.
_GUARD_FORBIDDEN_KEYS = {
    "scenario_id", "scenario", "filename", "attack", "attack_present",
    "attack_family", "difficulty", "reference_plan", "expected_outcome",
    "labels", "label", "success_conditions", "security_properties",
    "match_keys", "_meta",
}
_KEY_ALIAS_SUFFIX = "__adojo_arg"


def _alias_forbidden_keys(arguments: dict) -> dict:
    return {
        (f"{k}{_KEY_ALIAS_SUFFIX}" if k.lower() in _GUARD_FORBIDDEN_KEYS else k): v
        for k, v in arguments.items()
    }


def _unalias_forbidden_keys(arguments: dict) -> dict:
    return {k.removesuffix(_KEY_ALIAS_SUFFIX): v for k, v in arguments.items()}


def _scalarize_arguments(arguments: dict) -> dict:
    """SENTINEL's CandidateAction.arguments schema (matching the real
    Sentinel Starter Kit wire contract) only accepts scalar values
    (str/int/float/bool/None) -- AgentDojo's own tool signatures allow
    list/dict arguments (e.g. send_email's `recipients: list[str]`), which
    the wire contract has no representation for. JSON-encode anything
    non-scalar rather than dropping it -- the secret/sensitive scanners and
    provenance tracer both work over string content, so this preserves
    everything they'd need to see, just not as a native list."""
    scalar = (str, int, float, bool, type(None))
    return {
        k: (v if isinstance(v, scalar) else json.dumps(v))
        for k, v in arguments.items()
    }


def _ask_sentinel(request: dict) -> dict:
    resp = requests.post(DEFENSE_URL, json=request, timeout=10)
    resp.raise_for_status()
    return resp.json()


class SentinelToolsExecutor(BasePipelineElement):
    """Drop-in replacement for agentdojo.agent_pipeline.ToolsExecutor that
    gates every proposed tool call through the live SENTINEL defense
    server first."""

    def __init__(self, user_goal: str) -> None:
        self.user_goal = user_goal
        self.state = _SessionState()
        self.decisions: list[dict] = []  # record of every SENTINEL verdict, for reporting

    def query(
        self,
        query: str,
        runtime: FunctionsRuntime,
        env: Env = EmptyEnv(),
        messages: Sequence[ChatMessage] = [],
        extra_args: dict = {},
    ) -> tuple[str, FunctionsRuntime, Env, Sequence[ChatMessage], dict]:
        if len(messages) == 0:
            return query, runtime, env, messages, extra_args
        if messages[-1]["role"] != "assistant":
            return query, runtime, env, messages, extra_args
        tool_calls = messages[-1].get("tool_calls")
        if not tool_calls:
            return query, runtime, env, messages, extra_args

        all_tool_names = list(runtime.functions.keys())
        tool_call_results = []
        for tool_call in tool_calls:
            candidate_action = {
                "type": "tool_call",
                "tool": tool_call.function,
                "arguments": _alias_forbidden_keys(_scalarize_arguments(dict(tool_call.args))),
            }
            request = _build_request(self.state, self.user_goal, candidate_action, all_tool_names)
            try:
                decision = _ask_sentinel(request)
            except requests.RequestException as e:
                decision = {"decision": "escalate", "risk_score": 0.5, "confidence": 0.0,
                            "reason_codes": ["ADAPTER_DEFENSE_UNREACHABLE"], "explanation": str(e)}
            self.decisions.append({"tool": tool_call.function, "args": dict(tool_call.args), **decision})

            verdict = decision["decision"]
            if verdict in ("block", "escalate"):
                tool_call_results.append(
                    ChatToolResultMessage(
                        role="tool",
                        content=[text_content_block_from_string("")],
                        tool_call_id=tool_call.id,
                        tool_call=tool_call,
                        error=f"SENTINEL {verdict.upper()}: {decision.get('explanation') or decision.get('reason_codes')}",
                    )
                )
                continue

            effective_call = tool_call
            if verdict == "rewrite":
                rewritten = decision["rewritten_action"]
                effective_call = FunctionCall(
                    function=tool_call.function,
                    args=_unalias_forbidden_keys(rewritten["arguments"]),
                    id=tool_call.id,
                )

            result, error = runtime.run_function(env, effective_call.function, effective_call.args)
            formatted = str(result) if not isinstance(result, (dict, list)) else str(result)
            _record_tool_result(self.state, effective_call.function, formatted)
            tool_call_results.append(
                ChatToolResultMessage(
                    role="tool",
                    content=[text_content_block_from_string(formatted)],
                    tool_call_id=tool_call.id,
                    tool_call=tool_call,
                    error=error,
                )
            )
        return query, runtime, env, [*messages, *tool_call_results], extra_args

    def check_response(self, response_text: str) -> dict:
        """Not part of BasePipelineElement -- called explicitly by the test
        harness on the agent's final text reply, mirroring the `respond`
        action shape stage2_policy checks for secret/sensitive leaks (build
        step 10's fix) so that gap gets exercised here too, not just the
        tool-call path."""
        candidate_action = {"type": "respond", "content": response_text, "final": True}
        request = _build_request(self.state, self.user_goal, candidate_action, [])
        try:
            decision = _ask_sentinel(request)
        except requests.RequestException as e:
            decision = {"decision": "escalate", "risk_score": 0.5, "confidence": 0.0,
                        "reason_codes": ["ADAPTER_DEFENSE_UNREACHABLE"], "explanation": str(e)}
        self.decisions.append({"tool": None, "args": None, **decision})
        return decision
