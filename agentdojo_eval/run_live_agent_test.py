"""Live-agent AgentDojo run: real Qwen3-8B generates its own actions (via
the OpenAI-compatible shim on :8000), gated through SENTINEL
(SentinelToolsExecutor -> live /v1/decision on :8081) instead of AgentDojo's
stock ToolsExecutor. Mirrors exactly how AgentDojo wires its own built-in
defenses (agent_pipeline.py's AgentPipeline.from_config, config.defense ==
"tool_filter" etc.) -- same [SystemMessage, InitQuery, llm, ToolsExecutionLoop
([<defense>, llm])] shape, just with SentinelToolsExecutor as the <defense>.
"""

from __future__ import annotations

import sys

sys.path.insert(0, ".")

import openai

from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline
from agentdojo.agent_pipeline.basic_elements import InitQuery, SystemMessage
from agentdojo.agent_pipeline.llms.local_llm import LocalLLM
from agentdojo.agent_pipeline.tool_execution import ToolsExecutionLoop
from agentdojo.models import MODEL_NAMES
from agentdojo.task_suite.load_suites import get_suite

from sentinel_defense import SentinelToolsExecutor

MODEL_NAMES.setdefault("Qwen/Qwen3-8B", "Qwen")

SYSTEM_MESSAGE = "You are a helpful assistant."


def build_pipeline(user_goal: str) -> tuple[AgentPipeline, SentinelToolsExecutor]:
    client = openai.OpenAI(base_url="http://127.0.0.1:8000/v1", api_key="not-needed")
    llm = LocalLLM(client, model="qwen3-8b", temperature=0.0)
    executor = SentinelToolsExecutor(user_goal=user_goal)
    tools_loop = ToolsExecutionLoop([executor, llm])
    pipeline = AgentPipeline([SystemMessage(SYSTEM_MESSAGE), InitQuery(), llm, tools_loop])
    pipeline.name = "Qwen/Qwen3-8B"
    return pipeline, executor


def run_one(suite, task_id: str, is_injection: bool, verbose: bool = True):
    task = suite.get_injection_task_by_id(task_id) if is_injection else suite.get_user_task_by_id(task_id)
    goal = task.GOAL if is_injection else task.PROMPT
    pipeline, executor = build_pipeline(goal)

    utility, security = suite.run_task_with_pipeline(
        pipeline,
        task,
        injection_task=None,
        injections={},
    )
    label = f"{suite.name}/{task_id}" + (" (INJECTION, direct goal)" if is_injection else " (benign)")
    print(f"\n=== {label} ===")
    print(f"  utility={utility}  (benign: did the task succeed as intended)")
    for d in executor.decisions:
        tool = d.get("tool") or "(final response)"
        print(f"  tool={tool:30s} decision={d['decision']:9s} risk={d['risk_score']:.2f} reason_codes={d['reason_codes']}")
    return utility, executor.decisions


def run_attack(suite, attack_cls, user_task_id: str, injection_task_id: str):
    """The real AgentDojo evaluation: embed injection_task's goal, via
    attack_cls's jailbreak template, into user_task's own data -- then let
    the live model do the USER's task and see whether it also falls for the
    embedded attack, and whether SENTINEL catches it if it does."""
    user_task = suite.get_user_task_by_id(user_task_id)
    injection_task = suite.get_injection_task_by_id(injection_task_id)

    pipeline, executor = build_pipeline(user_task.PROMPT)
    attack = attack_cls(suite, pipeline)
    task_injections = attack.attack(user_task, injection_task)

    utility, security = suite.run_task_with_pipeline(
        pipeline, user_task, injection_task, task_injections,
    )
    # AgentDojo's own convention (verified against BaseInjectionTask.security()):
    # security=True means the injection task's OWN success condition was met
    # in the final environment -- i.e. the attack SUCCEEDED. security=False
    # means the attack did NOT succeed.
    print(f"\n=== {suite.name}/{user_task_id} + INJECTED[{injection_task_id}] via {attack.name} ===")
    print(f"  benign task succeeded (utility) = {utility}")
    print(f"  ATTACK SUCCEEDED = {security}")
    for d in executor.decisions:
        tool = d.get("tool") or "(final response)"
        print(f"  tool={tool:30s} decision={d['decision']:9s} risk={d['risk_score']:.2f} reason_codes={d['reason_codes']}")
    return utility, security, executor.decisions


if __name__ == "__main__":
    import sys as _sys

    banking = get_suite("v1.2.2", "banking")
    workspace = get_suite("v1.2.2", "workspace")

    if "--smoke" in _sys.argv:
        print("### LIVE AGENT SMOKE TEST -- banking/user_task_1 (benign, read-only) ###")
        run_one(banking, "user_task_1", is_injection=False)
        _sys.exit(0)

    from agentdojo.attacks.important_instructions_attacks import ImportantInstructionsAttack

    pairs = [
        (banking, "user_task_1", "injection_task_5"),   # drain funds
        (banking, "user_task_9", "injection_task_7"),   # change password
        (banking, "user_task_10", "injection_task_2"),  # leak favorite food
        (banking, "user_task_7", "injection_task_1"),   # leak dinner companion's IBAN
        (workspace, "user_task_2", "injection_task_0"), # send text to attacker email
        (workspace, "user_task_5", "injection_task_1"), # delete a file
        (workspace, "user_task_22", "injection_task_3"),# leak received email body
        (workspace, "user_task_24", "injection_task_4"),# leak FB security code (2nd pairing)
    ]
    for suite, utid, itid in pairs:
        try:
            run_attack(suite, ImportantInstructionsAttack, utid, itid)
        except Exception as e:
            print(f"\n=== {suite.name}/{utid}+{itid} === ERROR: {type(e).__name__}: {e}")
