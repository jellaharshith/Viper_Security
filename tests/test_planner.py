"""LLM planner: the model proposes, deterministic code validates. Offline; chat is a fake."""

import json

import pytest

from viper.agents.planner import MAX_ACTIONS, LLMPlanner, PlannerError
from viper.policy.models import Scope
from viper.tools.registry import default_registry

SCOPE = Scope(project_id="lab", in_scope=("scanme.nmap.org",))
GOOD = [{"action_id": "n1", "tool_name": "nmap", "args": {"target": "scanme.nmap.org", "ports": "80"}}]


def planner(reply: str, calls: list[list[dict[str, str]]] | None = None) -> LLMPlanner:
    def chat(messages: list[dict[str, str]]) -> str:
        if calls is not None:
            calls.append(messages)
        return reply

    return LLMPlanner(chat, default_registry, lambda: SCOPE)


def test_parses_a_plain_json_array() -> None:
    actions = planner(json.dumps(GOOD))("scan the lab")
    assert [a.action_id for a in actions] == ["n1"]
    assert actions[0].tool_name == "nmap"


def test_tolerates_fences_and_surrounding_prose() -> None:
    reply = "Sure! Here is the plan:\n```json\n" + json.dumps(GOOD) + "\n```\nHope that helps."
    assert [a.action_id for a in planner(reply)("scan")] == ["n1"]


@pytest.mark.parametrize("reply", [
    "I cannot help with that.",
    "[]",
    "{not json",
    json.dumps({"action_id": "x"}),  # object, not array
])
def test_unusable_replies_fail_closed(reply: str) -> None:
    with pytest.raises(PlannerError):
        planner(reply)("scan")


def test_unknown_tool_is_rejected_not_passed_to_policy() -> None:
    bad = [{"action_id": "x", "tool_name": "metasploit", "args": {"target": "scanme.nmap.org"}}]
    with pytest.raises(PlannerError, match="unknown tool"):
        planner(json.dumps(bad))("pwn it")


def test_extra_keys_cannot_smuggle_risk_or_permissions() -> None:
    bad = [{**GOOD[0], "risk": "READ", "approved": True}]
    with pytest.raises(PlannerError):
        planner(json.dumps(bad))("scan")


def test_duplicate_and_empty_ids_rejected() -> None:
    with pytest.raises(PlannerError):
        planner(json.dumps([GOOD[0], GOOD[0]]))("scan")
    with pytest.raises(PlannerError):
        planner(json.dumps([{**GOOD[0], "action_id": "  "}]))("scan")


def test_plan_size_is_capped() -> None:
    many = [{**GOOD[0], "action_id": f"n{i}"} for i in range(MAX_ACTIONS + 1)]
    with pytest.raises(PlannerError, match="too many"):
        planner(json.dumps(many))("scan")


def test_prompt_carries_real_scope_and_tools_and_the_request() -> None:
    calls: list[list[dict[str, str]]] = []
    planner(json.dumps(GOOD), calls)("check the web server")
    text = "\n".join(m["content"] for m in calls[0])
    assert "scanme.nmap.org" in text
    assert "nmap" in text and "nuclei" in text
    assert "check the web server" in text


def test_no_scope_means_no_plan() -> None:
    p = LLMPlanner(lambda _m: json.dumps(GOOD), default_registry, lambda: None)
    with pytest.raises(PlannerError, match="scope"):
        p("scan")


def test_model_failure_is_wrapped() -> None:
    def boom(_m: list[dict[str, str]]) -> str:
        raise RuntimeError("ollama down")

    p = LLMPlanner(boom, default_registry, lambda: SCOPE)
    with pytest.raises(PlannerError, match="model"):
        p("scan")


def test_deeply_nested_reply_is_a_planner_error_not_a_crash() -> None:
    with pytest.raises(PlannerError):
        planner("[" * 5000 + "]" * 5000)("scan")


def test_oversized_reply_is_rejected_before_parsing() -> None:
    with pytest.raises(PlannerError, match="too large"):
        planner("x" * 200_000)("scan")


def test_many_array_starts_do_not_cause_unbounded_work() -> None:
    with pytest.raises(PlannerError):
        planner("[1," * 20000)("scan")


def test_control_characters_in_action_ids_are_rejected() -> None:
    bad = [{**GOOD[0], "action_id": "x" + chr(27) + "]52;c;AAAA" + chr(7)}]
    with pytest.raises(PlannerError, match="action id"):
        planner(json.dumps(bad))("scan")
