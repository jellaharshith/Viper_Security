"""Pins the LangGraph behaviours the approval flow depends on (see ADR 0008)."""

from typing import TypedDict

from langgraph.checkpoint.memory import InMemorySaver
from langgraph.graph import END, START, StateGraph
from langgraph.types import Command, interrupt


class State(TypedDict):
    answer: str


def test_interrupt_pauses_resume_restarts_node():
    calls: list[int] = []

    def node(state: State) -> dict[str, str]:
        calls.append(1)  # runs again on resume: code before interrupt() must be idempotent
        return {"answer": interrupt({"question": "approve?"})}

    graph = (StateGraph(State).add_node("n", node).add_edge(START, "n").add_edge("n", END)
             .compile(checkpointer=InMemorySaver()))
    cfg = {"configurable": {"thread_id": "t1"}}

    paused = graph.invoke({"answer": ""}, cfg)
    assert paused["__interrupt__"][0].value == {"question": "approve?"}
    assert graph.get_state(cfg).next == ("n",)

    done = graph.invoke(Command(resume="yes"), cfg)
    assert done["answer"] == "yes"
    assert len(calls) == 2
