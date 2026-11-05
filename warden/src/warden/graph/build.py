"""Assemble the graph: plan -> investigate -> verify -> (investigate | report).

    graph = build_graph(deps, checkpointer)
    graph.invoke(initial_state(deps.store, "WRD-0001"), {"configurable": {"thread_id": "WRD-0001"}})

Thread id = incident id, so a restarted process resumes the right run.
"""

from __future__ import annotations

from langgraph.graph import END, START, StateGraph

from warden.graph.nodes import (
    GraphDeps, investigate_node, plan_node, report_node, route_after_verify, verify_node,
)
from warden.graph.state import WardenState


def build_graph(deps: GraphDeps, checkpointer=None):
    g = StateGraph(WardenState)
    g.add_node("plan", plan_node(deps))
    g.add_node("investigate", investigate_node(deps))
    g.add_node("verify", verify_node(deps))
    g.add_node("report", report_node(deps))
    g.add_edge(START, "plan")
    g.add_edge("plan", "investigate")
    g.add_edge("investigate", "verify")
    g.add_conditional_edges("verify", route_after_verify(deps),
                            {"investigate": "investigate", "report": "report"})
    g.add_edge("report", END)
    return g.compile(checkpointer=checkpointer)


def initial_state(store, incident_id: str) -> dict:
    return {"incident_id": incident_id, "alert": store.alert(incident_id)}


def thread_config(incident_id: str) -> dict:
    return {"configurable": {"thread_id": incident_id}}
