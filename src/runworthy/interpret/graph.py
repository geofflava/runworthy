"""The LangGraph interpretation graph: map → translate → synthesize.

The node logic lives in ``nodes.py`` (plain, tested functions); this module wires
them into a ``StateGraph`` and exposes ``interpret()``. ``langgraph`` is imported
lazily so importing the package — or running ``--no-llm`` — needs neither it nor a
key.
"""

from __future__ import annotations

from typing import Any, TypedDict

from ..models import OperationalAnswer, ReadinessReport
from ..model.client import ModelUnavailable, StructuredModel
from .nodes import MapContext, MapItem, assemble, build_context, run_map, run_translate


class GraphState(TypedDict, total=False):
    report: ReadinessReport
    answers: list[OperationalAnswer]
    ctx: MapContext
    items: list[MapItem]
    translations: dict[int, tuple[str, str]]
    notes: list[str]
    result: ReadinessReport


def build_graph(model: StructuredModel) -> Any:
    """Compile the interpretation graph bound to ``model``."""
    try:
        from langgraph.graph import END, START, StateGraph
    except ImportError as exc:  # pragma: no cover - environment-dependent
        raise ModelUnavailable(
            "the 'langgraph' package is required for the interpretation layer: "
            "pip install 'runworthy[llm]'"
        ) from exc

    def n_map(state: GraphState) -> dict:
        ctx = build_context(state["report"], state["answers"])
        items, notes = run_map(model, ctx)
        return {"ctx": ctx, "items": items, "notes": notes}

    def n_translate(state: GraphState) -> dict:
        return {"translations": run_translate(model, state["items"], state["ctx"])}

    def n_synthesize(state: GraphState) -> dict:
        result = assemble(
            state["report"], state["items"], state["translations"], state["answers"], state["notes"]
        )
        return {"result": result}

    g = StateGraph(GraphState)
    g.add_node("map", n_map)
    g.add_node("translate", n_translate)
    g.add_node("synthesize", n_synthesize)
    g.add_edge(START, "map")
    g.add_edge("map", "translate")
    g.add_edge("translate", "synthesize")
    g.add_edge("synthesize", END)
    return g.compile()


def interpret(
    report: ReadinessReport,
    *,
    model: StructuredModel,
    answers: list[OperationalAnswer] | None = None,
) -> ReadinessReport:
    """Turn a Phase-0 provisional report into an AFR-graded one.

    Pure over ``(report, answers, model)``: the same inputs and the same cassette
    produce the same graded report, which is what the eval suite relies on.
    """
    graph = build_graph(model)
    final = graph.invoke({"report": report, "answers": list(answers or [])})
    return final["result"]
