"""Model registry. Add a new decision model here."""

from __future__ import annotations

from collections.abc import Callable

from .base import QUESTION, DecisionModel, ModelError, Verdict
from .mock import MockModel
from .openai_decisions import OpenAIDecisions

REGISTRY: dict[str, Callable[[], DecisionModel]] = {
    OpenAIDecisions.name: OpenAIDecisions,
    MockModel.name: MockModel,
}


def get_model(name: str) -> DecisionModel:
    if name not in REGISTRY:
        raise ModelError(f"Unknown model '{name}'. Known: {', '.join(sorted(REGISTRY))}", fatal=True)
    return REGISTRY[name]()


__all__ = ["QUESTION", "REGISTRY", "DecisionModel", "ModelError", "Verdict", "get_model"]
