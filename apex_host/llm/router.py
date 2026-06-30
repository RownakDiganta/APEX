"""Model routing seam for future LLM-backed planning/parsing.

Today's planners and parsers are deterministic and rule-based (per
CLAUDE.md Section 11) and do not call any of these methods. ``ModelRouter``
exists as the seam; ``FakeModelRouter`` is what tests and the dry-run CLI
path use so no network calls or API keys are required to exercise the
graph end-to-end.
"""
from __future__ import annotations

import os
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from apex_host.config import ApexConfig


class ModelRouter(Protocol):
    """Returns a LangChain-compatible chat model per role."""

    def planner_llm(self) -> object: ...
    def executor_llm(self) -> object: ...
    def parser_llm(self) -> object: ...
    def reflector_llm(self) -> object: ...


class FakeModelRouter:
    """Deterministic stand-in. Every role returns None — callers must treat
    a None model as "no LLM configured" and fall back to rule-based logic."""

    def planner_llm(self) -> object:
        return None

    def executor_llm(self) -> object:
        return None

    def parser_llm(self) -> object:
        return None

    def reflector_llm(self) -> object:
        return None


class OpenAIModelRouter:
    """Real router backed by langchain-openai's ChatOpenAI.

    Compatible with OpenRouter and other OpenAI-API-compatible endpoints via
    ``OPENAI_BASE_URL``. API keys are read from the environment
    (``OPENAI_API_KEY``) — never hardcoded. Construction does not make any
    network calls.
    """

    def __init__(self, config: "ApexConfig") -> None:
        self._config = config
        self._base_url = os.environ.get("OPENAI_BASE_URL")
        self._api_key = os.environ.get("OPENAI_API_KEY")

    def _build(self, model: str) -> object:
        from langchain_openai import ChatOpenAI

        kwargs: dict[str, object] = {"model": model, "api_key": self._api_key}
        if self._base_url:
            kwargs["base_url"] = self._base_url
        return ChatOpenAI(**kwargs)  # type: ignore[arg-type]

    def planner_llm(self) -> object:
        return self._build(self._config.planner_model)

    def executor_llm(self) -> object:
        return self._build(self._config.executor_model)

    def parser_llm(self) -> object:
        return self._build(self._config.parser_model)

    def reflector_llm(self) -> object:
        return self._build(self._config.planner_model)
