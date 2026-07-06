"""Structured-output model client with a token budget and a replay/record cache.

Three responsibilities, one small surface:

1. **Structured output.** ``complete(...)`` forces Claude to answer through a
   single tool whose ``input_schema`` is the caller's JSON schema, so every
   model node returns validated JSON — never prose we have to parse.

2. **A token budget.** Per spec §4 cost control, spend is metered and a breach
   **fails loud** (``BudgetExceeded``) rather than silently truncating. We
   practice AFR-15 on ourselves.

3. **A response cache that doubles as an eval cassette.** Responses are keyed by
   ``(namespace, call-hash)`` where ``namespace = commit_sha :: engine_version``
   (spec §4: "cache by commit SHA"). The same store powers three modes:
   - ``replay``  — read only; a miss is a hard error (CI runs here, keyless).
   - ``record``  — read, else call live and persist (regenerating eval cassettes).
   - ``live``    — read, else call live and persist (a normal CLI scan; a repeat
     scan of the same SHA is a cache hit).

Two live transports sit behind ``complete``: the default ``anthropic`` (direct
Messages API, forced tool-use) and ``openai_compat`` (any OpenAI-compatible
endpoint — OpenRouter by default — using ``response_format: json_schema``). The
second is the product's BYOK breadth feature: many target users hold an
OpenRouter key, not an Anthropic one. Direct Anthropic stays the default: one
fewer intermediary in the privacy story. Either SDK is imported lazily inside its
live path, so importing this module — or running ``--no-llm`` — needs neither
package nor a key.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

Mode = Literal["replay", "record", "live"]
Transport = Literal["anthropic", "openai_compat"]

DEFAULT_MODEL = os.environ.get("RW_MODEL", "claude-sonnet-5")
DEFAULT_TRANSPORT: str = os.environ.get("RUNWORTHY_MODEL_TRANSPORT", "anthropic")
DEFAULT_BASE_URL: str = os.environ.get("RUNWORTHY_MODEL_BASE_URL", "")
OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"


class ModelUnavailable(RuntimeError):
    """No API key / the anthropic SDK isn't installed — the LLM step can't run."""


class CassetteMiss(RuntimeError):
    """A replay-mode call had no recorded response. Re-record with a live key."""


class BudgetExceeded(RuntimeError):
    """The per-scan token budget was exhausted. Loud by design — never truncate."""


# --- token budget ------------------------------------------------------------


@dataclass
class TokenBudget:
    """Meters model spend for one scan. ``max_tokens=None`` disables the ceiling.

    The check runs *before* each call: once the running total reaches the ceiling
    we refuse to start another request, so the budget is a hard wall, not a
    post-hoc report.
    """

    max_tokens: int | None
    input_tokens: int = 0
    output_tokens: int = 0
    calls: int = 0

    @property
    def total(self) -> int:
        return self.input_tokens + self.output_tokens

    def guard(self) -> None:
        if self.max_tokens is not None and self.total >= self.max_tokens:
            raise BudgetExceeded(
                f"token budget of {self.max_tokens} reached ({self.total} used over "
                f"{self.calls} call(s)) — raise --token-budget or narrow the scan"
            )

    def add(self, input_tokens: int, output_tokens: int) -> None:
        self.input_tokens += input_tokens
        self.output_tokens += output_tokens
        self.calls += 1


# --- response store (cache / cassette) ---------------------------------------


def openrouter_slug(model_id: str) -> str:
    """Map an internal/Anthropic model id to an OpenRouter model slug. OpenRouter
    namespaces Anthropic models under ``anthropic/`` (e.g. ``claude-sonnet-5`` ->
    ``anthropic/claude-sonnet-5``); an id that already contains a '/' is treated as
    a full slug and passed through. The exact cheapest Claude tier that passes the
    eval labels is pinned at recording time via ``RW_MODEL``."""
    return model_id if "/" in model_id else f"anthropic/{model_id}"


def _provider_prefs(base_url: str) -> dict[str, Any] | None:
    """Pin OpenRouter routing to Anthropic upstream, fallbacks off, so recorded
    cassettes aren't polluted by cross-provider variance (VF-2 §3). Only OpenRouter
    reads these; other OpenAI-compatible hosts get nothing extra.

    We deliberately do NOT set ``require_parameters``: Anthropic's OpenRouter entry
    doesn't advertise ``response_format: json_schema`` (Anthropic uses tool-use
    natively), so requiring it 404s the request even though OpenRouter translates
    structured output to Anthropic tool-use fine at runtime. The pin + no-fallback
    is what gives determinism; our validate-reject-retry loop covers correctness."""
    if "openrouter.ai" in base_url:
        return {"order": ["Anthropic"], "allow_fallbacks": False}
    return None


def _parse_json_content(content: str) -> dict[str, Any]:
    """Parse the JSON object an ``openai_compat`` model returns as message content.
    The validate-reject-retry loop upstream is still the real guarantee — this only
    turns the transport's string into a dict."""
    try:
        obj = json.loads(content)
    except (json.JSONDecodeError, TypeError) as exc:
        raise ModelUnavailable("openai_compat model did not return valid JSON content") from exc
    if not isinstance(obj, dict):
        raise ModelUnavailable("openai_compat model returned non-object JSON")
    return obj


def call_key(node: str, system: str, user: str, schema: dict[str, Any]) -> str:
    """A stable hash of everything that determines the response. Changing a prompt
    changes the key — a cassette miss that correctly forces a re-record."""
    blob = json.dumps(
        {"node": node, "system": system, "user": user, "schema": schema},
        sort_keys=True,
        ensure_ascii=False,
    )
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]


@dataclass
class FileResponseStore:
    """One JSON file per namespace under ``root``. Human-inspectable: each entry
    records the node it came from beside the response, so a cassette reads like a
    transcript."""

    root: Path

    def _path(self, namespace: str) -> Path:
        safe = namespace.replace("/", "_").replace(":", "-").replace("\\", "_")
        return self.root / f"{safe}.json"

    def _load(self, namespace: str) -> dict[str, Any]:
        p = self._path(namespace)
        if not p.exists():
            return {}
        return json.loads(p.read_text(encoding="utf-8"))

    def get(self, namespace: str, key: str) -> dict[str, Any] | None:
        entry = self._load(namespace).get(key)
        return entry["response"] if entry else None

    def put(self, namespace: str, key: str, node: str, response: dict[str, Any]) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        data = self._load(namespace)
        data[key] = {"node": node, "response": response}
        p = self._path(namespace)
        p.write_text(json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")


# --- the model ---------------------------------------------------------------


@dataclass
class StructuredModel:
    mode: Mode = "live"
    store: FileResponseStore | None = None
    namespace: str = "nosha::0"
    budget: TokenBudget = field(default_factory=lambda: TokenBudget(max_tokens=None))
    model_id: str = DEFAULT_MODEL
    api_key: str | None = None  # falls back to a transport-specific env key at call time
    transport: str = DEFAULT_TRANSPORT  # "anthropic" | "openai_compat"
    base_url: str = DEFAULT_BASE_URL  # openai_compat only; defaults to OpenRouter
    max_tokens: int = 3072  # a full 29-control map with rationales needs headroom
    temperature: float = 0.0

    def complete(self, *, node: str, system: str, user: str, schema: dict[str, Any]) -> dict[str, Any]:
        """Return a JSON object conforming to ``schema`` for this prompt."""
        key = call_key(node, system, user, schema)
        if self.store is not None:
            hit = self.store.get(self.namespace, key)
            if hit is not None:
                return hit

        if self.mode == "replay":
            raise CassetteMiss(
                f"no recorded response for node={node!r} in namespace={self.namespace!r}. "
                "Record it with a live key (RW_MODEL_MODE=record) before replaying."
            )

        self.budget.guard()
        response, usage = self._call_live(system=system, user=user, schema=schema)
        self.budget.add(*usage)

        if self.store is not None:  # record + live both persist (live = cache for repeat SHAs)
            self.store.put(self.namespace, key, node, response)
        return response

    # -- live providers --
    def _call_live(self, *, system: str, user: str, schema: dict[str, Any]) -> tuple[dict[str, Any], tuple[int, int]]:
        if self.transport == "openai_compat":
            return self._call_openai_compat(system=system, user=user, schema=schema)
        return self._call_anthropic(system=system, user=user, schema=schema)

    def _call_anthropic(self, *, system: str, user: str, schema: dict[str, Any]) -> tuple[dict[str, Any], tuple[int, int]]:
        key = self.api_key or os.environ.get("ANTHROPIC_API_KEY")
        if not key:
            raise ModelUnavailable(
                "ANTHROPIC_API_KEY is not set. Set it (or pass --byok / a key) to run the "
                "interpretation layer, or use --no-llm for deterministic findings only."
            )
        try:
            import anthropic  # lazy: only the LLM path needs the SDK
        except ImportError as exc:  # pragma: no cover - environment-dependent
            raise ModelUnavailable(
                "the 'anthropic' package is required for the interpretation layer: "
                "pip install 'runworthy[llm]'"
            ) from exc

        client = anthropic.Anthropic(api_key=key)
        tool_name = "emit"
        msg = client.messages.create(
            model=self.model_id,
            max_tokens=self.max_tokens,
            temperature=self.temperature,
            system=system,
            tools=[{"name": tool_name, "description": "Return the structured result.", "input_schema": schema}],
            tool_choice={"type": "tool", "name": tool_name},
            messages=[{"role": "user", "content": user}],
        )
        payload: dict[str, Any] | None = None
        for block in msg.content:
            if getattr(block, "type", None) == "tool_use" and block.name == tool_name:
                payload = dict(block.input)
                break
        if payload is None:  # pragma: no cover - model contract violation
            raise ModelUnavailable("model did not return the forced tool call")
        usage = (int(msg.usage.input_tokens), int(msg.usage.output_tokens))
        return payload, usage

    def _call_openai_compat(self, *, system: str, user: str, schema: dict[str, Any]) -> tuple[dict[str, Any], tuple[int, int]]:
        key = (
            self.api_key
            or os.environ.get("OPENROUTER_API_KEY")
            or os.environ.get("RUNWORTHY_MODEL_API_KEY")
        )
        if not key:
            raise ModelUnavailable(
                "no OpenRouter key. Set OPENROUTER_API_KEY (or RUNWORTHY_MODEL_API_KEY) to run the "
                "interpretation layer over an OpenAI-compatible endpoint, or use --no-llm for "
                "deterministic findings only."
            )
        try:
            import openai  # lazy: only the openai_compat path needs the SDK
        except ImportError as exc:  # pragma: no cover - environment-dependent
            raise ModelUnavailable(
                "the 'openai' package is required for the openai_compat transport: "
                "pip install 'runworthy[llm]'"
            ) from exc

        base_url = self.base_url or OPENROUTER_BASE_URL
        client = openai.OpenAI(api_key=key, base_url=base_url)
        extra_body: dict[str, Any] = {}
        prefs = _provider_prefs(base_url)
        if prefs is not None:
            extra_body["provider"] = prefs
            # OpenRouter defaults extended thinking ON for Claude; our map/translate
            # are mechanical, so thinking just burns the token budget and returns
            # empty content on truncation. Turn it off.
            extra_body["reasoning"] = {"enabled": False}
        resp = client.chat.completions.create(
            model=openrouter_slug(self.model_id),
            max_tokens=self.max_tokens,
            temperature=self.temperature,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            response_format={
                "type": "json_schema",
                "json_schema": {"name": "emit", "strict": True, "schema": schema},
            },
            extra_body=extra_body or None,
        )
        content = resp.choices[0].message.content
        payload = _parse_json_content(content or "")
        usage = (int(resp.usage.prompt_tokens), int(resp.usage.completion_tokens))
        return payload, usage
