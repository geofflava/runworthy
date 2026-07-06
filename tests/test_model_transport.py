"""VF-2 openai_compat transport — no key, no `openai` package required.

The pure helpers are unit-tested directly, and the live path is exercised with a
fake OpenAI SDK injected into ``sys.modules`` so we validate request-building
(slug, strict json_schema, Anthropic provider pin) and usage mapping without a
network call. Eval replay stays transport-agnostic (cassettes are keyed by
call-hash, not transport), so nothing here touches the recorded corpus.
"""

from __future__ import annotations

import sys
from types import SimpleNamespace

import pytest

from runworthy.model import ModelUnavailable, StructuredModel, TokenBudget
from runworthy.model.client import (
    OPENROUTER_BASE_URL,
    _parse_json_content,
    _provider_prefs,
    openrouter_slug,
)

SCHEMA = {
    "type": "object",
    "properties": {"items": {"type": "array", "items": {"type": "object"}}},
    "required": ["items"],
    "additionalProperties": False,
}


def test_openrouter_slug_namespaces_anthropic():
    assert openrouter_slug("claude-sonnet-5") == "anthropic/claude-sonnet-5"
    assert openrouter_slug("anthropic/claude-3.5-sonnet") == "anthropic/claude-3.5-sonnet"
    assert openrouter_slug("openai/gpt-4o") == "openai/gpt-4o"


def test_provider_prefs_only_for_openrouter():
    assert _provider_prefs(OPENROUTER_BASE_URL) == {
        "order": ["Anthropic"],
        "allow_fallbacks": False,
    }
    assert _provider_prefs("https://api.openai.com/v1") is None


def test_parse_json_content():
    assert _parse_json_content('{"items": []}') == {"items": []}
    with pytest.raises(ModelUnavailable):
        _parse_json_content("not json")
    with pytest.raises(ModelUnavailable):
        _parse_json_content("[1, 2, 3]")  # valid JSON, but not an object


def test_openai_compat_without_key_is_unavailable(monkeypatch):
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    monkeypatch.delenv("RUNWORTHY_MODEL_API_KEY", raising=False)
    m = StructuredModel(
        mode="live", store=None, namespace="s::v",
        budget=TokenBudget(None), transport="openai_compat",
    )
    with pytest.raises(ModelUnavailable, match="OpenRouter"):
        m.complete(node="map", system="s", user="u", schema=SCHEMA)


class _FakeCreate:
    def __init__(self):
        self.captured: dict = {}

    def __call__(self, **kwargs):
        self.captured = kwargs
        return SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content='{"items": []}'))],
            usage=SimpleNamespace(prompt_tokens=11, completion_tokens=4),
        )


def _install_fake_openai(monkeypatch):
    create = _FakeCreate()
    init_kwargs: dict = {}

    class _Client:
        def __init__(self, **kwargs):
            init_kwargs.update(kwargs)
            self.chat = SimpleNamespace(completions=SimpleNamespace(create=create))

    monkeypatch.setitem(sys.modules, "openai", SimpleNamespace(OpenAI=_Client))
    return create, init_kwargs


def test_openai_compat_builds_request_and_maps_usage(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    create, init_kwargs = _install_fake_openai(monkeypatch)
    budget = TokenBudget(max_tokens=None)
    m = StructuredModel(
        mode="live", store=None, namespace="s::v", budget=budget,
        transport="openai_compat", model_id="claude-sonnet-5",
    )
    out = m.complete(node="map", system="SYS", user="USR", schema=SCHEMA)

    assert out == {"items": []}
    assert (budget.input_tokens, budget.output_tokens) == (11, 4)  # usage mapped to budget
    assert init_kwargs["base_url"] == OPENROUTER_BASE_URL
    assert init_kwargs["api_key"] == "sk-or-test"

    req = create.captured
    assert req["model"] == "anthropic/claude-sonnet-5"
    assert req["response_format"]["type"] == "json_schema"
    assert req["response_format"]["json_schema"]["strict"] is True
    assert req["response_format"]["json_schema"]["schema"] == SCHEMA
    assert req["extra_body"]["provider"] == {
        "order": ["Anthropic"], "allow_fallbacks": False,
    }
    assert req["extra_body"]["reasoning"] == {"enabled": False}  # thinking off for mechanical calls
    assert req["messages"] == [
        {"role": "system", "content": "SYS"},
        {"role": "user", "content": "USR"},
    ]


def test_openai_compat_custom_base_url_omits_provider_pin(monkeypatch):
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    monkeypatch.setenv("RUNWORTHY_MODEL_API_KEY", "sk-test")
    create, init_kwargs = _install_fake_openai(monkeypatch)
    m = StructuredModel(
        mode="live", store=None, namespace="s::v", budget=TokenBudget(None),
        transport="openai_compat", base_url="https://api.openai.com/v1",
        model_id="openai/gpt-4o-mini",
    )
    m.complete(node="map", system="s", user="u", schema=SCHEMA)

    req = create.captured
    assert init_kwargs["base_url"] == "https://api.openai.com/v1"
    assert init_kwargs["api_key"] == "sk-test"  # generic key env honored
    assert req["model"] == "openai/gpt-4o-mini"  # already a slug, passed through
    assert req.get("extra_body") is None  # no OpenRouter prefs on a non-OpenRouter host
