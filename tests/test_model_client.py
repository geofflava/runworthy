"""Model-client tests that need no API key: the token budget (loud breach) and
the replay/record cache (cassette hit, cache hit on a repeat SHA)."""

from __future__ import annotations

import pytest

from runworthy.model import (
    BudgetExceeded,
    CassetteMiss,
    FileResponseStore,
    ModelUnavailable,
    StructuredModel,
    TokenBudget,
)
from runworthy.model.client import call_key

SCHEMA = {"type": "object", "properties": {"ok": {"type": "boolean"}}, "required": ["ok"]}


def test_budget_wall_is_loud():
    b = TokenBudget(max_tokens=10)
    b.add(6, 6)  # 12 > 10
    with pytest.raises(BudgetExceeded, match="token budget"):
        b.guard()


def test_budget_none_never_blocks():
    b = TokenBudget(max_tokens=None)
    b.add(10_000, 10_000)
    b.guard()  # no ceiling -> no raise


def test_store_round_trip(tmp_path):
    store = FileResponseStore(root=tmp_path)
    k = call_key("map", "sys", "user", SCHEMA)
    assert store.get("sha1::0.1.0", k) is None
    store.put("sha1::0.1.0", k, "map", {"ok": True})
    assert store.get("sha1::0.1.0", k) == {"ok": True}


def test_replay_miss_is_hard_error(tmp_path):
    m = StructuredModel(mode="replay", store=FileResponseStore(root=tmp_path), namespace="sha::v")
    with pytest.raises(CassetteMiss, match="no recorded response"):
        m.complete(node="map", system="s", user="u", schema=SCHEMA)


def test_replay_hit_returns_cassette(tmp_path):
    store = FileResponseStore(root=tmp_path)
    store.put("sha::v", call_key("map", "s", "u", SCHEMA), "map", {"ok": True})
    m = StructuredModel(mode="replay", store=store, namespace="sha::v")
    assert m.complete(node="map", system="s", user="u", schema=SCHEMA) == {"ok": True}


def test_live_cache_hit_needs_no_key(tmp_path):
    """A repeat scan of an already-seen SHA is served from cache — no key, no
    spend (AC6: cache hit demonstrated on a repeat scan)."""
    store = FileResponseStore(root=tmp_path)
    store.put("shaX::v", call_key("synth", "s", "u", SCHEMA), "synth", {"ok": True})
    budget = TokenBudget(max_tokens=100)
    m = StructuredModel(mode="live", store=store, namespace="shaX::v", budget=budget)
    assert m.complete(node="synth", system="s", user="u", schema=SCHEMA) == {"ok": True}
    assert budget.total == 0  # served from cache, nothing spent


def test_live_budget_breach_before_any_call(tmp_path):
    """With the budget already spent, a live call fails loud before it reaches the
    provider — proving the wall (AC6: tiny budget -> loud failure)."""
    budget = TokenBudget(max_tokens=1)
    budget.add(5, 5)
    m = StructuredModel(mode="live", store=None, namespace="s::v", budget=budget)
    with pytest.raises(BudgetExceeded):
        m.complete(node="map", system="s", user="u", schema=SCHEMA)


def test_live_without_key_is_unavailable(tmp_path, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    m = StructuredModel(mode="live", store=None, namespace="s::v", budget=TokenBudget(None))
    with pytest.raises(ModelUnavailable, match="ANTHROPIC_API_KEY"):
        m.complete(node="map", system="s", user="u", schema=SCHEMA)
