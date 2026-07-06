"""Fingerprint unit tests (toolless) — criterion 7.

Covers LangGraph app, CrewAI app, skills-only repo, and the no-agent early-exit.
"""

from __future__ import annotations

from pathlib import Path

from runworthy.fingerprint import fingerprint
from runworthy.intake import open_target

FIXTURES = Path(__file__).parent / "fixtures"


def _fp(name: str):
    with open_target(str(FIXTURES / name)) as src:
        return fingerprint(src.root, src.target)


def test_langgraph_app_fingerprint():
    am = _fp("langgraph_app")
    assert "LangGraph" in am.frameworks
    assert "LangChain" in am.frameworks
    assert any("agent.py" in e for e in am.entrypoints)
    assert "shell-exec" in am.tools
    assert "network-http" in am.tools
    assert "declared-tools" in am.tools
    assert am.memory_stores  # MemorySaver
    assert not am.is_empty()


def test_crewai_app_fingerprint():
    am = _fp("crewai_app")
    assert "CrewAI" in am.frameworks
    assert not am.is_empty()


def test_skill_repo_fingerprint():
    am = _fp("skill_repo")
    assert any("SKILL.md" in s for s in am.skills)
    assert am.mcp_servers  # mcp.json
    assert not am.is_empty()


def test_noagent_repo_is_empty():
    am = _fp("noagent_repo")
    assert am.is_empty()
