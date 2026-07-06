"""Fingerprint & scope reduction (spec §3 [2]).

Deterministic, cheap: find the agent surface so we never feed a whole repo to a
model downstream. Detect frameworks, skill/MCP artifacts, and the capability
surface into an ``AgentMap``. If nothing agent-shaped is found, the engine exits
early with an honest "no agent surface detected" — it never fabricates findings.
"""

from __future__ import annotations

import re
from pathlib import Path

from .models import AgentMap, ScanTarget

# --- signatures --------------------------------------------------------------

# Dependency-name substrings -> framework label (matched against manifests).
_FRAMEWORK_DEPS: dict[str, tuple[str, ...]] = {
    "LangGraph": ("langgraph",),
    "LangChain": ("langchain",),
    "CrewAI": ("crewai",),
    "AutoGen": ("autogen", "pyautogen", "ag2", "autogen-agentchat"),
    "OpenAI Agents SDK": ("openai-agents", "openai_agents", "agents-sdk"),
    "Anthropic SDK": ("anthropic",),
    "LlamaIndex": ("llama-index", "llama_index", "llamaindex"),
    "Semantic Kernel": ("semantic-kernel", "semantic_kernel"),
    "MCP": ("modelcontextprotocol", "fastmcp"),
}

# Import/usage signatures in source -> framework label.
_FRAMEWORK_IMPORTS: dict[str, tuple[re.Pattern[str], ...]] = {
    "LangGraph": (re.compile(r"\b(?:import|from)\s+langgraph"),),
    "LangChain": (re.compile(r"\b(?:import|from)\s+langchain"),),
    "CrewAI": (re.compile(r"\b(?:import|from)\s+crewai"),),
    "AutoGen": (re.compile(r"\b(?:import|from)\s+(?:autogen|ag2)"),),
    "OpenAI Agents SDK": (re.compile(r"\bfrom\s+agents\s+import"),),
    "Anthropic SDK": (re.compile(r"\b(?:import|from)\s+anthropic"),),
    "LlamaIndex": (re.compile(r"\b(?:import|from)\s+llama_index"),),
    "Semantic Kernel": (re.compile(r"\b(?:import|from)\s+semantic_kernel"),),
    "MCP": (re.compile(r"\b(?:import|from)\s+mcp\b"), re.compile(r"\bFastMCP\b")),
}

_ENTRY_PATTERNS = re.compile(
    r"\b("
    r"StateGraph|create_react_agent|create_agent|MessageGraph|"  # langgraph
    r"Crew\s*\(|@crew|@agent|@task|"  # crewai
    r"AssistantAgent|ConversableAgent|RoutedAgent|GroupChat|"  # autogen
    r"Swarm\s*\(|Runner\.run|"  # openai agents / swarm
    r"FastMCP\s*\(|mcp\.server|Server\s*\("  # mcp servers
    r")"
)

# Capability surface: pattern -> capability tag.
_CAP_PATTERNS: dict[str, re.Pattern[str]] = {
    "shell-exec": re.compile(r"\b(?:subprocess\.|os\.system|os\.popen|pty\.spawn)|shell\s*=\s*True|\bexec\s*\(|\beval\s*\("),
    "file-write": re.compile(r"open\s*\([^)]*['\"][wa]\+?b?['\"]|\.write_text\s*\(|\.write_bytes\s*\(|shutil\.(?:move|rmtree)|os\.remove\b"),
    "network-http": re.compile(r"\b(?:requests|httpx|aiohttp)\.(?:get|post|put|delete|request)|urllib\.request|\.fetch\s*\("),
    "database": re.compile(r"\b(?:sqlalchemy|psycopg2?|sqlite3|pymongo|redis|asyncpg)\b|cursor\.execute\s*\("),
    "email": re.compile(r"\bsmtplib\b|\bsendgrid\b|send_email\s*\(|\bresend\b"),
    "payment": re.compile(r"\bstripe\b|checkout\.session|\bpaypal\b|PaymentIntent"),
    "browser": re.compile(r"\bplaywright\b|\bselenium\b|\bpuppeteer\b"),
    "code-interpreter": re.compile(r"\bPythonREPL|CodeInterpreter|run_code\s*\("),
}

_MEMORY_PATTERNS = re.compile(
    r"\b(MemorySaver|SqliteSaver|AsyncSqliteSaver|PostgresSaver|InMemoryStore|"
    r"chromadb|faiss|pinecone|weaviate|qdrant|\.from_documents|VectorStore|"
    r"RedisStore|RedisSaver)\b"
)

_TOOL_DECL = re.compile(r"@tool\b|FunctionTool\b|StructuredTool\b|Tool\.from_function|BaseTool\b")

_SKILL_NAMES = {"skill.md", "soul.md", "agent.md", "agents.md"}
_MCP_CONFIG_NAMES = {"mcp.json", ".mcp.json", "claude_desktop_config.json", ".well-known/mcp.json"}
_PROMPT_HINT = re.compile(r"(?i)\b(SYSTEM_PROMPT|system_prompt|You are (?:a|an|the)\b)")

_MANIFESTS = {
    "requirements.txt",
    "pyproject.toml",
    "setup.py",
    "setup.cfg",
    "Pipfile",
    "poetry.lock",
    "package.json",
    "environment.yml",
}

_READ_EXT = {".py", ".ipynb", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".md", ".json", ".yaml", ".yml", ".toml", ".txt", ".cfg"}
_MAX_READ_BYTES = 400_000


def _read(path: Path) -> str:
    try:
        if path.stat().st_size > _MAX_READ_BYTES:
            with path.open("r", encoding="utf-8", errors="ignore") as fh:
                return fh.read(_MAX_READ_BYTES)
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def _sorted_unique(values) -> list[str]:  # type: ignore[no-untyped-def]
    return sorted(set(values))


def fingerprint(root: Path, target: ScanTarget) -> AgentMap:
    frameworks: set[str] = set()
    entrypoints: set[str] = set()
    tools: set[str] = set()
    prompts: set[str] = set()
    mcp_servers: set[str] = set()
    skills: set[str] = set()
    memory_stores: set[str] = set()

    for rel in target.file_tree:
        p = root / rel
        base = Path(rel).name.lower()
        rel_lower = rel.lower()

        # --- artifacts by filename ---
        if base == "skill.md" or base in _SKILL_NAMES:
            if base in ("skill.md", "soul.md"):
                skills.add(rel)
        if base == "skill.md" or base.endswith(".skill.md"):
            skills.add(rel)
        if base in {"mcp.json", ".mcp.json", "claude_desktop_config.json"} or rel_lower.endswith(".well-known/mcp.json"):
            mcp_servers.add(rel)
        if base == "langgraph.json":
            frameworks.add("LangGraph")
            entrypoints.add(rel)
        if re.search(r"(?i)(^|/)(system_?prompt|prompts?)(\.|/|$)", rel) or base.endswith(".prompt"):
            prompts.add(rel)

        # SKILL.md is case-sensitive in the ecosystem; catch exact too
        if Path(rel).name == "SKILL.md":
            skills.add(rel)

        # --- content-based signals ---
        if Path(rel).suffix.lower() not in _READ_EXT and base not in {m.lower() for m in _MANIFESTS}:
            continue
        content = _read(p)
        if not content:
            continue

        is_manifest = Path(rel).name in _MANIFESTS
        if is_manifest:
            low = content.lower()
            for label, needles in _FRAMEWORK_DEPS.items():
                if any(n in low for n in needles):
                    frameworks.add(label)
            if '"mcpservers"' in low or "mcpservers" in low:
                mcp_servers.add(rel)

        # framework imports
        for label, pats in _FRAMEWORK_IMPORTS.items():
            if any(pat.search(content) for pat in pats):
                frameworks.add(label)

        # entrypoints
        if _ENTRY_PATTERNS.search(content):
            entrypoints.add(rel)

        # capability surface
        for tag, pat in _CAP_PATTERNS.items():
            if pat.search(content):
                tools.add(tag)
        if _TOOL_DECL.search(content):
            tools.add("declared-tools")

        # mcp server command references
        if re.search(r"(?i)\b(?:npx|uvx)\b[^\n]{0,80}(?:mcp|server)", content) or '"mcpservers"' in content.lower():
            mcp_servers.add(rel)

        # memory stores
        if _MEMORY_PATTERNS.search(content):
            memory_stores.add(rel)

        # prompt files by content
        if Path(rel).suffix.lower() in {".py", ".md", ".txt", ".yaml", ".yml"} and _PROMPT_HINT.search(content):
            prompts.add(rel)

    return AgentMap(
        frameworks=_sorted_unique(frameworks),
        entrypoints=_sorted_unique(entrypoints),
        tools=_sorted_unique(tools),
        prompts=_sorted_unique(prompts),
        mcp_servers=_sorted_unique(mcp_servers),
        skills=_sorted_unique(skills),
        memory_stores=_sorted_unique(memory_stores),
    )
