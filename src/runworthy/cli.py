"""``runworthy`` command-line interface (spec §5): ``scan`` and ``doctor``.

``scan`` runs the deterministic Phase-0 engine, then — unless ``--no-llm`` — the
Phase-1 interpretation layer and the operational overlay, and renders a
human-readable Markdown report (``--format json`` for the machine contract).
Without a key it degrades honestly to the provisional report rather than failing.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .engine import scan
from .tools import check_tools

DEFAULT_TOKEN_BUDGET = 120_000


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _cache_store(commit_sha: str | None):
    """A response cache keyed by commit SHA (spec §4). Disabled for a dirty local
    directory (no SHA) — caching content that can change between runs would serve
    stale grades."""
    if not commit_sha:
        return None
    from .model import FileResponseStore

    root = Path(os.environ.get("RW_CACHE_DIR") or (Path.home() / ".runworthy" / "cache"))
    return FileResponseStore(root=root)


def _interpret(report, args):
    from .model import ModelUnavailable, StructuredModel, TokenBudget
    from .model.client import DEFAULT_MODEL
    from .interpret import interpret

    budget_cap = args.token_budget if args.token_budget and args.token_budget > 0 else None
    model = StructuredModel(
        mode="live",
        store=_cache_store(report.commit_sha),
        namespace=f"{report.commit_sha or 'local'}::{report.engine_version}",
        budget=TokenBudget(max_tokens=budget_cap),
        model_id=args.model or DEFAULT_MODEL,
    )
    try:
        graded = interpret(report, model=model)
    except ModelUnavailable as exc:
        if args.byok:
            print(f"runworthy: {exc}", file=sys.stderr)
            raise SystemExit(2)
        print(f"runworthy: {exc}", file=sys.stderr)
        print(
            "runworthy: returning the provisional (deterministic) report. Set ANTHROPIC_API_KEY "
            "for an AFR grade, or pass --no-llm to silence this.",
            file=sys.stderr,
        )
        return report

    if not args.non_interactive and sys.stdin.isatty():
        from . import overlay

        answers = overlay.ask(graded, now=_now_iso())
        if answers:
            graded = overlay.merge(graded, answers)
    return graded


def _resolve_format(args) -> str:
    if args.format:
        return args.format
    if args.output:
        ext = os.path.splitext(args.output)[1].lower()
        if ext == ".json":
            return "json"
        if ext in (".md", ".markdown"):
            return "md"
    return "md"


def _render(report, fmt: str, pretty: bool) -> str:
    if fmt == "json":
        return json.dumps(report.model_dump(mode="json"), indent=2 if pretty else None)
    from .render import render_markdown

    return render_markdown(report)


def _cmd_scan(args: argparse.Namespace) -> int:
    from .model import BudgetExceeded

    try:
        report = scan(args.target)
        if not args.no_llm and not report.agent_map.is_empty():
            report = _interpret(report, args)
    except (FileNotFoundError, ValueError, RuntimeError) as exc:
        if isinstance(exc, BudgetExceeded):
            print(f"runworthy: token budget exceeded: {exc}", file=sys.stderr)
            return 3
        print(f"runworthy: scan failed: {exc}", file=sys.stderr)
        return 2

    fmt = _resolve_format(args)
    payload = _render(report, fmt, args.pretty)
    if args.output:
        parent = os.path.dirname(args.output)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(payload + "\n")
        print(f"runworthy: report written to {args.output}", file=sys.stderr)
    else:
        print(payload)

    _print_summary(report)
    return 0


def _print_summary(report) -> None:
    n = len(report.findings)
    band = report.band or f"provisional ({report.assessed_controls}/{report.total_controls})"
    fw = ", ".join(report.agent_map.frameworks) or "none detected"
    print(
        f"runworthy: {report.verdict} · band: {band} · {n} finding(s) · frameworks: {fw}",
        file=sys.stderr,
    )


def _cmd_doctor(_args: argparse.Namespace) -> int:
    statuses = check_tools()
    any_missing = False
    print("runworthy doctor - external detector tools (pinned, PATH-resolved):\n")
    for st in statuses:
        mark = {"OK": "OK", "PIN_MISMATCH": "!!", "UNKNOWN_VERSION": "??", "MISSING": "XX"}[st.state]
        ver = st.version or "-"
        print(f"  [{mark}] {st.key:<14} {st.state:<15} found={ver:<10} pinned={st.pinned}")
        if st.state == "MISSING":
            any_missing = True
            print(f"        install: {st.install_hint}")
        elif st.state == "PIN_MISMATCH":
            print(f"        warning: version {ver} differs from pinned {st.pinned} (results may drift)")
    print()
    if any_missing:
        print("runworthy: one or more required tools are missing — see install hints above.", file=sys.stderr)
        return 1
    print("runworthy: all detector tools present.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="runworthy",
        description="Agent operations scanner — grades a repo against the Agent Flight Rules (AFR).",
    )
    parser.add_argument("--version", action="version", version=f"runworthy {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="scan a local path or public repo URL")
    p_scan.add_argument("target", help="local directory path or a public git repo URL (or owner/repo)")
    p_scan.add_argument("-o", "--output", help="write the report to this file (format inferred from extension)")
    p_scan.add_argument("--format", choices=["md", "json"], help="output format (default: md, or json for a .json -o)")
    p_scan.add_argument("--pretty", action="store_true", help="pretty-print JSON output")
    p_scan.add_argument("--no-llm", action="store_true", help="deterministic findings only — no model, fully offline")
    p_scan.add_argument("--non-interactive", action="store_true", help="never prompt (skips the operational overlay)")
    p_scan.add_argument("--byok", action="store_true", help="require your own ANTHROPIC_API_KEY; error if it's missing")
    p_scan.add_argument("--model", help="override the model id (default: RW_MODEL or claude-sonnet-5)")
    p_scan.add_argument(
        "--token-budget", type=int, default=DEFAULT_TOKEN_BUDGET,
        help="per-scan token ceiling; a breach fails loud (0 disables)",
    )
    p_scan.set_defaults(func=_cmd_scan)

    p_doctor = sub.add_parser("doctor", help="verify pinned external detector tools")
    p_doctor.set_defaults(func=_cmd_doctor)
    return parser


def main(argv: list[str] | None = None) -> int:
    # Report text carries Unicode (✓ ✕ ★ — ). Force UTF-8 so a Windows cp1252
    # console can't crash the run on `print`.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
        except (AttributeError, ValueError):  # pragma: no cover - non-reconfigurable stream
            pass

    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
