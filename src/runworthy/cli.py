"""``runworthy`` command-line interface (spec §5): ``scan`` and ``doctor``."""

from __future__ import annotations

import argparse
import json
import os
import sys

from . import __version__
from .engine import scan
from .tools import check_tools


def _cmd_scan(args: argparse.Namespace) -> int:
    try:
        report = scan(args.target)
    except (FileNotFoundError, ValueError, RuntimeError) as exc:
        print(f"runworthy: scan failed: {exc}", file=sys.stderr)
        return 2

    payload = json.dumps(report.model_dump(mode="json"), indent=2 if args.pretty else None)
    if args.output:
        parent = os.path.dirname(args.output)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(payload + "\n")
        print(f"runworthy: report written to {args.output}", file=sys.stderr)
    else:
        print(payload)

    # A one-line human summary to stderr (keeps stdout clean for piping).
    n = len(report.findings)
    by_det: dict[str, int] = {}
    for f in report.findings:
        by_det[f.detector] = by_det.get(f.detector, 0) + 1
    detail = ", ".join(f"{k}: {v}" for k, v in sorted(by_det.items())) or "no findings"
    fw = ", ".join(report.agent_map.frameworks) or "none detected"
    print(
        f"runworthy: {report.verdict} - {n} finding(s) [{detail}] | frameworks: {fw}",
        file=sys.stderr,
    )
    return 0


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
        description="Agent operations scanner — deterministic findings (Phase 0).",
    )
    parser.add_argument("--version", action="version", version=f"runworthy {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="scan a local path or public repo URL")
    p_scan.add_argument("target", help="local directory path or a public git repo URL (or owner/repo)")
    p_scan.add_argument("-o", "--output", help="write the ReadinessReport JSON to this file")
    p_scan.add_argument("--pretty", action="store_true", help="pretty-print the JSON")
    p_scan.set_defaults(func=_cmd_scan)

    p_doctor = sub.add_parser("doctor", help="verify pinned external detector tools")
    p_doctor.set_defaults(func=_cmd_doctor)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
