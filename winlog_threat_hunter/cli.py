from __future__ import annotations

import argparse
import sys

from .engine import run_rules
from .html_report import write_html_report
from .parser import load_events
from .report import print_console_report, write_csv_report, write_json_report


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="winlog-threat-hunter",
        description="Parse exported Windows Security/Sysmon events and flag suspicious patterns.",
    )
    p.add_argument("input", help="Path to a .jsonl or .csv event export")
    p.add_argument("--json-out", help="Write findings to this JSON file")
    p.add_argument("--csv-out", help="Write findings to this CSV file")
    p.add_argument("--html-out", help="Write a self-contained HTML threat-board report to this file")
    p.add_argument("--no-color", action="store_true", help="Disable ANSI color in console output")
    p.add_argument("--fail-on", choices=["critical", "high", "medium", "low"],
                   help="Exit with a non-zero status if any finding at or above this severity is present (useful in CI)")
    return p


_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        events = load_events(args.input)
    except (ValueError, FileNotFoundError) as exc:
        print(f"Error loading '{args.input}': {exc}", file=sys.stderr)
        return 2

    findings = run_rules(events)

    print_console_report(findings, len(events), color=not args.no_color)

    if args.json_out:
        write_json_report(findings, args.json_out)
        print(f"\nWrote JSON report: {args.json_out}")
    if args.csv_out:
        write_csv_report(findings, args.csv_out)
        print(f"Wrote CSV report: {args.csv_out}")
    if args.html_out:
        write_html_report(findings, events, args.html_out, source_name=args.input)
        print(f"Wrote HTML report: {args.html_out}")

    if args.fail_on:
        threshold = _SEVERITY_ORDER[args.fail_on]
        if any(_SEVERITY_ORDER.get(f.severity, 99) <= threshold for f in findings):
            return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
