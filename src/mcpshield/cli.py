"""Command-line interface for MCPShield."""

import argparse
import json
from pathlib import Path
import sys

from mcpshield import __version__
from mcpshield.scanner import ScanError, scan_path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcpshield",
        description="Statically scan MCP JSON configs and SKILL.md files for risky patterns.",
    )
    parser.add_argument("path", help="File or directory to scan")
    parser.add_argument("--json", action="store_true", help="Print findings as JSON")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        findings = scan_path(Path(args.path))
    except ScanError as exc:
        print(f"mcpshield: error: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps([finding.to_dict() for finding in findings], indent=2))
    elif not findings:
        print("MCPShield: no matching risky patterns found.")
        print("Note: this does not prove the files are safe.")
    else:
        for finding in findings:
            print(f"[{finding.severity.upper()}] {finding.rule_id} {finding.path}:{finding.line}")
            print(f"  {finding.title}")
            print(f"  Evidence: {finding.evidence}")
            print(f"  Fix: {finding.recommendation}")
            print()

    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
