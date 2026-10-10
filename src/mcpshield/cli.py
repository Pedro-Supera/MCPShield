"""Command-line interface for MCPShield."""

import argparse
import json
from pathlib import Path
import sys

from mcpshield import __version__
from mcpshield.python_analysis import PythonAnalysisError, analyze_python_path
from mcpshield.scanner import ScanError, scan_path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcpshield",
        description="Statically inspect MCP configurations, skills, and Python source.",
    )
    parser.add_argument("path", help="File or directory to scan")
    parser.add_argument("--json", action="store_true", help="Print findings as JSON")
    parser.add_argument(
        "--analyze-python",
        action="store_true",
        help="Inventory Python MCP tool decorators and visible capabilities",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.analyze_python:
        try:
            report = analyze_python_path(Path(args.path))
        except PythonAnalysisError as exc:
            print(f"mcpshield: error: {exc}", file=sys.stderr)
            return 2

        if args.json:
            print(json.dumps(report.to_dict(), indent=2))
        else:
            print("MCPShield Python source inventory")
            print(f"Files analyzed: {report.files_scanned}")
            if not report.tools:
                print("No tool decorators recognized.")
            for tool in report.tools:
                print(f"\n[TOOL] {tool.name} ({tool.path}:{tool.line})")
                print(f"  Function: {tool.function}")
                if tool.description:
                    print(f"  Description: {tool.description}")
                for capability in tool.capabilities:
                    chain = " -> ".join(capability.call_chain)
                    print(
                        f"  [OBSERVED IN SOURCE] {capability.capability}: "
                        f"{capability.api} ({capability.path}:{capability.line}; {chain})"
                    )
                if tool.unresolved_calls:
                    print(f"  Unresolved calls: {len(tool.unresolved_calls)}")
            for issue in report.issues:
                location = f"{issue.path}:{issue.line}" if issue.line else issue.path
                print(f"\n[{issue.severity.upper()}] {issue.code} {location}")
                print(f"  {issue.message}")
            print("\nObserved source calls are not proof of runtime execution or malicious intent.")
            for limitation in report.limitations:
                print(f"- {limitation}")
        return 2 if any(issue.severity == "error" for issue in report.issues) else 0

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
