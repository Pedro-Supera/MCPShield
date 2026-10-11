"""SARIF 2.1.0 serialization for scanner and Python inventory results."""

from __future__ import annotations

from hashlib import sha256
from pathlib import Path
from urllib.parse import quote

from mcpshield.models import Finding
from mcpshield.python_analysis import AnalysisReport
from mcpshield.rules import ANALYSIS_RULES, RULES, Rule


_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_INFORMATION_URI = "https://github.com/Pedro-Supera/MCPShield"
_SEVERITY_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
    "warning": "warning",
    "error": "error",
}
_CAPABILITY_RULE = {
    "process_execution": "MCP101",
    "filesystem_access": "MCP102",
    "network_communication": "MCP103",
}
_RULES_BY_ID = {rule.rule_id: rule for rule in (*RULES, *ANALYSIS_RULES)}


def _relative_path(path: str, root: Path) -> str:
    candidate = Path(path)
    try:
        relative = candidate.resolve(strict=False).relative_to(
            root.resolve(strict=False)
        )
    except (OSError, RuntimeError, ValueError):
        relative = Path(candidate.name)
    return quote(relative.as_posix(), safe="/-._")


def _rule(rule_id: str) -> Rule:
    if rule_id in _RULES_BY_ID:
        return _RULES_BY_ID[rule_id]
    if rule_id == "MCP901":
        return next(item for item in ANALYSIS_RULES if item.rule_id == rule_id)
    raise ValueError(f"Unknown SARIF rule id: {rule_id}")


def _fingerprint(
    rule_id: str, path: str, line: int, identity: str
) -> str:
    material = "\0".join((rule_id, path, str(line), identity)).encode("utf-8")
    return sha256(material).hexdigest()


def _result(
    *,
    rule_id: str,
    root: Path,
    path: str,
    line: int,
    message: str,
    identity: str,
    level: str | None = None,
    properties: dict[str, object] | None = None,
) -> dict[str, object]:
    relative = _relative_path(path, root)
    result: dict[str, object] = {
        "ruleId": rule_id,
        "level": level or _SEVERITY_LEVEL[_rule(rule_id).severity],
        "message": {"text": message},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": relative},
                    "region": {"startLine": max(1, line)},
                }
            }
        ],
        "partialFingerprints": {
            "primaryLocationLineHash": _fingerprint(
                rule_id, relative, line, identity
            )
        },
    }
    if properties:
        result["properties"] = properties
    return result


def _sarif_document(
    results: list[dict[str, object]],
    rule_ids: set[str],
    *,
    run_properties: dict[str, object] | None = None,
) -> dict[str, object]:
    ordered_rule_ids = sorted(rule_ids)
    rules: list[dict[str, object]] = []
    for rule_id in ordered_rule_ids:
        rule = _rule(rule_id)
        entry: dict[str, object] = {
            "id": rule.rule_id,
            "name": rule.title,
            "shortDescription": {"text": rule.title},
            "fullDescription": {"text": rule.description},
            "defaultConfiguration": {
                "level": _SEVERITY_LEVEL[rule.severity]
            },
            "help": {"text": rule.recommendation},
            "properties": {
                "tags": ["security", "mcp", "static-analysis"],
                "examples": list(rule.examples),
                "limitations": list(rule.limitations),
            },
        }
        if rule.cwe_id:
            entry["relationships"] = [
                {
                    "target": {"id": rule.cwe_id, "toolComponent": {"name": "CWE"}},
                    "kinds": ["superset"],
                }
            ]
        rules.append(entry)

    run: dict[str, object] = {
        "tool": {
            "driver": {
                "name": "MCPShield",
                "informationUri": _INFORMATION_URI,
                "rules": rules,
            }
        },
        "results": results,
    }
    if run_properties:
        run["properties"] = run_properties
    return {
        "$schema": _SCHEMA,
        "version": "2.1.0",
        "runs": [run],
    }


def findings_to_sarif(
    findings: list[Finding], root: str | Path
) -> dict[str, object]:
    """Convert text-scanner findings into a deterministic SARIF run."""
    root_path = Path(root)
    results = [
        _result(
            rule_id=finding.rule_id,
            root=root_path,
            path=finding.path,
            line=finding.line,
            message=f"{finding.title}: {finding.evidence}",
            identity=f"{finding.title}:{finding.evidence}",
            properties={
                "severity": finding.severity,
                "recommendation": finding.recommendation,
            },
        )
        for finding in findings
    ]
    return _sarif_document(results, {finding.rule_id for finding in findings})


def analysis_to_sarif(
    report: AnalysisReport, root: str | Path
) -> dict[str, object]:
    """Convert inventory evidence into SARIF without implying exploitability."""
    root_path = Path(root)
    results: list[dict[str, object]] = []
    rule_ids: set[str] = set()
    for tool in report.tools:
        for capability in tool.capabilities:
            rule_id = _CAPABILITY_RULE[capability.capability]
            rule_ids.add(rule_id)
            results.append(
                _result(
                    rule_id=rule_id,
                    root=root_path,
                    path=capability.path,
                    line=capability.line,
                    message=(
                        f"Potential {capability.capability.replace('_', ' ')} "
                        f"({capability.operation}) observed in source via "
                        f"{capability.api}; runtime behavior is not established."
                    ),
                    identity=f"{tool.function_id}:{capability.api}",
                    level="note",
                    properties={
                        "toolName": tool.name,
                        "functionId": capability.function_id,
                        "callChain": list(capability.call_chain_ids),
                        "evidenceBasis": capability.evidence_basis,
                        "interpretation": capability.interpretation,
                    },
                )
            )
        for flow in tool.data_flows:
            rule_ids.add(flow.rule_id)
            results.append(
                _result(
                    rule_id=flow.rule_id,
                    root=root_path,
                    path=flow.path,
                    line=flow.line,
                    message=(
                        f"Potential flow from tool parameter(s) "
                        f"{', '.join(flow.source_parameters)} to "
                        f"{flow.sink_kind} via {flow.sink_api}; review required."
                    ),
                    identity=f"{tool.function_id}:{flow.sink_api}:{flow.sink_kind}",
                    properties={
                        "toolName": tool.name,
                        "sourceParameters": list(flow.source_parameters),
                        "functionId": flow.function_id,
                        "callChain": list(flow.call_chain_ids),
                        "sanitizersObserved": list(flow.sanitizers_observed),
                        "confidence": flow.confidence,
                        "interpretation": flow.interpretation,
                    },
                )
            )

    for issue in report.issues:
        rule_id = "MCP204" if issue.code == "description_effect_mismatch" else "MCP901"
        rule_ids.add(rule_id)
        results.append(
            _result(
                rule_id=rule_id,
                root=root_path,
                path=issue.path,
                line=issue.line or 1,
                message=issue.message,
                identity=f"{issue.code}:{issue.path}:{issue.line or 1}",
                properties={
                    "analysisIssueCode": issue.code,
                    "severity": issue.severity,
                },
            )
        )
    results.sort(
        key=lambda item: (
            str(item["ruleId"]),
            str(item["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]),
            int(item["locations"][0]["physicalLocation"]["region"]["startLine"]),
        )
    )
    return _sarif_document(
        results,
        rule_ids,
        run_properties={
            "analysisStatus": report.status,
            "analysisComplete": report.analysis_complete,
            "schemaVersion": report.schema_version,
            "metrics": {
                "bytesScanned": report.metrics.bytes_scanned,
                "astNodes": report.metrics.ast_nodes,
                "functionsDiscovered": report.metrics.functions_discovered,
                "callsDiscovered": report.metrics.calls_discovered,
                "graphCallsExamined": report.metrics.graph_calls_examined,
            },
        },
    )
