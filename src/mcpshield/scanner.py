"""Local, non-executing file and directory scanner."""

from pathlib import Path
import re

from mcpshield.models import Finding
from mcpshield.rules import matching_rules
from mcpshield.safe_io import read_limited_text

MAX_FILE_BYTES = 1_000_000
_SECRET_VALUE_RE = re.compile(
    r"""(?i)(api[_-]?key|access[_-]?token|client[_-]?secret|password|secret)(\s*["']?\s*[:=]\s*["'])[^"'\r\n]+(["'])"""
)


class ScanError(Exception):
    """Raised when an input cannot be scanned safely."""


def _redact_evidence(line: str) -> str:
    """Redact likely credential values before including evidence in reports."""
    return _SECRET_VALUE_RE.sub(r"\1\2[REDACTED]\3", line.strip())[:240]


def scan_text(text: str, path: str = "<memory>") -> list[Finding]:
    """Scan text without parsing or executing its contents."""
    findings: list[Finding] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        for rule in matching_rules(line):
            findings.append(
                Finding(
                    rule_id=rule.rule_id,
                    severity=rule.severity,  # type: ignore[arg-type]
                    title=rule.title,
                    description=rule.description,
                    path=path,
                    line=line_number,
                    evidence=_redact_evidence(line),
                    recommendation=rule.recommendation,
                )
            )
    return findings


def _is_supported(path: Path) -> bool:
    return path.suffix.lower() == ".json" or path.name.lower() == "skill.md"


def scan_path(path: str | Path) -> list[Finding]:
    """Scan one supported file or recursively scan a directory.

    Symlinks are rejected rather than followed. Files larger than the configured
    limit are skipped. No scanned content is executed or sent over the network.
    """
    target = Path(path).expanduser()
    if not target.exists():
        raise ScanError(f"Path does not exist: {target}")
    if target.is_symlink():
        raise ScanError(f"Refusing to scan a symbolic link: {target}")

    if target.is_file():
        candidates = [target] if _is_supported(target) else []
    elif target.is_dir():
        candidates = []
        for item in target.rglob("*"):
            if item.is_symlink():
                continue
            if item.is_file() and _is_supported(item):
                candidates.append(item)
    else:
        raise ScanError(f"Not a regular file or directory: {target}")

    findings: list[Finding] = []
    for candidate in sorted(candidates):
        try:
            content = read_limited_text(candidate, MAX_FILE_BYTES)
            if content is None:
                continue
        except OSError as exc:
            raise ScanError(f"Could not read {candidate}: {exc}") from exc
        findings.extend(scan_text(content, path=str(candidate)))
    return findings
