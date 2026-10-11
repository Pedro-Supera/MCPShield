"""Local, non-executing file and directory scanner."""

from pathlib import Path
import os
import re

from mcpshield.models import Finding
from mcpshield.rules import matching_rules
from mcpshield.safe_io import read_limited_text

MAX_FILE_BYTES = 1_000_000
MAX_SCAN_FILES = 5_000
MAX_SCAN_TOTAL_BYTES = 50_000_000
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
    limit, or scans that exceed aggregate budgets, raise ``ScanError``. No
    scanned content is executed or sent over the network.
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
        traversal_errors: list[OSError] = []
        for root, directories, filenames in os.walk(
            target, followlinks=False, onerror=traversal_errors.append
        ):
            directories[:] = sorted(
                directory
                for directory in directories
                if not (Path(root) / directory).is_symlink()
            )
            for filename in sorted(filenames):
                item = Path(root) / filename
                if item.is_symlink():
                    continue
                if item.is_file() and _is_supported(item):
                    if len(candidates) == MAX_SCAN_FILES:
                        raise ScanError(
                            f"Scan stopped at the {MAX_SCAN_FILES}-file limit."
                        )
                    candidates.append(item)
        if traversal_errors:
            error = traversal_errors[0]
            raise ScanError(
                f"Could not inspect directory: {error.strerror or error}"
            ) from error
    else:
        raise ScanError(f"Not a regular file or directory: {target}")

    findings: list[Finding] = []
    bytes_scanned = 0
    for candidate in sorted(candidates):
        try:
            candidate_size = candidate.stat().st_size
            if candidate_size > MAX_FILE_BYTES:
                raise ScanError(
                    f"File exceeds the {MAX_FILE_BYTES}-byte scan limit: {candidate.name}"
                )
            if bytes_scanned + candidate_size > MAX_SCAN_TOTAL_BYTES:
                raise ScanError(
                    f"Scan stopped at the {MAX_SCAN_TOTAL_BYTES}-byte total limit."
                )
            content = read_limited_text(candidate, MAX_FILE_BYTES)
            if content is None:
                raise ScanError(
                    f"File changed or exceeded the {MAX_FILE_BYTES}-byte scan limit: "
                    f"{candidate.name}"
                )
            bytes_scanned += len(content.encode("utf-8"))
            if bytes_scanned > MAX_SCAN_TOTAL_BYTES:
                raise ScanError(
                    f"Scan stopped at the {MAX_SCAN_TOTAL_BYTES}-byte total limit."
                )
        except ScanError:
            raise
        except OSError as exc:
            raise ScanError(f"Could not read {candidate.name}: {exc}") from exc
        findings.extend(scan_text(content, path=str(candidate)))
    return findings
