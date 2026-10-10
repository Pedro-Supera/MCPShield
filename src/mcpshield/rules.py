"""Small, explainable heuristic rules for untrusted configuration text."""

from dataclasses import dataclass
import re


@dataclass(frozen=True, slots=True)
class Rule:
    rule_id: str
    severity: str
    title: str
    description: str
    pattern: re.Pattern[str]
    recommendation: str


RULES = (
    Rule(
        "MCP001", "critical", "Destructive root filesystem command",
        "The text contains a command pattern that may recursively delete the root filesystem.",
        re.compile(r"\brm\s+(?:-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*|-[a-zA-Z]*f[a-zA-Z]*r[a-zA-Z]*)\s+/(?:\s|$)", re.I),
        "Remove the command. Never allow an agent to run destructive filesystem commands without explicit review.",
    ),
    Rule(
        "MCP002", "high", "Remote content piped to a shell",
        "The text appears to download remote content and pipe it directly into a shell interpreter.",
        re.compile(r"(?:curl|wget)\b[^\n|]*\|\s*(?:ba)?sh\b", re.I),
        "Download and inspect scripts before execution; pin and verify their integrity.",
    ),
    Rule(
        "MCP003", "high", "Broad permission change",
        "The text contains chmod 777, which grants read, write, and execute permissions to everyone.",
        re.compile(r"\bchmod\s+(?:-R\s+)?777\b", re.I),
        "Use the narrowest permissions needed instead of chmod 777.",
    ),
    Rule(
        "MCP004", "high", "Possible instruction override",
        "The text asks an agent to ignore previous or higher-priority instructions.",
        re.compile(r"\b(ignore|disregard|override)\s+(all\s+)?(previous|prior|above|system)\s+instructions\b", re.I),
        "Review the skill's provenance and remove instruction-override language unless there is a clear, safe reason for it.",
    ),
    Rule(
        "MCP005", "high", "Possible credential exfiltration",
        "The text appears to instruct a tool or agent to send credentials, tokens, or secrets to an external destination.",
        re.compile(r"\b(send|upload|exfiltrat\w*|post)\b.{0,100}\b(passwords?|credentials?|api keys?|tokens?|secrets?)\b.{0,100}\b(external|server|url|webhook|http|remote)\b", re.I),
        "Do not transmit secrets. Use scoped credentials and inspect any network destination before approving it.",
    ),
    Rule(
        "MCP006", "medium", "Access to SSH private-key directory",
        "The text references the user's SSH directory, which may contain private keys and sensitive configuration.",
        re.compile(r"(?:~[/\\]\.ssh|/home/[^\s/]+/\.ssh|/root/\.ssh)", re.I),
        "Avoid broad access to ~/.ssh. If access is essential, restrict it to a specific public-key file and review the use.",
    ),
    Rule(
        "MCP007", "high", "Possible hardcoded credential",
        "A value assigned to a credential-like key appears to be a literal secret rather than an environment variable placeholder.",
        re.compile(r"""(?i)\b(api[_-]?key|access[_-]?token|client[_-]?secret|password|secret)\b\s*["']?\s*[:=]\s*["'](?!\$\{|<|REDACTED|YOUR_|CHANGE_ME|CHANGEME)[^"'\r\n]{8,}["']"""),
        "Move credentials to a secret manager or environment variable. Rotate the value if it has been committed or shared.",
    ),
)


def matching_rules(line: str) -> list[Rule]:
    """Return rules whose patterns match a single line."""
    return [rule for rule in RULES if rule.pattern.search(line)]
