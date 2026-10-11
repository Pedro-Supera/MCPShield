"""Small, explainable heuristic rules for untrusted configuration text."""

from dataclasses import dataclass
import re


@dataclass(frozen=True, slots=True)
class Rule:
    rule_id: str
    severity: str
    title: str
    description: str
    pattern: re.Pattern[str] | None
    recommendation: str
    cwe_id: str | None = None
    examples: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()


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

ANALYSIS_RULES = (
    Rule(
        "MCP101",
        "info",
        "Process execution capability",
        "A recognized process API call is reachable from a statically identified MCP tool.",
        None,
        "Review command construction, argument validation, and required process permissions.",
        examples=("subprocess.run(command)", "os.system(command)"),
        limitations=("A source call does not prove that a process is started at runtime.",),
    ),
    Rule(
        "MCP102",
        "info",
        "Filesystem capability",
        "A recognized filesystem API call is reachable from a statically identified MCP tool.",
        None,
        "Review the paths, access mode, and minimum filesystem permissions required.",
        examples=('Path(path).read_text()', 'open(path, "w")'),
        limitations=("The analyzer does not establish the runtime path or resulting file contents.",),
    ),
    Rule(
        "MCP103",
        "info",
        "Network capability",
        "A recognized network API call is reachable from a statically identified MCP tool.",
        None,
        "Review destinations, authentication, data sent, and network access requirements.",
        examples=('requests.get(url)', 'socket.connect(address)'),
        limitations=("The analyzer does not establish the runtime destination or whether a connection succeeds.",),
    ),
    Rule(
        "MCP201",
        "medium",
        "Tool input reaches process API",
        "A tool parameter may reach an argument of a recognized process API.",
        None,
        "Review command construction, shell mode, argument separation, and context-specific sanitization.",
        limitations=("This is a conservative static flow; it is not proof of command injection or exploitability.",),
    ),
    Rule(
        "MCP202",
        "medium",
        "Tool input reaches filesystem API",
        "A tool parameter may reach a path argument of a recognized filesystem API.",
        None,
        "Review path normalization, allowed roots, and whether the operation can escape the intended scope.",
        limitations=("The analyzer does not evaluate path normalization, runtime values, or filesystem state.",),
    ),
    Rule(
        "MCP203",
        "medium",
        "Tool input reaches network API",
        "A tool parameter may reach a destination argument of a recognized network API.",
        None,
        "Review destination allowlists, redirect handling, authentication, and SSRF exposure.",
        limitations=("This is not proof of SSRF or successful network access.",),
    ),
    Rule(
        "MCP204",
        "medium",
        "Description and source effect differ",
        "A tool description appears to deny an effect that a reachable source call suggests.",
        None,
        "Review the human-visible description and implementation together; do not infer intent from the mismatch.",
        limitations=("Description matching is lexical and may misinterpret natural language.",),
    ),
    Rule(
        "MCP901",
        "warning",
        "Static analysis incomplete",
        "A source file, traversal, or analysis budget prevented full processing of the selected inputs.",
        None,
        "Resolve the reported input issue or adjust the source set before treating the inventory as complete.",
        limitations=("Completeness covers only discovered source and implemented static-analysis patterns.",),
    ),
)


def matching_rules(line: str) -> list[Rule]:
    """Return rules whose patterns match a single line."""
    return [
        rule
        for rule in RULES
        if rule.pattern is not None and rule.pattern.search(line)
    ]
