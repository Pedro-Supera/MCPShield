# MCPShield

**Security scanner for MCP server configurations and AI agent skills.**

MCPShield statically inspects local configuration files and `SKILL.md` documents for potentially risky commands, exposed secrets, and unsafe instructions. It reports findings with severity, evidence, and remediation guidance.

> **Status:** early development. Detection rules are heuristic and can produce false positives or miss risks. MCPShield is not a substitute for a security review.

## Goals

- Inspect files without executing them.
- Work locally and offline by default.
- Explain each finding and how to address it.
- Produce human-readable terminal output and machine-readable JSON.
- Keep the first version small, testable, and easy to extend.

## Planned first version

- [ ] Scan MCP-style JSON configuration files and `SKILL.md` files.
- [ ] Detect a small set of high-signal risky patterns.
- [ ] Provide severity, rule ID, file location, evidence, and remediation.
- [ ] Add a command-line interface and JSON output.
- [ ] Add tests and continuous integration.

## Safety model

MCPShield treats scanned files as untrusted data. It must never execute commands, load scanned configuration as live application configuration, or connect to servers described in scanned files. Findings are static indicators, not proof that a system is exploitable.

## Development

The project targets Python 3.10+ and aims to keep runtime dependencies at zero for the initial scanner.

Setup instructions will be added as the CLI and test suite land.

## License

MIT. See [LICENSE](LICENSE) once added.
