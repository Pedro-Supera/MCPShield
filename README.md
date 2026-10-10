# MCPShield

**Security scanner for MCP server configurations and AI agent skills.**

MCPShield statically inspects local JSON configuration files and files named `SKILL.md` for risky command patterns, possible hardcoded credentials, and suspicious instructions. It reports findings with severity, evidence, and remediation guidance.

> **Status: early development.** Detection rules are heuristic. They may produce false positives or miss risks, so MCPShield is not a substitute for a security review.

## Current capabilities

- Scans JSON files and `SKILL.md` files.
- Checks for risky shell patterns, instruction overrides, SSH-directory references, and possible hardcoded credentials.
- Redacts likely credential values from finding evidence.
- Prints human-readable output or JSON.
- Does not execute scanned files or contact configured servers.
- Has no runtime dependencies beyond the Python standard library.

## Install

Requires Python 3.10 or newer.

```bash
git clone https://github.com/Pedro-Supera/MCPShield.git
cd MCPShield
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
```

## Use

```bash
mcpshield ./path/to/config.json
mcpshield ./path/to/skills/
mcpshield ./path/to/project --json
```

Exit codes: `0` means no rules matched, `1` means findings were reported, and `2` means the input could not be scanned. A clean result does not prove that a file or system is safe.

## Detection rules

| Rule | Severity | Purpose |
| --- | --- | --- |
| MCP001 | Critical | Detect a destructive root-filesystem command pattern |
| MCP002 | High | Detect remote content piped directly to a shell |
| MCP003 | High | Detect broad permission changes |
| MCP004 | High | Detect possible instruction-override language |
| MCP005 | High | Detect possible instructions to send credentials externally |
| MCP006 | Medium | Detect references to SSH private-key directories |
| MCP007 | High | Detect possible literal credentials assigned to credential-like keys |

These are small, explainable heuristics. They do not understand the complete semantics of every configuration or skill format.

## Safety and limitations

- Treat scanned files as untrusted text.
- MCPShield does not execute commands, import scanned modules, start MCP servers, or make network requests.
- Likely credential values are redacted in finding evidence. Review reports before sharing them from sensitive environments.
- Files larger than 1 MB are skipped; symbolic links are ignored during directory scans.
- Static pattern matching can miss obfuscated behavior and flag benign examples or documentation.

## Development

```bash
python -m pytest
```

GitHub Actions tests Python 3.10–3.13.

## Roadmap

- [ ] Parse MCP configuration structures and flag risky server-launch settings.
- [ ] Add regression fixtures for benign and suspicious examples.
- [ ] Add SARIF output for code-scanning workflows.
- [ ] Document every rule with examples and limitations.

## License

MIT. See [LICENSE](LICENSE).
