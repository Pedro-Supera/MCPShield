# MCPShield

**Static security and capability inventory for MCP servers and AI agent skills.**

MCPShield statically inspects local JSON configuration files and files named `SKILL.md` for risky command patterns, possible hardcoded credentials, and suspicious instructions. It reports findings with severity, evidence, and remediation guidance.

It can also parse local Python source to inventory MCP-style tool decorators, trace uniquely resolved direct calls to local functions, and report selected process, filesystem, and network API calls with source locations.

> **Status: early development.** Detection rules are heuristic. They may produce false positives or miss risks, so MCPShield is not a substitute for a security review.

## Current capabilities

- Scans JSON files and `SKILL.md` files.
- Checks for risky shell patterns, instruction overrides, SSH-directory references, and possible hardcoded credentials.
- Redacts likely credential values from finding evidence.
- Prints human-readable output or JSON.
- Analyzes Python source with the standard-library AST parser, without importing or executing it.
- Recognizes functions decorated with an attribute named `.tool` as a heuristic MCP tool convention.
- Follows unique direct local function calls and reports selected process, filesystem, and network capabilities with evidence locations.
- Labels source observations as potential capabilities; it does not infer malicious intent or prove runtime behavior.
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
mcpshield ./path/to/python-server --analyze-python
mcpshield ./path/to/python-server --analyze-python --json
```

For Python analysis, `--analyze-python` accepts a `.py` file or a directory. It emits an inventory of recognized tools, reachable local helper functions, observed API calls, unresolved calls, and parser/size issues. `--json` prints the report as JSON with `schema_version: 1`. This mode returns `2` when any source file has a syntax error or the input cannot be read; a clean/empty inventory does not prove that a server is safe.

The first source-analysis version recognizes decorators whose final attribute is `tool` (for example, `@mcp.tool()`), follows direct calls only when the local target is unambiguous, and maps selected calls to:

- **Process execution:** `subprocess` calls and selected `os` process APIs.
- **Filesystem access:** `open`, selected `os`/`pathlib.Path` operations, `shutil`, and `tempfile`.
- **Network communication:** selected calls from `requests`, `httpx`, `urllib`, `urllib3`, `aiohttp`, and `socket`.

Each capability means that a matching call expression was found in source. It is not proof that the call runs, succeeds, receives untrusted input, or is malicious. Unresolved calls are reported as unknown rather than guessed.

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
- MCPShield does not execute commands, import scanned modules, start MCP servers, or make network requests during either scan mode.
- Likely credential values are redacted in finding evidence. Review reports before sharing them from sensitive environments.
- Files larger than 1 MB are skipped; symbolic links are ignored during directory scans. Python source analysis also skips common generated, hidden, and virtual-environment directories and stops after 5,000 source files.
- Static pattern matching can miss obfuscated behavior and flag benign examples or documentation.
- Python analysis does not resolve reflection, dynamic imports, generated code, indirect dispatch, or dependency internals. It follows only direct local calls with uniquely resolved targets; runtime configuration and control/data flow are not established.
- Tool detection is heuristic and may match a non-MCP decorator named `.tool`, or miss other MCP registration styles.

## Development

```bash
python -m pytest
```

GitHub Actions tests Python 3.10–3.13.

## Roadmap

- [ ] Expand MCP tool registration support based on real-world Python fixtures.
- [ ] Improve import-aware call resolution without treating ambiguous calls as confirmed.
- [ ] Add regression fixtures for benign and suspicious examples.
- [ ] Add SARIF output for code-scanning workflows.
- [ ] Document every rule with examples and limitations.

## License

MIT. See [LICENSE](LICENSE).
