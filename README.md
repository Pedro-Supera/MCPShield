# MCPShield

**Static security and capability inventory for MCP servers and AI agent skills.**

MCPShield statically inspects local JSON configuration files and files named
`SKILL.md` for risky command patterns, possible hardcoded credentials, and
suspicious instructions. It also parses Python source to inventory MCP-style
tools, trace selected local calls, and report process, filesystem, and network
capabilities with source evidence.

> **Status: early development.** Rules and code analysis are heuristic. Findings
> can be false positives or miss behavior; MCPShield is not a substitute for
> security review.

## Capabilities

- Scans JSON configuration and `SKILL.md` files for risky shell patterns,
  instruction overrides, SSH-directory references, and possible literal
  credentials. Likely credential values are redacted from finding evidence.
- Parses Python source with the standard-library `ast` module, without
  importing or executing it.
- Recognizes `.tool` decorators and simple `.add_tool(function)` /
  `.register_tool(function)` calls as heuristic tool-registration patterns.
- Follows uniquely resolved direct calls to local functions, including selected
  `self.method()` and `cls.method()` calls.
- Reports selected process execution, filesystem access, and network
  communication operations, including source locations and call chains.
- Reports potential flows from tool parameters to selected sensitive API
  arguments. The limited analysis can also note `shlex.quote` use, but does not
  treat that observation as proof of safe sanitization.
- Flags a possible lexical mismatch when a tool description explicitly denies
  an effect that appears in its statically traced source.
- Emits human-readable output, JSON, or SARIF 2.1.0. JSON source-analysis
  reports currently use `schema_version: 2`.
- Has no runtime dependencies beyond the Python standard library; pytest is
  used for development and tests.

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
mcpshield ./path/to/python-server --analyze-python --sarif
mcpshield ./path/to/skills --sarif
```

`--json` and `--sarif` are mutually exclusive. `--analyze-python` accepts a
`.py` file or a directory. JSON includes recognized tools, reachable local
functions, capabilities, potential data flows, unresolved calls, processing
metrics, issues, and analysis limitations. SARIF output uses version 2.1.0 and
can be consumed by compatible code-scanning tools.

Exit codes:

- `0`: no text-scanner findings, or Python inputs processed within the declared
  limits.
- `1`: one or more text-scanner findings.
- `2`: input error or partial Python analysis.

An empty or complete inventory does not prove that a server is safe. In
particular, `analysis_complete: true` means only that the discovered source
inputs were processed within implemented limits; it does not mean that every
runtime tool or behavior was discovered.

## Python analysis model

Recognized tool registrations are heuristic conventions, not a full
implementation of the MCP protocol. They can match non-MCP APIs and miss
registrations performed through other frameworks, factories, decorators,
conditional logic, or dynamic code.

Selected observed capability APIs include:

- **Process execution:** `subprocess` and selected `os` / `asyncio` APIs.
- **Filesystem access:** built-in `open`, selected `io`, `os`,
  `pathlib.Path`, `shutil`, and `tempfile` APIs.
- **Network communication:** selected `requests`, `httpx`, `urllib`, `urllib3`,
  `aiohttp`, and `socket` APIs.

The analyzer recognizes APIs through selected imports and builtins; it avoids
classifying an arbitrary same-named local module or shadowed name as a
confirmed standard API. A capability means that a recognized call expression
was found along a statically traced path from a recognized tool. It does not
prove the call runs, succeeds, reaches the network or filesystem, or is
malicious.

Potential data-flow findings track tool parameter names through simple local
assignments and direct local helper-call arguments into selected sensitive API
arguments. This is not full taint analysis: control flow, complex expressions,
containers, aliasing, callbacks, many forms of argument binding, runtime values,
and external dependency internals are not modeled. `shlex.quote` is only a
sanitizer-like observation; correctness and context-specific safety are not
established. Description/effect findings use narrow lexical matching and are
review prompts, not claims about developer intent.

Unresolved calls and unsupported behavior remain unknown rather than guessed.
Reflection, dynamic imports, generated code, indirect dispatch, dependency
internals, runtime configuration, and conditional registration semantics
cannot be confirmed by this analysis.

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
| MCP101–MCP103 | Informational | Report observed process, filesystem, and network capabilities |
| MCP201–MCP203 | Medium | Report potential tool-parameter flows to sensitive API arguments |
| MCP204 | Medium | Flag a possible lexical description/source-effect mismatch |
| MCP901 | Warning | Report incomplete source processing |

These are explainable heuristics. They do not understand the complete
semantics of every configuration, skill, or Python program.

## Safety, limits, and privacy

- Scanned content is treated as untrusted input. MCPShield does not execute
  commands, import analyzed modules, start MCP servers, or make network
  requests during scanning.
- Symbolic links are not followed. Unsupported files are not analyzed.
- Scanner and Python-analysis limits are 1 MB per file, 5,000 files, and 50 MB
  total. Python analysis also has explicit AST-node, function, call, and
  call-graph budgets. When a Python input cannot be processed within limits,
  the report is marked `partial` with an issue; scanner errors are surfaced as
  errors rather than clean results.
- Python analysis skips common hidden, generated, and virtual-environment
  directories.
- Static text rules can miss obfuscated behavior or match benign documentation
  and examples.
- Tool registration and API recognition are limited, conservative patterns,
  not proofs about runtime behavior.
- Potential parameter flow is not proof of a vulnerability, exploitability,
  unsafe input, or missing validation. No finding alone establishes malicious
  intent.
- Likely credential values in text findings and tool descriptions are
  redacted, but reports can still contain file paths, source metadata, and
  evidence. Review reports before sharing them.
- SARIF fingerprints include source locations; moving code can change a
  fingerprint.

## Development and tests

```bash
python -m pytest
```

The tests feed source fixtures to the parser; they do not import or execute
those fixtures. GitHub Actions tests Python 3.10–3.13. JSON schema and rule
identifiers may evolve while the project is in early development; consumers
should pin MCPShield versions if they depend on them.

## License

MIT. See [LICENSE](LICENSE).
