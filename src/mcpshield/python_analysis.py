"""Conservative, non-executing inventory of Python MCP tool implementations."""

import ast
from collections import deque
from dataclasses import asdict, dataclass
import os
from pathlib import Path
import re
import stat
from typing import Literal

from mcpshield.safe_io import read_limited_text


MAX_FILE_BYTES = 1_000_000
MAX_FILES = 5_000
MAX_TOTAL_BYTES = 50_000_000
MAX_AST_NODES = 1_000_000
MAX_FUNCTIONS = 50_000
MAX_CALLS = 250_000
MAX_GRAPH_CALLS = 500_000
_IGNORED_DIRECTORIES = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "node_modules",
    "site-packages",
    "venv",
}
_PROCESS_CALLS = {
    "asyncio.create_subprocess_exec",
    "asyncio.create_subprocess_shell",
    "os.popen",
    "os.system",
    "os.fork",
    "os.forkpty",
    "os.startfile",
}
_FILESYSTEM_CALLS = {
    "builtins.open",
    "open",
    "io.open",
    "os.chmod",
    "os.listdir",
    "os.mkdir",
    "os.open",
    "os.read",
    "os.remove",
    "os.rename",
    "os.replace",
    "os.rmdir",
    "os.scandir",
    "os.stat",
    "os.unlink",
    "os.walk",
    "os.write",
}
_PATH_METHODS = {
    "chmod",
    "glob",
    "iterdir",
    "mkdir",
    "open",
    "read_bytes",
    "read_text",
    "rename",
    "replace",
    "rglob",
    "rmdir",
    "stat",
    "touch",
    "unlink",
    "write_bytes",
    "write_text",
}
_NETWORK_PREFIXES = (
    "aiohttp.",
    "httpx.",
    "requests.",
    "socket.",
    "urllib3.",
)


def _recognized_sanitizers(node: ast.AST, aliases: dict[str, str]) -> tuple[str, ...]:
    sanitizers = {
        sanitizer
        for child in ast.walk(node)
        if isinstance(child, ast.Call)
        and (sanitizer := _call_expression(child.func, aliases)) == "shlex.quote"
    }
    return tuple(sorted(sanitizers))


def _literal_value(node: ast.AST) -> object | None:
    if isinstance(node, ast.Constant) and isinstance(
        node.value, (str, int, float, bool, type(None))
    ):
        return node.value
    return None


class PythonAnalysisError(Exception):
    """Raised when a Python source path cannot be read safely."""


@dataclass(frozen=True, slots=True)
class AnalysisIssue:
    path: str
    line: int | None
    code: str
    message: str
    severity: Literal["warning", "error"]


@dataclass(frozen=True, slots=True)
class AnalysisMetrics:
    """Resource usage and fixed limits applied during source analysis."""

    bytes_scanned: int
    ast_nodes: int
    functions_discovered: int
    calls_discovered: int
    graph_calls_examined: int
    max_total_bytes: int
    max_ast_nodes: int
    max_functions: int
    max_calls: int
    max_graph_calls: int


@dataclass(frozen=True, slots=True)
class FunctionLocation:
    """Stable, repository-relative identity for a discovered function."""

    id: str
    name: str
    path: str
    line: int


@dataclass(frozen=True, slots=True)
class UnresolvedCall:
    caller: str
    expression: str
    path: str
    line: int


@dataclass(frozen=True, slots=True)
class CapabilityEvidence:
    capability: str
    operation: str
    api: str
    function: str
    function_id: str
    path: str
    line: int
    call_chain: tuple[str, ...]
    call_chain_ids: tuple[str, ...]
    evidence_basis: str
    status: str = "observed_in_source"
    interpretation: str = "potential_capability"


@dataclass(frozen=True, slots=True)
class DataFlowEvidence:
    """Potential flow from a tool parameter to a sensitive API argument."""

    rule_id: str
    source_parameters: tuple[str, ...]
    sink_api: str
    sink_kind: str
    path: str
    line: int
    function: str
    function_id: str
    call_chain: tuple[str, ...]
    call_chain_ids: tuple[str, ...]
    sanitizers_observed: tuple[str, ...]
    confidence: Literal["low", "medium"]
    interpretation: str = "potential_untrusted_input_flow"


@dataclass(frozen=True, slots=True)
class ToolAnalysis:
    name: str
    function: str
    function_id: str
    path: str
    line: int
    description: str | None
    reachable_functions: tuple[str, ...]
    reachable_function_locations: tuple[FunctionLocation, ...]
    capabilities: tuple[CapabilityEvidence, ...]
    data_flows: tuple[DataFlowEvidence, ...]
    unresolved_calls: tuple[UnresolvedCall, ...]
    analysis_limited: bool


@dataclass(frozen=True, slots=True)
class AnalysisReport:
    schema_version: int
    status: Literal["complete", "partial"]
    analysis_complete: bool
    files_scanned: int
    metrics: AnalysisMetrics
    tools: tuple[ToolAnalysis, ...]
    issues: tuple[AnalysisIssue, ...]
    limitations: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-serializable representation."""
        return asdict(self)


@dataclass(frozen=True, slots=True)
class _Call:
    expression: str
    normalized_expression: str
    line: int
    argument_names: tuple[tuple[str, ...], ...]
    keyword_names: tuple[tuple[str, tuple[str, ...]], ...]
    literal_arguments: tuple[object | None, ...]
    literal_keywords: tuple[tuple[str, object | None], ...]
    argument_sanitizers: tuple[tuple[str, ...], ...]
    receiver_names: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _Function:
    module: str
    name: str
    qualified_name: str
    path: str
    line: int
    description: str | None
    tool_name: str | None
    owner_class: str | None
    aliases: dict[str, str]
    module_shadowed_names: frozenset[str]
    parent_scope: tuple[str, ...]
    parent_functions: tuple[str, ...]
    parameters: tuple[str, ...]
    positional_parameters: tuple[str, ...]
    keyword_parameters: tuple[str, ...]
    vararg_parameter: str | None
    local_names: frozenset[str]
    shadowed_names: frozenset[str]
    assignments: tuple[tuple[tuple[str, ...], tuple[str, ...]], ...]
    sanitized_assignments: tuple[
        tuple[tuple[str, ...], tuple[str, ...], str], ...
    ]
    calls: tuple[_Call, ...]


class _FunctionCallVisitor(ast.NodeVisitor):
    def __init__(self, aliases: dict[str, str]) -> None:
        self.aliases = aliases
        self.calls: list[_Call] = []
        self.local_names: set[str] = set()
        self.shadowed_names: set[str] = set()
        self.assignments: list[tuple[tuple[str, ...], tuple[str, ...]]] = []
        self.sanitized_assignments: list[
            tuple[tuple[str, ...], tuple[str, ...], str]
        ] = []

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.local_names.add(node.name)
        self.shadowed_names.add(node.name)
        return

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self.local_names.add(node.name)
        self.shadowed_names.add(node.name)
        return

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.local_names.add(node.name)
        self.shadowed_names.add(node.name)

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.local_names.add(alias.asname or alias.name.split(".")[0])

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        for alias in node.names:
            self.local_names.add(alias.asname or alias.name)

    def visit_Lambda(self, node: ast.Lambda) -> None:
        return

    def visit_Call(self, node: ast.Call) -> None:
        expression = _expression_name(node.func) or "<dynamic call>"
        normalized = _call_expression(node.func, self.aliases)
        self.calls.append(
            _Call(
                expression=expression,
                normalized_expression=normalized or expression,
                line=node.lineno,
                argument_names=tuple(
                    _names_in_expression(argument) for argument in node.args
                ),
                keyword_names=tuple(
                    (keyword.arg or "", _names_in_expression(keyword.value))
                    for keyword in node.keywords
                ),
                literal_arguments=tuple(
                    _literal_value(argument) for argument in node.args
                ),
                literal_keywords=tuple(
                    (keyword.arg or "", _literal_value(keyword.value))
                    for keyword in node.keywords
                ),
                argument_sanitizers=tuple(
                    _recognized_sanitizers(argument, self.aliases)
                    for argument in node.args
                ),
                receiver_names=(
                    _names_in_expression(node.func.value)
                    if isinstance(node.func, ast.Attribute)
                    else ()
                ),
            )
        )
        self.generic_visit(node)

    def visit_Name(self, node: ast.Name) -> None:
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            self.local_names.add(node.id)
            self.shadowed_names.add(node.id)
        elif isinstance(node.ctx, ast.Load):
            pass

    def visit_Assign(self, node: ast.Assign) -> None:
        targets = tuple(
            sorted(
                name
                for target in node.targets
                for name in _target_names(target)
            )
        )
        self.assignments.append((targets, _names_in_expression(node.value)))
        self._record_sanitized_assignment(node.targets, node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        targets = _target_names(node.target)
        if node.value is not None:
            self.assignments.append((targets, _names_in_expression(node.value)))
            self._record_sanitized_assignment((node.target,), node.value)
        self.generic_visit(node)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
        self.assignments.append(
            (_target_names(node.target), _names_in_expression(node.value))
        )
        self._record_sanitized_assignment((node.target,), node.value)
        self.generic_visit(node)

    def _record_sanitized_assignment(
        self, targets: tuple[ast.expr, ...] | list[ast.expr], value: ast.expr
    ) -> None:
        if not isinstance(value, ast.Call):
            return
        sanitizer = _call_expression(value.func, self.aliases)
        if sanitizer not in {"shlex.quote"}:
            return
        self.sanitized_assignments.append(
            (
                tuple(
                    sorted(name for target in targets for name in _target_names(target))
                ),
                _names_in_expression(value),
                sanitizer,
            )
        )


def _target_names(node: ast.AST) -> tuple[str, ...]:
    return tuple(
        sorted(
            {
                child.id
                for child in ast.walk(node)
                if isinstance(child, ast.Name)
                and isinstance(child.ctx, (ast.Store, ast.Del))
            }
        )
    )


def _names_in_expression(node: ast.AST) -> tuple[str, ...]:
    return tuple(
        sorted(
            {
                child.id
                for child in ast.walk(node)
                if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Load)
            }
        )
    )


def _expression_name(node: ast.expr) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _expression_name(node.value)
        return f"{parent}.{node.attr}" if parent else ""
    return ""


def _normalize_import_alias(expression: str, aliases: dict[str, str]) -> str:
    head, separator, tail = expression.partition(".")
    replacement = aliases.get(head, head)
    return f"{replacement}.{tail}" if separator else replacement


def _call_expression(node: ast.expr, aliases: dict[str, str]) -> str:
    expression = _expression_name(node)
    if expression:
        return _normalize_import_alias(expression, aliases)
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Call):
        constructor = _expression_name(node.value.func)
        if constructor and _normalize_import_alias(constructor, aliases) == "pathlib.Path":
            return f"pathlib.Path.{node.attr}"
    return ""


def _relative_import_module(
    module: str, level: int, current_module: str, *, is_package_init: bool = False
) -> str:
    if level == 0:
        return module
    package = (
        current_module.split(".")
        if is_package_init
        else current_module.split(".")[:-1]
    )
    if level > len(package):
        return f"{'.' * level}{module}"
    package = package[: max(0, len(package) - level + 1)]
    prefix = ".".join(package)
    return ".".join(part for part in (prefix, module) if part)


def _import_aliases(
    tree: ast.Module, current_module: str, *, is_package_init: bool = False
) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                local_name = alias.asname or alias.name.split(".")[0]
                imported_name = alias.name if alias.asname else local_name
                aliases[local_name] = imported_name
        elif isinstance(node, ast.ImportFrom):
            imported_module = _relative_import_module(
                node.module or "",
                node.level,
                current_module,
                is_package_init=is_package_init,
            )
            for alias in node.names:
                local_name = alias.asname or alias.name
                aliases[local_name] = ".".join(
                    part for part in (imported_module, alias.name) if part
                )
    bound_names = _module_shadowed_names(tree)
    for name in bound_names:
        aliases.pop(name, None)
    return aliases


def _module_shadowed_names(tree: ast.Module) -> frozenset[str]:
    bound_names: set[str] = set()

    class ModuleBindings(ast.NodeVisitor):
        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            bound_names.add(node.name)

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            bound_names.add(node.name)

        def visit_ClassDef(self, node: ast.ClassDef) -> None:
            bound_names.add(node.name)

        def visit_Lambda(self, node: ast.Lambda) -> None:
            return

        def visit_Name(self, node: ast.Name) -> None:
            if isinstance(node.ctx, (ast.Store, ast.Del)):
                bound_names.add(node.id)

    bindings = ModuleBindings()
    for statement in tree.body:
        bindings.visit(statement)
    return frozenset(bound_names)


def _function_import_aliases(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    module_aliases: dict[str, str],
    current_module: str,
    *,
    is_package_init: bool,
) -> dict[str, str]:
    aliases = dict(module_aliases)
    shadowed: set[str] = set()

    class LocalScopeVisitor(ast.NodeVisitor):
        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            shadowed.add(node.name)

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            shadowed.add(node.name)

        def visit_ClassDef(self, node: ast.ClassDef) -> None:
            shadowed.add(node.name)

        def visit_Lambda(self, node: ast.Lambda) -> None:
            return

        def visit_Import(self, node: ast.Import) -> None:
            for alias in node.names:
                local_name = alias.asname or alias.name.split(".")[0]
                aliases[local_name] = alias.name if alias.asname else local_name

        def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
            imported_module = _relative_import_module(
                node.module or "",
                node.level,
                current_module,
                is_package_init=is_package_init,
            )
            for alias in node.names:
                local_name = alias.asname or alias.name
                aliases[local_name] = ".".join(
                    part for part in (imported_module, alias.name) if part
                )

        def visit_Name(self, node: ast.Name) -> None:
            if isinstance(node.ctx, (ast.Store, ast.Del)):
                shadowed.add(node.id)

    visitor = LocalScopeVisitor()
    for statement in function.body:
        visitor.visit(statement)
    for argument in (
        *function.args.posonlyargs,
        *function.args.args,
        *function.args.kwonlyargs,
    ):
        aliases.pop(argument.arg, None)
    if function.args.vararg:
        aliases.pop(function.args.vararg.arg, None)
    if function.args.kwarg:
        shadowed.add(function.args.kwarg.arg)
    for name in shadowed:
        aliases.pop(name, None)
    return aliases


def _registered_tool_names(tree: ast.Module) -> dict[str, str]:
    registered: dict[str, str] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        if node.func.attr not in {"add_tool", "register_tool"} or not node.args:
            continue
        tool = node.args[0]
        if not isinstance(tool, ast.Name):
            continue
        name = tool.id
        for keyword in node.keywords:
            if (
                keyword.arg == "name"
                and isinstance(keyword.value, ast.Constant)
                and isinstance(keyword.value.value, str)
            ):
                name = keyword.value.value
        registered[tool.id] = name
    return registered


def _tool_name(function: ast.FunctionDef | ast.AsyncFunctionDef) -> str | None:
    for decorator in function.decorator_list:
        target = decorator.func if isinstance(decorator, ast.Call) else decorator
        if not isinstance(target, ast.Attribute) or target.attr != "tool":
            continue
        if isinstance(decorator, ast.Call):
            for keyword in decorator.keywords:
                if keyword.arg == "name" and isinstance(keyword.value, ast.Constant):
                    if isinstance(keyword.value.value, str):
                        return keyword.value.value
        return function.name
    return None


def _function_records(
    tree: ast.Module,
    path: str,
    module: str,
    aliases: dict[str, str],
) -> list[_Function]:
    functions: list[_Function] = []
    registered_tools = _registered_tool_names(tree)
    module_shadowed_names = _module_shadowed_names(tree)

    class FunctionVisitor(ast.NodeVisitor):
        def __init__(self) -> None:
            self.parents: list[str] = []
            self.function_scopes: list[str] = []
            self.class_scopes: list[str] = []

        def _visit_function(
            self, node: ast.FunctionDef | ast.AsyncFunctionDef
        ) -> None:
            qualified_name = ".".join((*self.parents, node.name))
            function_aliases = _function_import_aliases(
                node,
                aliases,
                module,
                is_package_init=Path(path).name == "__init__.py",
            )
            visitor = _FunctionCallVisitor(function_aliases)
            for statement in node.body:
                visitor.visit(statement)
            positional_parameters = tuple(
                argument.arg
                for argument in (
                    *node.args.posonlyargs,
                    *node.args.args,
                )
            )
            keyword_parameters = tuple(
                argument.arg
                for argument in (*node.args.args, *node.args.kwonlyargs)
            )
            parameters = (
                *positional_parameters,
                *(argument.arg for argument in node.args.kwonlyargs),
            )
            visitor.local_names.update(parameters)
            visitor.shadowed_names.update(parameters)
            vararg_parameter = None
            if node.args.vararg:
                visitor.local_names.add(node.args.vararg.arg)
                visitor.shadowed_names.add(node.args.vararg.arg)
                parameters += (node.args.vararg.arg,)
                vararg_parameter = node.args.vararg.arg
            if node.args.kwarg:
                visitor.local_names.add(node.args.kwarg.arg)
                visitor.shadowed_names.add(node.args.kwarg.arg)
                parameters += (node.args.kwarg.arg,)
            description = ast.get_docstring(node)
            functions.append(
                _Function(
                    module=module,
                    name=node.name,
                    qualified_name=qualified_name,
                    path=path,
                    line=node.lineno,
                    description=_sanitize_description(description),
                    tool_name=_tool_name(node) or registered_tools.get(node.name),
                    owner_class=(
                        self.class_scopes[-1]
                        if self.class_scopes and not self.function_scopes
                        else None
                    ),
                    aliases=function_aliases,
                    module_shadowed_names=module_shadowed_names,
                    parent_scope=tuple(self.parents),
                    parent_functions=tuple(self.function_scopes),
                    parameters=parameters,
                    positional_parameters=positional_parameters,
                    keyword_parameters=keyword_parameters,
                    vararg_parameter=vararg_parameter,
                    local_names=frozenset(visitor.local_names),
                    shadowed_names=frozenset(visitor.shadowed_names),
                    assignments=tuple(visitor.assignments),
                    sanitized_assignments=tuple(visitor.sanitized_assignments),
                    calls=tuple(visitor.calls),
                )
            )
            self.parents.append(node.name)
            self.function_scopes.append(qualified_name)
            self.generic_visit(node)
            self.function_scopes.pop()
            self.parents.pop()

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            self._visit_function(node)

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            self._visit_function(node)

        def visit_ClassDef(self, node: ast.ClassDef) -> None:
            self.parents.append(node.name)
            self.class_scopes.append(".".join(self.parents))
            self.generic_visit(node)
            self.class_scopes.pop()
            self.parents.pop()

    FunctionVisitor().visit(tree)
    return functions


def _sanitize_description(description: str | None) -> str | None:
    if description is None:
        return None
    secret_pattern = re.compile(
        r"""(?i)\b(api[_-]?key|access[_-]?token|client[_-]?secret|password|secret)\b(\s*["']?\s*[:=]\s*["'])[^"'\r\n]+(["'])"""
    )
    return secret_pattern.sub(r"\1\2[REDACTED]\3", description)[:1_000]


def _resolved_api(
    call: _Call,
    function: _Function,
    local_module_roots: frozenset[str],
) -> str | None:
    expression = call.expression
    if expression == "<dynamic call>":
        if (
            call.normalized_expression.startswith("pathlib.Path.")
            and "pathlib" not in local_module_roots
        ):
            return call.normalized_expression
        return None
    head, separator, tail = expression.partition(".")
    if head in function.shadowed_names or (
        head in function.module_shadowed_names and head not in function.aliases
    ):
        return None
    if (
        expression == "open"
        and "open" not in function.aliases
        and "open" not in function.module_shadowed_names
    ):
        return "builtins.open"
    imported = function.aliases.get(head)
    if imported is None:
        return None
    if imported.split(".", 1)[0] in local_module_roots:
        return None
    return f"{imported}.{tail}" if separator else imported


def _capability(api: str) -> str | None:
    if (
        api.startswith("subprocess.")
        or api in _PROCESS_CALLS
        or api.startswith("os.exec")
        or api.startswith("os.spawn")
    ):
        return "process_execution"
    if (
        api in _FILESYSTEM_CALLS
        or api.startswith("shutil.")
        or api.startswith("tempfile.")
        or (
            api.startswith("pathlib.Path.")
            and api.rpartition(".")[2] in _PATH_METHODS
        )
    ):
        return "filesystem_access"
    if (
        api.startswith(_NETWORK_PREFIXES)
        or api == "urllib.request.urlopen"
        or api.startswith("urllib.request.")
    ):
        return "network_communication"
    return None


def _operation(api: str, call: _Call) -> str:
    terminal = api.rpartition(".")[2]
    if _capability(api) == "process_execution":
        if terminal in {"system", "popen", "create_subprocess_shell"}:
            return "shell_command"
        if terminal in {"exec", "execl", "execle", "execlp", "execv", "execve", "execvp", "execvpe"}:
            return "replace_process"
        if terminal in {"spawn", "spawnl", "spawnle", "spawnlp", "spawnv", "spawnve", "spawnvp", "spawnvpe"}:
            return "spawn_process"
        return "run_process"
    if _capability(api) == "filesystem_access":
        if terminal in {"write_text", "write_bytes", "touch", "mkdir", "chmod"}:
            return "write_or_change_file"
        if terminal in {"unlink", "remove", "rmdir", "rmtree"}:
            return "delete_file"
        if terminal in {"rename", "replace", "move", "copy", "copy2"}:
            return "move_or_copy_file"
        if terminal in {"read_text", "read_bytes", "listdir", "scandir", "iterdir", "glob", "rglob"}:
            return "read_or_list_files"
        if api == "builtins.open" or api == "pathlib.Path.open":
            mode = dict(call.literal_keywords).get("mode")
            if mode is None and len(call.literal_arguments) > 1:
                mode = call.literal_arguments[1]
            if isinstance(mode, str):
                if any(flag in mode for flag in "wax"):
                    return "write_or_change_file"
                if "+" in mode:
                    return "read_and_write_file"
                return "read_file"
            return "open_file"
        return "filesystem_operation"
    if _capability(api) == "network_communication":
        if terminal in {"get", "post", "put", "patch", "delete", "request", "urlopen"}:
            return "http_request"
        if terminal in {"connect", "connect_ex"}:
            return "network_connect"
        if terminal in {"bind", "listen", "accept"}:
            return "network_listen"
        if terminal in {"send", "sendall", "recv", "recvfrom"}:
            return "socket_communication"
        return "network_operation"
    return "unknown"


def _module_name(relative_path: str) -> str:
    path = Path(relative_path)
    parts = list(path.with_suffix("").parts)
    if parts and parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def _python_files(target: Path) -> tuple[list[Path], bool, list[OSError]]:
    if target.is_file():
        return ([target] if target.suffix.lower() == ".py" else []), False, []

    files: list[Path] = []
    truncated = False
    traversal_errors: list[OSError] = []
    for root, directories, filenames in os.walk(
        target, followlinks=False, onerror=traversal_errors.append
    ):
        directories[:] = sorted(
            directory
            for directory in directories
            if directory not in _IGNORED_DIRECTORIES
            and not directory.startswith(".")
            and not (Path(root) / directory).is_symlink()
        )
        for filename in sorted(filenames):
            candidate = Path(root) / filename
            if candidate.suffix.lower() != ".py" or candidate.is_symlink():
                continue
            if len(files) == MAX_FILES:
                truncated = True
                return files, truncated, traversal_errors
            files.append(candidate)
    return files, truncated, traversal_errors


def _function_id(function: _Function) -> str:
    return f"{function.path}:{function.line}:{function.qualified_name}"


def _function_location(function: _Function) -> FunctionLocation:
    return FunctionLocation(
        id=_function_id(function),
        name=function.qualified_name,
        path=function.path,
        line=function.line,
    )


def _resolve_call(
    call: _Call,
    caller: _Function,
    functions_by_module_name: dict[tuple[str, str], list[_Function]],
) -> _Function | None:
    if (
        caller.owner_class
        and call.expression.startswith(("self.", "cls."))
        and call.expression.count(".") == 1
    ):
        method_name = call.expression.partition(".")[2]
        matches = functions_by_module_name.get(
            (caller.module, f"{caller.owner_class}.{method_name}"), []
        )
        return matches[0] if len(matches) == 1 else None

    if "." in call.normalized_expression:
        local_module = call.expression.partition(".")[0]
        if (
            local_module not in caller.aliases
            or local_module in caller.shadowed_names
        ):
            return None
        module, _, name = call.normalized_expression.rpartition(".")
        imported_function = functions_by_module_name.get((module, name), [])
        return imported_function[0] if len(imported_function) == 1 else None
    name = call.normalized_expression
    scopes = [caller.qualified_name, *reversed(caller.parent_functions)]
    for index in range(len(caller.parent_scope), 0, -1):
        scopes.append(".".join(caller.parent_scope[:index]))
    for scope in dict.fromkeys(scopes):
        nested_matches = functions_by_module_name.get(
            (caller.module, f"{scope}.{name}"), []
        )
        if len(nested_matches) == 1:
            return nested_matches[0]
        if nested_matches:
            return None

    if name in caller.shadowed_names:
        return None

    same_module = functions_by_module_name.get((caller.module, name), [])
    if len(same_module) == 1:
        return same_module[0]
    return None


def _count_nodes(tree: ast.AST, limit: int) -> int:
    count = 0
    pending = [tree]
    while pending and count <= limit:
        node = pending.pop()
        count += 1
        pending.extend(ast.iter_child_nodes(node))
    return count


def _description_effect_issues(tools: tuple[ToolAnalysis, ...]) -> list[AnalysisIssue]:
    issues: list[AnalysisIssue] = []
    for tool in tools:
        description = (tool.description or "").casefold()
        claimed_absences = (
            (
                ("read-only", "read only", "without modifying", "does not modify"),
                {"write_or_change_file", "delete_file", "move_or_copy_file", "read_and_write_file"},
                "filesystem mutation",
            ),
            (
                ("no network", "without network", "does not access the network"),
                {"http_request", "network_connect", "network_listen", "socket_communication"},
                "network communication",
            ),
            (
                ("does not execute", "no shell", "without running commands"),
                {"shell_command", "run_process", "spawn_process", "replace_process"},
                "process execution",
            ),
        )
        for phrases, operations, effect_name in claimed_absences:
            if not any(phrase in description for phrase in phrases):
                continue
            evidence = next(
                (
                    capability
                    for capability in tool.capabilities
                    if capability.operation in operations
                ),
                None,
            )
            if evidence is None:
                continue
            issues.append(
                AnalysisIssue(
                    evidence.path,
                    evidence.line,
                    "description_effect_mismatch",
                    (
                        f"Tool {tool.name!r} has a description that appears to "
                        f"deny {effect_name}, while a reachable source call is "
                        f"classified as {evidence.operation}. This is a review "
                        "signal, not proof of runtime behavior or intent."
                    ),
                    "warning",
                )
            )
            break
    return issues


def _tainted_values(
    function: _Function,
    incoming: dict[str, set[str]],
) -> tuple[dict[str, set[str]], dict[str, set[str]]]:
    values = {name: set(sources) for name, sources in incoming.items()}
    sanitizers: dict[str, set[str]] = {}
    changed = True
    while changed:
        changed = False
        for targets, sources in function.assignments:
            combined = set().union(*(values.get(name, set()) for name in sources))
            for target in targets:
                current = values.setdefault(target, set())
                if not combined.issubset(current):
                    current.update(combined)
                    changed = True
        for targets, sources, sanitizer in function.sanitized_assignments:
            combined = set().union(*(values.get(name, set()) for name in sources))
            if not combined:
                continue
            for target in targets:
                current = sanitizers.setdefault(target, set())
                if sanitizer not in current:
                    current.add(sanitizer)
                    changed = True
    return values, sanitizers


def _sink_inputs(api: str, call: _Call) -> tuple[str, tuple[str, ...]] | None:
    capability = _capability(api)
    if capability == "process_execution":
        if call.argument_names:
            return "process_argument", call.argument_names[0]
        command = dict(call.keyword_names).get("args") or dict(
            call.keyword_names
        ).get("command")
        if command:
            return "process_argument", command
    elif capability == "filesystem_access":
        if api.startswith("pathlib.Path."):
            return "filesystem_path", call.receiver_names
        if call.argument_names:
            return "filesystem_path", call.argument_names[0]
        for key in ("file", "path", "src", "dst"):
            names = dict(call.keyword_names).get(key)
            if names:
                return "filesystem_path", names
    elif capability == "network_communication":
        for key in ("url", "uri", "address", "host"):
            names = dict(call.keyword_names).get(key)
            if names:
                return "network_destination", names
        if call.argument_names:
            return "network_destination", call.argument_names[0]
    return None


def _analyze_tool(
    tool: _Function,
    functions_by_module_name: dict[tuple[str, str], list[_Function]],
    local_module_roots: frozenset[str],
    remaining_graph_calls: list[int],
) -> ToolAnalysis:
    tool_id = _function_id(tool)
    tool_sources = {
        parameter: {parameter}
        for parameter in tool.parameters
        if parameter not in {"self", "cls"}
    }
    reached: dict[str, tuple[_Function, tuple[_Function, ...]]] = {
        tool_id: (tool, (tool,))
    }
    incoming_sources: dict[str, dict[str, set[str]]] = {tool_id: tool_sources}
    queue: deque[_Function] = deque([tool])
    capabilities: dict[
        tuple[str, str, str, int], CapabilityEvidence
    ] = {}
    data_flows: dict[tuple[str, int, str], DataFlowEvidence] = {}
    unresolved: dict[tuple[str, str, int], UnresolvedCall] = {}
    analysis_limited = False

    while queue:
        current = queue.popleft()
        current_id = _function_id(current)
        chain = reached[current_id][1]
        tainted_values, sanitizers = _tainted_values(
            current, incoming_sources.get(current_id, {})
        )
        for call in current.calls:
            if remaining_graph_calls[0] <= 0:
                analysis_limited = True
                queue.clear()
                break
            remaining_graph_calls[0] -= 1
            api = _resolved_api(call, current, local_module_roots)
            category = _capability(api) if api else None
            if category:
                key = (category, current.path, api or call.normalized_expression, call.line)
                capabilities[key] = CapabilityEvidence(
                    capability=category,
                    operation=_operation(api or call.normalized_expression, call),
                    api=api or call.normalized_expression,
                    function=current.qualified_name,
                    function_id=current_id,
                    path=current.path,
                    line=call.line,
                    call_chain=tuple(function.qualified_name for function in chain),
                    call_chain_ids=tuple(_function_id(function) for function in chain),
                    evidence_basis="recognized_import_or_builtin_and_call_expression",
                )

                sink = _sink_inputs(api or call.normalized_expression, call)
                if sink:
                    sink_kind, input_names = sink
                    source_parameters = set().union(
                        *(tainted_values.get(name, set()) for name in input_names)
                    )
                    if source_parameters:
                        observed_sanitizers = set().union(
                            *(sanitizers.get(name, set()) for name in input_names)
                        )
                        observed_sanitizers.update(
                            sanitizer
                            for item in call.argument_sanitizers
                            for sanitizer in item
                        )
                        rule_id = {
                            "process_execution": "MCP201",
                            "filesystem_access": "MCP202",
                            "network_communication": "MCP203",
                        }[category]
                        data_flows[(rule_id, call.line, api or "")] = DataFlowEvidence(
                            rule_id=rule_id,
                            source_parameters=tuple(sorted(source_parameters)),
                            sink_api=api or call.normalized_expression,
                            sink_kind=sink_kind,
                            path=current.path,
                            line=call.line,
                            function=current.qualified_name,
                            function_id=current_id,
                            call_chain=tuple(
                                function.qualified_name for function in chain
                            ),
                            call_chain_ids=tuple(
                                _function_id(function) for function in chain
                            ),
                            sanitizers_observed=tuple(sorted(observed_sanitizers)),
                            confidence=(
                                "medium" if len(chain) == 1 else "low"
                            ),
                        )

            target = _resolve_call(call, current, functions_by_module_name)
            if target is None:
                if category:
                    continue
                key = (current_id, call.expression, call.line)
                unresolved[key] = UnresolvedCall(
                    caller=current.qualified_name,
                    expression=call.expression,
                    path=current.path,
                    line=call.line,
                )
                continue

            target_id = _function_id(target)
            new_target = target_id not in reached
            target_sources: dict[str, set[str]] = {}
            for index, names in enumerate(call.argument_names):
                if index < len(target.positional_parameters):
                    parameter = target.positional_parameters[index]
                elif target.vararg_parameter:
                    parameter = target.vararg_parameter
                else:
                    break
                propagated = set().union(
                    *(tainted_values.get(name, set()) for name in names)
                )
                if propagated:
                    target_sources.setdefault(parameter, set()).update(
                        propagated
                    )
            for parameter, names in call.keyword_names:
                if parameter in target.keyword_parameters:
                    propagated = set().union(
                        *(tainted_values.get(name, set()) for name in names)
                    )
                    if propagated:
                        target_sources.setdefault(parameter, set()).update(propagated)

            if new_target:
                reached[target_id] = (
                    target,
                    (*chain, target),
                )
                incoming_sources[target_id] = {}
            pending = incoming_sources.setdefault(target_id, {})
            source_set_changed = False
            for parameter, sources in target_sources.items():
                known_sources = pending.setdefault(parameter, set())
                new_sources = sources - known_sources
                if new_sources:
                    known_sources.update(new_sources)
                    source_set_changed = True
            if new_target or source_set_changed:
                queue.append(target)

    reached_functions = tuple(
        sorted(
            (
                _function_location(function)
                for identifier, (function, _) in reached.items()
                if identifier != tool_id
            ),
            key=lambda item: (item.path, item.line, item.id),
        )
    )
    return ToolAnalysis(
        name=tool.tool_name or tool.name,
        function=tool.qualified_name,
        function_id=tool_id,
        path=tool.path,
        line=tool.line,
        description=tool.description,
        reachable_functions=tuple(item.name for item in reached_functions),
        reachable_function_locations=reached_functions,
        capabilities=tuple(
            sorted(
                capabilities.values(),
                key=lambda item: (item.capability, item.path, item.line, item.api),
            )
        ),
        data_flows=tuple(
            sorted(
                data_flows.values(),
                key=lambda item: (item.path, item.line, item.rule_id),
            )
        ),
        unresolved_calls=tuple(
            sorted(
                unresolved.values(),
                key=lambda item: (item.path, item.line, item.expression),
            )
        ),
        analysis_limited=analysis_limited,
    )


def analyze_python_path(path: str | Path) -> AnalysisReport:
    """Inventory Python MCP tool decorators and statically visible capabilities.

    Source files are parsed with :mod:`ast`; they are never imported or run.
    Only uniquely resolved, direct calls to local functions are followed.
    """
    target = Path(path).expanduser()
    try:
        target_stat = target.lstat()
    except OSError as exc:
        raise PythonAnalysisError(
            f"Could not inspect analysis path: {exc.strerror or exc}"
        ) from exc
    if stat.S_ISLNK(target_stat.st_mode):
        raise PythonAnalysisError(f"Refusing to analyze a symbolic link: {target}")
    if not (stat.S_ISREG(target_stat.st_mode) or stat.S_ISDIR(target_stat.st_mode)):
        raise PythonAnalysisError(f"Not a regular file or directory: {target}")
    if stat.S_ISREG(target_stat.st_mode) and target.suffix.lower() != ".py":
        raise PythonAnalysisError(f"Not a Python source file: {target}")

    root = target if stat.S_ISDIR(target_stat.st_mode) else target.parent
    candidates, truncated, traversal_errors = _python_files(target)
    functions: list[_Function] = []
    issues: list[AnalysisIssue] = []
    files_scanned = 0
    bytes_scanned = 0
    ast_nodes = 0
    functions_discovered = 0
    calls_discovered = 0

    for error in traversal_errors:
        error_path = Path(error.filename) if error.filename else target
        try:
            relative_path = error_path.relative_to(root).as_posix()
        except ValueError:
            relative_path = "."
        issues.append(
            AnalysisIssue(
                relative_path,
                None,
                "directory_read_error",
                error.strerror or "Could not inspect directory.",
                "warning",
            )
        )

    for candidate in candidates:
        relative_path = candidate.relative_to(root).as_posix()
        try:
            candidate_size = candidate.stat().st_size
            if candidate_size > MAX_FILE_BYTES:
                issues.append(
                    AnalysisIssue(
                        relative_path,
                        None,
                        "file_too_large",
                        f"File exceeds the {MAX_FILE_BYTES}-byte analysis limit.",
                        "warning",
                    )
                )
                continue
            remaining_bytes = MAX_TOTAL_BYTES - bytes_scanned
            if candidate_size > remaining_bytes:
                issues.append(
                    AnalysisIssue(
                        relative_path,
                        None,
                        "total_byte_limit_reached",
                        f"Analysis stopped at the {MAX_TOTAL_BYTES}-byte total source limit.",
                        "warning",
                    )
                )
                break
            source = read_limited_text(
                candidate,
                min(MAX_FILE_BYTES, remaining_bytes),
                decode_errors="strict",
            )
            if source is None:
                issues.append(
                    AnalysisIssue(
                        relative_path,
                        None,
                        "file_changed_or_exceeded_limit",
                        "File changed or exceeded a configured byte limit while being read.",
                        "warning",
                    )
                )
                break
        except UnicodeDecodeError:
            issues.append(
                AnalysisIssue(
                    relative_path,
                    None,
                    "encoding_error",
                    "Python source is not valid UTF-8.",
                    "error",
                )
            )
            continue
        except OSError as exc:
            issues.append(
                AnalysisIssue(
                    relative_path,
                    None,
                    "file_read_error",
                    exc.strerror or str(exc),
                    "error",
                )
            )
            continue

        source_bytes = len(source.encode("utf-8"))
        if bytes_scanned + source_bytes > MAX_TOTAL_BYTES:
            issues.append(
                AnalysisIssue(
                    relative_path,
                    None,
                    "total_byte_limit_reached",
                    f"Analysis stopped at the {MAX_TOTAL_BYTES}-byte total source limit.",
                    "warning",
                )
            )
            break
        bytes_scanned += source_bytes
        files_scanned += 1
        try:
            tree = ast.parse(source, filename=relative_path)
        except SyntaxError as exc:
            issues.append(
                AnalysisIssue(
                    relative_path,
                    exc.lineno,
                    "syntax_error",
                    exc.msg,
                    "error",
                )
            )
            continue
        except (RecursionError, ValueError) as exc:
            issues.append(
                AnalysisIssue(
                    relative_path,
                    None,
                    "parse_error",
                    str(exc) or "Python parser could not analyze this file.",
                    "error",
                )
            )
            continue

        remaining_nodes = MAX_AST_NODES - ast_nodes
        file_nodes = _count_nodes(tree, remaining_nodes)
        if file_nodes > remaining_nodes:
            ast_nodes = MAX_AST_NODES
            issues.append(
                AnalysisIssue(
                    relative_path,
                    None,
                    "ast_node_limit_reached",
                    f"Analysis stopped at the {MAX_AST_NODES}-node AST budget.",
                    "warning",
                )
            )
            break
        ast_nodes += file_nodes

        module = _module_name(relative_path)
        aliases = _import_aliases(
            tree, module, is_package_init=Path(relative_path).name == "__init__.py"
        )
        try:
            file_functions = _function_records(tree, relative_path, module, aliases)
        except RecursionError as exc:
            issues.append(
                AnalysisIssue(
                    relative_path,
                    None,
                    "parse_error",
                    str(exc) or "Python source is too deeply nested to analyze.",
                    "error",
                )
            )
            continue

        file_calls = sum(len(function.calls) for function in file_functions)
        if functions_discovered + len(file_functions) > MAX_FUNCTIONS:
            issues.append(
                AnalysisIssue(
                    relative_path,
                    None,
                    "function_limit_reached",
                    f"Analysis stopped at the {MAX_FUNCTIONS}-function budget.",
                    "warning",
                )
            )
            break
        if calls_discovered + file_calls > MAX_CALLS:
            issues.append(
                AnalysisIssue(
                    relative_path,
                    None,
                    "call_limit_reached",
                    f"Analysis stopped at the {MAX_CALLS}-call budget.",
                    "warning",
                )
            )
            break
        functions.extend(file_functions)
        functions_discovered += len(file_functions)
        calls_discovered += file_calls

    if truncated:
        issues.append(
            AnalysisIssue(
                ".",
                None,
                "file_limit_reached",
                f"Analysis stopped after {MAX_FILES} Python files.",
                "warning",
            )
        )

    local_module_roots = frozenset(
        _module_name(candidate.relative_to(root).as_posix()).split(".", 1)[0]
        for candidate in candidates
        if _module_name(candidate.relative_to(root).as_posix())
    )
    by_module_and_name: dict[tuple[str, str], list[_Function]] = {}
    for function in functions:
        by_module_and_name.setdefault((function.module, function.name), []).append(
            function
        )
        if function.qualified_name != function.name:
            by_module_and_name.setdefault(
                (function.module, function.qualified_name), []
            ).append(function)

    graph_budget = [MAX_GRAPH_CALLS]
    tools_list: list[ToolAnalysis] = []
    for function in functions:
        if function.tool_name is None:
            continue
        if graph_budget[0] <= 0:
            issues.append(
                AnalysisIssue(
                    ".",
                    None,
                    "call_graph_limit_reached",
                    f"Tool graph processing stopped at the shared {MAX_GRAPH_CALLS}-call budget.",
                    "warning",
                )
            )
            break
        tool = _analyze_tool(
            function, by_module_and_name, local_module_roots, graph_budget
        )
        tools_list.append(tool)
        if tool.analysis_limited:
            issues.append(
                AnalysisIssue(
                    tool.path,
                    tool.line,
                    "call_graph_limit_reached",
                    (
                        f"Call graph analysis reached the shared "
                        f"{MAX_GRAPH_CALLS}-call budget."
                    ),
                    "warning",
                )
            )
            break
    tools = tuple(
        sorted(tools_list, key=lambda item: (item.path, item.line, item.name))
    )
    issues.extend(_description_effect_issues(tools))
    issues_tuple = tuple(
        sorted(issues, key=lambda item: (item.path, item.line or 0, item.code))
    )
    analysis_complete = not any(
        issue.code != "description_effect_mismatch" for issue in issues_tuple
    )
    graph_calls_examined = MAX_GRAPH_CALLS - graph_budget[0]
    return AnalysisReport(
        schema_version=2,
        status="complete" if analysis_complete else "partial",
        analysis_complete=analysis_complete,
        files_scanned=files_scanned,
        metrics=AnalysisMetrics(
            bytes_scanned=bytes_scanned,
            ast_nodes=ast_nodes,
            functions_discovered=functions_discovered,
            calls_discovered=calls_discovered,
            graph_calls_examined=graph_calls_examined,
            max_total_bytes=MAX_TOTAL_BYTES,
            max_ast_nodes=MAX_AST_NODES,
            max_functions=MAX_FUNCTIONS,
            max_calls=MAX_CALLS,
            max_graph_calls=MAX_GRAPH_CALLS,
        ),
        tools=tools,
        issues=issues_tuple,
        limitations=(
            "Complete means the discovered source inputs were processed within fixed budgets; it does not mean every runtime tool was identified.",
            "Tool detection supports attribute decorators named 'tool' and direct add_tool/register_tool calls as heuristics.",
            "Capabilities require recognized imports or the unshadowed built-in open; local modules that shadow known API names remain unknown.",
            "Direct parameter-to-sink flows use conservative name/assignment propagation and are potential flows, not proof of exploitability.",
            "Only unique direct local calls, explicit imports, and direct self/cls method calls are followed.",
            "Dynamic dispatch, reflection, generated code, runtime registration/configuration, dependency internals, and branch-sensitive sanitization are not resolved.",
            "The analyzer recognizes shlex.quote as a sanitizer signal but does not prove context-safe sanitization or suppress potential flows.",
            "Descriptions are untrusted data; likely credential values are redacted, but other sensitive or hostile text may remain.",
        ),
    )
