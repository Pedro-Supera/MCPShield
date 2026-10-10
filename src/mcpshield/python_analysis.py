"""Conservative, non-executing inventory of Python MCP tool implementations."""

import ast
from collections import deque
from dataclasses import asdict, dataclass
import os
from pathlib import Path

from mcpshield.safe_io import read_limited_text


MAX_FILE_BYTES = 1_000_000
MAX_FILES = 5_000
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


class PythonAnalysisError(Exception):
    """Raised when a Python source path cannot be read safely."""


@dataclass(frozen=True, slots=True)
class AnalysisIssue:
    path: str
    line: int | None
    code: str
    message: str
    severity: str


@dataclass(frozen=True, slots=True)
class UnresolvedCall:
    caller: str
    expression: str
    path: str
    line: int


@dataclass(frozen=True, slots=True)
class CapabilityEvidence:
    capability: str
    api: str
    function: str
    path: str
    line: int
    call_chain: tuple[str, ...]
    status: str = "observed_in_source"
    interpretation: str = "potential_capability"


@dataclass(frozen=True, slots=True)
class ToolAnalysis:
    name: str
    function: str
    path: str
    line: int
    description: str | None
    reachable_functions: tuple[str, ...]
    capabilities: tuple[CapabilityEvidence, ...]
    unresolved_calls: tuple[UnresolvedCall, ...]


@dataclass(frozen=True, slots=True)
class AnalysisReport:
    schema_version: int
    files_scanned: int
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


@dataclass(frozen=True, slots=True)
class _Function:
    module: str
    name: str
    qualified_name: str
    path: str
    line: int
    description: str | None
    tool_name: str | None
    aliases: dict[str, str]
    parent_scope: tuple[str, ...]
    parent_functions: tuple[str, ...]
    local_names: frozenset[str]
    calls: tuple[_Call, ...]


class _FunctionCallVisitor(ast.NodeVisitor):
    def __init__(self, aliases: dict[str, str]) -> None:
        self.aliases = aliases
        self.calls: list[_Call] = []
        self.local_names: set[str] = set()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        return

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        return

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.local_names.add(node.name)

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
            )
        )
        self.generic_visit(node)

    def visit_Name(self, node: ast.Name) -> None:
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            self.local_names.add(node.id)


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
    return aliases


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
    tree: ast.Module, path: str, module: str, aliases: dict[str, str]
) -> list[_Function]:
    functions: list[_Function] = []

    class FunctionVisitor(ast.NodeVisitor):
        def __init__(self) -> None:
            self.parents: list[str] = []
            self.function_scopes: list[str] = []

        def _visit_function(
            self, node: ast.FunctionDef | ast.AsyncFunctionDef
        ) -> None:
            qualified_name = ".".join((*self.parents, node.name))
            visitor = _FunctionCallVisitor(aliases)
            for statement in node.body:
                visitor.visit(statement)
            visitor.local_names.update(argument.arg for argument in node.args.posonlyargs)
            visitor.local_names.update(argument.arg for argument in node.args.args)
            visitor.local_names.update(argument.arg for argument in node.args.kwonlyargs)
            if node.args.vararg:
                visitor.local_names.add(node.args.vararg.arg)
            if node.args.kwarg:
                visitor.local_names.add(node.args.kwarg.arg)
            functions.append(
                _Function(
                    module=module,
                    name=node.name,
                    qualified_name=qualified_name,
                    path=path,
                    line=node.lineno,
                    description=ast.get_docstring(node),
                    tool_name=_tool_name(node),
                    aliases=aliases,
                    parent_scope=tuple(self.parents),
                    parent_functions=tuple(self.function_scopes),
                    local_names=frozenset(visitor.local_names),
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
            self.generic_visit(node)
            self.parents.pop()

    FunctionVisitor().visit(tree)
    return functions


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


def _resolve_call(
    call: _Call,
    caller: _Function,
    functions_by_module_name: dict[tuple[str, str], list[_Function]],
) -> _Function | None:
    if "." in call.normalized_expression:
        local_module = call.expression.partition(".")[0]
        if local_module not in caller.aliases:
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

    if name in caller.local_names:
        return None

    same_module = functions_by_module_name.get((caller.module, name), [])
    if len(same_module) == 1:
        return same_module[0]
    return None


def _analyze_tool(
    tool: _Function,
    functions_by_module_name: dict[tuple[str, str], list[_Function]],
) -> ToolAnalysis:
    tool_id = _function_id(tool)
    reached: dict[str, tuple[_Function, tuple[str, ...]]] = {
        tool_id: (tool, (tool.qualified_name,))
    }
    queue: deque[_Function] = deque([tool])
    capabilities: dict[
        tuple[str, str, str, int], CapabilityEvidence
    ] = {}
    unresolved: dict[tuple[str, str, int], UnresolvedCall] = {}

    while queue:
        current = queue.popleft()
        current_id = _function_id(current)
        chain = reached[current_id][1]
        for call in current.calls:
            category = _capability(call.normalized_expression)
            if category:
                key = (category, current.path, call.normalized_expression, call.line)
                capabilities[key] = CapabilityEvidence(
                    capability=category,
                    api=call.normalized_expression,
                    function=current.qualified_name,
                    path=current.path,
                    line=call.line,
                    call_chain=chain,
                )
                continue

            target = _resolve_call(call, current, functions_by_module_name)
            if target is None:
                key = (current_id, call.expression, call.line)
                unresolved[key] = UnresolvedCall(
                    caller=current.qualified_name,
                    expression=call.expression,
                    path=current.path,
                    line=call.line,
                )
            elif _function_id(target) not in reached:
                target_id = _function_id(target)
                reached[target_id] = (
                    target,
                    (*chain, target.qualified_name),
                )
                queue.append(target)

    return ToolAnalysis(
        name=tool.tool_name or tool.name,
        function=tool.qualified_name,
        path=tool.path,
        line=tool.line,
        description=tool.description,
        reachable_functions=tuple(
            sorted(
                function.qualified_name
                for identifier, (function, _) in reached.items()
                if identifier != tool_id
            )
        ),
        capabilities=tuple(
            sorted(
                capabilities.values(),
                key=lambda item: (item.capability, item.path, item.line, item.api),
            )
        ),
        unresolved_calls=tuple(
            sorted(
                unresolved.values(),
                key=lambda item: (item.path, item.line, item.expression),
            )
        ),
    )


def analyze_python_path(path: str | Path) -> AnalysisReport:
    """Inventory Python MCP tool decorators and statically visible capabilities.

    Source files are parsed with :mod:`ast`; they are never imported or run.
    Only uniquely resolved, direct calls to local functions are followed.
    """
    target = Path(path).expanduser()
    if not target.exists():
        raise PythonAnalysisError(f"Path does not exist: {target}")
    if target.is_symlink():
        raise PythonAnalysisError(f"Refusing to analyze a symbolic link: {target}")
    if not target.is_file() and not target.is_dir():
        raise PythonAnalysisError(f"Not a regular file or directory: {target}")
    if target.is_file() and target.suffix.lower() != ".py":
        raise PythonAnalysisError(f"Not a Python source file: {target}")

    root = target if target.is_dir() else target.parent
    candidates, truncated, traversal_errors = _python_files(target)
    functions: list[_Function] = []
    issues: list[AnalysisIssue] = []
    files_scanned = 0

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
            source = read_limited_text(candidate, MAX_FILE_BYTES)
            if source is None:
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

        module = _module_name(relative_path)
        aliases = _import_aliases(
            tree, module, is_package_init=Path(relative_path).name == "__init__.py"
        )
        try:
            functions.extend(
                _function_records(tree, relative_path, module, aliases)
            )
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

    by_module_and_name: dict[tuple[str, str], list[_Function]] = {}
    for function in functions:
        by_module_and_name.setdefault((function.module, function.name), []).append(
            function
        )
        if function.qualified_name != function.name:
            by_module_and_name.setdefault(
                (function.module, function.qualified_name), []
            ).append(function)

    tools = [
        _analyze_tool(function, by_module_and_name)
        for function in functions
        if function.tool_name is not None
    ]
    return AnalysisReport(
        schema_version=1,
        files_scanned=files_scanned,
        tools=tuple(sorted(tools, key=lambda item: (item.path, item.line, item.name))),
        issues=tuple(issues),
        limitations=(
            "Tool detection is heuristic: any function decorated with an attribute named 'tool' is included.",
            "Only direct calls to unambiguous functions in the same source module or explicitly imported project modules are followed.",
            "Observed API calls indicate potential capability in source, not runtime execution or malicious intent.",
            "Dynamic dispatch, reflection, generated code, runtime configuration, and dependency internals are not resolved.",
        ),
    )
