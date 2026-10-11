from pathlib import Path

from mcpshield.python_analysis import analyze_python_path


def test_finds_fastmcp_style_tool_and_name_override(tmp_path: Path):
    source = tmp_path / "server.py"
    source.write_text(
        '''
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("sample")

@mcp.tool(name="read_report")
def report():
    """Read a report."""
    return "ok"
''',
        encoding="utf-8",
    )

    report = analyze_python_path(source)

    assert len(report.tools) == 1
    tool = report.tools[0]
    assert tool.name == "read_report"
    assert tool.function == "report"
    assert tool.description == "Read a report."
    assert tool.path == "server.py"
    assert tool.line == 7


def test_traces_local_helper_to_process_filesystem_and_network(tmp_path: Path):
    source = tmp_path / "server.py"
    source.write_text(
        '''
import subprocess as child_process
from pathlib import Path as LocalPath
import requests as http

@mcp.tool()
def inspect():
    execute()

def execute():
    child_process.run(["echo", "safe"])
    LocalPath("report.txt").write_text("content")
    http.get("https://example.invalid")
''',
        encoding="utf-8",
    )

    tool = analyze_python_path(source).tools[0]

    assert tool.reachable_functions == ("execute",)
    assert {item.capability for item in tool.capabilities} == {
        "process_execution",
        "filesystem_access",
        "network_communication",
    }
    assert all(item.call_chain == ("inspect", "execute") for item in tool.capabilities)
    assert all(item.status == "observed_in_source" for item in tool.capabilities)
    assert all(item.interpretation == "potential_capability" for item in tool.capabilities)
    assert {item.line for item in tool.capabilities} == {11, 12, 13}


def test_does_not_attribute_capabilities_from_unreachable_functions(tmp_path: Path):
    source = tmp_path / "server.py"
    source.write_text(
        '''
import subprocess

@mcp.tool()
def harmless():
    return "ok"

def unused():
    subprocess.run(["echo", "not reachable"])
''',
        encoding="utf-8",
    )

    tool = analyze_python_path(source).tools[0]

    assert tool.capabilities == ()
    assert tool.reachable_functions == ()


def test_resolves_unique_direct_helper_across_files(tmp_path: Path):
    (tmp_path / "server.py").write_text(
        '''
from helpers import read_data

@mcp.tool()
def load():
    return read_data()
''',
        encoding="utf-8",
    )
    (tmp_path / "helpers.py").write_text(
        '''
from pathlib import Path

def read_data():
    return Path("data.txt").read_text()
''',
        encoding="utf-8",
    )

    tool = analyze_python_path(tmp_path).tools[0]

    assert tool.reachable_functions == ("read_data",)
    assert len(tool.capabilities) == 1
    assert tool.capabilities[0].capability == "filesystem_access"
    assert tool.capabilities[0].path == "helpers.py"
    assert tool.capabilities[0].call_chain == ("load", "read_data")


def test_resolves_relative_imports_inside_a_package(tmp_path: Path):
    package = tmp_path / "sample"
    package.mkdir()
    (package / "server.py").write_text(
        '''
from .helpers import read_data

@mcp.tool()
def load():
    return read_data()
''',
        encoding="utf-8",
    )
    (package / "helpers.py").write_text(
        '''
from pathlib import Path

def read_data():
    return Path("data.txt").read_text()
''',
        encoding="utf-8",
    )

    tool = analyze_python_path(tmp_path).tools[0]

    assert tool.reachable_functions == ("read_data",)
    assert tool.capabilities[0].path == "sample/helpers.py"


def test_resolves_relative_imports_from_package_initializer(tmp_path: Path):
    package = tmp_path / "sample"
    package.mkdir()
    (package / "__init__.py").write_text(
        '''
from .helpers import read_data

@mcp.tool()
def load():
    return read_data()
''',
        encoding="utf-8",
    )
    (package / "helpers.py").write_text(
        '''
from pathlib import Path

def read_data():
    return Path("data.txt").read_text()
''',
        encoding="utf-8",
    )

    tool = analyze_python_path(tmp_path).tools[0]

    assert tool.reachable_functions == ("read_data",)
    assert tool.capabilities[0].path == "sample/helpers.py"


def test_does_not_resolve_relative_import_without_known_package_context(
    tmp_path: Path,
):
    (tmp_path / "server.py").write_text(
        '''
from .helpers import helper

@mcp.tool()
def inspect():
    return helper()
''',
        encoding="utf-8",
    )
    (tmp_path / "helpers.py").write_text(
        "def helper():\n    return None\n", encoding="utf-8"
    )

    tool = analyze_python_path(tmp_path).tools[0]

    assert tool.reachable_functions == ()
    assert tool.unresolved_calls[0].expression == "helper"


def test_keeps_same_named_helpers_from_distinct_modules_separate(tmp_path: Path):
    (tmp_path / "server.py").write_text(
        '''
from first import helper as first_helper
from second import helper as second_helper

@mcp.tool()
def inspect():
    first_helper()
    second_helper()
''',
        encoding="utf-8",
    )
    (tmp_path / "first.py").write_text(
        '''
from pathlib import Path

def helper():
    Path("first.txt").read_text()
''',
        encoding="utf-8",
    )
    (tmp_path / "second.py").write_text(
        '''
import subprocess

def helper():
    subprocess.run(["echo", "safe"])
''',
        encoding="utf-8",
    )

    tool = analyze_python_path(tmp_path).tools[0]

    assert len(tool.reachable_functions) == 2
    assert {item.path for item in tool.capabilities} == {
        "first.py",
        "second.py",
    }


def test_does_not_resolve_a_call_shadowed_by_a_parameter(tmp_path: Path):
    source = tmp_path / "server.py"
    source.write_text(
        '''
from pathlib import Path

def helper():
    Path("data.txt").read_text()

@mcp.tool()
def inspect(helper):
    return helper()
''',
        encoding="utf-8",
    )

    tool = analyze_python_path(source).tools[0]

    assert tool.reachable_functions == ()
    assert tool.capabilities == ()
    assert tool.unresolved_calls[0].expression == "helper"


def test_resolves_nested_local_helper(tmp_path: Path):
    source = tmp_path / "server.py"
    source.write_text(
        '''
@mcp.tool()
def inspect():
    def helper():
        return read_secret()
    return helper()

def read_secret():
    return open("data.txt").read()
''',
        encoding="utf-8",
    )

    tool = analyze_python_path(source).tools[0]

    assert tool.reachable_functions == ("inspect.helper", "read_secret")
    assert tool.capabilities[0].function == "read_secret"


def test_does_not_resolve_ambiguous_local_function_names(tmp_path: Path):
    (tmp_path / "server.py").write_text(
        '''
@mcp.tool()
def load():
    helper()
''',
        encoding="utf-8",
    )
    (tmp_path / "one.py").write_text("def helper():\n    return None\n", encoding="utf-8")
    (tmp_path / "two.py").write_text("def helper():\n    return None\n", encoding="utf-8")

    tool = analyze_python_path(tmp_path).tools[0]

    assert tool.reachable_functions == ()
    assert tool.unresolved_calls[0].expression == "helper"


def test_does_not_guess_unimported_cross_module_functions(tmp_path: Path):
    (tmp_path / "server.py").write_text(
        '''
@mcp.tool()
def load():
    helper()
''',
        encoding="utf-8",
    )
    (tmp_path / "helpers.py").write_text(
        "def helper():\n    return None\n", encoding="utf-8"
    )

    tool = analyze_python_path(tmp_path).tools[0]

    assert tool.reachable_functions == ()
    assert tool.unresolved_calls[0].expression == "helper"


def test_does_not_treat_an_unimported_attribute_as_a_module_call(tmp_path: Path):
    (tmp_path / "server.py").write_text(
        '''
@mcp.tool()
def inspect():
    delegate.helper()
''',
        encoding="utf-8",
    )
    (tmp_path / "delegate.py").write_text(
        "def helper():\n    return None\n", encoding="utf-8"
    )

    tool = analyze_python_path(tmp_path).tools[0]

    assert tool.reachable_functions == ()
    assert tool.unresolved_calls[0].expression == "delegate.helper"


def test_syntax_errors_are_reported_and_other_files_still_analyzed(tmp_path: Path):
    (tmp_path / "broken.py").write_text("def broken(:\n", encoding="utf-8")
    (tmp_path / "server.py").write_text(
        "@mcp.tool()\ndef okay():\n    return None\n", encoding="utf-8"
    )

    report = analyze_python_path(tmp_path)

    assert report.files_scanned == 2
    assert [tool.name for tool in report.tools] == ["okay"]
    assert report.issues[0].code == "syntax_error"
    assert report.issues[0].severity == "error"
    assert report.issues[0].line == 1


def test_ignores_virtualenvs_hidden_directories_and_symlinks(tmp_path: Path):
    (tmp_path / ".venv").mkdir()
    (tmp_path / ".venv" / "ignored.py").write_text(
        "@mcp.tool()\ndef ignored():\n    return None\n", encoding="utf-8"
    )
    (tmp_path / "server.py").write_text(
        "@mcp.tool()\ndef visible():\n    return None\n", encoding="utf-8"
    )
    target = tmp_path / "server.py"
    (tmp_path / "linked.py").symlink_to(target)

    report = analyze_python_path(tmp_path)

    assert report.files_scanned == 1
    assert [tool.name for tool in report.tools] == ["visible"]


def test_reports_oversized_source_without_parsing_it(tmp_path: Path, monkeypatch):
    import mcpshield.python_analysis as python_analysis

    source = tmp_path / "large.py"
    source.write_text("@mcp.tool()\ndef ignored(): pass\n", encoding="utf-8")
    monkeypatch.setattr(python_analysis, "MAX_FILE_BYTES", 1)

    report = analyze_python_path(source)

    assert report.files_scanned == 0
    assert report.tools == ()
    assert report.issues[0].code == "file_too_large"
    assert report.issues[0].severity == "warning"


def test_parses_source_without_executing_top_level_code(tmp_path: Path):
    marker = tmp_path / "executed.txt"
    source = tmp_path / "server.py"
    source.write_text(
        f'''
from pathlib import Path
Path({str(marker)!r}).write_text("must not happen")

@mcp.tool()
def read():
    return "safe"
''',
        encoding="utf-8",
    )

    report = analyze_python_path(source)

    assert len(report.tools) == 1
    assert not marker.exists()


def test_reports_dynamic_and_external_calls_as_unresolved(tmp_path: Path):
    source = tmp_path / "server.py"
    source.write_text(
        '''
@mcp.tool()
def run():
    getattr(object(), "execute")()
''',
        encoding="utf-8",
    )

    tool = analyze_python_path(source).tools[0]

    assert tool.unresolved_calls
    assert any(
        item.expression == "getattr" for item in tool.unresolved_calls
    )
    assert any(
        item.expression == "<dynamic call>" for item in tool.unresolved_calls
    )


def test_recognizes_network_call_from_dotted_import(tmp_path: Path):
    source = tmp_path / "server.py"
    source.write_text(
        '''
import urllib.request

@mcp.tool()
def fetch():
    urllib.request.urlopen("https://example.invalid")
''',
        encoding="utf-8",
    )

    tool = analyze_python_path(source).tools[0]

    assert len(tool.capabilities) == 1
    assert tool.capabilities[0].api == "urllib.request.urlopen"
    assert tool.capabilities[0].capability == "network_communication"


def test_directory_with_no_python_tools_is_a_valid_empty_inventory(tmp_path: Path):
    (tmp_path / "notes.txt").write_text("not Python", encoding="utf-8")

    report = analyze_python_path(tmp_path)

    assert report.files_scanned == 0
    assert report.tools == ()


def test_reports_recursion_errors_during_ast_walk_and_continues(
    tmp_path: Path, monkeypatch
):
    import mcpshield.python_analysis as python_analysis

    (tmp_path / "deep.py").write_text("def deep(): pass\n", encoding="utf-8")
    (tmp_path / "server.py").write_text(
        "@mcp.tool()\ndef visible(): pass\n", encoding="utf-8"
    )
    original = python_analysis._function_records

    def fail_for_deep_file(tree, path, module, aliases):
        if path == "deep.py":
            raise RecursionError("nesting limit")
        return original(tree, path, module, aliases)

    monkeypatch.setattr(python_analysis, "_function_records", fail_for_deep_file)

    report = analyze_python_path(tmp_path)

    assert [tool.name for tool in report.tools] == ["visible"]
    assert [(issue.path, issue.code) for issue in report.issues] == [
        ("deep.py", "parse_error")
    ]


def test_local_imports_inside_tool_functions_resolve_capabilities(tmp_path: Path):
    source = tmp_path / "server.py"
    source.write_text(
        '''
@mcp.tool()
def run(command):
    from subprocess import run as launch
    return launch(command)
''',
        encoding="utf-8",
    )

    tool = analyze_python_path(source).tools[0]

    assert [item.api for item in tool.capabilities] == ["subprocess.run"]
    assert tool.data_flows[0].source_parameters == ("command",)


def test_shadowed_api_names_are_not_treated_as_imported_capabilities(tmp_path: Path):
    source = tmp_path / "server.py"
    source.write_text(
        '''
import subprocess

@mcp.tool()
def run(subprocess):
    subprocess.run(["not a real subprocess API"])
''',
        encoding="utf-8",
    )

    tool = analyze_python_path(source).tools[0]

    assert tool.capabilities == ()
    assert tool.unresolved_calls[0].expression == "subprocess.run"


def test_project_module_shadowing_does_not_claim_external_api(tmp_path: Path):
    (tmp_path / "server.py").write_text(
        '''
import requests

@mcp.tool()
def fetch():
    requests.get("https://example.invalid")
''',
        encoding="utf-8",
    )
    (tmp_path / "requests.py").write_text(
        "def get(url):\n    return url\n", encoding="utf-8"
    )

    tool = analyze_python_path(tmp_path).tools[0]

    assert tool.capabilities == ()
    assert tool.reachable_functions == ("get",)


def test_follows_direct_self_method_calls_and_emits_stable_function_locations(
    tmp_path: Path,
):
    source = tmp_path / "server.py"
    source.write_text(
        '''
from pathlib import Path

class Server:
    @mcp.tool()
    def read(self, path):
        return self.load(path)

    def load(self, path):
        return Path(path).read_text()
''',
        encoding="utf-8",
    )

    tool = analyze_python_path(source).tools[0]

    assert tool.reachable_functions == ("Server.load",)
    assert tool.reachable_function_locations[0].path == "server.py"
    assert tool.reachable_function_locations[0].id.endswith(":Server.load")
    assert tool.capabilities[0].call_chain == ("Server.read", "Server.load")
    assert len(tool.capabilities[0].call_chain_ids) == 2


def test_recognizes_imperative_tool_registration(tmp_path: Path):
    source = tmp_path / "server.py"
    source.write_text(
        '''
def inspect_data(path):
    return open(path).read()

mcp.add_tool(inspect_data, name="inspect")
''',
        encoding="utf-8",
    )

    report = analyze_python_path(source)

    assert len(report.tools) == 1
    assert report.tools[0].name == "inspect"
    assert report.tools[0].capabilities[0].api == "builtins.open"


def test_reports_tool_parameter_flow_through_local_helper_to_process_sink(
    tmp_path: Path,
):
    source = tmp_path / "server.py"
    source.write_text(
        '''
import subprocess

@mcp.tool()
def run(command):
    return helper(command)

def helper(value):
    return subprocess.run(value)
''',
        encoding="utf-8",
    )

    flow = analyze_python_path(source).tools[0].data_flows[0]

    assert flow.rule_id == "MCP201"
    assert flow.source_parameters == ("command",)
    assert flow.sink_api == "subprocess.run"
    assert flow.call_chain == ("run", "helper")
    assert flow.confidence == "low"
    assert flow.interpretation == "potential_untrusted_input_flow"


def test_maps_keyword_only_helper_arguments_by_keyword(tmp_path: Path):
    source = tmp_path / "server.py"
    source.write_text(
        '''
import subprocess

@mcp.tool()
def run(command):
    return helper(command=command)

def helper(*, command):
    return subprocess.run(command)
''',
        encoding="utf-8",
    )

    report = analyze_python_path(source)

    assert report.tools[0].data_flows[0].source_parameters == ("command",)


def test_does_not_map_positional_argument_to_keyword_only_helper_parameter(
    tmp_path: Path,
):
    source = tmp_path / "server.py"
    source.write_text(
        '''
import subprocess

@mcp.tool()
def run(command):
    return helper(command)

def helper(*, option):
    return subprocess.run(option)
''',
        encoding="utf-8",
    )

    report = analyze_python_path(source)

    assert report.tools[0].data_flows == ()


def test_maps_overflowing_positional_arguments_to_varargs(tmp_path: Path):
    source = tmp_path / "server.py"
    source.write_text(
        '''
import subprocess

@mcp.tool()
def run(command):
    return helper("fixed", command)

def helper(first, *values):
    return subprocess.run(values)
''',
        encoding="utf-8",
    )

    report = analyze_python_path(source)

    assert report.tools[0].data_flows[0].source_parameters == ("command",)


def test_reports_shlex_quote_as_signal_without_claiming_flow_is_safe(
    tmp_path: Path,
):
    source = tmp_path / "server.py"
    source.write_text(
        '''
import shlex
import subprocess

@mcp.tool()
def run(command):
    safe_command = shlex.quote(command)
    return subprocess.run(safe_command, shell=True)
''',
        encoding="utf-8",
    )

    flow = analyze_python_path(source).tools[0].data_flows[0]

    assert flow.sanitizers_observed == ("shlex.quote",)
    assert flow.interpretation == "potential_untrusted_input_flow"
    assert flow.confidence == "medium"


def test_flags_read_only_description_that_reaches_write_operation(tmp_path: Path):
    source = tmp_path / "server.py"
    source.write_text(
        '''
from pathlib import Path

@mcp.tool()
def inspect(path, value):
    """This tool is read-only."""
    return Path(path).write_text(value)
''',
        encoding="utf-8",
    )

    report = analyze_python_path(source)

    assert report.analysis_complete
    assert report.status == "complete"
    assert report.issues[0].code == "description_effect_mismatch"
    assert "not proof" in report.issues[0].message


def test_redacts_likely_secrets_from_tool_descriptions(tmp_path: Path):
    source = tmp_path / "server.py"
    source.write_text(
        '''
@mcp.tool()
def inspect():
    """Use password="do-not-leak-this-value" to inspect."""
    return None
''',
        encoding="utf-8",
    )

    description = analyze_python_path(source).tools[0].description

    assert description is not None
    assert "do-not-leak-this-value" not in description
    assert "[REDACTED]" in description


def test_reports_invalid_encoding_as_incomplete(tmp_path: Path):
    source = tmp_path / "invalid.py"
    source.write_bytes(b"def invalid():\n    return '\xff'\n")

    report = analyze_python_path(source)

    assert report.status == "partial"
    assert not report.analysis_complete
    assert report.issues[0].code == "encoding_error"


def test_total_byte_budget_makes_result_explicitly_partial(
    tmp_path: Path, monkeypatch
):
    import mcpshield.python_analysis as python_analysis

    source = tmp_path / "server.py"
    source.write_text("@mcp.tool()\ndef okay(): pass\n", encoding="utf-8")
    monkeypatch.setattr(python_analysis, "MAX_TOTAL_BYTES", 1)

    report = analyze_python_path(source)

    assert report.status == "partial"
    assert report.issues[0].code == "total_byte_limit_reached"
    assert report.metrics.bytes_scanned == 0


def test_ast_node_budget_makes_result_explicitly_partial(
    tmp_path: Path, monkeypatch
):
    import mcpshield.python_analysis as python_analysis

    source = tmp_path / "server.py"
    source.write_text("@mcp.tool()\ndef okay(): return 1\n", encoding="utf-8")
    monkeypatch.setattr(python_analysis, "MAX_AST_NODES", 2)

    report = analyze_python_path(source)

    assert report.status == "partial"
    assert report.issues[0].code == "ast_node_limit_reached"
    assert report.metrics.ast_nodes == 2


def test_function_budget_makes_result_explicitly_partial(
    tmp_path: Path, monkeypatch
):
    import mcpshield.python_analysis as python_analysis

    source = tmp_path / "server.py"
    source.write_text("@mcp.tool()\ndef okay(): pass\n", encoding="utf-8")
    monkeypatch.setattr(python_analysis, "MAX_FUNCTIONS", 0)

    report = analyze_python_path(source)

    assert report.status == "partial"
    assert report.issues[0].code == "function_limit_reached"


def test_call_budget_makes_result_explicitly_partial(tmp_path: Path, monkeypatch):
    import mcpshield.python_analysis as python_analysis

    source = tmp_path / "server.py"
    source.write_text(
        "@mcp.tool()\ndef okay():\n    one()\n    two()\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(python_analysis, "MAX_CALLS", 1)

    report = analyze_python_path(source)

    assert report.status == "partial"
    assert report.issues[0].code == "call_limit_reached"


def test_call_graph_budget_makes_result_explicitly_partial(
    tmp_path: Path, monkeypatch
):
    import mcpshield.python_analysis as python_analysis

    source = tmp_path / "server.py"
    source.write_text(
        "@mcp.tool()\ndef okay():\n    helper()\n\ndef helper():\n    return None\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(python_analysis, "MAX_GRAPH_CALLS", 0)

    report = analyze_python_path(source)

    assert report.status == "partial"
    assert report.issues[0].code == "call_graph_limit_reached"


def test_real_world_python_fixtures_are_analyzed_without_importing(tmp_path: Path):
    from shutil import copytree

    from mcpshield.python_analysis import __file__ as analysis_module_path

    fixtures = Path(analysis_module_path).parents[2] / "tests" / "fixtures" / "python"
    project = tmp_path / "project"
    copytree(fixtures, project)

    report = analyze_python_path(project)

    assert {tool.name for tool in report.tools} == {"inspect", "report"}
    assert all(tool.function_id for tool in report.tools)
    assert {capability.capability for tool in report.tools for capability in tool.capabilities} == {
        "process_execution",
        "filesystem_access",
    }
