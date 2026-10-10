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
