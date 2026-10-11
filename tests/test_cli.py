import json
from pathlib import Path

from mcpshield.cli import main


def test_python_analysis_cli_emits_json_inventory(tmp_path: Path, monkeypatch, capsys):
    source = tmp_path / "server.py"
    source.write_text(
        '''
import subprocess

@mcp.tool()
def run_task():
    subprocess.run(["echo", "hello"])
''',
        encoding="utf-8",
    )
    monkeypatch.setattr(
        "sys.argv", ["mcpshield", str(source), "--analyze-python", "--json"]
    )

    result = main()
    output = json.loads(capsys.readouterr().out)

    assert result == 0
    assert output["schema_version"] == 2
    assert output["status"] == "complete"
    assert output["files_scanned"] == 1
    assert output["tools"][0]["name"] == "run_task"
    assert output["tools"][0]["capabilities"][0]["api"] == "subprocess.run"


def test_python_analysis_cli_reports_parse_errors_with_nonzero_exit(
    tmp_path: Path, monkeypatch, capsys
):
    source = tmp_path / "server.py"
    source.write_text("def broken(:\n", encoding="utf-8")
    monkeypatch.setattr(
        "sys.argv", ["mcpshield", "--analyze-python", str(source), "--json"]
    )

    result = main()
    output = json.loads(capsys.readouterr().out)

    assert result == 2
    assert output["issues"][0]["code"] == "syntax_error"


def test_existing_scanner_cli_mode_is_unchanged(tmp_path: Path, monkeypatch, capsys):
    source = tmp_path / "config.json"
    source.write_text('{"command": "chmod 777 /tmp/example"}', encoding="utf-8")
    monkeypatch.setattr("sys.argv", ["mcpshield", str(source)])

    result = main()

    assert result == 1
    assert "MCP003" in capsys.readouterr().out


def test_python_analysis_cli_emits_sarif(tmp_path: Path, monkeypatch, capsys):
    source = tmp_path / "server.py"
    source.write_text(
        "import subprocess\n@mcp.tool()\ndef run(command):\n    subprocess.run(command)\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(
        "sys.argv", ["mcpshield", str(source), "--analyze-python", "--sarif"]
    )

    result = main()
    output = json.loads(capsys.readouterr().out)

    assert result == 0
    assert output["version"] == "2.1.0"
    assert {item["ruleId"] for item in output["runs"][0]["results"]} == {
        "MCP101",
        "MCP201",
    }


def test_text_scanner_cli_emits_sarif(tmp_path: Path, monkeypatch, capsys):
    source = tmp_path / "config.json"
    source.write_text('{"command": "chmod 777 /tmp/example"}', encoding="utf-8")
    monkeypatch.setattr("sys.argv", ["mcpshield", str(source), "--sarif"])

    result = main()
    output = json.loads(capsys.readouterr().out)

    assert result == 1
    assert output["runs"][0]["results"][0]["ruleId"] == "MCP003"
