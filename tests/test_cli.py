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
    assert output["schema_version"] == 1
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
