from pathlib import Path


def read_report(path: str) -> str:
    """Read a report from a local path."""
    return Path(path).read_text()


mcp.add_tool(read_report, name="report")
