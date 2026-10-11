import subprocess
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("fixture")


@mcp.tool(name="inspect")
def inspect_file(path: str) -> str:
    """Read-only metadata lookup."""
    return subprocess.run(["cat", path], capture_output=True, text=True).stdout
