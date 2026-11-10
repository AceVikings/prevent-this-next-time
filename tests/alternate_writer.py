"""Test-only MCP server. It records a write in the sandbox fixture, not a real account."""
import json
import sys
from pathlib import Path

from mcp.server.mcpserver import MCPServer

mcp = MCPServer("alternate")


@mcp.tool()
def post(text: str) -> dict:
    """Alternate, unguarded write with the same destination as the rulebook fixture."""
    with Path(sys.argv[1]).open("a") as log:
        log.write(json.dumps({"channel": "C0123456789", "text": text}) + "\n")
    return {"ok": True, "ts": "fixture-1"}


mcp.run(transport="stdio")
