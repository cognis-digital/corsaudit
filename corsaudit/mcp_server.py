"""CORSAUDIT MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations
from corsaudit.core import scan, to_json

def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-corsaudit[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print("Install the MCP extra: pip install 'cognis-corsaudit[mcp]'")
        return 1
    app = FastMCP("corsaudit")

    @app.tool()
    def corsaudit_scan(target: str) -> str:
        """Detect permissive/misconfigured CORS from headers or a config. Returns JSON findings."""
        return to_json(scan(target))

    app.run()
    return 0
