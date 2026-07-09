"""
Service Screener v2 — MCP Server
Well-Architected assessment of running AWS accounts via Model Context Protocol.

Usage:
    python mcp_server/server.py
"""

import sys
import os
import asyncio

# Resolve paths — the server must be run from service-screener-v2 root
# or we compute the correct paths here
SERVER_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SERVER_DIR)

# Add mcp_server/ to path so tools/, cache, scanner can be found
sys.path.insert(0, SERVER_DIR)
# Add service-screener-v2 root to path for service-screener modules
sys.path.insert(0, PROJECT_ROOT)

# Change working directory to project root (needed for scanner.py subprocess calls)
os.chdir(PROJECT_ROOT)

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

from tools.rules import TOOLS as RULES_TOOLS, handle_tool as handle_rules
from tools.findings import TOOLS as FINDINGS_TOOLS, handle_tool as handle_findings
from tools.scan import TOOLS as SCAN_TOOLS, handle_tool as handle_scan
from tools.wa_pillars import TOOLS as WA_TOOLS, handle_tool as handle_wa

# All tools combined
ALL_TOOLS = RULES_TOOLS + FINDINGS_TOOLS + SCAN_TOOLS + WA_TOOLS

# Route tool calls to the right handler
TOOL_HANDLERS = {}
for tool in RULES_TOOLS:
    TOOL_HANDLERS[tool.name] = handle_rules
for tool in FINDINGS_TOOLS:
    TOOL_HANDLERS[tool.name] = handle_findings
for tool in SCAN_TOOLS:
    TOOL_HANDLERS[tool.name] = handle_scan
for tool in WA_TOOLS:
    TOOL_HANDLERS[tool.name] = handle_wa

# Create the MCP server
app = Server("service-screener")


@app.list_tools()
async def list_tools():
    return ALL_TOOLS


@app.call_tool()
async def call_tool(name: str, arguments: dict):
    handler = TOOL_HANDLERS.get(name)
    if not handler:
        return [TextContent(type="text", text=f"Unknown tool: {name}")]
    return await handler(name, arguments)


async def main():
    """Run the MCP server via stdio."""
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
