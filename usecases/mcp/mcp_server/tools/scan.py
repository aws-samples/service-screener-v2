"""
Scan tools — trigger and manage Service Screener scans.

run_scan starts the scan asynchronously (non-blocking) and returns immediately.
Use get_scan_status to poll for completion.
"""

import json
from mcp.types import Tool, TextContent, ToolAnnotations

from scanner import (
    run_scan_async, get_scan_progress,
    get_available_services, get_available_frameworks, ScanError
)
from cache import cache_manager

# --- Tool definitions ---

TOOLS = [
    Tool(
        name="run_scan",
        description=(
            "Start a Service Screener scan on the current AWS account. "
            "The scan runs in the background (non-blocking) and typically takes 60-120 seconds. "
            "Use get_scan_status to check progress. "
            "Once complete, results are cached for query tools."
        ),
        annotations=ToolAnnotations(
            readOnlyHint=False,
            destructiveHint=False,
            idempotentHint=False,
            openWorldHint=True,
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "regions": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "AWS regions to scan (e.g., ['ap-southeast-1']). Defaults to current region.",
                },
                "services": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Services to scan (e.g., ['ec2', 'iam', 's3']). Defaults to all supported.",
                },
                "frameworks": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Compliance frameworks to evaluate (e.g., ['CIS', 'NIST']). Defaults to all.",
                },
            },
        },
    ),
    Tool(
        name="list_supported_services",
        description=(
            "List all AWS services that Service Screener can scan. "
            "No AWS credentials needed."
        ),
        annotations=ToolAnnotations(readOnlyHint=True),
        inputSchema={"type": "object", "properties": {}},
    ),
    Tool(
        name="list_supported_frameworks",
        description=(
            "List all compliance frameworks supported by Service Screener "
            "(e.g., CIS, NIST, RMiT, FTR). No AWS credentials needed."
        ),
        annotations=ToolAnnotations(readOnlyHint=True),
        inputSchema={"type": "object", "properties": {}},
    ),
    Tool(
        name="get_scan_status",
        description=(
            "Check scan status: whether a scan is running, completed, or if cached results exist. "
            "Call this after run_scan to check progress."
        ),
        annotations=ToolAnnotations(readOnlyHint=True),
        inputSchema={
            "type": "object",
            "properties": {
                "account_id": {
                    "type": "string",
                    "description": "AWS account ID to check (optional)",
                },
            },
        },
    ),
]


# --- Tool handler ---

async def handle_tool(name: str, arguments: dict) -> list[TextContent]:
    if name == "run_scan":
        return await _handle_run_scan(arguments)
    elif name == "list_supported_services":
        return await _handle_list_services(arguments)
    elif name == "list_supported_frameworks":
        return await _handle_list_frameworks(arguments)
    elif name == "get_scan_status":
        return await _handle_scan_status(arguments)
    return [TextContent(type="text", text=f"Unknown scan tool: {name}")]


async def _handle_run_scan(args: dict) -> list[TextContent]:
    result = run_scan_async(
        regions=args.get("regions"),
        services=args.get("services"),
        frameworks=args.get("frameworks"),
    )
    return [TextContent(type="text", text=json.dumps(result, indent=2))]


async def _handle_list_services(args: dict) -> list[TextContent]:
    services = get_available_services()
    return [TextContent(type="text", text=json.dumps({
        "total": len(services),
        "services": services,
    }, indent=2))]


async def _handle_list_frameworks(args: dict) -> list[TextContent]:
    frameworks = get_available_frameworks()
    return [TextContent(type="text", text=json.dumps({
        "total": len(frameworks),
        "frameworks": frameworks,
    }, indent=2))]


async def _handle_scan_status(args: dict) -> list[TextContent]:
    # First check if a scan is actively running
    progress = get_scan_progress()

    if progress["status"] == "running":
        return [TextContent(type="text", text=json.dumps(progress, indent=2))]

    if progress["status"] == "completed":
        return [TextContent(type="text", text=json.dumps(progress, indent=2))]

    if progress["status"] == "failed":
        return [TextContent(type="text", text=json.dumps(progress, indent=2))]

    # No active scan — check cache
    account_id = args.get("account_id")
    has_cache = cache_manager.has_cache(account_id)
    age = cache_manager.get_cache_age_seconds(account_id)

    result = {
        "status": "idle",
        "has_cached_results": has_cache,
        "cache_age_seconds": age,
        "cache_age_human": _humanize_seconds(age) if age else None,
        "recommendation": "Results are fresh." if age and age < 86400
            else "Consider re-scanning — results are over 24 hours old." if age
            else "No scan results found. Run a scan to get started.",
    }
    return [TextContent(type="text", text=json.dumps(result, indent=2))]


def _humanize_seconds(seconds: float) -> str:
    if seconds < 60:
        return f"{int(seconds)}s ago"
    elif seconds < 3600:
        return f"{int(seconds / 60)}m ago"
    elif seconds < 86400:
        return f"{int(seconds / 3600)}h ago"
    else:
        return f"{int(seconds / 86400)}d ago"
