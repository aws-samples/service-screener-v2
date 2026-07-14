"""
Well-Architected pillar tools — the key differentiator from Prowler.

Each tool provides pillar-specific insights. If no cache exists,
triggers a scan automatically (cache-first with auto-scan fallback).
"""

import json
from mcp.types import Tool, TextContent, ToolAnnotations

from cache import cache_manager
from scanner import run_scan, ScanError
from tools.findings import _extract_findings, CATEGORY_MAP


# Pillar descriptions for context
PILLAR_DESCRIPTIONS = {
    "Security": "Identity, access, data protection, network security, incident response",
    "Reliability": "High availability, fault tolerance, backup, disaster recovery",
    "Operational Excellence": "Monitoring, alerting, automation, runbooks, change management",
    "Performance Efficiency": "Right-sizing, caching, modern architectures, scaling",
    "Cost Optimization": "Waste elimination, reserved capacity, right-sizing, governance",
}

# --- Tool definitions ---

TOOLS = [
    Tool(
        name="get_wa_score",
        description=(
            "Get a Well-Architected score across all 5 pillars. "
            "Returns finding counts per pillar with severity breakdown. "
            "Triggers a scan if no cached results exist."
        ),
        annotations=ToolAnnotations(readOnlyHint=True),
        inputSchema={
            "type": "object",
            "properties": {
                "auto_scan": {
                    "type": "boolean",
                    "description": "If true (default), auto-triggers a scan when no cache exists.",
                    "default": True,
                },
                "regions": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Regions to scan if auto-scan triggers (e.g., ['ap-southeast-1'])",
                },
            },
        },
    ),
    Tool(
        name="get_security_risks",
        description="Get security findings: IAM issues, encryption gaps, network exposure, data protection.",
        annotations=ToolAnnotations(readOnlyHint=True),
        inputSchema={
            "type": "object",
            "properties": {
                "severity": {"type": "string", "description": "Filter: High, Medium, Low (default: all)"},
                "limit": {"type": "integer", "default": 30},
            },
        },
    ),
    Tool(
        name="get_reliability_risks",
        description="Get reliability findings: single points of failure, missing backups, no HA, disaster recovery gaps.",
        annotations=ToolAnnotations(readOnlyHint=True),
        inputSchema={
            "type": "object",
            "properties": {
                "severity": {"type": "string"},
                "limit": {"type": "integer", "default": 30},
            },
        },
    ),
    Tool(
        name="get_operational_gaps",
        description="Get operational excellence findings: missing alarms, no notifications, unmonitored resources, automation gaps.",
        annotations=ToolAnnotations(readOnlyHint=True),
        inputSchema={
            "type": "object",
            "properties": {
                "severity": {"type": "string"},
                "limit": {"type": "integer", "default": 30},
            },
        },
    ),
    Tool(
        name="get_performance_opportunities",
        description="Get performance findings: old-gen instances, missing optimizations, architecture improvements (e.g., ARM migration, EBS-optimized).",
        annotations=ToolAnnotations(readOnlyHint=True),
        inputSchema={
            "type": "object",
            "properties": {
                "severity": {"type": "string"},
                "limit": {"type": "integer", "default": 30},
            },
        },
    ),
    Tool(
        name="get_cost_waste",
        description="Get cost optimization findings: unused resources, oversized instances, missing reservations, idle capacity.",
        annotations=ToolAnnotations(readOnlyHint=True),
        inputSchema={
            "type": "object",
            "properties": {
                "severity": {"type": "string"},
                "limit": {"type": "integer", "default": 30},
            },
        },
    ),
]


# --- Tool handler ---

async def handle_tool(name: str, arguments: dict) -> list[TextContent]:
    if name == "get_wa_score":
        return await _handle_wa_score(arguments)
    elif name == "get_security_risks":
        return await _handle_pillar("Security", arguments)
    elif name == "get_reliability_risks":
        return await _handle_pillar("Reliability", arguments)
    elif name == "get_operational_gaps":
        return await _handle_pillar("Operational Excellence", arguments)
    elif name == "get_performance_opportunities":
        return await _handle_pillar("Performance Efficiency", arguments)
    elif name == "get_cost_waste":
        return await _handle_pillar("Cost Optimization", arguments)
    return [TextContent(type="text", text=f"Unknown WA tool: {name}")]


async def _ensure_cache(args: dict) -> dict | None:
    """Get cache, optionally triggering a scan if missing."""
    cached = cache_manager.get_scan_results()
    if cached:
        return cached

    auto_scan = args.get("auto_scan", True)
    if not auto_scan:
        return None

    try:
        run_scan(regions=args.get("regions"))
    except ScanError as e:
        return {"error": str(e)}

    return cache_manager.get_scan_results()


async def _handle_wa_score(args: dict) -> list[TextContent]:
    cached = await _ensure_cache(args)

    if not cached:
        return [TextContent(type="text", text=json.dumps({
            "status": "no_results",
            "message": "No scan results and auto_scan is disabled. Call run_scan first.",
        }))]

    if "error" in cached:
        return [TextContent(type="text", text=json.dumps({
            "status": "scan_error",
            "message": cached["error"],
        }))]

    findings = _extract_findings(cached["data"])

    pillars = {}
    for pillar_name, desc in PILLAR_DESCRIPTIONS.items():
        pillar_findings = [f for f in findings if f["pillar"] == pillar_name]
        severity_counts = {}
        for f in pillar_findings:
            sev = f["severity"]
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        pillars[pillar_name] = {
            "description": desc,
            "total_findings": len(pillar_findings),
            "by_severity": severity_counts,
            "top_services": _top_n([f["service"] for f in pillar_findings], 5),
        }

    result = {
        "scanned_at": cached.get("scanned_at"),
        "total_findings": len(findings),
        "pillars": pillars,
    }

    return [TextContent(type="text", text=json.dumps(result, indent=2))]


async def _handle_pillar(pillar: str, args: dict) -> list[TextContent]:
    cached = await _ensure_cache(args)

    if not cached:
        return [TextContent(type="text", text=json.dumps({
            "status": "no_results",
            "message": "No scan results found. Call run_scan first.",
        }))]

    if "error" in cached:
        return [TextContent(type="text", text=json.dumps({
            "status": "scan_error",
            "message": cached["error"],
        }))]

    findings = _extract_findings(cached["data"])
    pillar_findings = [f for f in findings if f["pillar"] == pillar]

    if severity := args.get("severity"):
        pillar_findings = [f for f in pillar_findings if f["severity"].lower() == severity.lower()]

    severity_order = {"High": 0, "Medium": 1, "Low": 2, "Informational": 3, "Unknown": 4}
    pillar_findings.sort(key=lambda f: severity_order.get(f["severity"], 5))

    limit = args.get("limit", 30)
    total = len(pillar_findings)

    result = {
        "pillar": pillar,
        "description": PILLAR_DESCRIPTIONS[pillar],
        "scanned_at": cached.get("scanned_at"),
        "total_findings": total,
        "returned": min(limit, total),
        "findings": pillar_findings[:limit],
    }

    return [TextContent(type="text", text=json.dumps(result, indent=2))]


def _top_n(items: list, n: int) -> dict:
    """Count items and return top N."""
    counts = {}
    for item in items:
        counts[item] = counts.get(item, 0) + 1
    return dict(sorted(counts.items(), key=lambda x: -x[1])[:n])
