"""
Findings tools — query scan results (cache-first pattern).

If no scan results exist, instructs the caller to run a scan first.
"""

import json
from mcp.types import Tool, TextContent, ToolAnnotations

from cache import cache_manager

# Category code → pillar
CATEGORY_MAP = {
    "S": "Security",
    "O": "Operational Excellence",
    "T": "Operational Excellence",
    "R": "Reliability",
    "P": "Performance Efficiency",
    "C": "Cost Optimization",
    "CP": "Cost Optimization",
}

# Criticality code → label
CRITICALITY_MAP = {
    "H": "High",
    "M": "Medium",
    "L": "Low",
    "I": "Informational",
}

# --- Tool definitions ---

TOOLS = [
    Tool(
        name="get_findings",
        description=(
            "Get findings from the latest scan. Filters by service, severity, "
            "pillar, or status. Returns findings from cache if available, "
            "otherwise indicates a scan is needed."
        ),
        annotations=ToolAnnotations(readOnlyHint=True),
        inputSchema={
            "type": "object",
            "properties": {
                "service": {
                    "type": "string",
                    "description": "Filter by service (e.g., 'ec2', 'iam')",
                },
                "severity": {
                    "type": "string",
                    "description": "Filter by severity: High, Medium, Low, Informational",
                },
                "pillar": {
                    "type": "string",
                    "description": "Filter by WA pillar: Security, Reliability, Operational Excellence, Performance Efficiency, Cost Optimization",
                },
                "status": {
                    "type": "string",
                    "description": "Filter by status: New, Pass, Fail",
                },
                "limit": {
                    "type": "integer",
                    "description": "Max findings to return (default: 50)",
                    "default": 50,
                },
            },
        },
    ),
    Tool(
        name="get_summary",
        description=(
            "Get an aggregated summary of scan results — counts by service, "
            "pillar, and severity. Useful for quick health overview."
        ),
        annotations=ToolAnnotations(readOnlyHint=True),
        inputSchema={
            "type": "object",
            "properties": {
                "account_id": {
                    "type": "string",
                    "description": "AWS account ID (optional, uses latest scan if omitted)",
                },
            },
        },
    ),
]


# --- Tool handler ---

async def handle_tool(name: str, arguments: dict) -> list[TextContent]:
    if name == "get_findings":
        return await _handle_get_findings(arguments)
    elif name == "get_summary":
        return await _handle_get_summary(arguments)
    return [TextContent(type="text", text=f"Unknown findings tool: {name}")]


async def _handle_get_findings(args: dict) -> list[TextContent]:
    account_id = args.get("account_id")
    cached = cache_manager.get_scan_results(account_id)

    if not cached:
        return [TextContent(
            type="text",
            text=json.dumps({
                "status": "no_scan_results",
                "message": "No scan results found. Run a scan first using the 'run_scan' tool.",
                "hint": "Call run_scan with your desired regions and services."
            })
        )]

    findings = _extract_findings(cached["data"])

    # Apply filters
    if service := args.get("service"):
        findings = [f for f in findings if f["service"].lower() == service.lower()]
    if severity := args.get("severity"):
        findings = [f for f in findings if f["severity"].lower() == severity.lower()]
    if pillar := args.get("pillar"):
        findings = [f for f in findings if f["pillar"].lower() == pillar.lower()]
    if status := args.get("status"):
        findings = [f for f in findings if f["status"].lower() == status.lower()]

    limit = args.get("limit", 50)
    total = len(findings)
    findings = findings[:limit]

    result = {
        "scanned_at": cached.get("scanned_at"),
        "cache_age_seconds": cached.get("age_seconds"),
        "total_findings": total,
        "returned": len(findings),
        "findings": findings,
    }

    return [TextContent(type="text", text=json.dumps(result, indent=2))]


async def _handle_get_summary(args: dict) -> list[TextContent]:
    account_id = args.get("account_id")
    cached = cache_manager.get_scan_results(account_id)

    if not cached:
        return [TextContent(
            type="text",
            text=json.dumps({
                "status": "no_scan_results",
                "message": "No scan results found. Run a scan first using the 'run_scan' tool.",
            })
        )]

    findings = _extract_findings(cached["data"])

    by_service = {}
    by_pillar = {}
    by_severity = {}

    for f in findings:
        by_service[f["service"]] = by_service.get(f["service"], 0) + 1
        by_pillar[f["pillar"]] = by_pillar.get(f["pillar"], 0) + 1
        by_severity[f["severity"]] = by_severity.get(f["severity"], 0) + 1

    result = {
        "scanned_at": cached.get("scanned_at"),
        "cache_age_seconds": cached.get("age_seconds"),
        "total_findings": len(findings),
        "by_service": dict(sorted(by_service.items(), key=lambda x: -x[1])),
        "by_pillar": dict(sorted(by_pillar.items(), key=lambda x: -x[1])),
        "by_severity": dict(sorted(by_severity.items(), key=lambda x: -x[1])),
    }

    return [TextContent(type="text", text=json.dumps(result, indent=2))]


# --- Helper ---

def _extract_findings(data: dict) -> list[dict]:
    """
    Extract flat findings list from the api-full.json structure.

    Structure: data[service]["detail"][region][resource_id][check_name] =
               {criticality, shortDesc, __categoryMain, value}

    All entries in "detail" are findings (failures). Passing checks are not listed.
    """
    findings = []

    for service, service_data in data.items():
        if not isinstance(service_data, dict):
            continue
        if "detail" not in service_data:
            continue

        for region, resources in service_data.get("detail", {}).items():
            if not isinstance(resources, dict):
                continue
            for resource_id, checks in resources.items():
                if not isinstance(checks, dict):
                    continue
                for check_name, check_data in checks.items():
                    if not isinstance(check_data, dict) or "criticality" not in check_data:
                        continue
                    findings.append({
                        "service": service,
                        "region": region,
                        "resource_id": resource_id,
                        "check": check_name,
                        "severity": CRITICALITY_MAP.get(check_data.get("criticality", ""), "Unknown"),
                        "pillar": CATEGORY_MAP.get(check_data.get("__categoryMain", ""), "Unknown"),
                        "status": "FAIL",
                        "description": check_data.get("shortDesc", ""),
                    })

    return findings
