"""
Rules tools — query available checks/rules without requiring a scan.

These tools read from services/{service}/{service}.reporter.json which is
static metadata baked into the repo. No AWS credentials needed.
"""

import json
from pathlib import Path
from mcp.types import Tool, TextContent, ToolAnnotations

BASE_DIR = Path(__file__).parent.parent.parent
SERVICES_DIR = BASE_DIR / "services"

# Category code → Well-Architected pillar mapping
CATEGORY_MAP = {
    "S": "Security",
    "O": "Operational Excellence",
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


def _load_all_rules() -> dict:
    """Load all rules from all service reporter.json files."""
    all_rules = {}
    for service_dir in SERVICES_DIR.iterdir():
        if not service_dir.is_dir() or service_dir.name.startswith("_"):
            continue

        service_name = service_dir.name.rstrip("_")

        # Try multiple reporter file naming patterns
        reporter_file = None
        for candidate in [
            service_dir / f"{service_name}.reporter.json",
            service_dir / f"{service_dir.name}.reporter.json",
        ]:
            if candidate.exists():
                reporter_file = candidate
                break

        if not reporter_file:
            continue

        try:
            with open(reporter_file) as f:
                rules = json.load(f)
            for rule_id, rule_data in rules.items():
                all_rules[rule_id] = {
                    "service": service_name,
                    "rule_id": rule_id,
                    "pillar": CATEGORY_MAP.get(rule_data.get("category", ""), "Unknown"),
                    "criticality": CRITICALITY_MAP.get(rule_data.get("criticality", ""), "Unknown"),
                    "short_description": rule_data.get("shortDesc", ""),
                    "description": rule_data.get("^description", ""),
                    "references": rule_data.get("ref", []),
                    "downtime_risk": bool(rule_data.get("downtime", 0)),
                    "additional_cost": bool(rule_data.get("additionalCost", 0)),
                }
        except (json.JSONDecodeError, IOError):
            continue

    return all_rules


# --- Tool definitions ---

TOOLS = [
    Tool(
        name="list_rules",
        description=(
            "List all available Service Screener checks/rules. "
            "Can filter by service, pillar, or criticality. "
            "No AWS credentials or prior scan needed."
        ),
        annotations=ToolAnnotations(readOnlyHint=True),
        inputSchema={
            "type": "object",
            "properties": {
                "service": {
                    "type": "string",
                    "description": "Filter by AWS service (e.g., 'ec2', 'iam', 's3')",
                },
                "pillar": {
                    "type": "string",
                    "description": "Filter by Well-Architected pillar: Security, Reliability, Operational Excellence, Performance Efficiency, Cost Optimization",
                },
                "criticality": {
                    "type": "string",
                    "description": "Filter by criticality: High, Medium, Low, Informational",
                },
            },
        },
    ),
    Tool(
        name="get_rule_detail",
        description=(
            "Get detailed information about a specific check/rule including "
            "description, references, and remediation guidance."
        ),
        annotations=ToolAnnotations(readOnlyHint=True),
        inputSchema={
            "type": "object",
            "properties": {
                "rule_id": {
                    "type": "string",
                    "description": "The rule ID (e.g., 'EC2EbsOptimized', 'mfaActive')",
                },
            },
            "required": ["rule_id"],
        },
    ),
]


# --- Tool handler ---

async def handle_tool(name: str, arguments: dict) -> list[TextContent]:
    if name == "list_rules":
        return await _handle_list_rules(arguments)
    elif name == "get_rule_detail":
        return await _handle_get_rule_detail(arguments)
    return [TextContent(type="text", text=f"Unknown rules tool: {name}")]


async def _handle_list_rules(args: dict) -> list[TextContent]:
    all_rules = _load_all_rules()

    # Apply filters
    filtered = list(all_rules.values())

    if service := args.get("service"):
        filtered = [r for r in filtered if r["service"] == service.lower()]
    if pillar := args.get("pillar"):
        filtered = [r for r in filtered if r["pillar"].lower() == pillar.lower()]
    if criticality := args.get("criticality"):
        filtered = [r for r in filtered if r["criticality"].lower() == criticality.lower()]

    result = {
        "total_rules": len(filtered),
        "rules": [
            {
                "rule_id": r["rule_id"],
                "service": r["service"],
                "pillar": r["pillar"],
                "criticality": r["criticality"],
                "short_description": r["short_description"],
            }
            for r in filtered
        ],
    }

    return [TextContent(type="text", text=json.dumps(result, indent=2))]


async def _handle_get_rule_detail(args: dict) -> list[TextContent]:
    rule_id = args["rule_id"]
    all_rules = _load_all_rules()

    if rule_id not in all_rules:
        return [TextContent(type="text", text=f"Rule '{rule_id}' not found.")]

    return [TextContent(type="text", text=json.dumps(all_rules[rule_id], indent=2))]
