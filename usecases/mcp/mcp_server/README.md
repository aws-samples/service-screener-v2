# Service Screener MCP Server

An MCP (Model Context Protocol) server that exposes AWS Well-Architected assessment capabilities through AI assistants.

## What makes this different?

Unlike security-only tools (Prowler, Security Hub), Service Screener assesses **all 5 Well-Architected pillars**:
- **Security** — IAM, encryption, network exposure
- **Reliability** — HA, backups, fault tolerance
- **Operational Excellence** — monitoring, alerting, automation
- **Performance Efficiency** — right-sizing, modern architectures
- **Cost Optimization** — waste, idle resources, governance

## Tools

| Tool | Needs Scan? | Description |
|------|:-----------:|-------------|
| `list_rules` | No | Browse all 2600+ checks by service/pillar/severity |
| `get_rule_detail` | No | Get details and remediation for a specific check |
| `list_supported_services` | No | List scannable AWS services |
| `list_supported_frameworks` | No | List compliance frameworks (CIS, NIST, RMiT, etc.) |
| `run_scan` | - | Trigger a scan (regions, services, frameworks) |
| `get_scan_status` | No | Check cache freshness |
| `get_findings` | Yes* | Query findings with filters |
| `get_summary` | Yes* | Aggregated health overview |
| `get_wa_score` | Yes* | Score across all 5 pillars |
| `get_security_risks` | Yes* | Security pillar findings |
| `get_reliability_risks` | Yes* | Reliability pillar findings |
| `get_operational_gaps` | Yes* | Ops excellence findings |
| `get_performance_opportunities` | Yes* | Performance findings |
| `get_cost_waste` | Yes* | Cost optimization findings |

*Auto-triggers a scan if no cached results exist.

## Setup

```bash
cd service-screener-v2
pip install -r mcp_server/requirements.txt
```

## Usage

### With Claude Desktop / Cursor / Amazon Q

Add to your MCP client config:

```json
{
  "mcpServers": {
    "service-screener": {
      "command": "python",
      "args": ["/path/to/service-screener-v2/mcp_server/server.py"],
      "env": {
        "AWS_PROFILE": "your-profile",
        "AWS_DEFAULT_REGION": "ap-southeast-1"
      }
    }
  }
}
```

### Cache Behavior

1. First tool call requiring scan data → triggers full scan (~60-120s)
2. Results cached to `.mcp_cache/` and `adminlte/aws/res/`
3. Subsequent calls read from cache instantly
4. Cache age returned in every response — AI client decides freshness
5. Call `run_scan` to force a refresh

## Architecture

```
mcp_server/
├── server.py       # Entry point (stdio transport)
├── cache.py        # Cache-first result manager
├── scanner.py      # Subprocess wrapper for main.py
├── tools/
│   ├── rules.py       # Static rule metadata (no scan needed)
│   ├── findings.py    # Query cached findings
│   ├── scan.py        # Trigger & manage scans
│   └── wa_pillars.py  # Per-pillar insights (the differentiator)
└── requirements.txt
```

## AWS Credentials

The MCP server uses whatever AWS credentials are available in the environment:
- `AWS_PROFILE` environment variable
- `~/.aws/credentials` default profile
- IAM role (if running on EC2/CloudShell)
- SSO session

No additional auth layer needed.
