# Service Screener MCP Server

A [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) server that exposes AWS Well-Architected assessment capabilities to AI assistants.

Unlike security-only scanners, Service Screener MCP provides **deterministic findings across all 5 Well-Architected pillars** — Security, Reliability, Operational Excellence, Performance Efficiency, and Cost Optimization.

> **Current Limitation:** This MCP server currently supports **single-account scanning** only — it scans whichever account the configured AWS credentials belong to. Service Screener itself supports multi-account and organization-wide scanning (see [crossAccounts](../crossAccounts/) and [accountsWithinOrganization](../accountsWithinOrganization/) usecases) — MCP support for these is planned.

## Overview

| Feature | Details |
|---------|---------|
| **Transport** | stdio (local) |
| **Protocol** | MCP 2024-11-05 |
| **Tools** | 14 (13 read-only, 1 write) |
| **Auth** | AWS credentials (inherited from environment) |
| **Dependencies** | Python 3.12+, `mcp>=1.28.0` |

## Tools

### Static Metadata (no AWS credentials required)

| Tool | Description |
|------|-------------|
| `list_rules` | List all available checks — filter by service, pillar, or criticality |
| `get_rule_detail` | Detailed info about a specific check including remediation references |
| `list_supported_services` | List all scannable AWS services |
| `list_supported_frameworks` | List all supported compliance frameworks |

### Scan Management (requires AWS credentials)

| Tool | Description |
|------|-------------|
| `run_scan` | Start a scan (async, non-blocking). Returns immediately. |
| `get_scan_status` | Check scan progress — reports per-service completion % |

### Findings & Analysis (reads from cached scan results)

| Tool | Description |
|------|-------------|
| `get_findings` | Query findings with filters (service, severity, pillar, status) |
| `get_summary` | Aggregated counts by service, pillar, and severity |
| `get_wa_score` | Well-Architected score across all 5 pillars with severity breakdown |
| `get_security_risks` | Security pillar findings (IAM, encryption, network exposure) |
| `get_reliability_risks` | Reliability findings (HA, backups, fault tolerance) |
| `get_operational_gaps` | Ops excellence findings (monitoring, alerting, automation) |
| `get_performance_opportunities` | Performance findings (right-sizing, ARM, modern architectures) |
| `get_cost_waste` | Cost optimization findings (unused resources, idle capacity) |

## Prerequisites

1. **Python 3.12+**
2. **AWS credentials** configured (for scanning):
   - Default profile in `~/.aws/credentials`, OR
   - `AWS_PROFILE` environment variable, OR
   - IAM role (EC2/CloudShell)
3. **Service Screener dependencies** installed:
   ```bash
   pip install -r requirements.txt
   ```

## Installation

From the repository root:

```bash
cd service-screener-v2

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate  # Linux/Mac
# .venv\Scripts\Activate.ps1  # Windows PowerShell

# Install dependencies
pip install -r requirements.txt
pip install mcp>=1.28.0
```

**Windows (PowerShell):**
```powershell
cd service-screener-v2
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
pip install mcp>=1.28.0
```

## Configuration

### Claude Desktop / Cursor

Add to your MCP client configuration (`claude_desktop_config.json`):

**Mac/Linux:**
```json
{
  "mcpServers": {
    "service-screener": {
      "command": ".venv/bin/python",
      "args": ["mcp_server/server.py"],
      "env": {
        "AWS_PROFILE": "your-profile",
        "AWS_DEFAULT_REGION": "ap-southeast-1"
      }
    }
  }
}
```

**Windows:**
```json
{
  "mcpServers": {
    "service-screener": {
      "command": ".venv\\Scripts\\python.exe",
      "args": ["mcp_server\\server.py"],
      "env": {
        "AWS_PROFILE": "your-profile",
        "AWS_DEFAULT_REGION": "ap-southeast-1"
      }
    }
  }
}
```

### Amazon Quick

Paste in **Settings → Capabilities → MCP → Add Server**:

```json
{
  "name": "service-screener",
  "command": ".venv/bin/python",
  "args": ["mcp_server/server.py"],
  "cwd": "/path/to/service-screener-v2"
}
```

> **Tip:** On Amazon Quick, use absolute paths for `cwd` to ensure the server resolves correctly regardless of where Quick launches from.

### Kiro IDE

Create `.kiro/settings/mcp.json` in the `service-screener-v2` project root.

**Mac/Linux** (rename `mcp-linux.json` → `mcp.json`):
```json
{
  "mcpServers": {
    "service-screener": {
      "command": ".venv/bin/python",
      "args": ["mcp_server/server.py"]
    }
  }
}
```

**Windows** (rename `mcp-windows.json` → `mcp.json`):
```json
{
  "mcpServers": {
    "service-screener": {
      "command": ".venv\\Scripts\\python.exe",
      "args": ["mcp_server\\server.py"]
    }
  }
}
```

> **Note (macOS):** The scan uses `--sequential 1 --beta 1` flags automatically on macOS to avoid multiprocessing fork issues.

## Usage Examples

### Quick Health Check (no scan needed)

```
> "What services can you scan?"
> "List all high-criticality security rules for Lambda"
> "What compliance frameworks are supported?"
```

### Full Assessment Flow

```
> "Run a scan on ap-southeast-1"
  → Scan started (async). Check status to monitor progress.

> "Check scan status"
  → Running: 12/20 services complete (60%)

> "Show me the WA score"
  → 1,784 findings across 5 pillars: Security (522), Ops (643), ...

> "What are my high-severity security risks?"
  → 12 Lambda roles too permissive, 5 SGs with all ports open, ...

> "Show reliability risks"
  → 7 EBS volumes without snapshots, 3 Aurora single-instance clusters, ...
```

### Integration with AWS Documentation MCP

Service Screener identifies **what's wrong**; pair with AWS Documentation MCP for **how to fix**:

```
> "What are my Lambda security issues?"
  → [Service Screener] 12 functions with overly permissive roles

> "How do I scope down Lambda execution roles?"
  → [AWS Docs] Use IAM Access Analyzer to generate least-privilege policies...

> "Fix the Lambda issues"
  → AI proposes actions, you approve, it executes via AWS CLI
```

## Architecture

```
mcp_server/
├── server.py          # Entry point — stdio transport, tool routing
├── cache.py           # Cache-first result manager (reads from scan output)
├── scanner.py         # Subprocess wrapper for main.py (async scan support)
└── tools/
    ├── rules.py       # list_rules, get_rule_detail (static, no scan)
    ├── findings.py    # get_findings, get_summary (reads cache)
    ├── scan.py        # run_scan, list_supported_services/frameworks, get_scan_status
    └── wa_pillars.py  # get_wa_score + per-pillar query tools
```

### Cache Strategy

```
Tool call → Check cache (adminlte/aws/{account_id}/api-full.json)
  ├─ Cache EXISTS  → Parse and return (instant)
  └─ Cache MISSING → Return "no results, run scan first"
```

- One scan produces findings for **all pillars** — subsequent queries are filtered reads
- Cache age returned in every response so the client can decide freshness
- `run_scan` is non-blocking — starts in background, returns immediately
- `get_scan_status` reports progress (completed services / total)

## How It Differs from Prowler

| Dimension | Service Screener MCP | Prowler MCP |
|-----------|:---:|:---:|
| **WA Coverage** | All 5 Pillars | Security only |
| **Cost** | Free (<$0.01/scan) | Freemium SaaS |
| **Setup** | `git clone` + run | Account signup |
| **Infra** | None (runs locally/CloudShell) | Managed server or self-hosted |
| **Regional Compliance** | RMiT, RBI, SPIP, FTR | CIS, SOC2, HIPAA |
| **Multi-cloud** | AWS only | AWS, Azure, GCP |

## Supported Services & Compliance Frameworks

Service and framework lists are **auto-discovered from the repo** at runtime — no hardcoded lists to maintain.

To check what's currently supported, use the MCP tools directly:

```
> "What services can you scan?"        → calls list_supported_services
> "What frameworks are supported?"     → calls list_supported_frameworks
```

Or from the CLI:
```bash
ls services/          # Each directory = a supported service
ls frameworks/        # Each directory = a supported framework
```

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Timeout on `run_scan` | Full scan takes 3-5 min | Scan is async — use `get_scan_status` to poll |
| `ModuleNotFoundError: multiprocess` | Missing SS dependencies | `pip install -r requirements.txt` |
| `FileNotFoundError: adminlte/aws` | Wrong working directory | Server auto-resolves paths; ensure `mcp_server/server.py` path is correct |
| 0 findings returned | Cache path mismatch | Ensure scan completed — check `adminlte/aws/{account_id}/api-full.json` exists |
| `InvalidClientTokenId` | No/wrong AWS credentials | Set `AWS_PROFILE` or configure `~/.aws/credentials` |

## License

Apache-2.0 (same as Service Screener V2)

## Links

- [Service Screener V2](https://github.com/aws-samples/service-screener-v2)
- [Model Context Protocol](https://modelcontextprotocol.io/)
- [MCP Best Practices](https://github.com/lirantal/awesome-mcp-best-practices)
