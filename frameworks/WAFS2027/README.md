# WAFS2027 — Well-Architected Framework (Nov 2026 release) [Preview]

Preview framework for the AWS Well-Architected Framework release of **16 November 2026**, targeted
for general availability in Service Screener on **1 January 2027**. It runs alongside the existing
`WAFS` framework, which is unchanged.

```bash
# Opt in explicitly; WAFS2027 is not in the default --frameworks list
screener --regions ap-southeast-1 --frameworks WAFS2027

# Optional: write results to the AWS Well-Architected Tool
screener --regions ap-southeast-1 --frameworks WAFS2027 \
  --others '{"WA": {"region": "ap-southeast-1", "reportName": "SS_Report_2027", "newMileStone": 0}}'
```

## Scope

| Area | Questions |
|---|---|
| Security pillar (Workloads) | SEC01–SEC11 (all 52 best practices) |
| Cloud Foundations | FND01 Multi-account, FND02 IAM, FND03 Observability, FND04 Resource & inventory, FND05 Security & compliance, FND07 Networking |
| Reliability | REL09 Back up data, REL13 Disaster recovery |

FND06 (Cloud financial management) is out of scope. Practices that moved from the Security pillar to
Cloud Foundations (root user, sign-in, guardrails, emergency access, central logging, threat
detection, forensics) are covered under their new FND IDs.

Best practices that cannot be assessed through AWS APIs are listed for manual review, for example
SEC01-BP06 (threat model), SEC10-BP04 (simulations), SEC10-BP05 (learning from incidents),
SEC11-BP01 (ownership and training) and SEC11-BP04 (penetration testing). FND04-BP02/03/04/06/07/08
and FND07-BP01 have not been mapped yet.

## Map format

Keys are self-describing, so the report is readable without the WA Tool:

```json
"SEC01 Securely operate your workload": {
    "SEC01-BP01 Separate workloads using accounts": ["iam.hasOrganization", "..."]
}
```

`<service>.$length` entries are resource-count evidence (see `Framework.getContent`).

## Differences from WAFS

| | WAFS | WAFS2027 |
|---|---|---|
| Framework version | Older Security pillar numbering (pre-2024 in places) | Nov 2026 release |
| WA Tool matching | By position (Nth question / Nth choice) | By choice title or BP ID; never positional |
| WA Tool pillars | `security` only | Every pillar in the lens review (finds Foundations wherever it lives) |
| Lens version safety | None | Writes only when the lens review status is `CURRENT` |
| Existing selections | Overwritten | Preserved; SS only adds choices |
| WA Tool integration | Always attempted | Opt-in via `--others '{"WA": {...}}'` |
| Default workload name | `SS_Report` | `SS_Report_2027` (fresh workload on the new lens) |

## Release plan

1. Preview: opt-in via `--frameworks WAFS2027`.
2. After user testing: rename `WAFS` to `WAFS_pre2027` (folder names must be valid Python
   identifiers; a hyphen cannot be imported), then rename `WAFS2027` to `WAFS`, updating the class,
   page-builder names and `metadata.shortname`.

## Tests

```bash
python -m pytest tests/test_wafs2027.py -q
```

## IAM permissions

The scanning identity needs the AWS managed `ReadOnlyAccess` policy (see the main README). A few
WAFS2027 checks call APIs that `ReadOnlyAccess` does not include. Without them those checks report
`Unable to evaluate` instead of a result; nothing fails. For full coverage add:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "ServiceScreenerWAFS2027Extras",
    "Effect": "Allow",
    "Action": [
      "access-analyzer:ListFindingsV2",
      "cognito-identity:GetPrincipalTagAttributeMap",
      "controltower:GetLandingZone",
      "controltower:ListLandingZones",
      "controltower:ListEnabledBaselines",
      "controltower:ListEnabledControls",
      "cur:DescribeReportDefinitions",
      "lakeformation:DescribeLakeFormationIdentityCenterConfiguration",
      "security-ir:GetMembership",
      "security-ir:ListMemberships"
    ],
    "Resource": "*"
  }]
}
```

Organizations-level checks give a full answer only from the management account or a delegated
administrator account; elsewhere they report `Not evaluable from member account`.
