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

`<service>.$length` entries are resource-count context only. They are shown in the report, but a
count of zero never fails a best practice and a non-zero count never makes one pass.

## Compliance status

The base `Framework` treats any check that is missing from the failure summary as compliant.
WAFS2027 does not. It reads the full scan results (`api-raw.json`, written by Screener before the
frameworks run) and gives each best practice one status:

| Status | When |
|---|---|
| Need attention (-1) | At least one mapped check failed |
| Compliant (1) | At least one mapped check ran and passed, and no mapped check failed, was suppressed, or was unreadable. Mapped checks that did not run (service not scanned, no resources) or returned only informational results (`Not applicable`, `No ... in this region`) do not block a pass |
| Not available (0) | No mapped check passed, or any mapped check was unreadable on any resource: a status 0 result whose message says the data could not be read or interpreted (`Unable to evaluate`, `Not evaluable`, `Error: ...`, `Unknown mode: ...`, `could not`, `unparseable`, `not returned`, ...), or the check raised an exception on any resource (traceback in `error.txt`), even when it recorded no result at all. A raised `_check<Name>` method is matched to result keys case-insensitively, ignoring underscores, by name or suffix (`_checkCertExpired` -> `acmCertExpired`, `_check_code_signing_disabled` -> `lambdaCodeSigningDisabled`) or by the key literals in the method body and in the `self.<helper>()` methods it calls that are defined in the same driver file (followed transitively). The traceback's driver folder is mapped to the service name, so a Python keyword folder such as `services/lambda_` is the `lambda` service. Key literals in helpers from other files (base or common classes) and keys built at runtime (for example `'lambdaNotInUsed' + str(day) + 'Days'`) are not followed; when a raised method matches no known key of its service, every mapped check of that service is treated as unreadable (conservative: extra `Unable to evaluate`, never a false PASS). Also when a failure was suppressed or the practice needs manual review |

If `api-raw.json` cannot be read, no best practice is reported as compliant.

## Differences from WAFS

| | WAFS | WAFS2027 |
|---|---|---|
| Framework version | Older Security pillar numbering (pre-2024 in places) | Nov 2026 release |
| WA Tool matching | By position (Nth question / Nth choice) | By BP ID first, then by title only when the title identifies exactly one choice; titles shared by two BPs in the map (FND02-BP08 / SEC02-BP05) match only inside the BP's own pillar; never positional |
| WA Tool pillars | `security` only | Every pillar in the lens review (finds Foundations wherever it lives) |
| Lens version safety | None | Writes only when the lens review status is `CURRENT` |
| Selected choices | Overwritten | Only Compliant (1) BPs are selected. A choice whose BP failed is withdrawn. Choices SS selected in an earlier run are withdrawn when the BP no longer passes. Other choices the user selected are kept |
| Notes | Overwritten | The customer's notes are kept; SS rewrites only its own block (`***Generated by SS (WAFS2027)` ... `***End of SS (WAFS2027) notes`) |
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
