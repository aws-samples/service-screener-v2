# IRDAI Compliance Framework for Service Screener v2

## Overview

This framework maps AWS service configurations to the **IRDAI Information and Cyber Security Guidelines 2023** (notified April 24, 2023; revised April 6, 2026) and the **Outsourcing of Activities by Indian Insurers Regulations (2017)**.

It enables Indian insurance entities to evaluate their AWS environments against IRDAI regulatory requirements.

## Applicable Entities

| Entity Type | Scope |
|---|---|
| Life and General Insurers | Full compliance |
| Health Insurers | Full compliance + health data protections |
| Reinsurers | Applicable controls for India operations |
| Insurance Intermediaries | Brokers, corporate agents, web aggregators — proportionate compliance |
| TPAs, ISNPs, CSCs | Applicable controls |
| Insurance Repositories | Full compliance + enhanced data protection |
| Insurance Information Bureau (IIB) | Full compliance |

## Regulatory References

- [IRDAI Information and Cyber Security Guidelines 2023](https://www.irdai.gov.in/) — notified April 24, 2023
- [IRDAI 2026 Revised Cybersecurity Guidelines](https://www.irdai.gov.in/) — issued April 6, 2026
- [Outsourcing of Activities by Indian Insurers Regulations 2017](https://www.irdai.gov.in/)
- [AWS Compliance Center - India](https://aws.amazon.com/financial-services/security-compliance/compliance-center/in/)
- [IRDAI Cybersecurity Workbook (AWS Artifact)](https://aws.amazon.com/artifact/)

## Control Categories

| Code | Category | Auto-Checks | Manual |
|------|----------|:-----------:|:------:|
| **DS** | Data Security and Privacy | ✅ | 1 |
| **IAM** | Identity and Access Management | ✅ | — |
| **NS** | Network Security | ✅ | — |
| **ML** | Monitoring, Logging and Incident Response | ✅ | 1 |
| **VAPT** | Vulnerability Assessment and Penetration Testing | Partial | 3 |
| **BC** | Business Continuity and Disaster Recovery | ✅ | 1 |
| **OT** | Outsourcing and Third-Party Risk | Partial | 5 |
| **GRC** | Governance, Risk and Compliance | Partial | 4 |
| **WF** | Workforce and Endpoint Security | Partial | 3 |

## Detailed Control Mapping

### DS — Data Security and Privacy
| Control | Description | IRDAI Ref |
|---------|-------------|-----------|
| DS.1 | Encryption key management and rotation | Sec 3.2 |
| DS.2 | Data encryption at rest for all storage services | Sec 3.2 |
| DS.3 | Data encryption in transit (TLS/mTLS) | Sec 3.2 |
| DS.4 | Prevention of unintended data exposure | Sec 3.3 |
| DS.5 | Data integrity, versioning, and immutability | Sec 3.3 |
| DS.6 | Data localisation (India residency) — manual | Sec 3.4 |

### IAM — Identity and Access Management
| Control | Description | IRDAI Ref |
|---------|-------------|-----------|
| IAM.1 | Multi-factor authentication enforcement | Sec 4.1 |
| IAM.2 | Password and credential policy strength | Sec 4.1 |
| IAM.3 | Least privilege and role-based access | Sec 4.2 |
| IAM.4 | Root account security | Sec 4.2 |
| IAM.5 | Policy management (groups, SCPs, org) | Sec 4.3 |
| IAM.6 | Credential rotation and access reviews | Sec 4.3 |
| IAM.7 | Privileged access management (PAM) | Sec 4.4 |

### NS — Network Security
| Control | Description | IRDAI Ref |
|---------|-------------|-----------|
| NS.1 | Security group and firewall controls | Sec 5.1 |
| NS.2 | Network segmentation and isolation | Sec 5.1 |
| NS.3 | VPC and private connectivity | Sec 5.2 |
| NS.4 | DDoS and web application protection (WAF) | Sec 5.3 |
| NS.5 | Network flow log monitoring | Sec 5.4 |
| NS.6 | Intrusion detection (GuardDuty) | Sec 5.4 |

### ML — Monitoring, Logging and Incident Response
| Control | Description | IRDAI Ref |
|---------|-------------|-----------|
| ML.1 | Audit trail via CloudTrail | Sec 6.1 |
| ML.2 | Centralised log management and retention | Sec 6.1 |
| ML.3 | Threat detection (GuardDuty + SecurityHub) | Sec 6.2 |
| ML.4 | Service-level logging for all workloads | Sec 6.2 |
| ML.5 | Enhanced observability (X-Ray, detailed monitoring) | Sec 6.3 |
| ML.6 | Incident reporting to CERT-In (6h) and IRDAI (24h) — manual | Sec 6.4 |

### VAPT — Vulnerability Assessment and Penetration Testing
| Control | Description | IRDAI Ref |
|---------|-------------|-----------|
| VAPT.1 | Bi-annual VAPT by CERT-In empaneled auditor — manual | Sec 7.1 |
| VAPT.2 | Grey/white box PT (2026 Control 96) — manual | Sec 7.1 |
| VAPT.3 | Critical findings remediation within 30 days — manual | Sec 7.2 |
| VAPT.4 | External attack surface management | Sec 7.3 |

### BC — Business Continuity and Disaster Recovery
| Control | Description | IRDAI Ref |
|---------|-------------|-----------|
| BC.1 | High availability (multi-AZ deployments) | Sec 8.1 |
| BC.2 | Automated backups and point-in-time recovery | Sec 8.2 |
| BC.3 | Deletion protection | Sec 8.2 |
| BC.4 | Auto-scaling and capacity management | Sec 8.3 |
| BC.5 | Documented IT continuity/DR plan — manual | Sec 8.4 |

### OT — Outsourcing and Third-Party Risk
| Control | Description | IRDAI Ref |
|---------|-------------|-----------|
| OT.1 | AWS Organizations and SCPs for governance | Sec 9.1 |
| OT.2 | Third-party audit trail | Sec 9.2 |
| OT.3 | CSP MeitY empanelment verification — manual | Sec 9.3 |
| OT.4 | Sub-outsourcing written permission — manual | Sec 9.3 (2026 Control 148) |
| OT.5 | Data elimination at contract end — manual | Sec 9.4 (2026 Control 151) |
| OT.6 | NDAs for privacy, security, BCP — manual | Sec 9.4 |
| OT.7 | IRDAI audit rights in cloud agreements — manual | Sec 9.5 |

### GRC — Governance, Risk and Compliance
| Control | Description | IRDAI Ref |
|---------|-------------|-----------|
| GRC.1 | Board-approved CS Policy and ISRMC — manual | Sec 2.1 |
| GRC.2 | CISO independence from IT head (2026) — manual | Sec 2.2 |
| GRC.3 | Quarterly ISRMC reporting to Board — manual | Sec 2.3 |
| GRC.4 | Annual technology risk assessment — manual | Sec 2.4 |
| GRC.5 | Organisational structure and controls | Sec 2.5 |
| GRC.6 | Patch management and version currency | Sec 10.1 |
| GRC.7 | Recommendations and advisories | Sec 10.2 |
| GRC.8 | Compliance evidence and audit readiness | Sec 10.3 |
| GRC.9 | Cybersecurity budget (% of IT spend) — manual | Sec 2.6 |

### WF — Workforce and Endpoint Security
| Control | Description | IRDAI Ref |
|---------|-------------|-----------|
| WF.1 | Endpoint detection and response (EDR) — manual | Sec 11.1 |
| WF.2 | Device/volume encryption | Sec 11.2 |
| WF.3 | Background checks and HR security — manual | Sec 11.3 |
| WF.4 | Security awareness training — manual | Sec 11.4 |
| WF.5 | Acceptable use and social media policy — manual | Sec 11.5 |

## Controls Requiring Manual Evidence

Controls marked "manual" cannot be validated automatically via AWS APIs. The framework will display the `emptyCheckDefaultMsg` prompting users to provide evidence. Key manual controls include:

- **VAPT.1-3**: Penetration testing reports from CERT-In empaneled auditors
- **ML.6**: Incident notification logs showing 6-hour CERT-In / 24-hour IRDAI reporting
- **OT.3-7**: Contractual and governance documentation for outsourcing
- **GRC.1-4, GRC.9**: Board approvals, CISO reporting structure, budgets
- **WF.1, WF.3-5**: HR processes, training records, endpoint tooling

## Installation

Copy the `IRDAI/` folder into `frameworks/` in your service-screener-v2 installation:

```bash
cp -r IRDAI/ /path/to/service-screener-v2/frameworks/
```

## Usage

Run Service Screener with the IRDAI framework:

```bash
# Scan Mumbai region (typical for India-based insurers)
screener --regions ap-south-1 --frameworks IRDAI

# Combine with RBI for dual-regulated entities
screener --regions ap-south-1 --frameworks IRDAI,RBI

# Scan specific services
screener --regions ap-south-1 --services s3,iam,ec2,rds,kms --frameworks IRDAI
```

## File Structure

```
frameworks/IRDAI/
├── IRDAI.py      # Framework class (extends Framework base class)
├── map.json      # Control-to-check mapping (9 categories, 47 sub-controls)
└── README.md     # This file
```

## Key Differences from RBI Framework

| Aspect | RBI | IRDAI |
|--------|-----|-------|
| Applicability | Banks, NBFCs, payment operators | Insurers, intermediaries, TPAs, web aggregators |
| Incident reporting | — | 6 hours to CERT-In, 24 hours to IRDAI |
| VAPT frequency | Annual | Bi-annual (every 6 months) |
| PT methodology | Not specified | Grey/white box mandatory (2026) |
| CISO reporting | — | Must NOT report to Head of IT (2026) |
| Board meeting cadence | — | Quarterly ISRMC meetings (2026) |
| Data localisation | Primary data in India | All ICT logs and critical data in India |
| Outsourcing controls | Basic | Detailed (sub-outsourcing, MeitY empanelment, data elimination) |
