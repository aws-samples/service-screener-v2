# IAM Service Checks

## Overview

This service module implements comprehensive IAM security and operational checks aligned with AWS best practices and the Well-Architected Framework.

## Statistics

- **Total Checks:** 43
- **Coverage:** ~65% of AWS IAM best practices
- **Security Checks:** 29
- **Operational Checks:** 8
- **Cost Optimization Checks:** 2
- **Reliability Checks:** 1
- **Multi-Pillar Checks:** 3

## Recent Updates (2025-02-25)

Added 4 new Tier 1 checks to improve coverage from 53% to 65%:

### New Checks

1. **unusedCustomerManagedPolicy** (Operational, Low)
   - Detects customer managed policies not attached to any users, groups, or roles
   - Helps maintain operational hygiene and reduce attack surface

2. **iamUsersWithFederationAvailable** (Security, Medium)
   - When SAML or OIDC providers are configured, detects IAM users with long-term credentials
   - Encourages use of temporary credentials through federation

3. **wildcardActionsDetection** (Security, High)
   - Detects service-level wildcard actions (e.g., `s3:*`, `ec2:*`) beyond full admin access
   - Enhances least privilege enforcement

4. **unnecessaryCustomPolicies** (Operational, Low)
   - Identifies customer managed policies that may duplicate AWS managed policies
   - Recommends using AWS managed policies for simplified management

## Testing

### Unit Tests
```bash
python -m pytest tests/test_iam_new_checks.py -v
```

### Simulation Testing
```bash
cd services/iam/simulation
./create_test_resources.sh
# Run Service Screener
./cleanup_test_resources.sh
```

See `simulation/README.md` for detailed testing instructions.

## Documentation

- **Implementation Summary:** `.kiro/specs/service-review-iam/IMPLEMENTATION_SUMMARY.md`
- **Best Practices Coverage:** `.kiro/specs/service-review-iam/BEST_PRACTICES_COVERAGE.md`
- **Future Roadmap:** `.kiro/specs/service-review-iam/NEW_CHECKS_SUMMARY.md`

## Credits

1. Original Author: KuetTai
2. PHP to Python Convertor: KuetTai
3. Reviewer: HoonSin
4. Tier 1 Enhancement (2025-02-25): Service Screener v2 Team