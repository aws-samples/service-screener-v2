# Cognito Simulation Testing

Scripts that create three intentionally-insecure Cognito user pools plus a
Lambda function and IAM roles to exercise every `cognito*` service-screener
check that can be forced through the AWS API. Covers Phase 1 (checks 13-27)
plus Phase 2 (checks 28-37).

## Resources Created

All prefixed with `ss-test-`:

| Resource | Configuration | Directly Validates |
|---|---|---|
| Pool 1 `ss-test-cognito-pool-*` | MFA=OFF, weak PW (MinLen=6), no UserPoolAddOns, DeletionProtection=INACTIVE, no AutoVerifiedAttributes, no LambdaConfig, single recovery mechanism, no DeviceConfig, no tags, 0 users; app client with 24h/24h/365d token validity | Phase 1 #13–#27 (most) |
| Pool 2 `ss-test-cognito-pool2-*` | Same tier as Pool 1 + **LambdaConfig.DefineAuthChallenge=<lambda>**, **TemporaryPasswordValidityDays=30**, plus a Cognito group `phase2-admins` and an OAuth app client with the `aws.cognito.signin.user.admin` scope | **Phase 2 #30, #32, #36, #37** |
| Pool 3 `ss-test-cognito-pool3-*` | **PLUS tier**, `AdvancedSecurityMode=ENFORCED`, risk config (CompromisedCredentials.EventFilter=[SIGN_IN] only; ATO High/Medium Actions with Notify=false), MFA=ON with SoftwareTokenMfa disabled and no SMS config | **Phase 2 #28, #29, #33, #35** |
| Lambda `ss-test-cognito-authtrigger-*` | Python 3.11 stub, never invoked; wired as Pool 2 `DefineAuthChallenge` trigger | supports #37 |
| IAM role `ss-test-cognito-lambda-role-*` | Lambda execution role + `AWSLambdaBasicExecutionRole` | — |
| IAM role `ss-test-cognito-group-role-*` | Trusted by `cognito-identity.amazonaws.com` with a placeholder `aud` condition; inline policy `Action:*, Resource:*` | supports #36 |

## Coverage

### Phase 1 (checks 13-27, on Pool 1)

| # | Check | Simulated? |
|---:|---|---|
| 13 | cognitoMfaNotEnforced | ✓ FAIL |
| 14 | cognitoWeakPasswordPolicy | ✓ FAIL |
| 15 | cognitoAdvancedSecurityNotEnforced | ✓ FAIL (Pool 1 only; Pool 3 has it ENFORCED and PASSes — the check still fires with FAIL on Pool 1) |
| 16 | cognitoDeletionProtectionDisabled | ✓ FAIL |
| 17 | cognitoNoEmailPhoneVerification | ✓ FAIL |
| 18 | cognitoNoLambdaTriggers | ✓ FAIL (Pool 1); Pool 2 has triggers → PASS on Pool 2 |
| 19 | cognitoAccountRecoveryNotConfigured | ✗ Cognito API rejects `RecoveryMechanisms:[]` |
| 20 | cognitoSingleRecoveryOption | ✓ FAIL |
| 21 | cognitoUnusedUserPool | ✓ FAIL (0 users) |
| 22 | cognitoTokenValidityTooLong | ✓ FAIL |
| 23 | cognitoDeviceTrackingDisabled | ✓ FAIL |
| 24 | cognitoResourcesWithoutTags | ✓ FAIL |
| 25-27 | (Phase 1 batch 2, various) | ✓ exercised by Pool 1's pristine configuration |

### Phase 2 (checks 28-37)

| # | Check | Simulated? |
|---:|---|---|
| 28 | cognitoCompromisedCredentialIncompleteFilter | ✓ FAIL (Pool 3: EventFilter=[SIGN_IN] only) |
| 29 | cognitoNoThreatProtectionLogging | ✓ FAIL (Pool 3: AdvSec=ENFORCED, no `userAuthEvents` LogDelivery) |
| 30 | cognitoLongTemporaryPassword | ✓ FAIL (Pool 2: `TemporaryPasswordValidityDays=30`) |
| 31 | cognitoClientNoSecret | ✗ Cognito refuses to create a `client_credentials` app client without `--generate-secret`. The "confidential-client-without-a-secret" state cannot be forced through the current API — the check is defense-in-depth for legacy resources. |
| 32 | cognitoClientExcessiveScopes | ✓ INFO (Pool 2 OAuth client: scope `aws.cognito.signin.user.admin`) |
| 33 | cognitoNoMfaMethods | ✓ FAIL (Pool 3: MFA=ON + `SoftwareTokenMfa.Enabled=false` + no SMS) — Cognito accepts this state; the check catches it. |
| 34 | cognitoSmsOnlyMfa | ✗ requires full SMS MFA setup (SNS role with `ExternalId`, phone_number attribute, regional SMS support). Non-trivial + risks incidental SMS costs; skipped. |
| 35 | cognitoAccountTakeoverNoNotification | ✓ INFO (Pool 3: HighAction/MediumAction with `Notify=false`) |
| 36 | cognitoGroupOverlyPermissiveRole | ✓ FAIL (Pool 2 group `phase2-admins` with wildcard IAM role) |
| 37 | cognitoCustomAuthThreatProtectionDisabled | ✓ FAIL (Pool 2: `DefineAuthChallenge` Lambda trigger with AdvSec OFF) |

**Directly simulated (FAIL or INFO with expected reason): 8 of 10 Phase 2 checks.**

## Cost

Effectively **$0** with the following caveats:
- Cognito user pools are billed by monthly active users (MAU). Pools with
  zero sign-ins across LITE, ESSENTIALS, and PLUS tiers cost $0.
- Lambda: never invoked → no invocation charges, no request charges.
- IAM roles are free.
- Total cost per test run: **$0** if you clean up promptly.

## Usage

```bash
cd services/cognito/simulation
chmod +x create_test_resources.sh cleanup_test_resources.sh
./create_test_resources.sh --region ap-southeast-1
# ~30s of eventual-consistency waits are embedded (IAM + Cognito)
sleep 30
cd ../../..
python3 main.py --regions ap-southeast-1 --services cognito --beta 1 --sequential 1
cd services/cognito/simulation
./cleanup_test_resources.sh --force
```

## IAM Permissions Required

- `cognito-idp:CreateUserPool`, `cognito-idp:DeleteUserPool`,
  `cognito-idp:UpdateUserPool`, `cognito-idp:DescribeUserPool`,
  `cognito-idp:ListUserPools`,
  `cognito-idp:SetRiskConfiguration`, `cognito-idp:DescribeRiskConfiguration`,
  `cognito-idp:SetUserPoolMfaConfig`,
  `cognito-idp:CreateGroup`, `cognito-idp:DeleteGroup`,
  `cognito-idp:CreateUserPoolClient`, `cognito-idp:DeleteUserPoolClient`,
  `cognito-idp:DescribeUserPoolClient`, `cognito-idp:ListUserPoolClients`,
  `cognito-idp:GetLogDeliveryConfiguration`
- `iam:CreateRole`, `iam:DeleteRole`, `iam:GetRole`,
  `iam:PutRolePolicy`, `iam:DeleteRolePolicy`,
  `iam:AttachRolePolicy`, `iam:DetachRolePolicy`,
  `iam:ListAttachedRolePolicies`, `iam:ListRolePolicies`
- `lambda:CreateFunction`, `lambda:DeleteFunction`, `lambda:AddPermission`,
  `lambda:GetFunction`
- `sts:GetCallerIdentity`

## Notes

- The Cognito group role's trust policy uses a placeholder Identity Pool
  `aud` value (`us-east-1:ss-test-simulation-placeholder`). This is
  syntactically valid so IAM accepts the trust policy; the role is never
  actually assumed. The check inspects only inline+attached policies for
  broad Actions/Resources — the trust policy is not evaluated.
- Cognito's `set-user-pool-mfa-config` accepts `MfaConfiguration=ON` with
  `SoftwareTokenMfa.Enabled=false` and no SMS configuration, which is
  the exact state check #33 targets ("MFA required but no method
  configured — users can never step up").
- Pool 3 uses the PLUS tier because `set-risk-configuration` requires it
  for the account-takeover risk-configuration block. If PLUS is not
  available in the region, the script falls back to ESSENTIALS + AdvSec
  ENFORCED (which supports the compromised-credentials block only).
- Pool 3's app client is unset because the risk configuration and MFA
  configuration are pool-scoped, not client-scoped, for the Phase 2
  checks we're targeting.
- The Lambda function is invoked only if Cognito's custom-authentication
  flow runs against Pool 2 — we never sign a user in, so no invocations
  occur and no execution charges accrue.
