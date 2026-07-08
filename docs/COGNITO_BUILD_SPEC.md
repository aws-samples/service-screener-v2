# Cognito Service Build Spec

Project: /Users/kuettai/Documents/project/ss-genai/service-screener-v2

Build the Cognito service. Create ONLY files inside `services/cognito/` — do NOT modify any shared files (ArguParser, frameworks, info.json).

## Step 1: Research the API

- aws cognito-idp list-user-pools --max-results 10 --region us-east-1
- aws cognito-idp describe-user-pool --user-pool-id <id> --region us-east-1 (if any exist)
- Check response fields: MfaConfiguration, Policies.PasswordPolicy, AccountRecoverySetting, UserPoolAddOns (AdvancedSecurityMode), DeletionProtection, AdminCreateUserConfig

## Step 2: Define checks (10-12)

Focus areas:
- Security: MFA not enforced (MfaConfiguration != ON), weak password policy (MinimumLength < 12, no symbol/number required), no advanced security (UserPoolAddOns.AdvancedSecurityMode != ENFORCED), deletion protection disabled
- Operational: No email/phone verification required, no custom auth lambda triggers for monitoring
- Reliability: Account recovery not configured, no multiple recovery options
- Cost: Unused user pools (0 users estimated)
- Identity: Token validity too long (AccessTokenValidity, IdTokenValidity, RefreshTokenValidity), no device tracking

Reference: https://docs.aws.amazon.com/cognito/latest/developerguide/managing-security.html

## Step 3: Create files

1. `services/cognito/cognito.reporter.json` — all check definitions
2. `services/cognito/Cognito.py` — main service class. Use `cognito-idp` boto3 client. Paginate list_user_pools, then describe_user_pool for each.
3. `services/cognito/drivers/CognitoCommon.py` — all checks
4. `services/cognito/simulation/create_test_resources.sh` — create a user pool with weak settings (short password, no MFA, no advanced security, no deletion protection)
5. `services/cognito/simulation/cleanup_test_resources.sh`
6. `services/cognito/simulation/README.md`

## Step 4: Validate

- Verify all reporter keys match _check methods
- python3 -c "import json; json.load(open('services/cognito/cognito.reporter.json')); print('OK')"
- python3 -c "import py_compile; py_compile.compile('services/cognito/Cognito.py'); py_compile.compile('services/cognito/drivers/CognitoCommon.py'); print('compiles OK')"

## Step 5: Test

python3 main.py --regions us-east-1 --services cognito --beta 1 --sequential 1

## Step 6: Simulate

Run create_test_resources.sh, wait 30s, scan, verify FAILs, cleanup.

Report: check list, coverage percentage, any issues.

IMPORTANT: Do NOT modify utils/ArguParser.py, frameworks/*, info.json, or any file outside services/cognito/
