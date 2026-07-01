# SNS Simulation Testing

Scripts to create two intentionally-insecure SNS topics (standard + FIFO)
plus supporting subscriptions/queue so every `sns*` service-screener check
that can be forced through the AWS API is validated end-to-end. Covers
Phase 1 (checks 13-19) plus Phase 2 (checks 20-23).

## Resources Created

All prefixed with `ss-test-`:

| Resource | Configuration | Directly Validates |
|---|---|---|
| Standard SNS topic `ss-test-sns-topic-*` | No `KmsMasterKeyId`, `SignatureVersion=1`, default `TracingConfig`, no tags. Policy: `Principal:*` on `SNS:Publish`/`Subscribe`, no Condition, `Version="2008-10-17"` | Phase 1 #13/#14/#15/#16/#18, **Phase 2 #22 (snsPolicyVersionOutdated)** |
| HTTP subscription | `protocol=http` → `http://example.com/ss-test-sns` | Phase 1 #17 snsInsecureSubscription |
| SQS queue `ss-test-sns-dlq-source-*` + SQS subscription | Subscribed to standard topic, no RedrivePolicy | Phase 1 #19 snsSubscriptionNoDlq |
| SMS subscription | `protocol=sms` → `+15005550100` (fictional-use E.164 number; never Published to) | **Phase 2 #21 (snsSmsNoSpendLimit)** — only fires when the account has no `MonthlySpendLimit` or one >= $1000 |
| FIFO SNS topic `ss-test-sns-fifo-*.fifo` | `FifoTopic=true`, `ContentBasedDeduplication=false`, no `ArchivePolicy` | **Phase 2 #20 (snsFifoContentDeduplicationDisabled), #23 (snsFifoNoArchivePolicy)** |

## Coverage

### Phase 1 (checks 13-19)

| # | Check | Simulated? |
|---:|---|---|
| 13 | snsEncryptionAtRest | ✓ FAIL |
| 14 | snsEncryptionNotCMK | ✗ mutually exclusive with #13 |
| 15 | snsPublicAccess | ✓ FAIL |
| 16 | snsNoHttpsEnforcement | ✓ FAIL |
| 17 | snsInsecureSubscription | ✓ FAIL |
| 18 | snsSignatureVersionOld | ✓ FAIL |
| 19 | snsSubscriptionNoDlq | ✓ FAIL |

### Phase 2 (checks 20-23)

| # | Check | Simulated? |
|---:|---|---|
| 20 | snsFifoContentDeduplicationDisabled | ✓ INFO (FIFO topic without CBD — advisory) |
| 21 | snsSmsNoSpendLimit | ⚠ depends on account state — check fires ONLY when the account has no `MonthlySpendLimit` set (or set >= $1000) AND the topic has an SMS subscription. SNS sandbox accounts default to a $1 limit → the check reports PASS in that case. To force FAIL, temporarily set `MonthlySpendLimit=` (unset) via `aws sns set-sms-attributes --attributes MonthlySpendLimit=`, run scan, restore. **Not scripted** to avoid mutating account-level settings. |
| 22 | snsPolicyVersionOutdated | ✓ FAIL (both topics — SNS defaults to `Version="2008-10-17"` too, plus the standard topic gets an explicit deprecated-version policy) |
| 23 | snsFifoNoArchivePolicy | ✓ INFO (FIFO topic without ArchivePolicy — advisory) |

**Directly simulated (FAIL): 7 of 11.**
**Exercised (INFO or PASS with expected reason): 10 of 11.**

## Cost

Effectively **$0**:
- SNS topics with no `Publish` traffic are free.
- SQS queue with no messages is free.
- The SMS subscription only costs when a message is Published to it;
  this script never Publishes, so no SMS charges are incurred.
- FIFO topics without traffic are free.

## Usage

```bash
cd services/sns/simulation
chmod +x create_test_resources.sh cleanup_test_resources.sh
./create_test_resources.sh --region ap-southeast-1
# no IAM propagation wait needed — SNS is immediately consistent
cd ../../..
python3 main.py --regions ap-southeast-1 --services sns --beta 1 --sequential 1
cd services/sns/simulation
./cleanup_test_resources.sh --force
```

## IAM Permissions Required

- `sns:CreateTopic`, `sns:DeleteTopic`, `sns:SetTopicAttributes`,
  `sns:GetTopicAttributes`, `sns:Subscribe`, `sns:Unsubscribe`,
  `sns:ListSubscriptionsByTopic`, `sns:ListTopics`,
  `sns:GetSMSAttributes`
- `sqs:CreateQueue`, `sqs:DeleteQueue`, `sqs:GetQueueAttributes`,
  `sqs:SetQueueAttributes`
- `sts:GetCallerIdentity`

## Notes

- The HTTP subscription's URL is `http://example.com/ss-test-sns` —
  example.com returns HTTP 200 to any POST but never calls the SNS
  confirmation endpoint, so the subscription stays in
  `PendingConfirmation`. The check for insecure subscriptions inspects
  `Protocol='http'` and does not require confirmation.
- The SMS subscription's endpoint `+15005550100` is a fictional-use E.164
  number. If the account has SMS sandbox enabled, the destination is
  automatically added to the sandbox destination phone list.
- The FIFO topic is created with `FifoTopic=true` and
  `ContentBasedDeduplication=false`. Cognito Cognito's default topic
  policy for both standard and FIFO topics uses `Version="2008-10-17"`,
  so check #22 fires on the FIFO topic even though we don't explicitly
  set its policy.
- `snsPolicyVersionOutdated` firing on the FIFO topic is bonus coverage
  since SNS's own default policy uses the deprecated version.
