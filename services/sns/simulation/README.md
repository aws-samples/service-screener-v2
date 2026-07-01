# SNS Simulation Testing

Scripts to create an intentionally-insecure SNS topic (plus one supporting
SQS queue) to validate the 12 `sns*` service-screener checks.

## Resources Created

All prefixed with `ss-test-`:

| Resource | Configuration | Directly Validates |
|---|---|---|
| SNS Topic `ss-test-sns-topic-*` | No `KmsMasterKeyId`, `SignatureVersion=1`, `TracingConfig` default (`PassThrough`), no tags, policy grants `Principal:*` on `SNS:Publish`/`Subscribe` with no Condition and no SecureTransport deny | #1, #3, #4, #6, #9, #10, #11, #12 |
| Subscription (HTTP) | `protocol=http` pointing at `http://example.com/ss-test-sns` | #5 |
| SQS queue `ss-test-sns-dlq-source-*` + SQS subscription | Subscribed to the topic, RedrivePolicy NOT set on the subscription | #7 |

## Coverage

| # | Check | Simulated? |
|---:|---|---|
| 1 | snsEncryptionAtRest | ✓ FAIL |
| 2 | snsEncryptionNotCMK | ✗ mutually exclusive with #1 (unencrypted topic cannot also be "encrypted with AWS-managed key") |
| 3 | snsPublicAccess | ✓ FAIL |
| 4 | snsNoHttpsEnforcement | ✓ FAIL |
| 5 | snsInsecureSubscription | ✓ FAIL |
| 6 | snsSignatureVersionOld | ✓ FAIL |
| 7 | snsSubscriptionNoDlq | ✓ FAIL |
| 8 | snsPendingSubscription | ✓ FAIL (HTTP sub stays PendingConfirmation because example.com doesn't call ConfirmSubscription — bonus coverage) |
| 9 | snsDeliveryStatusLoggingDisabled | ✓ FAIL |
| 10 | snsTracingDisabled | ✓ FAIL |
| 11 | snsUnusedTopic | ✗ (SQS subscription confirms immediately, so `SubscriptionsConfirmed=1` — check will PASS) |
| 12 | snsResourcesWithoutTags | ✓ FAIL |

**Directly simulated: 9 of 12** (10 of 12 counting the pending-sub bonus).

The two unsimulatable checks — #2 (needs a CMK setup, orthogonal to the
"unencrypted" bad state) and #11 (a topic with a live SQS sub isn't idle) —
are validated in the reverse direction (they PASS on our test topic, proving
the checks distinguish the two states correctly).

## Cost

Effectively **$0** — SNS topics with no traffic are free; SQS queue with no
messages is free.

## Usage

```bash
cd services/sns/simulation
chmod +x create_test_resources.sh cleanup_test_resources.sh
./create_test_resources.sh
# no IAM propagation wait needed — SNS is immediately consistent
cd ../../..
python3 main.py --regions us-east-1 --services sns --beta 1 --sequential 1
cd services/sns/simulation
./cleanup_test_resources.sh --force
```

## IAM Permissions Required

- `sns:CreateTopic`, `sns:DeleteTopic`, `sns:SetTopicAttributes`,
  `sns:Subscribe`, `sns:Unsubscribe`, `sns:GetTopicAttributes`,
  `sns:ListSubscriptionsByTopic`, `sns:ListTopics`
- `sqs:CreateQueue`, `sqs:DeleteQueue`, `sqs:GetQueueAttributes`,
  `sqs:SetQueueAttributes`
- `sts:GetCallerIdentity`

## Notes

- The subscription URL is `http://example.com/ss-test-sns` — example.com
  returns HTTP 200 to any POST but never calls the SNS confirmation
  endpoint, so the subscription stays in `PendingConfirmation`. This is
  intentional and doesn't affect the checks — SNS still records the
  protocol as `http` and the check for insecure subscriptions relies on the
  protocol name, not the confirmation state.
- The SQS queue policy grants `sns.amazonaws.com` permission to publish, so
  the SQS subscription confirms automatically — that gives us
  `SubscriptionsConfirmed>0` and lets check #7 (subscription-without-DLQ)
  fire on a real, confirmed subscription.
