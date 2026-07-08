# Firehose Simulation Testing

Scripts to create an intentionally-insecure Amazon Data Firehose delivery
stream (plus its required destination S3 bucket + IAM role) so every
`firehose*` service-screener check that can be forced through the AWS API
is validated end-to-end.

## Resources Created

All prefixed with `ss-test-`:

| Resource | Configuration | Directly Validates |
|---|---|---|
| S3 bucket `ss-test-firehose-<account>-*` | Empty destination bucket. Default S3 encryption may be on (SSE-S3) but Firehose config sets `NoEncryptionConfig=NoEncryption` on its side, which is what the check reads. | — (dependency) |
| IAM role `ss-test-firehose-role-*` | `firehose.amazonaws.com` trust policy + inline S3 write policy scoped to the bucket. | — (dependency) |
| Firehose delivery stream `ss-test-firehose-*` | `DirectPut` source, `ExtendedS3Destination` to the bucket, **no server-side encryption** on the stream, **no KMS encryption** on the destination, **CloudWatch logging disabled**, `IntervalInSeconds=59` (below 60s threshold), `SizeInMBs=1` (AWS floor), **no user tags**. | See coverage below |

## Coverage

| # | Check | Simulated? |
|---:|---|---|
| 1 | `firehoseSSEDisabled` | ✓ FAIL — encryption never enabled |
| 2 | `firehoseSSEDefaultKey` | ✗ Not applicable — check reports `INFO` because #1 fires (mutually exclusive scenario) |
| 3 | `firehoseS3DestinationNoEncryption` | ✓ FAIL — `NoEncryptionConfig=NoEncryption` set on the destination |
| 4 | `firehoseLoggingDisabled` | ✓ FAIL — `CloudWatchLoggingOptions.Enabled=false` |
| 5 | `firehoseS3BackupDisabled` | ✗ Not applicable — check reports `INFO` because ProcessingConfiguration is not enabled (would need a Lambda transformer to force FAIL) |
| 6 | `firehoseBufferingSuboptimal` | ✓ FAIL — `IntervalInSeconds=59` (< 60s threshold) |
| 7 | `firehoseNoTags` | ✓ FAIL — no user tags added |
| 8 | `firehoseStreamNotActive` | ✓ PASS — expected. Terminal-failure states (`CREATING_FAILED`, `DELETING_FAILED`) cannot be reliably induced by a script; those require a specific race with a broken destination and are considered out-of-scope for automated simulation. |

**Directly simulated (FAIL): 5 of 8.**
**Exercised with expected reason (PASS or INFO): 8 of 8.**

## Cost

Effectively **$0** if the delivery stream is deleted within the same hour:

- Firehose has no minimum monthly charge — billing is per GB ingested and
  per GB delivered. This simulation never publishes records, so ingestion
  is $0.
- The S3 bucket is created empty and torn down empty.
- IAM roles are free.

If Firehose is left running (with no traffic) for a full month, cost is
still $0 — there is no idle charge.

## Usage

```bash
cd services/firehose/simulation
chmod +x create_test_resources.sh cleanup_test_resources.sh
./create_test_resources.sh --region ap-southeast-1

# Wait ~30-60s for the delivery stream to reach ACTIVE, then:
cd ../../..
python3 main.py --regions ap-southeast-1 --services firehose --beta 1 --sequential 1

cd services/firehose/simulation
./cleanup_test_resources.sh --force
```

You can run the scanner as soon as `create-delivery-stream` returns — the
stream will appear in `CREATING` state, which is treated as an
`INFO`-level advisory by `firehoseStreamNotActive` (transient, not
failed). Re-run once the stream is `ACTIVE` for the final "PASS" reading.

## IAM Permissions Required

To run this script you need:

- `s3:CreateBucket`, `s3:DeleteBucket`, `s3:PutObject`, `s3:DeleteObject`,
  `s3:ListBucket`
- `iam:CreateRole`, `iam:DeleteRole`, `iam:PutRolePolicy`,
  `iam:DeleteRolePolicy`, `iam:ListRolePolicies`, `iam:PassRole`
- `firehose:CreateDeliveryStream`, `firehose:DeleteDeliveryStream`,
  `firehose:DescribeDeliveryStream`, `firehose:ListDeliveryStreams`,
  `firehose:ListTagsForDeliveryStream`
- `sts:GetCallerIdentity`

## Notes

- The script uses `DirectPut` as the source, which is the simplest form.
  Kinesis-sourced delivery streams behave identically from the checks'
  point of view but require an existing Kinesis stream to point at.
- `SizeInMBs=1` is AWS's floor — you cannot go lower via the API. To
  force `firehoseBufferingSuboptimal` on the SizeInMBs axis you'd need
  an environment where the buffer is naturally below 1MB, which doesn't
  exist. The check therefore fires only on the `IntervalInSeconds` axis
  in this simulation, which is what we set to 59.
- The IAM trust policy includes `sts:ExternalId=<account>` as a defensive
  measure to prevent confused-deputy issues, following the current
  Firehose service-role guidance.
- If cleanup fails for the IAM role because the stream is still in
  DELETING state, re-run `cleanup_test_resources.sh` after ~2 minutes.
