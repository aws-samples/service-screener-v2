# Amazon Kinesis Data Streams — Service Screener v2 Check Catalogue

## Executive Summary

This document enumerates **all programmatically verifiable configurations** for Amazon Kinesis Data Streams (and Amazon Data Firehose) that a security/well-architected scanning tool can check via boto3 API calls.

**Recommendation: Treat Kinesis Data Streams and Amazon Data Firehose as SEPARATE services** in service-screener-v2:
- `kinesis` — boto3 client `kinesis` — Kinesis Data Streams
- `firehose` — boto3 client `firehose` — Amazon Data Firehose (now branded "Amazon Data Firehose")

Rationale: Different boto3 clients, different IAM namespaces (`kinesis:*` vs `firehose:*`), different Security Hub control families (`Kinesis.*` vs `DataFirehose.*`), different console sections.

---

## API Surface Available

### Kinesis Data Streams (`boto3.client('kinesis')`)
| API Call | Rate Limit | Purpose |
|----------|-----------|---------|
| `list_streams()` | 5 TPS | Enumerate all streams |
| `describe_stream_summary(StreamARN)` | 20 TPS | Stream config, encryption, monitoring, shard count |
| `describe_stream(StreamARN)` | 10 TPS | Full shard map + all config (prefer summary) |
| `list_tags_for_stream(StreamARN)` | 5 TPS | Tag compliance |
| `list_stream_consumers(StreamARN)` | 5 TPS | Enhanced fan-out consumers |
| `describe_limits()` | 1 TPS | Account shard limit |

### Amazon Data Firehose (`boto3.client('firehose')`)
| API Call | Rate Limit | Purpose |
|----------|-----------|---------|
| `list_delivery_streams()` | 5 TPS | Enumerate delivery streams |
| `describe_delivery_stream(DeliveryStreamName)` | 5 TPS | Full config including encryption, destinations |
| `list_tags_for_delivery_stream(DeliveryStreamName)` | 5 TPS | Tag compliance |

### Cross-Service (for enrichment)
| API Call | Client | Purpose |
|----------|--------|---------|
| `kms:DescribeKey(KeyId)` | `kms` | Validate KMS key status |
| `kms:GetKeyRotationStatus(KeyId)` | `kms` | Check key rotation |
| `cloudwatch:DescribeAlarms()` | `cloudwatch` | Check alarm coverage |

---

## TIER 1 — Critical Security & Compliance (Implement First)

These align with Security Hub controls and address data protection fundamentals.

### 1. `kinesisSSEDisabled`
| Field | Value |
|-------|-------|
| **Name** | Server-Side Encryption Not Enabled |
| **Security Hub** | Kinesis.1 |
| **API** | `describe_stream_summary` → `EncryptionType` |
| **FAIL Condition** | `EncryptionType == 'NONE'` |
| **Severity** | HIGH |
| **Pillar** | Security |
| **Usefulness** | ⭐⭐⭐⭐⭐ (10/10) — Direct compliance requirement |
| **Notes** | Most critical check. Data at rest is unencrypted. |

```python
# Check logic
summary = client.describe_stream_summary(StreamARN=arn)
stream = summary['StreamDescriptionSummary']
if stream['EncryptionType'] == 'NONE':
    FAIL("Server-side encryption is not enabled")
```

---

### 2. `kinesisSSEDefaultKey`
| Field | Value |
|-------|-------|
| **Name** | Encryption Using AWS-Managed Key Instead of CMK |
| **Security Hub** | — (enhancement beyond Kinesis.1) |
| **API** | `describe_stream_summary` → `KeyId` |
| **FAIL Condition** | `EncryptionType == 'KMS'` AND `KeyId` contains `alias/aws/kinesis` |
| **Severity** | MEDIUM |
| **Pillar** | Security |
| **Usefulness** | ⭐⭐⭐⭐ (8/10) — Best practice for key control |
| **Notes** | AWS-managed key (`alias/aws/kinesis`) doesn't allow cross-account access, key policy customization, or independent rotation control. |

```python
if stream['EncryptionType'] == 'KMS':
    key_id = stream.get('KeyId', '')
    if 'alias/aws/kinesis' in key_id or key_id == 'alias/aws/kinesis':
        FAIL("Using AWS-managed key; recommend CMK for full control")
```

---

### 3. `kinesisKMSKeyRotationDisabled`
| Field | Value |
|-------|-------|
| **Name** | KMS Key Rotation Not Enabled |
| **Security Hub** | — (relates to KMS.4) |
| **API** | `describe_stream_summary` → `KeyId`, then `kms:GetKeyRotationStatus(KeyId)` |
| **FAIL Condition** | Key is a CMK AND `KeyRotationEnabled == False` |
| **Severity** | MEDIUM |
| **Pillar** | Security |
| **Usefulness** | ⭐⭐⭐⭐ (8/10) — Compliance requirement (PCI-DSS, NIST) |
| **Notes** | Only applicable to customer-managed CMKs (not aws/kinesis alias). Must resolve key ARN first. |

```python
if stream['EncryptionType'] == 'KMS':
    key_id = stream.get('KeyId', '')
    if 'alias/aws/kinesis' not in key_id:
        # Resolve to key ARN if needed
        rotation = kms_client.get_key_rotation_status(KeyId=key_id)
        if not rotation['KeyRotationEnabled']:
            FAIL("KMS key rotation is not enabled")
```

---

### 4. `kinesisRetentionPeriodMinimum`
| Field | Value |
|-------|-------|
| **Name** | Data Retention Period at Minimum (24 hours) |
| **Security Hub** | Kinesis.3 (default threshold: 168 hours) |
| **API** | `describe_stream_summary` → `RetentionPeriodHours` |
| **FAIL Condition** | `RetentionPeriodHours == 24` (minimum/default) |
| **Severity** | MEDIUM |
| **Pillar** | Reliability |
| **Usefulness** | ⭐⭐⭐⭐⭐ (9/10) — Data loss risk during consumer outages |
| **Notes** | Security Hub default requires ≥168 hours. Consider making threshold configurable. Minimum is 24h, max is 8760h (365 days). |

```python
MINIMUM_RETENTION = 24
RECOMMENDED_RETENTION = 168  # Security Hub default

if stream['RetentionPeriodHours'] <= MINIMUM_RETENTION:
    FAIL("Retention at minimum 24 hours — high data loss risk")
elif stream['RetentionPeriodHours'] < RECOMMENDED_RETENTION:
    WARN("Retention below recommended 168 hours")
```

---

### 5. `kinesisNoTags`
| Field | Value |
|-------|-------|
| **Name** | Stream Has No Tags |
| **Security Hub** | Kinesis.2 |
| **API** | `list_tags_for_stream(StreamARN)` → `Tags` |
| **FAIL Condition** | `Tags` list is empty (no non-system tags) |
| **Severity** | LOW |
| **Pillar** | Operational Excellence |
| **Usefulness** | ⭐⭐⭐ (6/10) — Governance/cost allocation |
| **Notes** | Filter out `aws:` prefixed tags (system tags). |

```python
tags_resp = client.list_tags_for_stream(StreamARN=arn)
user_tags = [t for t in tags_resp['Tags'] if not t['Key'].startswith('aws:')]
if len(user_tags) == 0:
    FAIL("Stream has no user-defined tags")
```

---

## TIER 2 — Operational Excellence & Reliability

### 6. `kinesisEnhancedMonitoringDisabled`
| Field | Value |
|-------|-------|
| **Name** | Enhanced (Shard-Level) Monitoring Not Enabled |
| **Security Hub** | — (was previously referenced as shard-level metrics check) |
| **API** | `describe_stream_summary` → `EnhancedMonitoring[].ShardLevelMetrics` |
| **FAIL Condition** | `ShardLevelMetrics` list is empty for all monitoring entries |
| **Severity** | MEDIUM |
| **Pillar** | Operational Excellence |
| **Usefulness** | ⭐⭐⭐⭐⭐ (9/10) — Critical for troubleshooting throttling |
| **Notes** | Without shard-level metrics, you cannot identify hot shards or per-shard throughput issues. Check if ALL metrics are enabled or at least key ones. |

```python
enhanced = stream.get('EnhancedMonitoring', [])
has_metrics = False
for entry in enhanced:
    if entry.get('ShardLevelMetrics') and len(entry['ShardLevelMetrics']) > 0:
        has_metrics = True
        break
if not has_metrics:
    FAIL("Enhanced shard-level monitoring is not enabled")
```

---

### 7. `kinesisStreamNotActive`
| Field | Value |
|-------|-------|
| **Name** | Stream in Non-Active State |
| **API** | `describe_stream_summary` → `StreamStatus` |
| **FAIL Condition** | `StreamStatus` in `['CREATING', 'DELETING', 'UPDATING']` |
| **Severity** | HIGH (if stuck for extended period) |
| **Pillar** | Reliability |
| **Usefulness** | ⭐⭐⭐ (6/10) — Transient states are normal; only useful if combined with age check |
| **Notes** | CREATING/UPDATING are transient. Could compare with `StreamCreationTimestamp` to detect stuck streams. A stream stuck in CREATING for >10 minutes is anomalous. DELETING may indicate failed cleanup. |

```python
if stream['StreamStatus'] != 'ACTIVE':
    status = stream['StreamStatus']
    FAIL(f"Stream is in '{status}' state — may indicate a stuck operation")
```

---

### 8. `kinesisProvisionedModeNoAutoScaling`
| Field | Value |
|-------|-------|
| **Name** | Provisioned Mode Without Capacity Management |
| **API** | `describe_stream_summary` → `StreamModeDetails.StreamMode` |
| **FAIL Condition** | `StreamMode == 'PROVISIONED'` |
| **Severity** | LOW |
| **Pillar** | Performance Efficiency / Cost Optimization |
| **Usefulness** | ⭐⭐⭐ (5/10) — Informational; provisioned is valid for predictable workloads |
| **Notes** | This is advisory. Provisioned mode requires manual shard management or Application Auto Scaling configuration. Cannot determine if auto-scaling is configured from Kinesis API alone (would need `application-autoscaling` client). Consider WARN only. |

```python
if stream['StreamModeDetails']['StreamMode'] == 'PROVISIONED':
    WARN("Stream uses provisioned mode — ensure auto-scaling is configured or workload is predictable")
```

---

### 9. `kinesisShardUtilizationHigh`
| Field | Value |
|-------|-------|
| **Name** | Open Shard Count Approaching Account Limit |
| **API** | `describe_stream_summary` → `OpenShardCount` + `describe_limits()` → `ShardLimit` |
| **FAIL Condition** | `OpenShardCount / ShardLimit > 0.8` (80% utilization) |
| **Severity** | MEDIUM |
| **Pillar** | Reliability |
| **Usefulness** | ⭐⭐⭐⭐ (7/10) — Prevents capacity exhaustion |
| **Notes** | `describe_limits()` returns the account-level shard limit. Sum all streams' OpenShardCount and compare. Default limits: 20,000 (us-east-1, us-west-2, eu-west-1), 1,000–6,000 elsewhere. |

```python
limits = client.describe_limits()
shard_limit = limits['ShardLimit']
# Sum across all streams
total_shards = sum(s['OpenShardCount'] for s in all_stream_summaries)
utilization = total_shards / shard_limit
if utilization > 0.8:
    FAIL(f"Account shard utilization at {utilization*100:.0f}% — risk of hitting limit")
```

---

### 10. `kinesisNoConsumers`
| Field | Value |
|-------|-------|
| **Name** | No Registered Consumers (Potentially Unused Stream) |
| **API** | `describe_stream_summary` → `ConsumerCount` OR `list_stream_consumers(StreamARN)` |
| **FAIL Condition** | `ConsumerCount == 0` AND stream is ACTIVE AND age > 7 days |
| **Severity** | LOW |
| **Pillar** | Cost Optimization |
| **Usefulness** | ⭐⭐⭐ (5/10) — High false-positive rate (KCL/Lambda consumers don't register as EFO) |
| **Notes** | **Important caveat**: `ConsumerCount` and `list_stream_consumers` only count **Enhanced Fan-Out (EFO)** consumers. Standard KCL consumers, Lambda triggers, and Firehose sources do NOT appear here. This check catches unused streams or streams that could benefit from EFO, but cannot definitively prove a stream is unused. Consider this advisory/informational only. |

```python
consumer_count = stream.get('ConsumerCount', 0)
age_days = (datetime.now() - stream['StreamCreationTimestamp']).days
if consumer_count == 0 and stream['StreamStatus'] == 'ACTIVE' and age_days > 7:
    WARN("No enhanced fan-out consumers registered — verify stream is actively consumed")
```

---

## TIER 3 — Cost Optimization & Advanced Checks

### 11. `kinesisOnDemandPredictableWorkload`
| Field | Value |
|-------|-------|
| **Name** | On-Demand Mode (Cost Advisory) |
| **API** | `describe_stream_summary` → `StreamModeDetails.StreamMode` |
| **FAIL Condition** | `StreamMode == 'ON_DEMAND'` AND stream has been active > 30 days |
| **Severity** | LOW |
| **Pillar** | Cost Optimization |
| **Usefulness** | ⭐⭐ (4/10) — Pure advisory; on-demand is often optimal |
| **Notes** | On-demand is ~20% more expensive than provisioned for predictable throughput. This is purely informational — many customers prefer on-demand for operational simplicity. Consider making this opt-in. |

```python
if stream['StreamModeDetails']['StreamMode'] == 'ON_DEMAND':
    age_days = (datetime.now() - stream['StreamCreationTimestamp']).days
    if age_days > 30:
        INFO("Stream uses on-demand mode for 30+ days — review if provisioned mode would be more cost-effective")
```

---

### 12. `kinesisEnhancedMonitoringPartial`
| Field | Value |
|-------|-------|
| **Name** | Enhanced Monitoring Partially Enabled |
| **API** | `describe_stream_summary` → `EnhancedMonitoring[].ShardLevelMetrics` |
| **FAIL Condition** | Metrics enabled but `'ALL'` not in list (partial coverage) |
| **Severity** | LOW |
| **Pillar** | Operational Excellence |
| **Usefulness** | ⭐⭐⭐ (5/10) — Partial is better than none |
| **Notes** | If some metrics are enabled but not ALL, certain troubleshooting scenarios may be hindered. Check specifically for key metrics: `IteratorAgeMilliseconds`, `WriteProvisionedThroughputExceeded`, `ReadProvisionedThroughputExceeded`. |

```python
for entry in enhanced:
    metrics = entry.get('ShardLevelMetrics', [])
    if metrics and 'ALL' not in metrics:
        critical = ['IteratorAgeMilliseconds', 'WriteProvisionedThroughputExceeded', 'ReadProvisionedThroughputExceeded']
        missing = [m for m in critical if m not in metrics]
        if missing:
            WARN(f"Critical shard-level metrics not enabled: {missing}")
```

---

### 13. `kinesisConsumerStuck`
| Field | Value |
|-------|-------|
| **Name** | Enhanced Fan-Out Consumer in Non-Active State |
| **API** | `list_stream_consumers(StreamARN)` → `Consumers[].ConsumerStatus` |
| **FAIL Condition** | `ConsumerStatus` in `['CREATING', 'DELETING']` for > 10 minutes |
| **Severity** | MEDIUM |
| **Pillar** | Reliability |
| **Usefulness** | ⭐⭐⭐ (5/10) — Rare edge case |
| **Notes** | Consumer creation/deletion should complete quickly. Stuck consumers may indicate IAM or resource issues. |

```python
consumers = client.list_stream_consumers(StreamARN=arn)
for consumer in consumers['Consumers']:
    if consumer['ConsumerStatus'] != 'ACTIVE':
        age_minutes = (datetime.now(tz=timezone.utc) - consumer['ConsumerCreationTimestamp']).total_seconds() / 60
        if age_minutes > 10:
            FAIL(f"Consumer '{consumer['ConsumerName']}' stuck in {consumer['ConsumerStatus']} state")
```

---

## TIER 4 — Firehose Checks (Separate Service: `firehose`)

### 14. `firehoseSSEDisabled`
| Field | Value |
|-------|-------|
| **Name** | Delivery Stream Encryption Not Enabled |
| **Security Hub** | DataFirehose.1 |
| **API** | `describe_delivery_stream` → `DeliveryStreamEncryptionConfiguration.Status` |
| **FAIL Condition** | `Status == 'DISABLED'` or field absent |
| **Severity** | HIGH |
| **Pillar** | Security |
| **Usefulness** | ⭐⭐⭐⭐⭐ (10/10) — Direct compliance requirement |

```python
firehose_client = boto3.client('firehose')
desc = firehose_client.describe_delivery_stream(DeliveryStreamName=name)
stream = desc['DeliveryStreamDescription']
enc = stream.get('DeliveryStreamEncryptionConfiguration', {})
status = enc.get('Status', 'DISABLED')
if status == 'DISABLED':
    FAIL("Firehose delivery stream server-side encryption is not enabled")
```

---

### 15. `firehoseSSEDefaultKey`
| Field | Value |
|-------|-------|
| **Name** | Delivery Stream Using AWS-Owned CMK Instead of Customer-Managed |
| **API** | `describe_delivery_stream` → `DeliveryStreamEncryptionConfiguration.KeyType` |
| **FAIL Condition** | `KeyType == 'AWS_OWNED_CMK'` |
| **Severity** | MEDIUM |
| **Pillar** | Security |
| **Usefulness** | ⭐⭐⭐⭐ (7/10) — Best practice for key control |

```python
if enc.get('Status') == 'ENABLED' and enc.get('KeyType') == 'AWS_OWNED_CMK':
    WARN("Using AWS-owned CMK — recommend customer-managed CMK for full control")
```

---

### 16. `firehoseS3DestinationNoEncryption`
| Field | Value |
|-------|-------|
| **Name** | S3 Destination Encryption Not Configured |
| **API** | `describe_delivery_stream` → `Destinations[].ExtendedS3DestinationDescription.EncryptionConfiguration` |
| **FAIL Condition** | `EncryptionConfiguration.NoEncryptionConfig == 'NoEncryption'` AND no `KMSEncryptionConfig` |
| **Severity** | MEDIUM |
| **Pillar** | Security |
| **Usefulness** | ⭐⭐⭐⭐ (7/10) — Data-at-rest in S3 |
| **Notes** | Even if stream-level encryption is on, S3 destination should also have KMS encryption. Note: if the S3 bucket has default encryption, this may be redundant but still best practice to configure explicitly. |

```python
for dest in stream['Destinations']:
    s3_desc = dest.get('ExtendedS3DestinationDescription', dest.get('S3DestinationDescription', {}))
    enc_config = s3_desc.get('EncryptionConfiguration', {})
    if 'NoEncryptionConfig' in enc_config and not enc_config.get('KMSEncryptionConfig'):
        FAIL("S3 destination has no KMS encryption configured")
```

---

### 17. `firehoseLoggingDisabled`
| Field | Value |
|-------|-------|
| **Name** | CloudWatch Error Logging Not Enabled |
| **API** | `describe_delivery_stream` → `Destinations[].ExtendedS3DestinationDescription.CloudWatchLoggingOptions` |
| **FAIL Condition** | `CloudWatchLoggingOptions.Enabled == False` or absent |
| **Severity** | MEDIUM |
| **Pillar** | Operational Excellence |
| **Usefulness** | ⭐⭐⭐⭐⭐ (9/10) — Critical for troubleshooting delivery failures |

```python
for dest in stream['Destinations']:
    s3_desc = dest.get('ExtendedS3DestinationDescription', {})
    logging = s3_desc.get('CloudWatchLoggingOptions', {})
    if not logging.get('Enabled', False):
        FAIL("CloudWatch error logging not enabled on S3 destination")
```

---

### 18. `firehoseS3BackupDisabled`
| Field | Value |
|-------|-------|
| **Name** | Source Record Backup Not Enabled |
| **API** | `describe_delivery_stream` → `Destinations[].ExtendedS3DestinationDescription.S3BackupMode` |
| **FAIL Condition** | `S3BackupMode == 'Disabled'` AND processing is enabled |
| **Severity** | LOW |
| **Pillar** | Reliability |
| **Usefulness** | ⭐⭐⭐ (6/10) — Important when data transformation is active |
| **Notes** | Only relevant if `ProcessingConfiguration.Enabled == True`. Without backup, transformed data cannot be recovered to original form. |

```python
for dest in stream['Destinations']:
    s3_desc = dest.get('ExtendedS3DestinationDescription', {})
    processing = s3_desc.get('ProcessingConfiguration', {})
    if processing.get('Enabled', False):
        if s3_desc.get('S3BackupMode', 'Disabled') == 'Disabled':
            WARN("Data transformation enabled but source record backup is disabled")
```

---

### 19. `firehoseBufferingSuboptimal`
| Field | Value |
|-------|-------|
| **Name** | Buffering Configuration at Extremes |
| **API** | `describe_delivery_stream` → `Destinations[].ExtendedS3DestinationDescription.BufferingHints` |
| **FAIL Condition** | `IntervalInSeconds < 60` (too aggressive) OR `SizeInMBs < 1` (tiny files) |
| **Severity** | LOW |
| **Pillar** | Performance Efficiency / Cost Optimization |
| **Usefulness** | ⭐⭐ (4/10) — Very context-dependent |
| **Notes** | Very small buffer intervals create many small S3 objects (expensive for queries). Very large intervals increase data latency. This is advisory only. Default: 300s / 5MB. |

```python
for dest in stream['Destinations']:
    s3_desc = dest.get('ExtendedS3DestinationDescription', {})
    buffering = s3_desc.get('BufferingHints', {})
    interval = buffering.get('IntervalInSeconds', 300)
    size = buffering.get('SizeInMBs', 5)
    if interval < 60 or size < 1:
        INFO("Buffering configuration may create excessive small files in S3")
```

---

### 20. `firehoseNoTags`
| Field | Value |
|-------|-------|
| **Name** | Delivery Stream Has No Tags |
| **API** | `list_tags_for_delivery_stream(DeliveryStreamName)` |
| **FAIL Condition** | Empty tag list |
| **Severity** | LOW |
| **Pillar** | Operational Excellence |
| **Usefulness** | ⭐⭐⭐ (6/10) — Governance |

---

### 21. `firehoseStreamNotActive`
| Field | Value |
|-------|-------|
| **Name** | Delivery Stream in Failed State |
| **API** | `describe_delivery_stream` → `DeliveryStreamStatus` |
| **FAIL Condition** | `DeliveryStreamStatus` in `['CREATING_FAILED', 'DELETING_FAILED']` |
| **Severity** | HIGH |
| **Pillar** | Reliability |
| **Usefulness** | ⭐⭐⭐⭐ (8/10) — Indicates broken resource |

```python
status = stream['DeliveryStreamStatus']
if status in ['CREATING_FAILED', 'DELETING_FAILED']:
    FAIL(f"Delivery stream in failed state: {status}")
```

---

## TIER 5 — Cross-Service / Observability Checks

### 22. `kinesisNoCloudWatchAlarms`
| Field | Value |
|-------|-------|
| **Name** | No CloudWatch Alarms Configured for Stream |
| **API** | `cloudwatch:DescribeAlarms(Dimensions=[{Name:'StreamName', Value:stream_name}])` |
| **FAIL Condition** | No alarms found for the stream |
| **Severity** | LOW |
| **Pillar** | Operational Excellence |
| **Usefulness** | ⭐⭐⭐⭐ (7/10) — Operational monitoring |
| **Notes** | Key metrics to alarm on: `GetRecords.IteratorAgeMilliseconds`, `WriteProvisionedThroughputExceeded`, `ReadProvisionedThroughputExceeded`. This requires cross-service API call to CloudWatch. |

```python
cw_client = boto3.client('cloudwatch')
alarms = cw_client.describe_alarms(
    Dimensions=[{'Name': 'StreamName', 'Value': stream_name}]
)  # Note: This is a simplified approach
# More robust: describe_alarms_for_metric for each critical metric
if not alarms.get('MetricAlarms'):
    WARN("No CloudWatch alarms configured for this stream")
```

---

## Summary Table — All Checks

| # | Check Name | Tier | Severity | Pillar | API Client | Usefulness |
|---|-----------|------|----------|--------|-----------|-----------|
| 1 | `kinesisSSEDisabled` | 1 | HIGH | Security | kinesis | ⭐⭐⭐⭐⭐ |
| 2 | `kinesisSSEDefaultKey` | 1 | MEDIUM | Security | kinesis | ⭐⭐⭐⭐ |
| 3 | `kinesisKMSKeyRotationDisabled` | 1 | MEDIUM | Security | kinesis + kms | ⭐⭐⭐⭐ |
| 4 | `kinesisRetentionPeriodMinimum` | 1 | MEDIUM | Reliability | kinesis | ⭐⭐⭐⭐⭐ |
| 5 | `kinesisNoTags` | 1 | LOW | OpEx | kinesis | ⭐⭐⭐ |
| 6 | `kinesisEnhancedMonitoringDisabled` | 2 | MEDIUM | OpEx | kinesis | ⭐⭐⭐⭐⭐ |
| 7 | `kinesisStreamNotActive` | 2 | HIGH | Reliability | kinesis | ⭐⭐⭐ |
| 8 | `kinesisProvisionedModeNoAutoScaling` | 2 | LOW | PerfEff / Cost | kinesis | ⭐⭐⭐ |
| 9 | `kinesisShardUtilizationHigh` | 2 | MEDIUM | Reliability | kinesis | ⭐⭐⭐⭐ |
| 10 | `kinesisNoConsumers` | 2 | LOW | Cost | kinesis | ⭐⭐⭐ |
| 11 | `kinesisOnDemandPredictableWorkload` | 3 | LOW | Cost | kinesis | ⭐⭐ |
| 12 | `kinesisEnhancedMonitoringPartial` | 3 | LOW | OpEx | kinesis | ⭐⭐⭐ |
| 13 | `kinesisConsumerStuck` | 3 | MEDIUM | Reliability | kinesis | ⭐⭐⭐ |
| 14 | `firehoseSSEDisabled` | 1 | HIGH | Security | firehose | ⭐⭐⭐⭐⭐ |
| 15 | `firehoseSSEDefaultKey` | 1 | MEDIUM | Security | firehose | ⭐⭐⭐⭐ |
| 16 | `firehoseS3DestinationNoEncryption` | 1 | MEDIUM | Security | firehose | ⭐⭐⭐⭐ |
| 17 | `firehoseLoggingDisabled` | 2 | MEDIUM | OpEx | firehose | ⭐⭐⭐⭐⭐ |
| 18 | `firehoseS3BackupDisabled` | 2 | LOW | Reliability | firehose | ⭐⭐⭐ |
| 19 | `firehoseBufferingSuboptimal` | 3 | LOW | PerfEff / Cost | firehose | ⭐⭐ |
| 20 | `firehoseNoTags` | 1 | LOW | OpEx | firehose | ⭐⭐⭐ |
| 21 | `firehoseStreamNotActive` | 2 | HIGH | Reliability | firehose | ⭐⭐⭐⭐ |
| 22 | `kinesisNoCloudWatchAlarms` | 5 | LOW | OpEx | cloudwatch | ⭐⭐⭐⭐ |

---

## Implementation Recommendations

### Minimum Viable Service (Priority Order)
1. **kinesisSSEDisabled** — Aligns with Security Hub Kinesis.1
2. **kinesisRetentionPeriodMinimum** — Aligns with Security Hub Kinesis.3
3. **kinesisNoTags** — Aligns with Security Hub Kinesis.2
4. **kinesisEnhancedMonitoringDisabled** — High-value operational check
5. **kinesisSSEDefaultKey** — Beyond Security Hub baseline
6. **firehoseSSEDisabled** — Aligns with Security Hub DataFirehose.1

### IAM Permissions Required

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "kinesis:ListStreams",
        "kinesis:DescribeStream",
        "kinesis:DescribeStreamSummary",
        "kinesis:ListTagsForStream",
        "kinesis:ListStreamConsumers",
        "kinesis:DescribeLimits"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "firehose:ListDeliveryStreams",
        "firehose:DescribeDeliveryStream",
        "firehose:ListTagsForDeliveryStream"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "kms:DescribeKey",
        "kms:GetKeyRotationStatus"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "cloudwatch:DescribeAlarms",
        "cloudwatch:DescribeAlarmsForMetric"
      ],
      "Resource": "*"
    }
  ]
}
```

### API Call Cost Estimate (per run)
- **Per stream**: 1x `describe_stream_summary` + 1x `list_tags_for_stream` + 1x `list_stream_consumers` = 3 calls
- **Per account**: 1x `list_streams` + 1x `describe_limits` = 2 calls
- **Per Firehose stream**: 1x `describe_delivery_stream` + 1x `list_tags_for_delivery_stream` = 2 calls
- **Cross-service**: 1x `kms:GetKeyRotationStatus` per unique KMS key + 1x `cloudwatch:DescribeAlarms` per stream

For an account with 10 Kinesis streams + 5 Firehose streams: ~50 API calls total.

### Checks NOT Feasible via API (Out of Scope)
| Desired Check | Reason |
|--------------|--------|
| Consumer throughput/activity | Requires CloudWatch metrics querying (expensive, not config check) |
| Lambda trigger presence | Requires `lambda:ListEventSourceMappings` (separate service scope) |
| Application Auto Scaling config | Requires `application-autoscaling` API (separate service) |
| Stream capacity planning | Requires historical metrics analysis |
| VPC endpoint in use | Not a Kinesis-specific config |

### Firehose: Same Service or Separate?

**Recommendation: SEPARATE SERVICE** (`firehose`)

| Factor | Verdict |
|--------|---------|
| boto3 client | Different (`kinesis` vs `firehose`) |
| IAM namespace | Different (`kinesis:*` vs `firehose:*`) |
| Security Hub family | Different (`Kinesis.*` vs `DataFirehose.*`) |
| AWS Console | Separate section |
| Branding | "Amazon Data Firehose" (since 2024 rebrand) |
| Service-screener convention | Each boto3 client = separate service |
| User mental model | Separate (different pricing, different provisioning) |

The only argument for combining is that Firehose often consumes from Kinesis streams, but this is an architectural relationship, not an operational one.

---

## Response Fields Reference

### `describe_stream_summary` — Key Fields for Checks
```json
{
  "StreamDescriptionSummary": {
    "StreamName": "string",
    "StreamARN": "string",
    "StreamStatus": "CREATING|DELETING|ACTIVE|UPDATING",
    "StreamModeDetails": {
      "StreamMode": "PROVISIONED|ON_DEMAND"
    },
    "RetentionPeriodHours": 123,
    "StreamCreationTimestamp": "datetime",
    "EnhancedMonitoring": [
      {
        "ShardLevelMetrics": ["IncomingBytes", "OutgoingBytes", "ALL", ...]
      }
    ],
    "EncryptionType": "NONE|KMS",
    "KeyId": "string",
    "OpenShardCount": 123,
    "ConsumerCount": 123
  }
}
```

### `describe_delivery_stream` — Key Fields for Checks
```json
{
  "DeliveryStreamDescription": {
    "DeliveryStreamStatus": "CREATING|CREATING_FAILED|DELETING|DELETING_FAILED|ACTIVE",
    "DeliveryStreamEncryptionConfiguration": {
      "KeyARN": "string",
      "KeyType": "AWS_OWNED_CMK|CUSTOMER_MANAGED_CMK",
      "Status": "ENABLED|ENABLING|ENABLING_FAILED|DISABLED|DISABLING|DISABLING_FAILED"
    },
    "Destinations": [
      {
        "ExtendedS3DestinationDescription": {
          "BufferingHints": { "SizeInMBs": 123, "IntervalInSeconds": 123 },
          "EncryptionConfiguration": {
            "NoEncryptionConfig": "NoEncryption",
            "KMSEncryptionConfig": { "AWSKMSKeyARN": "string" }
          },
          "CloudWatchLoggingOptions": { "Enabled": true, "LogGroupName": "...", "LogStreamName": "..." },
          "S3BackupMode": "Disabled|Enabled",
          "ProcessingConfiguration": { "Enabled": true }
        }
      }
    ]
  }
}
```
