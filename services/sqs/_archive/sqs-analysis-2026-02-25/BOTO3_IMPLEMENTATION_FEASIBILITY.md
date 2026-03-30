# Boto3 Implementation Feasibility Analysis

**Generated:** 2024
**Purpose:** Research boto3 API availability for each identified gap and assess implementation feasibility

---

## Overview

This document analyzes the feasibility of implementing new checks for identified gaps in SQS best practices coverage. For each gap, we research:
- Available boto3 APIs
- Implementation complexity
- Value/impact of the check
- Overall feasibility rating

**Feasibility Ratings:**
- ✅ **Easy** - Straightforward implementation using existing APIs
- 🟡 **Moderate** - Requires additional logic or multiple API calls
- 🔴 **Complex** - Significant implementation effort or architectural changes
- ❌ **Not Feasible** - Cannot be implemented at queue level or requires application-level data

---

## Summary Table

| Gap # | Best Practice | Boto3 API Available | Complexity | Value | Feasibility |
|-------|--------------|---------------------|------------|-------|-------------|
| 1 | Wildcard Principal Detection | ✅ Yes (Policy attribute) | Easy | High | ✅ Easy |
| 2 | Role-Based Access Validation | ✅ Yes (Policy attribute) | Moderate | Medium | 🟡 Moderate |
| 3 | IAM Roles for Applications | ❌ No (Application-level) | N/A | Low | ❌ Not Feasible |
| 4 | VPC Endpoint Usage | ✅ Yes (Policy attribute) | Moderate | High | 🟡 Moderate |
| 5 | Long Polling Configuration | ✅ Yes (ReceiveMessageWaitTimeSeconds) | Easy | High | ✅ Easy |
| 6 | Polling Mode Guidance | ✅ Yes (ReceiveMessageWaitTimeSeconds) | Easy | Medium | ✅ Easy |
| 7 | maxReceiveCount=1 Detection | ✅ Yes (RedrivePolicy) | Easy | High | ✅ Easy |
| 8 | Idempotent Processing Guidance | ❌ No (Application-level) | N/A | Low | ❌ Not Feasible |
| 9 | Message Deduplication Validation | ✅ Yes (ContentBasedDeduplication) | Easy | Medium | ✅ Easy |
| 10 | Message Group Distribution | ❌ No (Runtime metrics) | N/A | Low | ❌ Not Feasible |
| 11 | ApproximateReceiveCount Monitoring | ✅ Yes (CloudWatch metrics) | Moderate | Medium | 🟡 Moderate |
| 12 | In-Flight Messages Monitoring | ✅ Yes (ApproximateNumberOfMessagesNotVisible) | Moderate | Medium | 🟡 Moderate |
| 13 | Queue Type Selection Guidance | ✅ Yes (FifoQueue attribute) | Easy | Medium | ✅ Easy |
| 14 | FIFO Appropriateness Validation | ✅ Yes (FifoQueue attribute) | Easy | Low | ✅ Easy |

**Summary:**
- ✅ **Easy**: 7 gaps (50%)
- 🟡 **Moderate**: 4 gaps (29%)
- 🔴 **Complex**: 0 gaps (0%)
- ❌ **Not Feasible**: 3 gaps (21%)

---

## Detailed Analysis

### Gap 1: Wildcard Principal Detection (Security)

**Best Practice:** Specifically flag wildcard principals ("*" or "") in queue policies as high-priority security issues

**Current Coverage:** 🟡 PARTIALLY COVERED by Check #3 (AccessPolicy)

**Boto3 API Research:**
- **API:** `get_queue_attributes()` with `AttributeNames=['Policy']`
- **Attribute:** `Policy` (JSON string containing IAM policy)
- **Data Available:** Full queue policy including Principal statements
- **Reference:** [boto3 SQS get_queue_attributes](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/sqs/client/get_queue_attributes.html)

**Implementation Approach:**
```python
# Get queue policy
attrs = sqs_client.get_queue_attributes(
    QueueUrl=queue_url,
    AttributeNames=['Policy']
)
policy = json.loads(attrs['Attributes'].get('Policy', '{}'))

# Check for wildcard principals
for statement in policy.get('Statement', []):
    principal = statement.get('Principal', {})
    if principal == '*' or principal == '' or principal.get('AWS') == '*':
        # Flag as high-priority security issue
        return FAIL
```

**Complexity:** Easy
- Simple JSON parsing of existing Policy attribute
- Pattern matching for wildcard values
- No additional API calls required

**Value:** High
- Critical security issue
- Common misconfiguration
- Easy to detect and fix

**Feasibility:** ✅ **Easy**

---

### Gap 2: Role-Based Access Validation (Security)

**Best Practice:** Validate that policies follow three access types: administrators, producers, consumers

**Current Coverage:** 🟡 PARTIALLY COVERED by Check #3 (AccessPolicy)

**Boto3 API Research:**
- **API:** `get_queue_attributes()` with `AttributeNames=['Policy']`
- **Attribute:** `Policy` (JSON string containing IAM policy)
- **Data Available:** Full queue policy including actions and principals
- **Reference:** [boto3 SQS get_queue_attributes](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/sqs/client/get_queue_attributes.html)

**Implementation Approach:**
```python
# Define role patterns
ADMIN_ACTIONS = ['sqs:*', 'sqs:DeleteQueue', 'sqs:SetQueueAttributes']
PRODUCER_ACTIONS = ['sqs:SendMessage', 'sqs:SendMessageBatch']
CONSUMER_ACTIONS = ['sqs:ReceiveMessage', 'sqs:DeleteMessage', 'sqs:ChangeMessageVisibility']

# Analyze policy statements
for statement in policy.get('Statement', []):
    actions = statement.get('Action', [])
    # Check if actions align with defined roles
    # Provide guidance on role-based access patterns
```

**Complexity:** Moderate
- Requires defining role patterns
- Complex policy analysis logic
- May need heuristics for mixed permissions

**Value:** Medium
- Improves security posture
- Helps enforce least privilege
- May be subjective in some cases

**Feasibility:** 🟡 **Moderate**

---

### Gap 3: IAM Roles for Applications (Security)

**Best Practice:** Ensure applications use IAM roles instead of hardcoded credentials

**Current Coverage:** ❌ NOT COVERED

**Boto3 API Research:**
- **API:** None available
- **Data Available:** Queue-level configuration only
- **Limitation:** Cannot detect how applications authenticate to SQS

**Implementation Approach:**
Not feasible - this is an application-level concern, not queue-level configuration.

**Complexity:** N/A

**Value:** Low (for queue-level checks)
- Important security practice
- But cannot be validated at queue level
- Requires application code analysis or CloudTrail analysis

**Feasibility:** ❌ **Not Feasible**
- Application architecture decision
- No queue-level indicators
- Would require CloudTrail analysis of API calls (complex and unreliable)

---

### Gap 4: VPC Endpoint Usage (Security)

**Best Practice:** Detect VPC endpoint usage and VPC-restricted access policies

**Current Coverage:** ❌ NOT COVERED

**Boto3 API Research:**
- **API:** `get_queue_attributes()` with `AttributeNames=['Policy']`
- **Attribute:** `Policy` (JSON string containing IAM policy)
- **Data Available:** Policy conditions including `aws:SourceVpce` and `aws:SourceVpc`
- **Reference:** [boto3 SQS get_queue_attributes](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/sqs/client/get_queue_attributes.html)

**Implementation Approach:**
```python
# Check for VPC endpoint conditions in policy
policy = json.loads(attrs['Attributes'].get('Policy', '{}'))

has_vpc_restriction = False
for statement in policy.get('Statement', []):
    condition = statement.get('Condition', {})
    if 'StringEquals' in condition:
        if 'aws:SourceVpce' in condition['StringEquals'] or \
           'aws:SourceVpc' in condition['StringEquals']:
            has_vpc_restriction = True
            break

if not has_vpc_restriction:
    # Recommend VPC endpoint usage
    return FAIL
```

**Complexity:** Moderate
- Policy parsing and condition analysis
- Need to understand VPC endpoint patterns
- May need to check for Deny statements without VPC conditions

**Value:** High
- Important security control
- Prevents public internet access
- Common compliance requirement

**Feasibility:** 🟡 **Moderate**

---

### Gap 5: Long Polling Configuration (Message Processing)

**Best Practice:** Enable long polling to reduce empty responses and costs

**Current Coverage:** ❌ NOT COVERED

**Boto3 API Research:**
- **API:** `get_queue_attributes()` with `AttributeNames=['ReceiveMessageWaitTimeSeconds']`
- **Attribute:** `ReceiveMessageWaitTimeSeconds` (integer, 0-20 seconds)
- **Data Available:** Direct attribute value
- **Reference:** [boto3 SQS get_queue_attributes](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/sqs/client/get_queue_attributes.html)

**Implementation Approach:**
```python
# Get ReceiveMessageWaitTimeSeconds attribute
attrs = sqs_client.get_queue_attributes(
    QueueUrl=queue_url,
    AttributeNames=['ReceiveMessageWaitTimeSeconds']
)

wait_time = int(attrs['Attributes'].get('ReceiveMessageWaitTimeSeconds', 0))

if wait_time == 0:
    # Short polling detected - recommend long polling
    return FAIL
elif wait_time < 5:
    # Suboptimal long polling - recommend 10-20 seconds
    return WARNING
else:
    return PASS
```

**Complexity:** Easy
- Single attribute check
- Simple integer comparison
- Clear pass/fail criteria

**Value:** High
- Cost optimization
- Performance improvement
- Easy to implement and fix

**Feasibility:** ✅ **Easy**

---

### Gap 6: Polling Mode Guidance (Message Processing)

**Best Practice:** Provide guidance on choosing appropriate polling mode

**Current Coverage:** ❌ NOT COVERED

**Boto3 API Research:**
- **API:** `get_queue_attributes()` with `AttributeNames=['ReceiveMessageWaitTimeSeconds']`
- **Attribute:** `ReceiveMessageWaitTimeSeconds` (integer, 0-20 seconds)
- **Data Available:** Direct attribute value
- **Reference:** [boto3 SQS get_queue_attributes](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/sqs/client/get_queue_attributes.html)

**Implementation Approach:**
```python
# Same as Gap 5 - provide informational guidance
wait_time = int(attrs['Attributes'].get('ReceiveMessageWaitTimeSeconds', 0))

# Provide guidance based on configuration
if wait_time == 0:
    message = "Short polling: Higher costs, immediate response. Consider long polling for most use cases."
elif wait_time >= 10:
    message = "Long polling: Cost-effective, slight latency. Good for most use cases."
else:
    message = "Partial long polling: Consider increasing to 10-20 seconds for better cost optimization."
```

**Complexity:** Easy
- Same API as Gap 5
- Informational check
- Can be combined with Gap 5

**Value:** Medium
- Educational value
- Helps users understand trade-offs
- Low priority (overlaps with Gap 5)

**Feasibility:** ✅ **Easy**

---

### Gap 7: maxReceiveCount=1 Detection (Error Handling)

**Best Practice:** Flag maxReceiveCount=1 as anti-pattern for distributed systems

**Current Coverage:** 🟡 PARTIALLY COVERED by Check #4 (DeadLetterQueue)

**Boto3 API Research:**
- **API:** `get_queue_attributes()` with `AttributeNames=['RedrivePolicy']`
- **Attribute:** `RedrivePolicy` (JSON string with maxReceiveCount)
- **Data Available:** maxReceiveCount value
- **Reference:** [boto3 SQS get_queue_attributes](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/sqs/client/get_queue_attributes.html)

**Implementation Approach:**
```python
# Get RedrivePolicy attribute
attrs = sqs_client.get_queue_attributes(
    QueueUrl=queue_url,
    AttributeNames=['RedrivePolicy']
)

redrive_policy = attrs['Attributes'].get('RedrivePolicy')
if redrive_policy:
    policy = json.loads(redrive_policy)
    max_receive_count = policy.get('maxReceiveCount', 0)
    
    if max_receive_count == 1:
        # Flag as anti-pattern
        return FAIL
    elif max_receive_count < 3:
        # Warn about low threshold
        return WARNING
```

**Complexity:** Easy
- JSON parsing of existing attribute
- Simple integer comparison
- Can enhance existing Check #4

**Value:** High
- Prevents common misconfiguration
- Important for distributed systems
- Easy to detect and fix

**Feasibility:** ✅ **Easy**

---

### Gap 8: Idempotent Processing Guidance (Error Handling)

**Best Practice:** Provide guidance on designing idempotent message processing

**Current Coverage:** ❌ NOT COVERED

**Boto3 API Research:**
- **API:** None available
- **Data Available:** Queue-level configuration only
- **Limitation:** Cannot detect application-level processing logic

**Implementation Approach:**
Not feasible - this is an application design concern, not queue-level configuration.

**Complexity:** N/A

**Value:** Low (for queue-level checks)
- Important application design principle
- But cannot be validated at queue level
- Requires application code analysis

**Feasibility:** ❌ **Not Feasible**
- Application architecture decision
- No queue-level indicators
- Could provide informational guidance only

---

### Gap 9: Message Deduplication Validation (Message Deduplication)

**Best Practice:** Validate message deduplication configuration for FIFO queues

**Current Coverage:** 🟡 PARTIALLY COVERED by Check #5 (FifoConfiguration)

**Boto3 API Research:**
- **API:** `get_queue_attributes()` with `AttributeNames=['ContentBasedDeduplication', 'FifoQueue']`
- **Attributes:** 
  - `ContentBasedDeduplication` (boolean)
  - `FifoQueue` (boolean)
- **Data Available:** Direct attribute values
- **Reference:** [boto3 SQS get_queue_attributes](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/sqs/client/get_queue_attributes.html)

**Implementation Approach:**
```python
# Get FIFO and deduplication attributes
attrs = sqs_client.get_queue_attributes(
    QueueUrl=queue_url,
    AttributeNames=['FifoQueue', 'ContentBasedDeduplication']
)

is_fifo = attrs['Attributes'].get('FifoQueue', 'false') == 'true'
content_dedup = attrs['Attributes'].get('ContentBasedDeduplication', 'false') == 'true'

if is_fifo and not content_dedup:
    # Recommend enabling content-based deduplication
    return WARNING  # Not FAIL because manual dedup IDs are valid
```

**Complexity:** Easy
- Simple attribute checks
- Boolean logic
- Can enhance existing Check #5

**Value:** Medium
- Improves FIFO queue reliability
- Prevents duplicate processing
- Already partially covered

**Feasibility:** ✅ **Easy**

---

### Gap 10: Message Group Distribution (Message Deduplication)

**Best Practice:** Monitor message group ID distribution to avoid backlogs

**Current Coverage:** ❌ NOT COVERED

**Boto3 API Research:**
- **API:** None available for message group distribution
- **Data Available:** Queue-level metrics only
- **Limitation:** Message group IDs are set by producers at runtime

**Implementation Approach:**
Not feasible - message group distribution is runtime behavior, not queue configuration.

**Complexity:** N/A

**Value:** Low (for queue-level checks)
- Important for FIFO queue performance
- But requires runtime message analysis
- Cannot be determined from queue attributes

**Feasibility:** ❌ **Not Feasible**
- Runtime behavior, not configuration
- Would require message sampling (expensive and unreliable)
- Could provide informational guidance only

---

### Gap 11: ApproximateReceiveCount Monitoring (Message Deduplication)

**Best Practice:** Track messages with high receive counts before DLQ threshold

**Current Coverage:** 🟡 PARTIALLY COVERED by Check #10 (QueueMonitoring)

**Boto3 API Research:**
- **API:** `cloudwatch.get_metric_statistics()` or `cloudwatch.put_metric_alarm()`
- **Metric:** Custom metric based on message attributes (not directly available)
- **Alternative:** Check for CloudWatch alarms on `ApproximateAgeOfOldestMessage`
- **Reference:** [boto3 CloudWatch](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/cloudwatch.html)

**Implementation Approach:**
```python
# Check for CloudWatch alarms on message age
cloudwatch = boto3.client('cloudwatch')

# List alarms for this queue
alarms = cloudwatch.describe_alarms_for_metric(
    MetricName='ApproximateAgeOfOldestMessage',
    Namespace='AWS/SQS',
    Dimensions=[
        {'Name': 'QueueName', 'Value': queue_name}
    ]
)

# Check if alarm exists and is properly configured
if not alarms['MetricAlarms']:
    return FAIL  # No monitoring for old messages
```

**Complexity:** Moderate
- Requires CloudWatch API calls
- Need to validate alarm configuration
- Indirect indicator of receive count issues

**Value:** Medium
- Helps identify problematic messages early
- Prevents message loss
- Complements DLQ configuration

**Feasibility:** 🟡 **Moderate**

---

### Gap 12: In-Flight Messages Monitoring (Visibility Timeout)

**Best Practice:** Monitor ApproximateNumberOfMessagesNotVisible metric

**Current Coverage:** 🟡 PARTIALLY COVERED by Check #10 (QueueMonitoring)

**Boto3 API Research:**
- **API:** `get_queue_attributes()` with `AttributeNames=['ApproximateNumberOfMessagesNotVisible']`
- **Attribute:** `ApproximateNumberOfMessagesNotVisible` (integer)
- **Alternative:** CloudWatch alarms on this metric
- **Reference:** [boto3 SQS get_queue_attributes](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/sqs/client/get_queue_attributes.html)

**Implementation Approach:**
```python
# Check for CloudWatch alarms on in-flight messages
cloudwatch = boto3.client('cloudwatch')

alarms = cloudwatch.describe_alarms_for_metric(
    MetricName='ApproximateNumberOfMessagesNotVisible',
    Namespace='AWS/SQS',
    Dimensions=[
        {'Name': 'QueueName', 'Value': queue_name}
    ]
)

if not alarms['MetricAlarms']:
    return FAIL  # No monitoring for in-flight messages

# Optionally check current value
attrs = sqs_client.get_queue_attributes(
    QueueUrl=queue_url,
    AttributeNames=['ApproximateNumberOfMessagesNotVisible']
)
in_flight = int(attrs['Attributes'].get('ApproximateNumberOfMessagesNotVisible', 0))
```

**Complexity:** Moderate
- Requires CloudWatch API calls
- Need to validate alarm configuration
- Can enhance existing Check #10

**Value:** Medium
- Identifies processing bottlenecks
- Helps tune visibility timeout
- Complements existing monitoring

**Feasibility:** 🟡 **Moderate**

---

### Gap 13: Queue Type Selection Guidance (Queue Type)

**Best Practice:** Provide guidance on choosing standard vs. FIFO queues

**Current Coverage:** ❌ NOT COVERED

**Boto3 API Research:**
- **API:** `get_queue_attributes()` with `AttributeNames=['FifoQueue']`
- **Attribute:** `FifoQueue` (boolean)
- **Data Available:** Queue type
- **Reference:** [boto3 SQS get_queue_attributes](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/sqs/client/get_queue_attributes.html)

**Implementation Approach:**
```python
# Get queue type
attrs = sqs_client.get_queue_attributes(
    QueueUrl=queue_url,
    AttributeNames=['FifoQueue']
)

is_fifo = attrs['Attributes'].get('FifoQueue', 'false') == 'true'

# Provide informational guidance
if is_fifo:
    message = "FIFO queue: Exactly-once processing, ordered delivery, 300 TPS limit. "
    message += "Consider standard queue if ordering not required and higher throughput needed."
else:
    message = "Standard queue: High throughput, at-least-once delivery. "
    message += "Consider FIFO queue if message ordering or exactly-once processing required."

return INFO  # Informational only
```

**Complexity:** Easy
- Single attribute check
- Informational guidance
- No complex logic

**Value:** Medium
- Educational value
- Helps users understand trade-offs
- Queue type cannot be changed after creation

**Feasibility:** ✅ **Easy**

---

### Gap 14: FIFO Appropriateness Validation (Queue Type)

**Best Practice:** Validate that FIFO is appropriate for the use case

**Current Coverage:** ❌ NOT COVERED

**Boto3 API Research:**
- **API:** `get_queue_attributes()` with `AttributeNames=['FifoQueue']`
- **Attribute:** `FifoQueue` (boolean)
- **Data Available:** Queue type only
- **Limitation:** Cannot determine use case appropriateness from queue attributes

**Implementation Approach:**
```python
# Same as Gap 13 - provide informational guidance
is_fifo = attrs['Attributes'].get('FifoQueue', 'false') == 'true'

# Can only provide general guidance, not validate appropriateness
if is_fifo:
    message = "FIFO queue detected. Ensure your use case requires: "
    message += "1) Message ordering, 2) Exactly-once processing, 3) Throughput < 300 TPS"
    return INFO
```

**Complexity:** Easy
- Same as Gap 13
- Informational only
- Cannot validate actual appropriateness

**Value:** Low
- Limited actionable value
- Cannot determine use case from queue config
- Overlaps with Gap 13

**Feasibility:** ✅ **Easy** (but limited value)

---

## Implementation Priority Recommendations

Based on feasibility analysis, recommended implementation order:

### Tier 1: High Priority (Easy + High Value)
1. **Gap 5: Long Polling Configuration** - ✅ Easy, High Value
2. **Gap 1: Wildcard Principal Detection** - ✅ Easy, High Value
3. **Gap 7: maxReceiveCount=1 Detection** - ✅ Easy, High Value

### Tier 2: Medium Priority (Moderate Complexity or Medium Value)
4. **Gap 4: VPC Endpoint Usage** - 🟡 Moderate, High Value
5. **Gap 11: ApproximateReceiveCount Monitoring** - 🟡 Moderate, Medium Value
6. **Gap 12: In-Flight Messages Monitoring** - 🟡 Moderate, Medium Value
7. **Gap 2: Role-Based Access Validation** - 🟡 Moderate, Medium Value

### Tier 3: Low Priority (Easy but Low Value)
8. **Gap 6: Polling Mode Guidance** - ✅ Easy, Medium Value (overlaps Gap 5)
9. **Gap 9: Message Deduplication Validation** - ✅ Easy, Medium Value (enhance existing)
10. **Gap 13: Queue Type Selection Guidance** - ✅ Easy, Medium Value (informational)
11. **Gap 14: FIFO Appropriateness Validation** - ✅ Easy, Low Value (overlaps Gap 13)

### Not Recommended for Implementation
- **Gap 3: IAM Roles for Applications** - ❌ Not Feasible (application-level)
- **Gap 8: Idempotent Processing Guidance** - ❌ Not Feasible (application-level)
- **Gap 10: Message Group Distribution** - ❌ Not Feasible (runtime behavior)

---

## Boto3 API Reference Summary

### Primary APIs Used:
1. **`sqs_client.get_queue_attributes()`** - Main API for queue configuration
   - Attributes: Policy, ReceiveMessageWaitTimeSeconds, RedrivePolicy, FifoQueue, ContentBasedDeduplication, ApproximateNumberOfMessagesNotVisible
   - Reference: [boto3 SQS get_queue_attributes](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/sqs/client/get_queue_attributes.html)

2. **`cloudwatch_client.describe_alarms_for_metric()`** - Check for monitoring alarms
   - Metrics: ApproximateAgeOfOldestMessage, ApproximateNumberOfMessagesNotVisible
   - Reference: [boto3 CloudWatch describe_alarms_for_metric](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/cloudwatch/client/describe_alarms_for_metric.html)

3. **`sqs_client.list_queues()`** - Already used in existing implementation
   - Reference: [boto3 SQS list_queues](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/sqs/client/list_queues.html)

### No Additional Clients Required:
- All feasible checks can be implemented using existing `sqs_client` and `cloudwatch_client`
- No new boto3 clients need to be added to the service class

---

## Next Steps

1. **Task 2.2.3**: Determine implementation complexity for each gap (completed in this document)
2. **Task 2.2.4**: Assess value/impact for each gap (completed in this document)
3. **Task 2.2.5**: Mark feasibility ratings (completed in this document)
4. **Task 2.3**: Prioritize checks into tiers based on this analysis

---

## References

- [Boto3 SQS Client Documentation](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/sqs.html)
- [Boto3 CloudWatch Client Documentation](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/cloudwatch.html)
- [AWS SQS Best Practices](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-best-practices.html)
- Current Implementation: `service-screener-v2/services/sqs/Sqs.py`
- Gap Analysis: `BEST_PRACTICES_COVERAGE.md`
