# SQS Service - Existing Checks

## Overview
This document lists all existing checks in the SQS service review, organized by category.

**Total Checks: 11**

---

## Security (S) - 3 Checks

### 1. EncryptionAtRest
- **Criticality:** High
- **Description:** Detects SQS queues without server-side encryption enabled
- **Recommendation:** Enable SSE-SQS or SSE-KMS to encrypt messages at rest
- **Impact:** Additional Cost
- **Reference:** [Encryption at rest](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-server-side-encryption.html)

### 2. EncryptionInTransit
- **Criticality:** Medium
- **Description:** Detects SQS queues without HTTPS-only access policies
- **Recommendation:** Add queue policies with aws:SecureTransport condition to enforce HTTPS
- **Impact:** No additional cost
- **Reference:** [Enforce HTTPS](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-security-best-practices.html)

### 3. AccessPolicy
- **Criticality:** High
- **Description:** Detects SQS queues with overly permissive access policies
- **Recommendation:** Review and restrict permissions to follow least privilege principle
- **Impact:** No additional cost
- **Reference:** [Access control](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-security-best-practices.html)

---

## Reliability (R) - 2 Checks

### 4. DeadLetterQueue
- **Criticality:** Medium
- **Description:** Detects SQS queues without dead letter queue configuration
- **Recommendation:** Configure DLQs to capture and analyze failed messages
- **Impact:** Additional Cost
- **Reference:** [Dead letter queues](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-dead-letter-queues.html)

### 5. FifoConfiguration
- **Criticality:** Medium
- **Description:** Detects FIFO queues with suboptimal configuration
- **Recommendation:** Enable content-based deduplication where appropriate and ensure proper message group ID usage
- **Impact:** No additional cost
- **Reference:** [FIFO queues](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/FIFO-queues.html)

---

## Performance (P) - 2 Checks

### 6. VisibilityTimeout
- **Criticality:** Medium
- **Description:** Detects SQS queues with default or inappropriate visibility timeout settings
- **Recommendation:** Adjust timeout based on processing requirements
- **Impact:** Potential slowness
- **Reference:** [Visibility timeout](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-visibility-timeout.html)

### 7. BatchOperations
- **Criticality:** Low
- **Description:** Identifies queues that could benefit from batch operations
- **Recommendation:** Use SendMessageBatch and ReceiveMessage with MaxNumberOfMessages > 1
- **Impact:** Cost reduction
- **Reference:** [Batch operations](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-batch-api-actions.html)

---

## Cost (C) - 2 Checks

### 8. MessageRetention
- **Criticality:** Low
- **Description:** Detects SQS queues with maximum message retention period (14 days)
- **Recommendation:** Reduce retention time if messages don't need to be stored that long
- **Impact:** Cost reduction
- **Reference:** [Message retention](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-message-metadata.html)

### 9. UnusedQueues
- **Criticality:** Low
- **Description:** Detects SQS queues with no activity in the past 30 days
- **Recommendation:** Review and consider deleting if no longer needed
- **Impact:** Cost reduction and reduced operational overhead
- **Reference:** [Cost optimization](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-cost-optimization.html)

---

## Operations (O) - 2 Checks

### 10. QueueMonitoring
- **Criticality:** Medium
- **Description:** Detects SQS queues without CloudWatch alarms configured
- **Recommendation:** Set up alarms for key metrics like message count and age
- **Impact:** Additional Cost
- **References:** 
  - [SQS Handling requests errors](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/handling-request-errors.html)
  - [SQS capture problematic messages](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/capturing-problematic-messages.html)

### 11. TaggingStrategy
- **Criticality:** Low
- **Description:** Detects SQS queues without proper tagging
- **Recommendation:** Implement consistent tagging strategy for cost allocation and resource management
- **Impact:** No additional cost
- **Reference:** [Tagging best practices](https://docs.aws.amazon.com/general/latest/gr/aws_tagging.html)

---

## Summary by Category

| Category | Count | High Criticality | Medium Criticality | Low Criticality |
|----------|-------|------------------|-------------------|-----------------|
| Security (S) | 3 | 2 | 1 | 0 |
| Reliability (R) | 2 | 0 | 2 | 0 |
| Performance (P) | 2 | 0 | 1 | 1 |
| Cost (C) | 2 | 0 | 0 | 2 |
| Operations (O) | 2 | 0 | 1 | 1 |
| **Total** | **11** | **2** | **5** | **4** |

---

## Coverage Analysis

### Well-Architected Framework Pillars
- ✅ **Security:** 3 checks (27%)
- ✅ **Reliability:** 2 checks (18%)
- ✅ **Performance Efficiency:** 2 checks (18%)
- ✅ **Cost Optimization:** 2 checks (18%)
- ✅ **Operational Excellence:** 2 checks (18%)

All five pillars of the AWS Well-Architected Framework are represented in the current implementation.
