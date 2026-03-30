# SQS Driver Structure Documentation

## Overview

The SQS service implementation follows a three-tier architecture:
1. **Service Class** (`Sqs.py`) - Resource discovery and orchestration
2. **Driver Class** (`SqsQueueDriver.py`) - Check implementation
3. **Reporter Configuration** (`sqs.reporter.json`) - Check metadata and descriptions

## Architecture Components

### 1. Service Class: `Sqs.py`

**Purpose**: Discovers SQS resources and orchestrates check execution

**Key Responsibilities**:
- Initialize AWS clients (SQS, CloudWatch, CloudTrail)
- Discover all SQS queues in the region
- Handle pagination and tag filtering
- Build DLQ relationship mapping
- Instantiate drivers for each queue
- Aggregate and return results

**Key Methods**:
- `__init__(region)` - Initialize boto3 clients
- `getResources()` - Discover and return all SQS queues with attributes
- `advise()` - Main entry point that runs checks on all queues

**Resource Discovery Flow**:
```python
1. List all queue URLs
2. For each queue:
   - Get queue attributes (encryption, retention, etc.)
   - Extract DLQ relationships
   - Apply tag filtering if specified
   - Build queue data structure
3. Add DLQ usage information (which queues use this as DLQ)
4. Return list of queue objects
```

### 2. Driver Class: `SqsQueueDriver.py`

**Purpose**: Implements individual checks for a single SQS queue

**Inheritance**: `Evaluator` (base class from framework)

**Key Attributes**:
- `queue` - Queue data from service discovery
- `sqs_client` - Boto3 SQS client
- `cloudwatch_client` - Boto3 CloudWatch client
- `cloudtrail_client` - Boto3 CloudTrail client (optional)
- `queue_url` - Queue URL
- `queue_name` - Queue name
- `attributes` - Queue attributes dictionary
- `results` - Dictionary storing check results

**Check Method Naming Convention**:
All check methods follow the pattern: `_check{CheckID}()`

Example: `_checkEncryptionAtRest()` corresponds to check ID "EncryptionAtRest"

**Check Method Structure**:
```python
def _checkCheckName(self):
    """
    Brief description of what this check validates.
    """
    # 1. Retrieve relevant data from queue attributes or AWS APIs
    # 2. Apply business logic to evaluate the check
    # 3. Store result in self.results dictionary
    
    # Result format: [status_code, message]
    # status_code: 1 (pass), 0 (warning), -1 (fail)
    self.results['CheckName'] = [status_code, 'Descriptive message']
```

**Framework Integration**:
- Inherits from `Evaluator` base class
- Uses `self.addII(key, value)` to store inventory information
- Uses `self.results[checkId] = [status, message]` to store check results
- Framework automatically discovers and runs all `_check*` methods
- Supports concurrent execution for better performance

### 3. Reporter Configuration: `sqs.reporter.json`

**Purpose**: Defines metadata for each check

**Structure**:
```json
{
    "CheckID": {
        "category": "S|R|P|C|O",  // Security, Reliability, Performance, Cost, Operational
        "^description": "Description with {$COUNT} placeholder",
        "shortDesc": "Brief description",
        "criticality": "H|M|L",  // High, Medium, Low
        "downtime": 0|1,
        "slowness": 0|1,
        "additionalCost": -1|0|1,  // Reduces cost, neutral, increases cost
        "needFullTest": 0|1,
        "ref": ["[Link text]<URL>"]
    }
}
```

**Categories**:
- **S** (Security) - Encryption, access control, policies
- **R** (Reliability) - DLQ, FIFO configuration
- **P** (Performance) - Visibility timeout, batch operations
- **C** (Cost) - Message retention, unused queues
- **O** (Operational) - Monitoring, tagging

## Current Implementation

### Implemented Checks

| Check ID | Category | Method | Description |
|----------|----------|--------|-------------|
| EncryptionAtRest | Security | `_checkEncryptionAtRest()` | Validates SSE-SQS or SSE-KMS encryption |
| EncryptionInTransit | Security | `_checkEncryptionInTransit()` | Validates HTTPS-only policy enforcement |
| DeadLetterQueue | Reliability | `_checkDeadLetterQueue()` | Validates DLQ configuration |
| VisibilityTimeout | Performance | `_checkVisibilityTimeout()` | Validates timeout settings (30s-12h) |
| MessageRetention | Cost | `_checkMessageRetention()` | Validates retention period optimization |
| QueueMonitoring | Operational | `_checkQueueMonitoring()` | Validates CloudWatch alarms |
| FifoConfiguration | Reliability | `_checkFifoConfiguration()` | Validates FIFO queue settings |
| AccessPolicy | Security | `_checkAccessPolicy()` | Validates least privilege policies |
| BatchOperations | Performance | `_checkBatchOperations()` | Suggests batch operation usage |
| UnusedQueues | Cost | `_checkUnusedQueues()` | Identifies inactive queues |
| TaggingStrategy | Operational | `_checkTaggingStrategy()` | Validates resource tagging |

### Check Execution Flow

```
1. Sqs.advise() called
   ↓
2. Sqs.getResources() discovers all queues
   ↓
3. For each queue:
   a. Create SqsQueueDriver instance
   b. Call driver.run(Sqs)
   c. Framework discovers all _check* methods
   d. Execute checks (concurrent by default)
   e. Store results in driver.results
   f. Call driver.getInfo() to retrieve results
   ↓
4. Aggregate all results
   ↓
5. Return results dictionary
```

## Data Flow

### Queue Attributes Available to Checks

The driver has access to all queue attributes via `self.attributes`:

```python
{
    'QueueArn': 'arn:aws:sqs:region:account:queue-name',
    'ApproximateNumberOfMessages': '0',
    'ApproximateNumberOfMessagesNotVisible': '0',
    'ApproximateNumberOfMessagesDelayed': '0',
    'CreatedTimestamp': '1234567890',
    'LastModifiedTimestamp': '1234567890',
    'VisibilityTimeout': '30',
    'MaximumMessageSize': '262144',
    'MessageRetentionPeriod': '345600',
    'DelaySeconds': '0',
    'ReceiveMessageWaitTimeSeconds': '0',
    'Policy': '{"Statement": [...]}',  // Queue policy JSON
    'RedrivePolicy': '{"deadLetterTargetArn": "...", "maxReceiveCount": 5}',
    'KmsMasterKeyId': 'arn:aws:kms:...',  // If KMS encrypted
    'SqsManagedSseEnabled': 'true',  // If SSE-SQS enabled
    'FifoQueue': 'true',  // For FIFO queues
    'ContentBasedDeduplication': 'true'  // For FIFO queues
}
```

### Additional Data Sources

Checks can query additional AWS services:

1. **CloudWatch Metrics** (via `self.cloudwatch_client`)
   - Message counts
   - Queue age
   - Activity patterns

2. **CloudTrail Events** (via `self.cloudtrail_client`)
   - API call history
   - Batch operation usage

3. **SQS Tags** (via `self.sqs_client.list_queue_tags()`)
   - Resource tagging information

## Adding New Checks

### Step-by-Step Process

1. **Add check definition to `sqs.reporter.json`**:
```json
"NewCheckName": {
    "category": "S",
    "^description": "Description with {$COUNT}",
    "shortDesc": "Brief description",
    "criticality": "H",
    "downtime": 0,
    "slowness": 0,
    "additionalCost": 0,
    "needFullTest": 1,
    "ref": ["[Link]<URL>"]
}
```

2. **Implement check method in `SqsQueueDriver.py`**:
```python
def _checkNewCheckName(self):
    """
    Description of what this check validates.
    """
    # Retrieve data
    attribute_value = self.attributes.get('AttributeName')
    
    # Apply logic
    if condition_passes:
        self.results['NewCheckName'] = [1, 'Pass message']
    else:
        self.results['NewCheckName'] = [-1, 'Fail message']
```

3. **Test the implementation**:
   - Framework automatically discovers the new method
   - No registration required
   - Method name must match check ID in reporter.json

### Best Practices

1. **Error Handling**: Wrap API calls in try/except blocks
2. **Result Format**: Always use `[status_code, message]` format
3. **Status Codes**: 
   - `1` = Pass (green)
   - `0` = Warning (yellow)
   - `-1` = Fail (red)
4. **Messages**: Be descriptive and actionable
5. **Performance**: Use concurrent execution (default)
6. **Documentation**: Add docstrings to check methods

## Framework Features

### Automatic Check Discovery

The framework automatically discovers and runs all methods starting with `_check`:

```python
methods = [method for method in dir(self) 
           if method.startswith('_check')]
```

### Concurrent Execution

By default, checks run concurrently for better performance:

```python
with cf.ThreadPoolExecutor() as executor:
    futures = [executor.submit(runSingleCheck, self, method) 
               for method in filteredMethods]
```

Use `--sequential` flag to disable concurrent execution for debugging.

### Rule Filtering

Run specific checks only:

```bash
# Run only encryption checks
screener --service sqs --rules encryptionatrest^encryptionintransit
```

### Tag Filtering

Filter resources by tags:

```bash
# Only scan queues with specific tags
screener --service sqs --tags Environment=Production
```

## Integration Points

### With Service Screener Framework

1. **Service Registration**: Service class inherits from `Service` base class
2. **Driver Registration**: Driver inherits from `Evaluator` base class
3. **Result Aggregation**: Framework collects results from all drivers
4. **Report Generation**: Framework uses reporter.json for formatting

### With AWS APIs

1. **SQS**: Queue attributes, tags
2. **CloudWatch**: Metrics, alarms
3. **CloudTrail**: API call history (optional)

## File Locations

```
service-screener-v2/services/sqs/
├── Sqs.py                      # Service class
├── sqs.reporter.json           # Check metadata
├── drivers/
│   └── SqsQueueDriver.py       # Driver implementation
├── best-practices.md           # AWS best practices reference
├── EXISTING_CHECKS.md          # Current check documentation
└── DRIVER_STRUCTURE.md         # This file
```

## Summary

The SQS driver structure follows a clean separation of concerns:

- **Service class** handles resource discovery
- **Driver class** implements check logic
- **Reporter config** defines check metadata

This architecture makes it easy to:
- Add new checks (just add method + reporter entry)
- Maintain existing checks (logic isolated in driver)
- Scale performance (concurrent execution)
- Filter execution (by rules or tags)
