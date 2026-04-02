# CloudWatch Service Driver Structure

## Overview

The CloudWatch service implementation follows the service-screener-v2 architecture pattern with a main service class and specialized driver classes for different resource types.

## Architecture Components

### 1. Main Service Class: `Cloudwatch.py`

**Location**: `service-screener-v2/services/cloudwatch/Cloudwatch.py`

**Purpose**: Orchestrates the scanning process by:
- Initializing AWS service clients (CloudWatch, CloudWatch Logs, CloudTrail)
- Collecting resources to be scanned
- Instantiating appropriate drivers for each resource
- Aggregating results from all drivers

**Key Responsibilities**:
- **Client Initialization**: Creates boto3 clients for:
  - `cloudwatch` - CloudWatch metrics and alarms
  - `logs` - CloudWatch Logs
  - `cloudtrail` - CloudTrail integration
  
- **Resource Collection**: 
  - `loopTrail()` - Collects CloudTrail trails with CloudWatch Logs integration
  - `getAllLogs()` - Collects all CloudWatch Log Groups
  
- **Driver Orchestration** (`advise()` method):
  - Iterates through collected resources
  - Creates driver instances for each resource
  - Calls `run()` on each driver to execute checks
  - Aggregates results into a dictionary keyed by resource identifier

**Inheritance**: Extends `Service` base class

### 2. Base Classes

#### Service (`services/Service.py`)
- Provides common service-level functionality
- Handles region configuration
- Manages boto3 session and client configuration
- Provides tag filtering capabilities
- Handles chart data aggregation

#### Evaluator (`services/Evaluator.py`)
- Base class for all driver implementations
- Provides check execution framework
- Handles result collection and reporting
- Manages concurrent/sequential check execution
- Tracks scanned resources and exceptions

**Key Methods**:
- `init()` - Initializes results and inventory dictionaries
- `run(serviceName)` - Executes all check methods (methods starting with `_check`)
- `getInfo()` - Returns results and inventory information
- `addII(k, v)` / `getII(k)` - Manages inventory information
- `setChartData()` - Stores chart/metrics data

### 3. Driver Classes

Drivers are specialized classes that implement checks for specific resource types. Each driver:
- Extends the `Evaluator` base class
- Focuses on a single resource type
- Implements check methods following naming convention `_check{Description}`
- Stores results in `self.results` dictionary

#### Current Drivers:

##### CloudwatchCommon (`drivers/CloudwatchCommon.py`)
**Resource Type**: CloudWatch Log Groups

**Constructor Parameters**:
- `log` - Log group information dictionary containing:
  - `logGroupName` - Name of the log group
  - `storedBytes` - Storage size
  - `retentionInDays` - Retention period (-1 if not set)
  - `dataProtectionStatus` - Data protection configuration
- `logClient` - boto3 CloudWatch Logs client

**Resource Identifier**: `self._resourceName = log['logGroupName']`

**Implemented Checks**:
- `_checkRetention()` - Validates log retention policies
  - Flags log groups without retention (`SetRetentionDays`)
  - Flags retention less than 365 days (`CISRetentionAtLeast1Yr`)

##### CloudwatchTrails (`drivers/CloudwatchTrails.py`)
**Resource Type**: CloudTrail trails with CloudWatch Logs integration

**Constructor Parameters**:
- `log` - Trail information array: `[TrailARN, CloudWatchLogsLogGroupArn, logGroupName]`
- `logname` - CloudWatch Log Group name
- `logClient` - boto3 CloudWatch Logs client

**Resource Identifier**: `self._resourceName = logname`

**Implemented Checks**:
- `_checkHasLogMetrics()` - Validates CloudWatch metric filters and alarms for CIS compliance
  - Checks if trail has CloudWatch Logs integration
  - Verifies log group exists
  - Validates metric filter count
  - Checks for 14 CIS-recommended metric patterns (root usage, unauthorized API calls, etc.)

**Special Features**:
- **CIS Metrics Mapping**: Maintains `CISMetricsMap` with 14 security event patterns
- **Regex Pattern Matching**: Converts CIS patterns to regex for validation
- **Pattern Caching**: Uses `Config` to cache compiled regex patterns for performance

## Check Method Convention

All check methods must follow these rules:

1. **Naming**: Start with `_check` prefix (e.g., `_checkRetention`, `_checkHasLogMetrics`)
2. **Discovery**: The `Evaluator.run()` method automatically discovers all methods starting with `_check`
3. **Results Storage**: Store findings in `self.results` dictionary
4. **Result Format**: `self.results[checkId] = [status, details]`
   - `status`: `-1` for failed check, `0` for warning, `1` for pass
   - `details`: Additional information about the finding
5. **Check IDs**: Must match keys in `cloudwatch.reporter.json`

## Reporter Configuration

**Location**: `service-screener-v2/services/cloudwatch/cloudwatch.reporter.json`

**Purpose**: Defines metadata for each check including:
- `category` - Check category (O=Operational, C=Cost, S=Security, etc.)
- `description` - Detailed explanation of the check
- `shortDesc` - Brief description for reports
- `criticality` - H (High), M (Medium), L (Low)
- `downtime` - Potential downtime impact (0-1)
- `slowness` - Performance impact (0-1)
- `additionalCost` - Cost impact (0-1)
- `needFullTest` - Testing requirements (0-1)
- `ref` - Reference links to AWS documentation

**Check ID Mapping**: The keys in reporter.json must match the keys used in `self.results` within driver check methods.

## Execution Flow

```
1. Cloudwatch.__init__()
   └─> Initialize boto3 clients (cloudwatch, logs, cloudtrail)

2. Cloudwatch.advise()
   ├─> loopTrail() - Collect CloudTrail trails
   │   └─> For each trail with CloudWatch Logs:
   │       ├─> Create CloudwatchTrails driver instance
   │       ├─> Call driver.run(Cloudwatch)
   │       │   └─> Evaluator.run() discovers and executes all _check* methods
   │       │       ├─> _checkHasLogMetrics()
   │       │       └─> [other check methods]
   │       └─> Collect results via driver.getInfo()
   │
   └─> getAllLogs() - Collect all log groups
       └─> For each log group:
           ├─> Create CloudwatchCommon driver instance
           ├─> Call driver.run(Cloudwatch)
           │   └─> Evaluator.run() discovers and executes all _check* methods
           │       ├─> _checkRetention()
           │       └─> [other check methods]
           └─> Collect results via driver.getInfo()

3. Return aggregated results dictionary
```

## Adding New Checks

To add a new check to the CloudWatch service:

### Step 1: Update Reporter Configuration
Add check definition to `cloudwatch.reporter.json`:
```json
{
  "NewCheckId": {
    "category": "O",
    "^description": "Detailed description...",
    "shortDesc": "Brief description",
    "criticality": "M",
    "downtime": 0,
    "slowness": 0,
    "additionalCost": 0,
    "needFullTest": 0,
    "ref": [
      "[Reference]<https://docs.aws.amazon.com/...>"
    ]
  }
}
```

### Step 2: Implement Check Method
Add method to appropriate driver class:

**For Log Group checks** → `CloudwatchCommon.py`:
```python
def _checkNewFeature(self):
    # Access log group data via self.log
    if condition_not_met:
        self.results['NewCheckId'] = [-1, 'details']
```

**For CloudTrail/Metrics checks** → `CloudwatchTrails.py`:
```python
def _checkNewFeature(self):
    # Access trail data via self.log
    if condition_not_met:
        self.results['NewCheckId'] = [-1, 'details']
```

### Step 3: Add New Driver (if needed)
If checking a new resource type (e.g., CloudWatch Alarms, Dashboards):

1. Create new driver file: `drivers/CloudwatchAlarms.py`
2. Extend `Evaluator` base class
3. Set `self._resourceName` in constructor
4. Implement check methods following `_check*` convention
5. Update `Cloudwatch.py`:
   - Import new driver
   - Add resource collection method
   - Instantiate driver in `advise()` method

## Key Design Patterns

### 1. Resource Identification
Each driver must set `self._resourceName` to uniquely identify the resource being scanned. This is used for:
- Result tracking
- Error reporting
- Resource inventory

### 2. Result Storage
Results are stored in `self.results` dictionary:
- **Key**: Check ID (must match reporter.json)
- **Value**: `[status, details]` tuple
  - Only failed checks (`status = -1`) are typically stored
  - Passing checks can be omitted (absence = pass)

### 3. Client Sharing
Boto3 clients are created once in the main service class and passed to drivers to avoid redundant client creation.

### 4. Concurrent Execution
The `Evaluator.run()` method supports concurrent check execution using ThreadPoolExecutor for improved performance. Sequential execution is available via `--sequential` flag for debugging.

### 5. Configuration Caching
The `Config` class provides global state management for:
- Caching expensive computations (e.g., regex patterns)
- Sharing data between drivers
- Tracking scan progress

## Current Coverage

### Resource Types Scanned:
1. **CloudWatch Log Groups** (via CloudwatchCommon)
   - Retention policies
   - Storage metrics

2. **CloudTrail CloudWatch Logs Integration** (via CloudwatchTrails)
   - Metric filters
   - CIS security alarms (14 patterns)

### Check Categories:
- **Operational (O)**: 16 checks (CIS metric alarms, log retention)
- **Cost (C)**: 1 check (retention configuration)

### Total Checks: 18

## Potential Expansion Areas

Based on the architecture, new drivers could be added for:
- CloudWatch Alarms (standalone alarm configuration checks)
- CloudWatch Dashboards (dashboard best practices)
- CloudWatch Metrics (custom metrics validation)
- CloudWatch Insights (query and analysis configuration)
- CloudWatch Contributor Insights (rule validation)
- CloudWatch Synthetics (canary configuration)
- CloudWatch Application Insights (application monitoring)

Each would follow the same pattern:
1. Create driver class extending `Evaluator`
2. Implement `_check*` methods
3. Add reporter.json entries
4. Update `Cloudwatch.advise()` to instantiate driver
