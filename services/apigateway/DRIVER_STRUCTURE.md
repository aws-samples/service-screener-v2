# API Gateway Driver Structure Documentation

## Overview

The API Gateway service implementation follows a three-tier architecture:
1. **Service Class** (`Apigateway.py`) - Entry point and orchestrator
2. **Driver Classes** (in `drivers/` directory) - Resource-specific evaluators
3. **Reporter Configuration** (`apigateway.reporter.json`) - Check definitions and metadata

## Architecture

```
Apigateway (Service)
    ├── ApiGatewayRest (Evaluator) - Handles REST APIs
    └── ApiGatewayCommon (Evaluator) - Handles HTTP/WebSocket APIs
```

## 1. Service Class: `Apigateway.py`

### Purpose
- Entry point for API Gateway service scanning
- Fetches all API Gateway resources from AWS
- Instantiates appropriate driver classes for each resource
- Orchestrates the evaluation process

### Key Components

#### Initialization
```python
def __init__(self, region):
    super().__init__(region)
    self.apis = []        # REST APIs
    self.apisv2 = []      # HTTP/WebSocket APIs
    self.apiClient = ssBoto.client('apigateway')      # REST API client
    self.apiv2Client = ssBoto.client('apigatewayv2')  # V2 API client
```

#### Resource Discovery
- `getRestApis()` - Fetches all REST APIs using `apigateway` client
- `getApis()` - Fetches all HTTP/WebSocket APIs using `apigatewayv2` client
- Both methods handle pagination using `position` parameter

#### Orchestration (`advise()` method)
1. Fetches all V2 APIs (HTTP/WebSocket)
2. For each V2 API:
   - Creates object name: `{ProtocolType}::{Name}`
   - Instantiates `ApiGatewayCommon` driver
   - Runs checks via `obj.run(self.__class__)`
   - Collects results via `obj.getInfo()`
3. Fetches all REST APIs
4. For each REST API:
   - Creates object name: `REST::{name}`
   - Instantiates `ApiGatewayRest` driver
   - Runs checks and collects results

## 2. Driver Classes (Evaluators)

### Base Class: `Evaluator`

All drivers inherit from `Evaluator` which provides:

#### Core Functionality
- `run(serviceName)` - Executes all check methods
- `getInfo()` - Returns results and inventory information
- `results` dict - Stores check outcomes
- `InventoryInfo` dict - Stores resource metadata

#### Check Execution Flow
1. Scans for all methods starting with `_check`
2. Filters methods based on rules (if specified)
3. Executes checks concurrently (default) or sequentially
4. Handles errors and tracks execution statistics
5. Stores results in `self.results` dictionary

#### Result Format
```python
self.results[CheckID] = [status, message]
# status: 1 (pass), -1 (fail)
# message: Context information (e.g., "Stage name: prod")
```

### Driver: `ApiGatewayRest.py`

**Handles:** REST APIs (API Gateway V1)

**Resource Initialization:**
```python
def __init__(self, api, apiClient):
    self.api = api              # API resource data
    self.apiClient = apiClient  # boto3 apigateway client
    self._resourceName = api['name']  # Used for reporting
```

**Check Methods:**

#### `_checkStage()`
Evaluates REST API stages for multiple security and operational checks:

1. **IdleAPIGateway** - Detects APIs with no stages deployed
2. **ExecutionLogging** - Verifies logging level is INFO or ERROR
3. **CachingEnabled** - Checks if caching is enabled (positive check)
4. **EncryptionAtRest** - Validates cache data encryption
5. **EncryptionInTransit** - Verifies client certificate configuration
6. **XRayTracing** - Checks if X-Ray tracing is enabled
7. **WAFWACL** - Validates WAF Web ACL association

**Implementation Pattern:**
```python
def _checkStage(self):
    resp = self.apiClient.get_stages(restApiId=self.api['id'])
    items = resp['item']
    
    # Check for idle API
    if items == []:
        self.results['IdleAPIGateway'] = [-1, "No stages found"]
        return
    
    # Iterate through stages
    for stage in items:
        # Check method settings
        for k, json in stage['methodSettings'].items():
            # Evaluate specific settings
            if key == 'loggingLevel' and value != 'INFO' or 'ERROR':
                self.results['ExecutionLogging'] = [-1, f"Stage name: {stage['stageName']}"]
        
        # Check for missing attributes
        try:
            certid = stage['clientCertificateId']
        except KeyError:
            self.results['EncryptionInTransit'] = [-1, f"Stage name: {stage['stageName']}"]
```

### Driver: `ApiGatewayCommon.py`

**Handles:** HTTP and WebSocket APIs (API Gateway V2)

**Resource Initialization:**
```python
def __init__(self, api, apiClient):
    self.api = api              # API resource data
    self.apiClient = apiClient  # boto3 apigatewayv2 client
    self._resourceName = api['Name']  # Used for reporting
```

**Check Methods:**

#### `_checkStage()`
Evaluates V2 API stages:

1. **ExecutionLogging** - Validates logging level for WebSocket APIs
2. **AccessLogging** - Checks if access logs are configured

**Implementation:**
```python
def _checkStage(self):
    resp = self.apiClient.get_stages(ApiId=self.api['ApiId'])
    items = resp['Items']
    
    for stage in items:
        # WebSocket-specific logging check
        if self.api['ProtocolType'] == 'WEBSOCKET':
            if stage['DefaultRouteSettings']['LoggingLevel'] != 'INFO' or 'ERROR':
                self.results['ExecutionLogging'] = [-1, f"Stage name: {stage['StageName']}"]
        
        # Access logging check
        try:
            accesslogs = stage['AccessLogSettings']
        except KeyError:
            self.results['AccessLogging'] = [-1, f"Stage name: {stage['StageName']}"]
```

#### `_checkRoute()`
Evaluates V2 API routes:

1. **AuthorizationType** - Ensures routes have authorization configured

**Implementation:**
```python
def _checkRoute(self):
    resp = self.apiClient.get_routes(ApiId=self.api['ApiId'])
    items = resp['Items']
    
    for route in items:
        if route['AuthorizationType'] == 'NONE':
            self.results['AuthorizationType'] = [-1, f"Route key: {route['RouteKey']}"]
```

## 3. Reporter Configuration: `apigateway.reporter.json`

### Purpose
Defines metadata for each check including descriptions, criticality, and references.

### Structure
```json
{
    "CheckID": {
        "category": "S|O|P|R|C",  // Security, Operational, Performance, Reliability, Cost
        "^description": "Detailed description",
        "shortDesc": "Brief description",
        "criticality": "H|M|L|I",  // High, Medium, Low, Info
        "downtime": 0|1|-1,        // Impact on downtime
        "slowness": 0|1|-1,        // Impact on performance
        "additionalCost": 0|1,     // Cost implications
        "needFullTest": 0|1|-1,    // Testing requirements
        "ref": ["[Link text]<URL>"]
    }
}
```

### Check ID Mapping
The CheckID in the JSON must match the key used in `self.results[CheckID]` in driver code.

**Example:**
- Driver code: `self.results['ExecutionLogging'] = [-1, message]`
- Reporter JSON: `"ExecutionLogging": { ... }`

## How Checks Are Implemented

### Step-by-Step Process

1. **Define Check in Reporter JSON**
   - Add entry with CheckID and metadata
   - Specify category, criticality, description, references

2. **Implement Check Method in Driver**
   - Create method with `_check` prefix (e.g., `_checkStage`)
   - Use boto3 API calls to fetch resource data
   - Evaluate conditions
   - Store results: `self.results[CheckID] = [status, message]`

3. **Execution Flow**
   - Service class fetches resources
   - Driver instantiated for each resource
   - `run()` method discovers and executes all `_check*` methods
   - Results collected and returned to service class

### Check Implementation Patterns

#### Pattern 1: Missing Attribute Check
```python
try:
    value = resource['attribute']
except KeyError:
    self.results['CheckID'] = [-1, "Context message"]
```

#### Pattern 2: Value Validation Check
```python
if resource['setting'] != expected_value:
    self.results['CheckID'] = [-1, "Context message"]
```

#### Pattern 3: Boolean Flag Check
```python
if not resource['enabled']:
    self.results['CheckID'] = [-1, "Context message"]
```

#### Pattern 4: Positive Check (Good Practice)
```python
if resource['feature_enabled']:
    self.results['CheckID'] = [1, "Context message"]
```

### Naming Conventions

- **Check Methods:** `_check{Purpose}` (e.g., `_checkStage`, `_checkRoute`)
- **Check IDs:** PascalCase descriptive names (e.g., `ExecutionLogging`, `EncryptionAtRest`)
- **Resource Names:** Set via `self._resourceName` for reporting

## Current Check Coverage

### REST APIs (ApiGatewayRest)
- IdleAPIGateway
- ExecutionLogging
- CachingEnabled
- EncryptionAtRest
- EncryptionInTransit
- XRayTracing
- WAFWACL

### HTTP/WebSocket APIs (ApiGatewayCommon)
- ExecutionLogging (WebSocket only)
- AccessLogging
- AuthorizationType

## Adding New Checks

### Checklist

1. **Research AWS Best Practice**
   - Identify the security/operational requirement
   - Find relevant boto3 API calls
   - Determine feasibility

2. **Update Reporter JSON**
   - Add new CheckID entry
   - Fill in all required fields
   - Add AWS documentation references

3. **Identify Appropriate Driver**
   - REST API → `ApiGatewayRest.py`
   - HTTP/WebSocket API → `ApiGatewayCommon.py`
   - Both → Implement in both drivers

4. **Implement Check Logic**
   - Add to existing `_check*` method or create new one
   - Use appropriate boto3 API calls
   - Follow existing patterns
   - Add error handling
   - Set `self.results[CheckID]` with status and message

5. **Test Implementation**
   - Create unit tests
   - Test with real AWS resources
   - Verify results appear in reports

## Key Insights

1. **Separation of Concerns:** Service class handles orchestration, drivers handle evaluation logic
2. **Concurrent Execution:** Checks run in parallel by default for performance
3. **Flexible Filtering:** Can run specific checks via rules parameter
4. **Consistent Patterns:** All drivers follow same structure and conventions
5. **Resource-Specific Drivers:** Different API types handled by specialized drivers
6. **Declarative Configuration:** Check metadata separated from implementation logic
