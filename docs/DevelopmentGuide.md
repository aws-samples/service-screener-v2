# Service Screener Development Guide

This guide will walk you through creating new services and checks for the Service Screener project. By the end of this tutorial, you'll understand how to contribute new AWS service assessments to the project.

**Quick Start**: Service Screener includes a `CreateService.py` script that automatically generates boilerplate code for new services, significantly speeding up development. See the [Using the CreateService.py Script](#using-the-createservicepy-script) section to get started quickly.

## Table of Contents
1. [Understanding the Architecture](#understanding-the-architecture)
2. [Project Structure](#project-structure)
3. [Creating a New Service](#creating-a-new-service)
   - [Using the CreateService.py Script](#using-the-createservicepy-script)
4. [Adding Individual Checks (Evaluations)](#adding-individual-checks)
5. [Creating the Reporter Configuration](#creating-the-reporter-configuration)
6. [Testing Your Service](#testing-your-service)
7. [Best Practices](#best-practices)
8. [Examples](#examples)

## Understanding the Architecture

Service Screener follows a modular architecture:

- **Service Classes**: Main service coordinators that handle AWS API calls and resource discovery
- **Driver Classes**: Individual check implementations that inherit from `Evaluator`
- **Reporter Configuration**: JSON files that define how findings are presented in reports
- **Base Classes**: `Service` and `Evaluator` provide common functionality

### Key Concepts

1. **Service**: Represents an AWS service (e.g., S3, KMS, RDS)
2. **Driver**: Implements specific checks for resources within a service
3. **Check Method**: Individual assessment functions that start with `_check`
4. **Results**: Dictionary storing check outcomes with format `[status, value]`
   - `1`: Pass/Good configuration
   - `-1`: Attention required
   - `0`: Informational

## Project Structure

```
services/
├── Service.py              # Base service class
├── Evaluator.py           # Base evaluator class
├── Reporter.py            # Report generation
├── PageBuilder.py         # HTML report builder
├── [service-name]/        # Individual service directory
│   ├── ServiceName.py     # Main service class
│   ├── service.reporter.json  # Reporter configuration
│   └── drivers/           # Individual check implementations
│       └── DriverName.py  # Specific check driver
```

## Creating a New Service

Service Screener includes a convenient script called `CreateService.py` that automatically generates the boilerplate code for new services.

### Using the CreateService.py Script

The script automatically generates boilerplate code for any AWS service supported by boto3.

#### Step 1: Run the CreateService Script

Note: If the CreateService.py throw a "service already exists" error, please try a different service.

```bash
# Install dependencies if not already available
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install boto3

# Create a new service (example: S3)
python3 CreateService.py -s s3
```

The script accepts any AWS service name from boto3's available services. You can see all available services by running:

```bash
python3 CreateService.py --help
```

#### Step 2: What Gets Generated

The script creates the following structure:

```
services/logs/
├── Logs.py                    # Main service class (needs customization)
├── logs.reporter.json         # Reporter configuration template
└── drivers/
    └── LogsCommon.py         # Driver template (needs customization)
```

#### Step 3: Customize the Main Service Class

After running the script, you'll need to customize the generated templates. Let's walk through creating a CloudWatch Logs service as an example.

Edit `services/logs/Logs.py` and replace the template with your implementation:

```python
import botocore
from utils.Config import Config
from services.Service import Service
from utils.Tools import _pi

# Import your drivers
from services.logs.drivers.LogGroupDriver import LogGroupDriver

class Logs(Service):  # Changed from ServiceName to Logs
    def __init__(self, region):
        super().__init__(region)
        self.region = region
        
        # Initialize AWS clients using the shared boto session
        ssBoto = self.ssBoto
        self.logsClient = ssBoto.client('logs', config=self.bConfig)
        
    def getResources(self):
        """
        Discover and return resources to be checked.
        This method should handle pagination and filtering.
        """
        log_groups = []
        
        try:
            # Get log groups with pagination
            paginator = self.logsClient.get_paginator('describe_log_groups')
            
            for page in paginator.paginate():
                for log_group in page.get('logGroups', []):
                    # Apply tag filtering if specified
                    if self.tags:
                        try:
                            tags_response = self.logsClient.list_tags_log_group(
                                logGroupName=log_group['logGroupName']
                            )
                            tags = [{'Key': k, 'Value': v} for k, v in tags_response.get('tags', {}).items()]
                            
                            if not self.resourceHasTags(tags):
                                continue
                        except botocore.exceptions.ClientError:
                            # Skip if unable to get tags
                            continue
                    
                    log_groups.append(log_group)
                    
        except botocore.exceptions.ClientError as e:
            print(f"Error getting log groups: {e}")
            
        return log_groups
    
    def advise(self):
        """
        Main method that runs checks on discovered resources.
        Returns a dictionary of check results.
        """
        objs = {}
        log_groups = self.getResources()
        
        for log_group in log_groups:
            log_group_name = log_group['logGroupName']
            _pi('LogGroup', log_group_name)  # Progress indicator
            
            # Create driver instance and run checks
            obj = LogGroupDriver(log_group, self.logsClient)
            obj.run(self.__class__)
            
            # Store results
            objs[f"LogGroup::{log_group_name}"] = obj.getInfo()
            del obj
            
        return objs

# Test harness for development
if __name__ == "__main__":
    Config.init()
    service = Logs('us-east-1')
    results = service.advise()
    print(results)
```

#### Step 4: Create the Driver Class

Create `services/logs/drivers/LogGroupDriver.py` (replace the generated `LogsCommon.py`):

```python
import botocore
import json
from datetime import datetime, timedelta

from utils.Config import Config
from services.Evaluator import Evaluator

class LogGroupDriver(Evaluator):
    def __init__(self, log_group, logs_client):
        super().__init__()
        self.log_group = log_group
        self.logs_client = logs_client
        self.log_group_name = log_group['logGroupName']
        
        # Store resource information for reporting
        self.addII('logGroupName', self.log_group_name)
        self.addII('creationTime', log_group.get('creationTime'))
        self.addII('retentionInDays', log_group.get('retentionInDays'))
        
        self.init()
    
    def _checkRetentionPolicy(self):
        """
        Check if log group has a retention policy set.
        Best practice: Set appropriate retention to manage costs.
        """
        retention_days = self.log_group.get('retentionInDays')
        
        if retention_days is None:
            self.results['RetentionPolicy'] = [-1, 'Not Set']
        elif retention_days > 365:
            self.results['RetentionPolicy'] = [-1, f'{retention_days} days (>1 year)']
        else:
            self.results['RetentionPolicy'] = [1, f'{retention_days} days']
    
    def _checkEncryption(self):
        """
        Check if log group is encrypted with KMS.
        Best practice: Encrypt sensitive log data.
        """
        kms_key_id = self.log_group.get('kmsKeyId')
        
        if kms_key_id:
            self.results['Encryption'] = [1, 'KMS Encrypted']
        else:
            self.results['Encryption'] = [-1, 'Not Encrypted']
    
    def _checkRecentActivity(self):
        """
        Check if log group has recent log events.
        Informational: Identify unused log groups.
        """
        try:
            # Check for recent log streams
            response = self.logs_client.describe_log_streams(
                logGroupName=self.log_group_name,
                orderBy='LastEventTime',
                descending=True,
                limit=1
            )
            
            log_streams = response.get('logStreams', [])
            if not log_streams:
                self.results['RecentActivity'] = [0, 'No log streams']
                return
            
            last_event_time = log_streams[0].get('lastEventTime')
            if last_event_time:
                last_event_date = datetime.fromtimestamp(last_event_time / 1000)
                days_ago = (datetime.now() - last_event_date).days
                
                if days_ago > 30:
                    self.results['RecentActivity'] = [0, f'Last activity {days_ago} days ago']
                else:
                    self.results['RecentActivity'] = [1, f'Active (last event {days_ago} days ago)']
            else:
                self.results['RecentActivity'] = [0, 'No recent events']
                
        except botocore.exceptions.ClientError as e:
            self.results['RecentActivity'] = [0, f'Unable to check: {e.response["Error"]["Code"]}']
    
    def _checkLogGroupSize(self):
        """
        Check log group storage size for cost optimization.
        Informational: Help identify high-cost log groups.
        """
        stored_bytes = self.log_group.get('storedBytes', 0)
        
        if stored_bytes == 0:
            self.results['StorageSize'] = [0, 'Empty']
        elif stored_bytes > 10 * 1024 * 1024 * 1024:  # 10GB
            size_gb = stored_bytes / (1024 * 1024 * 1024)
            self.results['StorageSize'] = [0, f'{size_gb:.2f} GB (High storage cost)']
        else:
            size_mb = stored_bytes / (1024 * 1024)
            self.results['StorageSize'] = [1, f'{size_mb:.2f} MB']
```

#### Step 5: Update the Reporter Configuration

Edit the generated `services/logs/logs.reporter.json` and replace the template with your check definitions:

```json
{
    "RetentionPolicy": {
        "category": "C",
        "^description": "You have {$COUNT} CloudWatch Log Groups without retention policies or with retention periods longer than 1 year. This can lead to unnecessary storage costs as logs are kept indefinitely. Consider setting appropriate retention periods based on your compliance and operational requirements.",
        "shortDesc": "Set appropriate log retention policy",
        "criticality": "M",
        "downtime": 0,
        "slowness": 0,
        "additionalCost": 0,
        "needFullTest": 0,
        "ref": [
            "[CloudWatch Logs retention]<https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/Working-with-log-groups-and-streams.html#SettingLogRetention>"
        ]
    },
    "Encryption": {
        "category": "S",
        "^description": "You have {$COUNT} CloudWatch Log Groups that are not encrypted with KMS. If your logs contain sensitive information, consider enabling KMS encryption to protect data at rest.",
        "shortDesc": "Enable KMS encryption for sensitive logs",
        "criticality": "M",
        "downtime": 0,
        "slowness": 0,
        "additionalCost": 1,
        "needFullTest": 0,
        "ref": [
            "[Encrypt log data in CloudWatch Logs]<https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/encrypt-log-data-kms.html>"
        ]
    },
    "RecentActivity": {
        "category": "C",
        "^description": "You have {$COUNT} CloudWatch Log Groups with no recent activity (>30 days). These may be unused and could be candidates for deletion to reduce costs.",
        "shortDesc": "Review unused log groups",
        "criticality": "L",
        "downtime": 0,
        "slowness": 0,
        "additionalCost": 0,
        "needFullTest": 1,
        "ref": [
            "[Working with log groups and log streams]<https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/Working-with-log-groups-and-streams.html>"
        ]
    },
    "StorageSize": {
        "category": "C",
        "^description": "You have {$COUNT} CloudWatch Log Groups with high storage usage (>10GB). Review these log groups for cost optimization opportunities such as adjusting retention policies or archiving to S3.",
        "shortDesc": "Optimize high-storage log groups",
        "criticality": "L",
        "downtime": 0,
        "slowness": 0,
        "additionalCost": 0,
        "needFullTest": 1,
        "ref": [
            "[CloudWatch Logs pricing]<https://aws.amazon.com/cloudwatch/pricing/>"
        ]
    }
}
```

#### Step 6: Register the Service

# TODO: Update this section

Add your service to `utils/Config.py` in the `SERVICES_IDENTIFIER_MAPPING`:

```python
SERVICES_IDENTIFIER_MAPPING = {
    # ... existing mappings ...
    'loggroupdriver': ['ATTR', 'log_group_name'],
}
```

## Adding Individual Checks (Evaluations)

### Check Method Naming Convention

All check methods must start with `_check` and use descriptive names in camelCase.

Note: Service Screener was migrated from PHP, hence the naming convension in camelCase over snake_case.

```python
def _checkRetentionPolicy(self):     # Good
def _checkEncryption(self):          # Good
def _check_ssl_config(self):         # Bad - inconsistent casing
def checkSomething(self):            # Bad - won't be discovered
```

### Check Result Format

Results are stored as `[status, value]` where:
- `status`: Integer indicating the result (-1: attention required, 0: info, 1: pass)
- `value`: String or data describing the finding

```python
# Examples
self.results['CheckName'] = [1, 'Enabled']      # Pass
self.results['CheckName'] = [-1, 'Disabled']    # Attention required
self.results['CheckName'] = [0, 'Information']  # Info
```

### Error Handling

Always handle AWS API errors gracefully:

```python
def _checkSomething(self):
    try:
        response = self.client.some_api_call()
        # Process response
        self.results['Something'] = [1, 'Good']
    except botocore.exceptions.ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'AccessDenied':
            # Skip this check
            return
        elif error_code == 'ResourceNotFound':
            self.results['Something'] = [-1, 'Not Found']
        else:
            # Log unexpected errors
            print(f"Unexpected error in _checkSomething: {error_code}")
```

## Reporter Configuration

The reporter JSON file defines how findings are presented in the HTML report.

### Reporter JSON Structure

```json
{
    "CheckName": {
        "category": "S|R|O|P|C",           // Well-Architected pillar
        "^description": "Description with {$COUNT} placeholder",
        "shortDesc": "Brief description",
        "criticality": "H|M|L",            // High, Medium, Low
        "downtime": 0|1,                   // Causes downtime
        "slowness": 0|1,                   // Causes performance impact
        "additionalCost": 0|1,             // Incurs additional cost
        "needFullTest": 0|1,               // Requires full testing
        "ref": [                           // Reference links
            "[Link text]<URL>"
        ]
    }
}
```

### Categories (Well-Architected Pillars)

- `S`: Security
- `R`: Reliability  
- `O`: Operational Excellence
- `P`: Performance Efficiency
- `C`: Cost Optimization

### Criticality Levels

- `H`: High - Critical security or reliability issues
- `M`: Medium - Important best practices
- `L`: Low - Minor optimizations or informational

## Testing Your Service

### 1. Unit Testing

Create a test script to verify your service works:

```python
# test_example.py
import sys
sys.path.append('.')

from utils.Config import Config
from services.example.Example import Example

def test_example_service():
    Config.init()
    Config.set('_AWS_OPTIONS', {'region': 'us-east-1'})
    
    service = Example('us-east-1')
    results = service.advise()
    
    print("Service Results:")
    for resource, data in results.items():
        print(f"\nResource: {resource}")
        print(f"Results: {data['results']}")
        print(f"Info: {data['info']}")

if __name__ == "__main__":
    test_example_service()
```

### 2. Integration Testing

Test with the main screener:

```bash
# Run only your service
python3 main.py --regions us-east-1 --services example
```

### 3. Validation Checklist

- [ ] Service class inherits from `Service`
- [ ] Driver classes inherit from `Evaluator`
- [ ] All check methods start with `_check`
- [ ] Results follow `[status, value]` format
- [ ] Reporter JSON is valid and complete
- [ ] Service is registered in Config.py
- [ ] Error handling is implemented
- [ ] Tag filtering works (if applicable)
- [ ] Pagination is handled for large result sets

## Best Practices

### 1. Resource Discovery

```python
def getResources(self):
    """Always implement proper pagination and error handling"""
    resources = []
    
    try:
        paginator = self.client.get_paginator('list_resources')
        for page in paginator.paginate():
            for resource in page.get('Resources', []):
                # Apply tag filtering
                if self.tags and not self._resource_matches_tags(resource):
                    continue
                resources.append(resource)
    except botocore.exceptions.ClientError as e:
        print(f"Error discovering resources: {e}")
        
    return resources
```

### 2. Efficient API Usage

```python
# Good: Batch operations when possible
def _checkMultipleResources(self):
    resource_ids = [r['Id'] for r in self.resources]
    response = self.client.describe_resources(ResourceIds=resource_ids)
    
# Avoid: Individual API calls in loops
def _checkResourcesIndividually(self):
    for resource in self.resources:
        response = self.client.describe_resource(ResourceId=resource['Id'])
```

### 3. Meaningful Check Names

```python
# Good: Descriptive and specific
def _checkEncryptionAtRest(self):
def _checkPublicAccessBlocked(self):
def _checkBackupRetentionPeriod(self):

# Bad: Vague or generic
def _checkSecurity(self):
def _checkConfig(self):
def _checkStuff(self):
```

### 4. Comprehensive Error Handling

```python
def _checkSomething(self):
    try:
        response = self.client.get_configuration()
        if response.get('Enabled'):
            self.results['Feature'] = [1, 'Enabled']
        else:
            self.results['Feature'] = [-1, 'Disabled']
            
    except botocore.exceptions.ClientError as e:
        error_code = e.response['Error']['Code']
        
        # Handle known error conditions
        if error_code in ['AccessDenied', 'UnauthorizedOperation']:
            # Skip check if no permissions
            return
        elif error_code == 'ResourceNotFound':
            self.results['Feature'] = [-1, 'Resource Not Found']
        else:
            # Log unexpected errors for debugging
            print(f"Unexpected error in _checkSomething: {error_code} - {e}")
```

## Examples

### Simple Service (Single Resource Type)

For services that check account-level configurations:

```python
class SimpleService(Service):
    def __init__(self, region):
        super().__init__(region)
        self.client = self.ssBoto.client('service-name', config=self.bConfig)
    
    def getResources(self):
        # Return a single dummy resource for account-level checks
        return [{'account': 'current'}]
    
    def advise(self):
        objs = {}
        obj = SimpleDriver(self.client)
        obj.run(self.__class__)
        objs["Account"] = obj.getInfo()
        return objs
```

### Complex Service (Multiple Resource Types)

For services with multiple resource types:

```python
class ComplexService(Service):
    def advise(self):
        objs = {}
        
        # Check different resource types
        clusters = self.getClusters()
        for cluster in clusters:
            obj = ClusterDriver(cluster, self.client)
            obj.run(self.__class__)
            objs[f"Cluster::{cluster['name']}"] = obj.getInfo()
        
        instances = self.getInstances()
        for instance in instances:
            obj = InstanceDriver(instance, self.client)
            obj.run(self.__class__)
            objs[f"Instance::{instance['id']}"] = obj.getInfo()
            
        return objs
```
