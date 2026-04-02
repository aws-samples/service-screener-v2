# CloudWatch Driver Mapping Analysis for Tier 1 Checks

## Executive Summary

This document analyzes the appropriate driver(s) for implementing CloudWatch checks. Based on the analysis of existing driver structure and the resource types involved, this document tracks the driver decisions and their current status.

## IMPORTANT: Driver Removal Decision

**Date**: Current  
**Decision**: Remove CloudwatchRDS and CloudwatchECS drivers from CloudWatch service

**Rationale**:
- RDS and ECS checks should be in their own respective services, not CloudWatch
- CloudWatch service should focus on CloudWatch-native resources (alarms, logs, trails)
- Monitoring configuration for other services (RDS Performance Insights, ECS Container Insights) belongs in those service modules

**Actions Taken**:
- ✅ Deleted `service-screener-v2/services/cloudwatch/drivers/CloudwatchRDS.py`
- ✅ Deleted `service-screener-v2/services/cloudwatch/drivers/CloudwatchECS.py`
- ✅ Removed RDS and ECS client initialization from `Cloudwatch.py`
- ✅ Removed RDS and ECS collection methods from `Cloudwatch.py`
- ✅ Removed RDS and ECS checks from `Cloudwatch.advise()` method
- ✅ Removed `rdsWithoutPerformanceInsights` from `cloudwatch.reporter.json`
- ✅ Removed `ecsWithoutContainerInsights` from `cloudwatch.reporter.json`

**Future Implementation**:
- RDS Performance Insights check should be implemented in a dedicated RDS service module
- ECS Container Insights check should be implemented in a dedicated ECS service module

---

## Current Driver Inventory

### Active Drivers

1. **CloudwatchCommon** (`drivers/CloudwatchCommon.py`)
   - **Resource Type**: CloudWatch Log Groups
   - **Resource Identifier**: `log['logGroupName']`
   - **Boto3 Client**: `logs` (CloudWatch Logs)
   - **Current Checks**: Log retention policies
   - **Collection Method**: `Cloudwatch.getAllLogs()`

2. **CloudwatchTrails** (`drivers/CloudwatchTrails.py`)
   - **Resource Type**: CloudTrail trails with CloudWatch Logs integration
   - **Resource Identifier**: CloudWatch Log Group name associated with trail
   - **Boto3 Client**: `logs` (CloudWatch Logs)
   - **Current Checks**: CIS metric filters and alarms
   - **Collection Method**: `Cloudwatch.loopTrail()`

3. **CloudwatchAlarms** (`drivers/CloudwatchAlarms.py`)
   - **Resource Type**: CloudWatch Alarms
   - **Resource Identifier**: `alarm['AlarmName']`
   - **Boto3 Client**: `cloudwatch`
   - **Current Checks**: SNS notifications, billing alarms
   - **Collection Method**: `Cloudwatch.getAllAlarms()`

### Removed Drivers

1. ~~**CloudwatchRDS**~~ - REMOVED (should be in RDS service)
2. ~~**CloudwatchECS**~~ - REMOVED (should be in ECS service)

### Available Boto3 Clients in Main Service

The `Cloudwatch` service class currently initializes:
- `self.cwClient` - CloudWatch client (for metrics and alarms)
- `self.cwLogClient` - CloudWatch Logs client (for log groups)
- `self.ctClient` - CloudTrail client (for trails)

---

## Active CloudWatch Checks

### Check 1: alarmsWithoutSNS
**Description**: Check CloudWatch alarms for SNS notifications

**Resource Type**: CloudWatch Alarms

**Driver**: ✅ **CloudwatchAlarms.py**

**Status**: Implemented

---

### Check 2: missingBillingAlarms
**Description**: Check for billing alarms in us-east-1

**Resource Type**: CloudWatch Alarms (specifically for billing metrics)

**Driver**: ✅ **CloudwatchAlarms.py**

**Status**: Implemented

**Special Logic**: Only runs in us-east-1 region

---

### Removed Checks (Moved to Other Services)

### ~~Check 3: rdsWithoutPerformanceInsights~~
**Status**: ❌ REMOVED from CloudWatch service

**Future Home**: Should be implemented in RDS service module

**Rationale**: RDS monitoring configuration belongs in RDS service, not CloudWatch

---

### ~~Check 4: ecsWithoutContainerInsights~~
**Status**: ❌ REMOVED from CloudWatch service

**Future Home**: Should be implemented in ECS service module

**Rationale**: ECS monitoring configuration belongs in ECS service, not CloudWatch

---

## Summary: Current Driver Mapping

| Check ID | Check Name | Resource Type | Driver | Status |
|----------|-----------|---------------|--------|--------|
| alarmsWithoutSNS | SNS Notifications for Alarms | CloudWatch Alarms | **CloudwatchAlarms** | ✅ Active |
| missingBillingAlarms | Billing Alarms | CloudWatch Alarms | **CloudwatchAlarms** | ✅ Active |
| ~~rdsWithoutPerformanceInsights~~ | ~~RDS Performance Insights~~ | ~~RDS Instances~~ | ~~CloudwatchRDS~~ | ❌ Removed |
| ~~ecsWithoutContainerInsights~~ | ~~ECS Container Insights~~ | ~~ECS Clusters~~ | ~~CloudwatchECS~~ | ❌ Removed |

---

## Design Principles

### Service Boundary Principle
Each AWS service module should focus on resources and configurations specific to that service:
- **CloudWatch service**: CloudWatch alarms, log groups, metric filters, CloudTrail integration
- **RDS service**: RDS instances, clusters, Performance Insights, backups, encryption
- **ECS service**: ECS clusters, tasks, services, Container Insights

### Cross-Service Monitoring
When monitoring features span multiple services (e.g., RDS Performance Insights is monitored via CloudWatch):
- The check should be implemented in the **resource owner's service** (RDS)
- Not in the monitoring service (CloudWatch)
- This maintains clear service boundaries and ownership

---

## Current Service Class Structure

### Cloudwatch.__init__()

```python
def __init__(self, region):
    super().__init__(region)
    ssBoto = self.ssBoto
    
    self.cwClient = ssBoto.client('cloudwatch', config=self.bConfig)
    self.cwLogClient = ssBoto.client('logs', config=self.bConfig)
    self.ctClient = ssBoto.client('cloudtrail', config=self.bConfig)
    
    self.ctLogs = []
    self.logGroups = []
    self.alarms = []
```

### Import Statements

```python
from services.cloudwatch.drivers.CloudwatchCommon import CloudwatchCommon
from services.cloudwatch.drivers.CloudwatchTrails import CloudwatchTrails
from services.cloudwatch.drivers.CloudwatchAlarms import CloudwatchAlarms
```

---

## Reporter Configuration

Active checks in `cloudwatch.reporter.json`:

1. **alarmsWithoutSNS** - CloudWatch alarms without SNS notifications
2. **missingBillingAlarms** - Missing billing alarms (us-east-1 only)
3. **CIS CloudWatch Controls** - Various CIS benchmark checks for CloudTrail/CloudWatch integration
4. **Log Retention Checks** - CloudWatch Logs retention policies

Removed checks:
- ~~rdsWithoutPerformanceInsights~~ (moved to RDS service)
- ~~ecsWithoutContainerInsights~~ (moved to ECS service)

---

## Conclusion

The CloudWatch service now focuses exclusively on CloudWatch-native resources:
- CloudWatch Alarms
- CloudWatch Log Groups
- CloudTrail integration with CloudWatch Logs

Monitoring configuration checks for other AWS services (RDS, ECS) have been removed and should be implemented in their respective service modules.

---

**Document Version**: 2.0  
**Last Updated**: Current (Driver removal)  
**Status**: Active - CloudWatch service boundaries clarified


