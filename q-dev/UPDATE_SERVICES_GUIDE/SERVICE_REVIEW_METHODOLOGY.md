# Service Review Methodology Guide

**Purpose**: Step-by-step process to analyze AWS service best practices and identify new checks for Service Screener v2

**Based on**: Successful implementation for Glue, SageMaker, and CloudFront services

---

## Overview

This guide walks through the complete process of reviewing a new AWS service to identify, analyze, and implement additional security, reliability, and cost optimization checks.

**Time Estimate**: 8-12 hours per service (analysis to implementation)

---

## Phase 1: Preparation (30 minutes)

### Step 1.1: Gather AWS Best Practices Documentation

**Goal**: Collect official AWS best practices for the target service

**Actions**:
1. Search AWS documentation for "{SERVICE} best practices"
2. Look for these specific documents:
   - Security best practices
   - Well-Architected Framework guidance
   - Operational excellence guides
   - Cost optimization recommendations
   - Performance optimization guides

**Example searches**:
- "AWS Lambda best practices"
- "Amazon RDS security best practices"
- "ECS Well-Architected"

**Output**: Create `service-screener-v2/services/{service}/best-practices.md`

**Template**:
```markdown
# {Service} Best Practices

## Security Best Practices
### Practice 1
- Description
- Why it matters
- Reference: [Link]

## Reliability Best Practices
...

## Performance Best Practices
...

## Cost Optimization Best Practices
...

## Operational Excellence Best Practices
...
```

---

### Step 1.2: Review Current Implementation

**Goal**: Understand what checks already exist

**Actions**:
1. Read `service-screener-v2/services/{service}/{service}.reporter.json`
2. List all existing checks with their categories
3. Understand the service's driver structure

**Questions to answer**:
- How many checks currently exist?
- What pillars are covered? (Security, Reliability, Performance, Cost, Ops)
- What resources does the service check? (e.g., instances, buckets, functions)
- How are checks organized? (single driver vs multiple drivers)

**Output**: Notes on current coverage

**Example**:
```
Current CloudFront checks: 8
- Security: 6 checks
- Reliability: 1 check
- Performance: 1 check
- Cost: 0 checks
- Ops: 0 checks

Resources checked: Distributions only
Driver structure: Single driver (cloudfrontDist.py)
```

---

## Phase 2: Gap Analysis (2-3 hours)

### Step 2.1: Create Best Practices Coverage Analysis

**Goal**: Compare AWS best practices against current implementation

**Actions**:
1. Create `BEST_PRACTICES_COVERAGE.md`
2. For each best practice, determine:
   - ✅ COVERED - Already implemented
   - ❌ NOT COVERED - Missing check
   - 🟡 PARTIALLY COVERED - Partially implemented

**Template Structure**:
```markdown
# {Service} Best Practices Coverage Analysis

## Current Implementation Status
[Table of existing checks]

## Best Practices Analysis

### Security Best Practices
#### ✅ COVERED
1. Practice Name - Covered by CheckID

#### ❌ NOT COVERED
1. Practice Name - Reason not covered

#### 🟡 PARTIALLY COVERED
1. Practice Name - What's missing

### [Repeat for each pillar]

## Summary Statistics
| Category | Total | Covered | Not Covered | Coverage % |
|----------|-------|---------|-------------|------------|
| Security | X | Y | Z | % |
...
```

**Key Questions**:
- Is this practice automatable via API?
- Does it provide actionable insights?
- Is it a configuration check or runtime metric?
- Would it duplicate an existing check?

---

### Step 2.2: Boto3 Implementation Feasibility Analysis

**Goal**: Determine which gaps can be implemented using boto3 APIs

**Actions**:
1. Create `BOTO3_IMPLEMENTATION_FEASIBILITY.md`
2. For each gap, analyze:
   - **Boto3 API Availability**: Can we get the data?
   - **Implementation Complexity**: Easy/Moderate/Complex
   - **Value**: High/Medium/Low
   - **Feasibility**: ✅ Easy | 🟡 Moderate | 🔴 Complex | ❌ Not Feasible

**Research Methods**:
- Check boto3 documentation: `boto3.client('{service}').{method}`
- Test API calls in AWS CLI: `aws {service} describe-{resource}`
- Review AWS SDK documentation
- Check for required permissions

**Template for Each Check**:
```markdown
### Check Name
**Status**: ✅ FEASIBLE (Easy/Moderate/Complex)

**Boto3 APIs**:
```python
client.method_name(params)
# Returns: { 'Field': 'value' }
```

**Implementation**:
- Step 1: Get resource
- Step 2: Check field
- Step 3: Determine pass/fail

**Value**: HIGH/MEDIUM/LOW - Why

**Complexity**: LOW/MODERATE/HIGH - Why

**Recommendation**: ✅ IMPLEMENT / 🟡 CONSIDER / ❌ SKIP

**Considerations**:
- Edge cases
- Permission requirements
- Performance impact
```

**Feasibility Criteria**:

✅ **Easy** (Implement):
- Simple field validation
- Single API call
- Clear pass/fail logic
- No complex dependencies

🟡 **Moderate** (Consider):
- Multiple API calls
- Some conditional logic
- Cross-service dependencies
- Permission complexity

🔴 **Complex** (Defer):
- Requires extensive logic
- Multiple service integrations
- Ambiguous criteria
- High maintenance burden

❌ **Not Feasible** (Skip):
- No API available
- Requires runtime metrics
- Subjective evaluation
- Manual review needed

---

### Step 2.3: Prioritize Checks into Tiers

**Goal**: Organize feasible checks by priority

**Actions**:
1. Create `NEW_CHECKS_SUMMARY.md`
2. Categorize checks into tiers:

**Tier 1 - High Priority** (Implement First):
- High value (security, reliability)
- Easy to implement
- Clear actionable results
- Aligns with compliance standards

**Tier 2 - Medium Priority** (Implement Second):
- Medium value (performance, cost)
- Easy to moderate implementation
- Advisory recommendations
- Nice-to-have improvements

**Tier 3 - Low Priority** (Future):
- Low value or very specific use cases
- Complex implementation
- Edge case scenarios
- Can be deferred

**Template**:
```markdown
# {Service} New Checks Implementation Summary

## Tier 1 - High Priority (X checks)
1. **CheckName** (Category - Criticality)
   - What it checks
   - Why it matters
   - Implementation approach
   - Estimated effort: X hours

## Tier 2 - Medium Priority (X checks)
...

## Tier 3 - Low Priority (X checks)
...

## Implementation Roadmap
### Phase 1: Tier 1 (Immediate)
- Checks: X
- Effort: Y hours
- Impact: Z% coverage increase

### Phase 2: Tier 2 (Optional)
...
```

---

## Phase 3: Implementation (4-6 hours)

### Step 3.1: Update Reporter Configuration

**Goal**: Add new check definitions to reporter.json

**Actions**:
1. Open `service-screener-v2/services/{service}/{service}.reporter.json`
2. Add new check definitions following the existing format

**Template**:
```json
{
  "CheckID": {
    "category": "S|R|P|C|O",
    "^description": "{$COUNT} resource(s) have issue description",
    "shortDesc": "Short actionable description",
    "criticality": "H|M|L|I",
    "downtime": 0|1,
    "slowness": 0|1,
    "additionalCost": -1|0|1,
    "needFullTest": 0|1,
    "ref": [
      "[Title]<URL>",
      "[Title]<URL>"
    ]
  }
}
```

**Field Definitions**:
- `category`: S=Security, R=Reliability, P=Performance, C=Cost, O=Ops
- `criticality`: H=High, M=Medium, L=Low, I=Info
- `downtime`: 1 if fixing requires downtime
- `slowness`: 1 if fixing may cause slowness
- `additionalCost`: -1=saves money, 0=neutral, 1=costs money
- `needFullTest`: 1 if requires full testing before production

---

### Step 3.2: Implement Check Logic

**Goal**: Add check methods to appropriate driver(s)

**Actions**:
1. Identify which driver should contain the check
2. Add check method following naming convention: `_check{CheckID}`
3. Implement the logic based on feasibility analysis

**Method Template**:
```python
def _checkCheckID(self):
    """Check description - what it validates"""
    # Get resource configuration
    config = self.resource_config
    
    # Extract relevant field
    field_value = config.get('FieldName', default_value)
    
    # Evaluate condition
    if condition_fails:
        self.results['CheckID'] = [-1, 'Optional context']
    
    # If condition passes, don't add to results (implicit pass)
```

**Best Practices**:
- Use descriptive variable names
- Add comments for complex logic
- Handle missing fields gracefully
- Provide context in failure messages
- Follow existing code style

**Common Patterns**:

**Pattern 1: Simple Field Validation**
```python
def _checkFieldEnabled(self):
    """Check if feature is enabled"""
    config = self.resource_config
    if not config.get('FeatureEnabled', False):
        self.results['FieldEnabled'] = [-1, '']
```

**Pattern 2: Iterating Resources**
```python
def _checkResourceProperty(self):
    """Check property across multiple resources"""
    resources = self.config['Resources']['Items']
    
    for resource in resources:
        if resource.get('Property') != 'expected_value':
            self.results['ResourceProperty'] = [-1, resource['Id']]
            break  # Stop at first failure
```

**Pattern 3: Cross-Service Check**
```python
def _checkExternalResource(self):
    """Check resource in another service"""
    resource_id = self.config.get('ResourceId')
    
    try:
        self.other_client.describe_resource(Id=resource_id)
    except self.other_client.exceptions.NotFound:
        self.results['ExternalResource'] = [-1, f'{resource_id} not found']
    except Exception as e:
        # Only fail on specific errors, not permission issues
        if 'NotFound' in str(e):
            self.results['ExternalResource'] = [-1, resource_id]
```

---

### Step 3.3: Update Service Class (if needed)

**Goal**: Add any required client initialization or resource discovery

**Actions**:
1. Open `service-screener-v2/services/{service}/{Service}.py`
2. Add new boto3 clients if needed
3. Update driver instantiation to pass new clients

**Example**:
```python
def __init__(self, region):
    super().__init__(region)
    ssBoto = self.ssBoto
    
    # Existing clients
    self.serviceClient = ssBoto.client('{service}')
    
    # Add new client if needed for cross-service checks
    self.otherClient = ssBoto.client('other-service')

def advise(self):
    # Pass new client to driver
    obj = Driver(resource_id, self.serviceClient, self.otherClient)
```

---

### Step 3.4: Create or Update Driver (if needed)

**Goal**: Create new driver if checking new resource types

**Actions**:
1. Determine if new driver is needed
2. Create `service-screener-v2/services/{service}/drivers/NewDriver.py`
3. Follow existing driver patterns

**Driver Template**:
```python
from services.Evaluator import Evaluator

class NewDriver(Evaluator):
    def __init__(self, resource_id, service_client):
        super().__init__()
        self.resource_id = resource_id
        self.service_client = service_client
        self._configPrefix = '{service}::{resource}::'
        
        # Fetch resource configuration
        self.resource_config = service_client.describe_resource(
            Id=resource_id
        )
        
        self._resourceName = resource_id
        self.init()
    
    def _checkSomething(self):
        """Check implementation"""
        pass
```

---

## Phase 4: Testing (2-3 hours)

### Step 4.1: Create Unit Tests

**Goal**: Comprehensive test coverage for all new checks

**Actions**:
1. Create `service-screener-v2/tests/test_{service}_new_checks.py`
2. Write tests for each check covering:
   - Pass scenarios (valid configuration)
   - Fail scenarios (invalid configuration)
   - Edge cases (missing fields, empty values)
   - Skip logic (irrelevant resources)

**Test Template**:
```python
import unittest
from unittest.mock import MagicMock
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from services.{service}.drivers.Driver import Driver

class Test{Service}NewChecks(unittest.TestCase):
    def setUp(self):
        """Set up test fixtures"""
        self.mock_client = MagicMock()
        self.resource_id = 'test-resource-123'
    
    def test_check_passes_when_valid(self):
        """Check should pass with valid configuration"""
        self.mock_client.describe_resource.return_value = {
            'Field': 'valid_value'
        }
        
        driver = Driver(self.resource_id, self.mock_client)
        driver._checkFieldValue()
        
        self.assertNotIn('FieldValue', driver.results)
    
    def test_check_fails_when_invalid(self):
        """Check should fail with invalid configuration"""
        self.mock_client.describe_resource.return_value = {
            'Field': 'invalid_value'
        }
        
        driver = Driver(self.resource_id, self.mock_client)
        driver._checkFieldValue()
        
        self.assertIn('FieldValue', driver.results)
        self.assertEqual(driver.results['FieldValue'][0], -1)

if __name__ == '__main__':
    unittest.main()
```

**Test Coverage Goals**:
- At least 2 tests per check (pass + fail)
- Edge cases for complex logic
- 100% pass rate before proceeding

**Run Tests**:
```bash
cd service-screener-v2
python -m pytest tests/test_{service}_new_checks.py -v
```

---

### Step 4.2: Create Simulation Scripts

**Goal**: Test checks against real AWS resources

**Actions**:
1. Create `service-screener-v2/services/{service}/simulation/` directory
2. Create three files:
   - `create_test_resources.sh`
   - `cleanup_test_resources.sh`
   - `README.md`

**create_test_resources.sh Template**:
```bash
#!/bin/bash
# Create intentionally misconfigured resources for testing

REGION="us-east-1"
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

echo "Creating test resources for {SERVICE}..."

# Create resource with issue 1
aws {service} create-resource \
  --name test-resource-1 \
  --config-with-issue \
  --region ${REGION}

# Create resource with issue 2
aws {service} create-resource \
  --name test-resource-2 \
  --another-config-issue \
  --region ${REGION}

echo "✅ Resources created"
echo "Validates X checks:"
echo "  ✓ CheckID1 - Description"
echo "  ✓ CheckID2 - Description"
```

**cleanup_test_resources.sh Template**:
```bash
#!/bin/bash
# Cleanup test resources

REGION="us-east-1"

echo "Cleaning up test resources..."

# Delete resources
aws {service} delete-resource --name test-resource-1 --region ${REGION}
aws {service} delete-resource --name test-resource-2 --region ${REGION}

echo "✅ Cleanup complete"
```

**README.md Template**:
```markdown
# {Service} Service Simulation

## Purpose
Test Service Screener checks against real AWS resources.

## Resources Created
| Resource | Configuration | Validates Checks |
|----------|--------------|------------------|
| Resource 1 | Issue description | CheckID1, CheckID2 |

## Coverage
- Total Checks: X
- Validated: Y (Z%)

## Cost
- Resource 1: $X/hour
- Total: $Y/hour

## Usage
```bash
# Create
./create_test_resources.sh

# Run Service Screener
cd ../../..
python3 main.py --regions us-east-1 --services {service} --beta 1 --sequential 1

# Cleanup
cd services/{service}/simulation
./cleanup_test_resources.sh
```

## Expected Results
- X checks should FAIL
- Y checks should PASS
```

**Make Scripts Executable**:
```bash
chmod +x service-screener-v2/services/{service}/simulation/*.sh
```

---

## Phase 5: Documentation (1-2 hours)

### Step 5.1: Create Implementation Summary

**Goal**: Document what was implemented

**Actions**:
1. Create summary document in service folder
2. Include:
   - Checks implemented
   - Coverage improvement
   - Test results
   - Implementation details

**Template**: See `CLOUDFRONT_IMPLEMENTATION_COMPLETE.md` as example

---

### Step 5.2: Update Project Documentation

**Goal**: Update main project documentation

**Actions**:
1. Update `IMPLEMENTATION_SUMMARY.md` or create new summary
2. Update `FINAL_PROJECT_SUMMARY.md` with new service
3. Archive analysis documents to `_archive/`

---

### Step 5.3: Archive Analysis Documents

**Goal**: Keep service directories clean

**Actions**:
1. Move analysis documents to archive:
   ```bash
   mv service-screener-v2/services/{service}/BEST_PRACTICES_COVERAGE.md _archive/
   mv service-screener-v2/services/{service}/BOTO3_IMPLEMENTATION_FEASIBILITY.md _archive/
   mv service-screener-v2/services/{service}/NEW_CHECKS_SUMMARY.md _archive/
   mv service-screener-v2/services/{service}/best-practices.md _archive/
   ```

2. Keep only production code and simulation READMEs in service directories

---

## Phase 6: Validation (1 hour)

### Step 6.1: Run All Tests

**Goal**: Ensure nothing broke

**Actions**:
```bash
# Run new tests
python -m pytest tests/test_{service}_new_checks.py -v

# Run all tests to ensure no regression
python -m pytest tests/ -v

# Check for 100% pass rate
```

---

### Step 6.2: Test with Simulation (Optional)

**Goal**: Validate against real AWS resources

**Actions**:
1. Run create script
2. Wait for resources to be ready
3. Run Service Screener
4. Verify expected results
5. Run cleanup script

**Validation Checklist**:
- ✅ Resources created successfully
- ✅ Service Screener detects all issues
- ✅ Check results match expectations
- ✅ Cleanup removes all resources
- ✅ No unexpected costs

---

### Step 6.3: Code Review Checklist

**Goal**: Ensure production quality

**Checklist**:
- ✅ All checks follow naming conventions
- ✅ Reporter.json entries are complete
- ✅ Check logic is clear and maintainable
- ✅ Error handling is appropriate
- ✅ Tests cover all scenarios
- ✅ Documentation is complete
- ✅ No hardcoded values
- ✅ Follows existing code style
- ✅ AWS references are accurate
- ✅ Simulation scripts work correctly

---

## Quick Reference Checklist

Use this checklist when reviewing a new service:

### Phase 1: Preparation
- [ ] Create `best-practices.md` with AWS documentation
- [ ] Review current `{service}.reporter.json`
- [ ] Document current coverage

### Phase 2: Analysis
- [ ] Create `BEST_PRACTICES_COVERAGE.md`
- [ ] Create `BOTO3_IMPLEMENTATION_FEASIBILITY.md`
- [ ] Create `NEW_CHECKS_SUMMARY.md`
- [ ] Prioritize checks into tiers

### Phase 3: Implementation
- [ ] Update `{service}.reporter.json`
- [ ] Implement check methods in driver(s)
- [ ] Update service class if needed
- [ ] Create new drivers if needed

### Phase 4: Testing
- [ ] Create `test_{service}_new_checks.py`
- [ ] Write unit tests (100% pass rate)
- [ ] Create simulation scripts
- [ ] Test simulation scripts

### Phase 5: Documentation
- [ ] Create implementation summary
- [ ] Update project documentation
- [ ] Archive analysis documents

### Phase 6: Validation
- [ ] Run all tests
- [ ] Test with simulation (optional)
- [ ] Complete code review checklist

---

## Time Estimates by Phase

| Phase | Time | Activities |
|-------|------|------------|
| 1. Preparation | 30 min | Gather docs, review current |
| 2. Analysis | 2-3 hours | Gap analysis, feasibility, prioritization |
| 3. Implementation | 4-6 hours | Code changes, new checks |
| 4. Testing | 2-3 hours | Unit tests, simulation scripts |
| 5. Documentation | 1-2 hours | Summaries, archive |
| 6. Validation | 1 hour | Final testing, review |
| **TOTAL** | **8-12 hours** | **Complete service review** |

---

## Tips for Success

### Do's ✅
- Start with official AWS documentation
- Focus on automatable checks
- Prioritize high-value, low-effort checks
- Write comprehensive tests
- Document your analysis
- Keep service directories clean
- Test against real resources when possible

### Don'ts ❌
- Don't implement checks requiring runtime metrics
- Don't add checks that need manual review
- Don't skip unit tests
- Don't leave analysis documents in service folders
- Don't implement everything at once (use tiers)
- Don't forget error handling
- Don't hardcode values

### Common Pitfalls
1. **Over-ambitious scope**: Start with Tier 1 only
2. **Insufficient testing**: Always test edge cases
3. **Poor documentation**: Future you will thank present you
4. **Ignoring feasibility**: Not everything can be automated
5. **Skipping simulation**: Real AWS testing catches issues

---

## Example: Quick Walkthrough

Let's say you want to review AWS Lambda:

1. **Gather docs** (30 min)
   - Search "AWS Lambda best practices"
   - Create `lambda/best-practices.md`

2. **Analyze gaps** (2 hours)
   - Compare against `lambda.reporter.json`
   - Identify: "Function timeout not optimized" - NOT COVERED
   - Check boto3: `lambda.get_function()` returns `Timeout` field ✅
   - Categorize as Tier 1 (Performance, Easy)

3. **Implement** (1 hour)
   - Add to `lambda.reporter.json`:
     ```json
     "TimeoutOptimization": {
       "category": "P",
       "^description": "{$COUNT} Lambda function(s) have timeout set to maximum (900s)",
       "shortDesc": "Optimize Lambda function timeout values",
       "criticality": "L"
     }
     ```
   - Add to driver:
     ```python
     def _checkTimeoutOptimization(self):
         timeout = self.function_config['Timeout']
         if timeout == 900:
             self.results['TimeoutOptimization'] = [-1, '']
     ```

4. **Test** (1 hour)
   - Write unit test
   - Create simulation script
   - Verify works

5. **Document** (30 min)
   - Create summary
   - Archive analysis docs

**Total**: ~5 hours for 1 check

---

## Conclusion

This methodology has been successfully used to implement 26 new checks across Glue, SageMaker, and CloudFront. Following these steps ensures:

- **Comprehensive analysis** before implementation
- **High-quality code** with full test coverage
- **Complete documentation** for maintainability
- **Production-ready** checks aligned with AWS best practices

Use this guide as a template for reviewing any AWS service!

