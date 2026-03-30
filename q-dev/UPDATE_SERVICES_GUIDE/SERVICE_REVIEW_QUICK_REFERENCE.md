# Service Review Quick Reference Card

**Quick guide for reviewing AWS services for new Service Screener checks**

---

## 🎯 Goal
Compare AWS best practices against current Service Screener implementation to identify and implement new checks.

---

## 📋 6-Phase Process

### Phase 1: Preparation (30 min)
```bash
# 1. Create best practices document
service-screener-v2/services/{service}/best-practices.md

# 2. Review current implementation
service-screener-v2/services/{service}/{service}.reporter.json

# 3. Note current coverage
```

### Phase 2: Analysis (2-3 hours)
```bash
# 1. Gap analysis
BEST_PRACTICES_COVERAGE.md

# 2. Feasibility analysis
BOTO3_IMPLEMENTATION_FEASIBILITY.md

# 3. Prioritization
NEW_CHECKS_SUMMARY.md
```

### Phase 3: Implementation (4-6 hours)
```python
# 1. Update reporter.json
{
  "CheckID": {
    "category": "S|R|P|C|O",
    "^description": "Description",
    "criticality": "H|M|L"
  }
}

# 2. Add check method to driver
def _checkCheckID(self):
    if condition_fails:
        self.results['CheckID'] = [-1, 'context']

# 3. Update service class (if needed)
self.newClient = ssBoto.client('service')
```

### Phase 4: Testing (2-3 hours)
```bash
# 1. Create unit tests
tests/test_{service}_new_checks.py

# 2. Create simulation scripts
services/{service}/simulation/
├── create_test_resources.sh
├── cleanup_test_resources.sh
└── README.md

# 3. Run tests
python -m pytest tests/test_{service}_new_checks.py -v
```

### Phase 5: Documentation (1-2 hours)
```bash
# 1. Create implementation summary
# 2. Update project docs
# 3. Archive analysis docs to _archive/
```

### Phase 6: Validation (1 hour)
```bash
# 1. Run all tests
python -m pytest tests/ -v

# 2. Test simulation (optional)
./create_test_resources.sh
python3 main.py --services {service}
./cleanup_test_resources.sh

# 3. Code review checklist
```

---

## 🔍 Analysis Questions

### For Each Best Practice:
1. ✅ **Covered?** - Already implemented?
2. 🤖 **Automatable?** - Can we check via API?
3. 💎 **Valuable?** - Provides actionable insights?
4. 🎯 **Clear criteria?** - Unambiguous pass/fail?

### Feasibility Rating:
- ✅ **Easy**: Simple field check, single API call
- 🟡 **Moderate**: Multiple calls, some logic
- 🔴 **Complex**: Extensive logic, multiple services
- ❌ **Not Feasible**: No API, requires metrics, subjective

---

## 📊 Prioritization Tiers

### Tier 1 - High Priority (Implement First)
- High value (Security, Reliability)
- Easy implementation
- Clear actionable results
- Compliance alignment

### Tier 2 - Medium Priority (Implement Second)
- Medium value (Performance, Cost)
- Moderate implementation
- Advisory recommendations

### Tier 3 - Low Priority (Future)
- Low value or specific use cases
- Complex implementation
- Can be deferred

---

## 📝 File Templates

### reporter.json Entry
```json
{
  "CheckID": {
    "category": "S",
    "^description": "{$COUNT} resource(s) description",
    "shortDesc": "Short actionable description",
    "criticality": "H",
    "downtime": 0,
    "slowness": 0,
    "additionalCost": 0,
    "needFullTest": 1,
    "ref": [
      "[Title]<URL>"
    ]
  }
}
```

### Check Method
```python
def _checkCheckID(self):
    """Check description"""
    config = self.resource_config
    field = config.get('Field', default)
    
    if condition_fails:
        self.results['CheckID'] = [-1, 'context']
```

### Unit Test
```python
def test_check_passes_when_valid(self):
    """Check should pass with valid config"""
    self.mock_client.describe.return_value = {'Field': 'valid'}
    driver = Driver('id', self.mock_client)
    driver._checkCheckID()
    self.assertNotIn('CheckID', driver.results)

def test_check_fails_when_invalid(self):
    """Check should fail with invalid config"""
    self.mock_client.describe.return_value = {'Field': 'invalid'}
    driver = Driver('id', self.mock_client)
    driver._checkCheckID()
    self.assertIn('CheckID', driver.results)
```

---

## ✅ Validation Checklist

### Before Committing:
- [ ] All unit tests pass (100%)
- [ ] Reporter.json entries complete
- [ ] Check methods follow conventions
- [ ] Error handling implemented
- [ ] Documentation complete
- [ ] Simulation scripts work
- [ ] Analysis docs archived
- [ ] Service directory clean

---

## ⏱️ Time Estimates

| Phase | Time | Key Activities |
|-------|------|----------------|
| Preparation | 30 min | Docs, review |
| Analysis | 2-3 hrs | Gap, feasibility, priority |
| Implementation | 4-6 hrs | Code, checks |
| Testing | 2-3 hrs | Unit tests, simulation |
| Documentation | 1-2 hrs | Summaries, archive |
| Validation | 1 hr | Final testing |
| **TOTAL** | **8-12 hrs** | **Complete service** |

---

## 🎓 Key Principles

### Do's ✅
- Start with AWS official docs
- Focus on automatable checks
- Prioritize high-value checks
- Write comprehensive tests
- Document everything
- Keep directories clean

### Don'ts ❌
- Runtime metrics checks
- Manual review checks
- Skip unit tests
- Leave analysis in service folders
- Implement everything at once
- Hardcode values

---

## 📚 Reference Examples

### Completed Services:
- **Glue**: 12 → 15 checks (+3)
- **SageMaker**: 11 → 21 checks (+10)
- **CloudFront**: 8 → 16 checks (+8)

### Example Files:
- Analysis: `_archive/prowler-analysis-2026-02-24/`
- Implementation: `service-screener-v2/services/{service}/`
- Tests: `service-screener-v2/tests/test_{service}_new_checks.py`
- Simulation: `service-screener-v2/services/{service}/simulation/`

---

## 🚀 Quick Start

```bash
# 1. Create best practices doc
vim service-screener-v2/services/{service}/best-practices.md

# 2. Compare with current
cat service-screener-v2/services/{service}/{service}.reporter.json

# 3. Create analysis docs
vim BEST_PRACTICES_COVERAGE.md
vim BOTO3_IMPLEMENTATION_FEASIBILITY.md
vim NEW_CHECKS_SUMMARY.md

# 4. Implement Tier 1 checks
vim service-screener-v2/services/{service}/{service}.reporter.json
vim service-screener-v2/services/{service}/drivers/Driver.py

# 5. Create tests
vim service-screener-v2/tests/test_{service}_new_checks.py
python -m pytest tests/test_{service}_new_checks.py -v

# 6. Create simulation
mkdir service-screener-v2/services/{service}/simulation
vim service-screener-v2/services/{service}/simulation/create_test_resources.sh
vim service-screener-v2/services/{service}/simulation/cleanup_test_resources.sh
vim service-screener-v2/services/{service}/simulation/README.md

# 7. Archive and cleanup
mv *_COVERAGE.md *_FEASIBILITY.md *_SUMMARY.md _archive/
```

---

## 📞 Need Help?

Refer to:
- **Full Guide**: `SERVICE_REVIEW_METHODOLOGY.md`
- **Project Summary**: `FINAL_PROJECT_SUMMARY.md`
- **Examples**: `_archive/prowler-analysis-2026-02-24/`

---

**Last Updated**: February 24, 2026  
**Based on**: Glue, SageMaker, CloudFront implementations
