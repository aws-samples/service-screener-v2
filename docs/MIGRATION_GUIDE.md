# Cloudscape UI Migration Guide

This guide helps you transition from the AdminLTE (legacy) UI to the new Cloudscape UI for Service Screener.

## Overview

The Cloudscape UI is a modern, lightweight replacement for the AdminLTE UI with:
- 90% smaller file size (2MB vs 20MB+)
- Better accessibility and mobile support
- Framework compliance reporting with charts
- Suppression management features
- Fully offline, single-file HTML

## Migration Timeline

### Phase 1: Parallel Output (Current)
**Status**: Available now with `--beta 1` flag

Both UIs are generated:
- `index.html` - New Cloudscape UI
- `index-legacy.html` - Original AdminLTE UI

**Action Required**: None. Both UIs available for comparison.

### Phase 2: Cloudscape as Default (Future)
**Status**: Planned

Cloudscape becomes the default:
- `index.html` - Cloudscape UI (default)
- `index-legacy.html` - AdminLTE UI (deprecated)

**Action Required**: Test Cloudscape UI and report issues.

### Phase 3: AdminLTE Removal (Future)
**Status**: Planned (3+ months notice)

AdminLTE UI removed:
- Only Cloudscape UI generated
- Legacy code removed from codebase

**Action Required**: Migrate any workflows to Cloudscape UI.

## Quick Start

### Enable Cloudscape UI

Add the `--beta 1` flag to your scan command:

```bash
# Before (AdminLTE only)
python3 main.py --regions us-east-1 --services s3,ec2

# After (Both UIs)
python3 main.py --regions us-east-1 --services s3,ec2 --beta 1
```

### Output Files

With `--beta 1`, you'll get:

```
adminlte/aws/{ACCOUNT_ID}/
├── index.html              # NEW: Cloudscape UI (2MB)
├── index-legacy.html       # OLD: AdminLTE UI (23KB + assets)
├── s3.html                 # AdminLTE service page
├── ec2.html                # AdminLTE service page
├── api-full.json           # Data file (used by Cloudscape)
├── workItem.xlsx           # Excel report (unchanged)
└── ...                     # Other AdminLTE files
```

### Opening the Reports

**Cloudscape UI:**
```bash
open adminlte/aws/{ACCOUNT_ID}/index.html
```

**Legacy AdminLTE UI:**
```bash
open adminlte/aws/{ACCOUNT_ID}/index-legacy.html
```

## Feature Comparison

| Feature | AdminLTE (Legacy) | Cloudscape (New) | Notes |
|---------|------------------|------------------|-------|
| **Dashboard** | ✅ Basic | ✅ Enhanced | KPI cards, better layout |
| **Service Pages** | ✅ | ✅ | Improved filtering/sorting |
| **Framework Pages** | ✅ Basic HTML | ✅ Interactive Charts | Pie/bar charts, CSV export |
| **Suppressions** | ❌ Not visible | ✅ Modal View | See active suppressions |
| **Search/Filter** | ✅ Basic | ✅ Real-time | Instant filtering |
| **Mobile Support** | ⚠️ Limited | ✅ Responsive | Works on all devices |
| **Accessibility** | ⚠️ Limited | ✅ WCAG 2.1 AA | Keyboard nav, screen readers |
| **File Size** | 20MB+ | 2MB | 90% reduction |
| **Offline** | ✅ | ✅ | Both work offline |
| **Excel Export** | ✅ | ✅ | Unchanged |

## What's Different

### Navigation

**AdminLTE:**
- Top menu bar with dropdowns
- Service pages are separate HTML files
- Framework pages are separate HTML files

**Cloudscape:**
- Left sidebar navigation
- Single-page application (SPA)
- All content in one HTML file
- Hash-based URLs (e.g., `#/service/s3`)

### Dashboard

**AdminLTE:**
- Simple service list
- Basic statistics

**Cloudscape:**
- KPI cards at top (Services, Findings, Priorities)
- Service cards with detailed stats
- Color-coded priority indicators
- Category badges

### Service Detail Pages

**AdminLTE:**
- Separate HTML file per service (e.g., `s3.html`)
- Basic table with findings
- Limited filtering

**Cloudscape:**
- Integrated in single HTML (`#/service/s3`)
- Advanced table with real-time search
- Expandable rows for full details
- Better sorting and filtering

### Framework Pages

**AdminLTE:**
- Separate HTML file per framework
- Static tables
- No visualizations

**Cloudscape:**
- Integrated in single HTML (`#/framework/MSR`)
- Interactive pie and bar charts
- Compliance summary statistics
- CSV export functionality
- Sortable/filterable tables

### Suppressions

**AdminLTE:**
- Not visible in UI
- Only in Excel file

**Cloudscape:**
- "Suppressions Active" button in top nav
- Modal showing all suppressions
- Service-level and resource-specific views
- Summary statistics

## Step-by-Step Migration

### Step 1: Test with Beta Flag

Run your normal scan with `--beta 1`:

```bash
python3 main.py \
  --regions us-east-1,us-west-2 \
  --services s3,ec2,rds \
  --beta 1
```

### Step 2: Compare Both UIs

Open both UIs side-by-side:

```bash
# Cloudscape (new)
open adminlte/aws/{ACCOUNT_ID}/index.html

# AdminLTE (legacy)
open adminlte/aws/{ACCOUNT_ID}/index-legacy.html
```

### Step 3: Verify Features

Check that all your required features work:

- [ ] Dashboard loads correctly
- [ ] All services appear in sidebar
- [ ] Service detail pages show findings
- [ ] Frameworks appear in sidebar (if using frameworks)
- [ ] Framework pages show compliance data
- [ ] Suppressions appear (if using suppressions)
- [ ] Search/filter works
- [ ] Charts render correctly
- [ ] CSV export works (frameworks)

### Step 4: Test Your Workflow

Run through your typical workflow:

1. Open report
2. Review dashboard
3. Navigate to specific services
4. Check high-priority findings
5. Review framework compliance
6. Export data if needed

### Step 5: Report Issues

If you find any issues:

1. Check browser console (F12) for errors
2. Try a different browser
3. Compare with legacy UI
4. Report issue with details:
   - Browser and version
   - Error message
   - Steps to reproduce

## Common Migration Scenarios

### Scenario 1: Automated Report Distribution

**Before:**
```bash
# Generate report
python3 main.py --regions us-east-1 --services s3,ec2

# Distribute index.html
aws s3 cp adminlte/aws/{ACCOUNT_ID}/index.html s3://reports/
```

**After:**
```bash
# Generate both UIs
python3 main.py --regions us-east-1 --services s3,ec2 --beta 1

# Distribute Cloudscape UI
aws s3 cp adminlte/aws/{ACCOUNT_ID}/index.html s3://reports/cloudscape.html

# Optional: Also distribute legacy
aws s3 cp adminlte/aws/{ACCOUNT_ID}/index-legacy.html s3://reports/legacy.html
```

### Scenario 2: CI/CD Pipeline

**Before:**
```yaml
- name: Run Service Screener
  run: python3 main.py --regions us-east-1 --services s3,ec2
  
- name: Upload Report
  uses: actions/upload-artifact@v2
  with:
    name: service-screener-report
    path: adminlte/aws/*/index.html
```

**After:**
```yaml
- name: Run Service Screener
  run: python3 main.py --regions us-east-1 --services s3,ec2 --beta 1
  
- name: Upload Cloudscape Report
  uses: actions/upload-artifact@v2
  with:
    name: service-screener-cloudscape
    path: adminlte/aws/*/index.html
    
- name: Upload Legacy Report
  uses: actions/upload-artifact@v2
  with:
    name: service-screener-legacy
    path: adminlte/aws/*/index-legacy.html
```

### Scenario 3: Scheduled Scans

**Before:**
```bash
#!/bin/bash
# daily-scan.sh
python3 main.py --regions us-east-1 --services s3,ec2,rds
cp adminlte/aws/*/index.html /var/www/html/reports/latest.html
```

**After:**
```bash
#!/bin/bash
# daily-scan.sh
python3 main.py --regions us-east-1 --services s3,ec2,rds --beta 1
cp adminlte/aws/*/index.html /var/www/html/reports/latest-cloudscape.html
cp adminlte/aws/*/index-legacy.html /var/www/html/reports/latest-legacy.html
```

### Scenario 4: With Suppressions

**Before:**
```bash
python3 main.py \
  --regions us-east-1 \
  --services s3 \
  --suppress_file suppressions.json
```

**After (same, just add --beta 1):**
```bash
python3 main.py \
  --regions us-east-1 \
  --services s3 \
  --suppress_file suppressions.json \
  --beta 1
```

**New Feature:** Suppressions now visible in UI!
- Click "Suppressions Active" button in top nav
- See all active suppressions
- View service-level and resource-specific suppressions

## Troubleshooting

### Issue: Cloudscape UI is blank

**Solutions:**
1. Check browser console (F12) for errors
2. Ensure JavaScript is enabled
3. Try Chrome or Firefox
4. Verify file is not corrupted
5. Check file size (should be ~2MB)

### Issue: Framework pages show "No data"

**Solutions:**
1. Ensure frameworks were generated during scan
2. Check that `--frameworks` parameter was used (or default frameworks)
3. Verify framework generation didn't fail in scan output
4. Check browser console: `window.__REPORT_DATA__.framework_MSR`

### Issue: Suppressions not showing

**Solutions:**
1. Verify `--suppress_file` was used during scan
2. Check suppressions.json file format
3. Verify suppressions were loaded (check scan output)
4. Check browser console: `window.__REPORT_DATA__.__metadata.suppressions`

### Issue: Charts not rendering

**Solutions:**
1. Check browser console for errors
2. Ensure browser supports modern JavaScript (ES6+)
3. Try Chrome or Firefox (best support)
4. Verify framework data exists

### Issue: File size too large

**Solutions:**
1. Check actual file size: `ls -lh adminlte/aws/*/index.html`
2. Should be ~2MB (acceptable)
3. If much larger, report as issue
4. Consider filtering services if scanning many services

### Issue: Performance is slow

**Solutions:**
1. Check number of findings (10,000+ may be slow)
2. Try filtering to fewer services
3. Use modern browser (Chrome/Firefox)
4. Check computer resources

## Backward Compatibility

### What Stays the Same

✅ **Command-line interface** - All existing flags work
✅ **Excel export** - workItem.xlsx unchanged
✅ **JSON files** - api-full.json, api-raw.json unchanged
✅ **Directory structure** - Output location unchanged
✅ **Legacy UI** - Still available as index-legacy.html

### What Changes

⚠️ **Default index.html** - Will be Cloudscape in future (currently with --beta 1)
⚠️ **File size** - index.html is now 2MB (was 23KB + assets)
⚠️ **Navigation** - Hash-based URLs instead of separate files

### Breaking Changes (Future Phase 3)

❌ **AdminLTE removal** - index-legacy.html will be removed
❌ **Service HTML files** - s3.html, ec2.html, etc. will be removed
❌ **Framework HTML files** - MSR.html, FTR.html, etc. will be removed

**Timeline:** 3+ months notice before Phase 3

## FAQ

### Q: Do I need to change my scripts?

**A:** Not immediately. Just add `--beta 1` to generate both UIs. Your existing scripts will continue to work.

### Q: Can I use both UIs?

**A:** Yes! With `--beta 1`, both UIs are generated. Use whichever you prefer.

### Q: When will AdminLTE be removed?

**A:** Not for at least 3 months after Cloudscape becomes the default. You'll receive advance notice.

### Q: What if I find a bug in Cloudscape?

**A:** Report it! You can continue using the legacy UI (`index-legacy.html`) while we fix it.

### Q: Will my automation break?

**A:** No. The output directory structure and file names remain the same. Just add `--beta 1` to your commands.

### Q: Do I need to install anything?

**A:** No. The Cloudscape UI is built into Service Screener. Just use the `--beta 1` flag.

### Q: Can I customize the Cloudscape UI?

**A:** The UI is built during the scan. To customize, you'd need to modify the React source code in `cloudscape-ui/` and rebuild.

### Q: Does it work offline?

**A:** Yes! Both UIs work completely offline with the `file://` protocol.

### Q: What about mobile devices?

**A:** Cloudscape UI is fully responsive and works on mobile. AdminLTE has limited mobile support.

### Q: Will Excel export change?

**A:** No. The Excel export (`workItem.xlsx`) remains unchanged.

## Getting Help

### Resources

- [Cloudscape UI README](cloudscape-ui/README.md) - Technical details
- [Browser Testing Guide](cloudscape-ui/BROWSER_TESTING_GUIDE.md) - Testing checklist
- [Main README](README.md) - Service Screener documentation

### Support

1. Check this migration guide
2. Review browser console for errors (F12)
3. Try the legacy UI to compare
4. Open an issue with details

### Feedback

We want to hear from you!

- What features do you love?
- What features are missing?
- What could be improved?
- Any bugs or issues?

Your feedback helps us improve the Cloudscape UI.

## Rollback Plan

If you encounter critical issues:

### Option 1: Use Legacy UI

```bash
# Continue using legacy UI
open adminlte/aws/{ACCOUNT_ID}/index-legacy.html
```

### Option 2: Disable Beta Mode

```bash
# Generate only legacy UI
python3 main.py --regions us-east-1 --services s3,ec2
# (omit --beta 1 flag)
```

### Option 3: Report Issue

Report the issue so we can fix it, then use legacy UI until resolved.

## Next Steps

1. ✅ Add `--beta 1` to your scan commands
2. ✅ Test Cloudscape UI with your data
3. ✅ Compare with legacy UI
4. ✅ Report any issues
5. ✅ Provide feedback
6. ⏳ Wait for Cloudscape to become default
7. ⏳ Migrate workflows (3+ months notice)

## Summary

The Cloudscape UI is a modern, improved replacement for AdminLTE with:
- Better performance (90% smaller)
- Better accessibility
- Better features (charts, suppressions)
- Better mobile support

Migration is gradual with no breaking changes in Phase 1. You have plenty of time to test and provide feedback before AdminLTE is removed.

**Start today:** Add `--beta 1` to your next scan!
