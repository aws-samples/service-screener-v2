# Browser Testing Guide - Cloudscape UI

## How to Open the Report

The generated report is a single HTML file that can be opened directly in your browser:

```bash
# The file is located at:
service-screener-v2/adminlte/aws/{ACCOUNT_ID}/index.html

# Open it with:
open adminlte/aws/956288449190/index.html

# Or drag and drop the file into your browser
```

## What You Should See

### 1. Dashboard (Landing Page)

**URL:** `file:///.../index.html#/`

**Expected Elements:**

#### Top Navigation Bar
- **Left:** "Service Screener" logo and title
- **Right:** 
  - 🟡 **"Suppressions Active"** button (if suppressions exist)
  - Account dropdown showing your AWS account ID

#### KPI Cards (Top Row)
Four cards showing:
- **Total Services:** Number of services scanned (e.g., 1)
- **Total Findings:** Total number of findings
- **High Priority:** Count in red
- **Medium Priority:** Count in orange

#### Services Overview Section
Cards for each service (e.g., S3) showing:
- Service name as header
- **"View Details"** button on the right
- Statistics: Total Findings, High Priority, Medium Priority, Low Priority
- Affected Categories as colored badges

#### Left Sidebar
- **Services** section with list of scanned services
- **Frameworks** section with list of compliance frameworks (MSR, FTR, SSB, etc.)

---

### 2. Service Detail Page

**URL:** `file:///.../index.html#/service/s3`

**How to Get There:** Click "View Details" on any service card

**Expected Elements:**

#### Header
- Service name (e.g., "S3")
- Breadcrumb navigation

#### Findings Table
- **Search box** at the top to filter findings
- **Columns:**
  - Rule Name
  - Priority (High/Medium/Low badge)
  - Category (colored badge)
  - Affected Resources (count)
  - Short Description

#### Expandable Rows
Click on any row to expand and see:
- Full Description
- Impact tags (blue badges)
- Recommendations (clickable links)
- Affected Resources by Region

#### Table Features
- **Sorting:** Click column headers to sort
- **Filtering:** Type in search box to filter
- **Pagination:** If many findings

---

### 3. Framework Detail Page

**URL:** `file:///.../index.html#/framework/MSR`

**How to Get There:** Click any framework in the left sidebar

**Expected Elements:**

#### Header
- Framework name (e.g., "MSR - Modernization and Security Readiness")
- Framework description

#### Compliance Summary
- **Pie Chart** showing compliance distribution:
  - Compliant (green)
  - Non-Compliant (red)
  - Not Applicable (gray)

#### Category Breakdown
- **Bar Chart** showing findings by category

#### Compliance Table
- **Search box** to filter
- **CSV Export** button
- **Columns:**
  - Control ID
  - Control Name
  - Service
  - Status (badge: Compliant/Non-Compliant/N/A)
  - Finding Count

#### Table Features
- **Sorting:** Click column headers
- **Filtering:** Type in search box
- **CSV Export:** Download compliance data

---

### 4. Suppression Modal

**How to Open:** Click the **"Suppressions Active"** button in top navigation

**Expected Elements:**

#### Summary Statistics (Top)
- Total suppressions count
- Service-level suppressions count
- Resource-specific suppressions count

#### Service-Level Suppressions Table
Shows suppressions that apply to all resources:
- **Columns:**
  - Service (e.g., "S3")
  - Rule (e.g., "BucketReplication")
  - Description/Reason

#### Resource-Specific Suppressions Table
Shows suppressions for specific resources:
- **Columns:**
  - Service
  - Rule
  - Resources (list of resource IDs)
  - Reason

#### Close Button
- X button in top right
- Click outside modal to close

---

## Testing Checklist

### ✅ Basic Functionality

- [ ] Dashboard loads without errors
- [ ] KPI cards show correct numbers
- [ ] Service cards display properly
- [ ] Click "View Details" navigates to service page
- [ ] Service detail page shows findings table
- [ ] Click on finding row expands details
- [ ] Search/filter works in findings table
- [ ] Click framework in sidebar navigates to framework page
- [ ] Framework page shows charts and compliance table
- [ ] CSV export button downloads file

### ✅ Suppression Features

- [ ] "Suppressions Active" button appears (if suppressions exist)
- [ ] Click button opens suppression modal
- [ ] Modal shows summary statistics
- [ ] Service-level suppressions table populated
- [ ] Resource-specific suppressions table populated (if any)
- [ ] Close button closes modal
- [ ] Click outside modal closes it

### ✅ Navigation

- [ ] Left sidebar shows all services
- [ ] Left sidebar shows all frameworks
- [ ] Click service in sidebar navigates to service page
- [ ] Click framework in sidebar navigates to framework page
- [ ] Browser back button works
- [ ] URL hash updates correctly

### ✅ Accessibility

- [ ] Press Tab key - focus moves through interactive elements
- [ ] Press Tab on page load - "Skip to content" link appears
- [ ] Press Enter on "Skip to content" - jumps to main content
- [ ] All buttons clickable with keyboard (Enter/Space)
- [ ] Modal can be closed with Escape key

### ✅ Responsive Design

- [ ] Resize browser window - layout adapts
- [ ] KPI cards stack on narrow screens
- [ ] Tables scroll horizontally if needed
- [ ] Sidebar collapses on mobile (hamburger menu)

### ✅ Error Handling

- [ ] No JavaScript errors in browser console (F12)
- [ ] If data missing, shows "No data available" message
- [ ] If service has no findings, shows empty state

---

## Browser Console Testing

Open browser console (F12) and check:

### Expected Console Output
```
✅ No errors
✅ Data loaded successfully
✅ All components rendered
```

### Check for Errors
```javascript
// Open console (F12) and run:
console.log(window.__REPORT_DATA__);

// Should show:
// - __metadata with accountId, regions, suppressions
// - Service data (e.g., s3)
// - Framework data (e.g., framework_MSR)
```

---

## Common Issues and Solutions

### Issue: Page is blank
**Solution:** 
- Check browser console for errors
- Ensure JavaScript is enabled
- Try a different browser

### Issue: "Suppressions Active" button not showing
**Solution:**
- Check if suppressions.json was used during scan
- Verify suppressions data in console: `window.__REPORT_DATA__.__metadata.suppressions`

### Issue: Framework page shows "No data"
**Solution:**
- Ensure frameworks were generated during scan
- Check console for framework data: `window.__REPORT_DATA__.framework_MSR`

### Issue: Charts not rendering
**Solution:**
- Check browser console for errors
- Ensure browser supports modern JavaScript
- Try Chrome or Firefox

---

## Performance Testing

### Load Time
- Page should load in < 2 seconds
- Initial render should be immediate
- No lag when navigating between pages

### Bundle Size
- File size: ~2MB (acceptable for offline use)
- Gzipped: ~470KB
- No external dependencies loaded

---

## Browser Compatibility

### Tested Browsers
- ✅ Chrome 90+
- ✅ Firefox 88+
- ✅ Safari 14+
- ✅ Edge 90+

### File:// Protocol
All browsers support opening local HTML files with `file://` protocol.

---

## Screenshot Checklist

Take screenshots of:
1. Dashboard with KPI cards and service cards
2. Service detail page with findings table
3. Expanded finding with full details
4. Framework page with charts
5. Suppression modal (if suppressions exist)

---

## Quick Test Script

Run this in browser console to verify data:

```javascript
// Check if data loaded
console.log('Data loaded:', !!window.__REPORT_DATA__);

// Check services
const services = Object.keys(window.__REPORT_DATA__).filter(k => !k.startsWith('_') && !k.startsWith('framework_'));
console.log('Services:', services);

// Check frameworks
const frameworks = Object.keys(window.__REPORT_DATA__).filter(k => k.startsWith('framework_'));
console.log('Frameworks:', frameworks);

// Check suppressions
const suppressions = window.__REPORT_DATA__.__metadata?.suppressions;
console.log('Has suppressions:', !!suppressions);
console.log('Service-level:', suppressions?.serviceLevelSuppressions?.length || 0);
console.log('Resource-specific:', suppressions?.resourceSuppressions?.length || 0);
```

Expected output:
```
Data loaded: true
Services: ['s3']
Frameworks: ['framework_MSR', 'framework_FTR', ...]
Has suppressions: true
Service-level: 3
Resource-specific: 0
```

---

## Next Steps After Testing

If everything looks good:
1. ✅ Mark Phase 2 as complete
2. ✅ Commit changes to git
3. ✅ Move to Phase 3 (Testing & Documentation) or Phase 4 (Deployment)

If issues found:
1. Note the issue and browser
2. Check browser console for errors
3. Report back for debugging
