# Service Screener - Cloudscape UI

Modern, lightweight UI for AWS Service Screener built with React and AWS Cloudscape Design System.

## Overview

The Cloudscape UI is a complete redesign of the Service Screener reporting interface, offering:

- **90% smaller bundle size** - Single 2MB HTML file vs 20MB+ AdminLTE
- **Modern design** - AWS Cloudscape Design System components
- **Offline-first** - No external dependencies, works with `file://` protocol
- **Accessibility** - WCAG 2.1 Level AA compliant
- **Framework support** - Compliance framework reporting with charts
- **Suppression management** - Visual suppression configuration display

## Features

### Dashboard
- **KPI Cards** - Quick overview of services, findings, and priorities
- **Service Cards** - Summary of findings per service with color-coded priorities
- **Category Badges** - Visual indicators for affected Well-Architected categories

### Service Detail Pages
- **Findings Table** - Sortable, filterable table of all findings
- **Expandable Details** - Full descriptions, recommendations, and affected resources
- **Search** - Real-time filtering of findings
- **Priority Badges** - Color-coded High/Medium/Low indicators
- **GuardDuty Special Handling** - Dedicated charts, settings, and grouped findings for GuardDuty

### Custom Pages
- **Cross-Service Findings** - Aggregated findings across all services with advanced filtering
- **Modernization Recommendations** - Interactive Sankey diagrams showing modernization pathways
- **Trusted Advisor Integration** - TA check results with pillar-based organization

### Framework Compliance
- **Compliance Charts** - Pie charts showing compliance distribution
- **Category Breakdown** - Bar charts for findings by category
- **Compliance Tables** - Detailed control-level compliance status
- **CSV Export** - Download compliance data for reporting

### Suppression Features
- **Suppression Indicator** - Visual indicator when suppressions are active
- **Suppression Modal** - Detailed view of all suppressions
- **Service-Level Suppressions** - Rules suppressed for all resources
- **Resource-Specific Suppressions** - Rules suppressed for specific resources

### Accessibility
- **Keyboard Navigation** - Full keyboard support with skip-to-content link
- **ARIA Labels** - Screen reader compatible
- **Responsive Design** - Works on desktop, tablet, and mobile

### Community Features
- **⭐ GitHub Star Integration** - Easy access to star the repository directly from the UI
- **Issue Reporting** - Quick link to raise issues on GitHub
- **Community Links** - Direct access to project repository and documentation
- **Focus Indicators** - Clear visual focus states

## Differences from AdminLTE UI

| Feature | AdminLTE (Legacy) | Cloudscape (New) |
|---------|------------------|------------------|
| **Bundle Size** | 20MB+ (multiple files) | 2MB (single file) |
| **Dependencies** | jQuery, Bootstrap, external CSS/JS | None (self-contained) |
| **Framework Support** | Basic HTML pages | Interactive charts & tables |
| **Suppressions** | Not visible in UI | Modal with detailed view |
| **Accessibility** | Limited | WCAG 2.1 Level AA |
| **Mobile Support** | Limited | Fully responsive |
| **Offline** | Requires local server | Works with file:// |
| **Search/Filter** | Basic | Real-time with highlighting |
| **Data Visualization** | Static | Interactive charts & Sankey diagrams |
| **GuardDuty Support** | Basic findings list | Dedicated charts, settings, grouped findings |
| **Cross-Service Analysis** | Not available | Aggregated findings with advanced filtering |
| **Modernization Guidance** | Not available | Interactive Sankey diagrams |
| **Trusted Advisor** | Not available | Integrated TA checks with pillar organization |

## Technology Stack

- **React 18** - UI framework
- **React Router** - Client-side routing with hash-based URLs
- **AWS Cloudscape Design System** - Component library
- **Vite** - Build tool with single-file plugin
- **Recharts** - Chart library for Sankey diagrams and data visualization

## Build Process

### Prerequisites
```bash
node >= 16.x
npm >= 8.x
```

### Development
```bash
cd cloudscape-ui
npm install
npm run dev
```

### Production Build
```bash
npm run build
# Output: dist/index.html (single file)
```

### Build Configuration
The build uses `vite-plugin-singlefile` to create a single HTML file with all assets inlined:
- JavaScript bundled and minified
- CSS bundled and minified
- No external dependencies
- Data embedded via `window.__REPORT_DATA__`

## Data Structure

The UI expects data in `window.__REPORT_DATA__` with this structure:

```javascript
{
  // Service data
  "s3": {
    "summary": {
      "RuleName": {
        "criticality": "H|M|L",
        "shortDesc": "Description",
        "^description": "Full description",
        "__categoryMain": "Category",
        "__affectedResources": {
          "region": ["resource1", "resource2"]
        }
      }
    }
  },
  
  // Framework data
  "framework_MSR": {
    "metadata": {
      "name": "Framework Name",
      "description": "Framework Description"
    },
    "summary": {
      "compliant": 10,
      "non_compliant": 5,
      "not_applicable": 2
    },
    "details": [
      {
        "controlId": "MSR-001",
        "controlName": "Control Name",
        "service": "s3",
        "status": "COMPLIANT|NON_COMPLIANT|NOT_APPLICABLE",
        "findingCount": 5
      }
    ]
  },
  
  // Custom Page data
  "customPage_findings": {
    "findings": [
      {
        "service": "s3",
        "Region": "us-east-1",
        "Check": "BucketEncryption",
        "Type": "Security",
        "ResourceID": "my-bucket",
        "Severity": "High"
      }
    ],
    "suppressed": []
  },
  
  "customPage_modernize": {
    "Computes": {
      "nodes": ["Resources (100)", "Computes (80)", "EC2 (75)", ...],
      "links": [{"source": 0, "target": 1, "value": 80}, ...]
    },
    "Databases": {
      "nodes": ["Resources (100)", "Databases (40)", "RDS (35)", ...],
      "links": [{"source": 0, "target": 1, "value": 40}, ...]
    }
  },
  
  "customPage_ta": {
    "error": null,
    "pillars": {
      "COST_OPTIMIZING": {
        "checks": [
          {
            "name": "Low Utilization Amazon EC2 Instances",
            "status": "warning",
            "resources": ["i-1234567890abcdef0"],
            "description": "EC2 instances with low utilization"
          }
        ]
      }
    }
  },
  
  // Metadata
  "__metadata": {
    "accountId": "123456789012",
    "regions": ["us-east-1", "us-west-2"],
    "suppressions": {
      "serviceLevelSuppressions": [
        {
          "service": "s3",
          "rule": "BucketReplication",
          "description": "Reason for suppression"
        }
      ],
      "resourceSuppressions": [
        {
          "service": "s3",
          "rule": "BucketEncryption",
          "resources": ["bucket-name-1", "bucket-name-2"],
          "reason": "Reason for suppression"
        }
      ]
    }
  }
}
```

## Component Architecture

```
src/
├── App.jsx                 # Main app with routing
├── main.jsx               # Entry point
├── components/
│   ├── Dashboard.jsx      # Landing page with KPIs
│   ├── ServiceDetail.jsx  # Service findings page
│   ├── FrameworkDetail.jsx # Framework compliance page
│   ├── GuardDutyDetail.jsx # GuardDuty special handling
│   ├── CustomPage.jsx     # Custom page router
│   ├── FindingsPage.jsx   # Cross-service findings
│   ├── SankeyDiagram.jsx  # Modernization Sankey diagrams
│   ├── TrustedAdvisorPage.jsx # Trusted Advisor integration
│   ├── TopNavigation.jsx  # Top nav bar
│   ├── SideNavigation.jsx # Left sidebar
│   ├── SuppressionModal.jsx # Suppression details
│   ├── ErrorBoundary.jsx  # Error handling
│   ├── EmptyState.jsx     # No data state
│   └── SkipToContent.jsx  # Accessibility
└── utils/
    ├── dataLoader.js      # Data loading utilities
    ├── formatters.js      # Display formatters
    └── htmlDecoder.js     # HTML entity decoder
```

## Routing

The UI uses hash-based routing for `file://` protocol compatibility:

- `#/` - Dashboard
- `#/service/:serviceName` - Service detail (e.g., `#/service/s3`)
- `#/service/guardduty` - GuardDuty special handling with charts and settings
- `#/framework/:frameworkName` - Framework detail (e.g., `#/framework/MSR`)
- `#/page/findings` - Cross-service findings aggregation
- `#/page/modernize` - Modernization recommendations with Sankey diagrams
- `#/page/ta` - Trusted Advisor integration

## Browser Support

- ✅ Chrome 90+
- ✅ Firefox 88+
- ✅ Safari 14+
- ✅ Edge 90+

All browsers support the `file://` protocol for local HTML files.

## File Size

- **Uncompressed**: ~2.0 MB
- **Gzipped**: ~470 KB
- **Target**: < 5 MB (achieved)
- **Reduction**: 90% smaller than AdminLTE

## Performance

- **Load Time**: < 2 seconds
- **Time to Interactive**: < 1 second
- **Bundle Size**: 1.8 MB (minified)
- **No Network Requests**: Fully offline

## Accessibility Features

### Keyboard Navigation
- Tab through all interactive elements
- Skip-to-content link (Tab on page load)
- Enter/Space to activate buttons
- Escape to close modals

### Screen Reader Support
- ARIA labels on all regions
- Semantic HTML structure
- Descriptive button labels
- Table headers properly associated

### Visual
- High contrast colors
- Focus indicators on all interactive elements
- Responsive text sizing
- Color is not the only indicator

## Known Limitations

### File:// Protocol
- Browser security restrictions apply
- No AJAX requests possible (not needed)
- Hash-based routing required
- Local storage may be restricted in some browsers

### Data Size
- Recommended max: 10,000 findings
- Large datasets may cause slow initial render
- Consider filtering services if performance issues occur

### Browser Compatibility
- Requires modern browser (ES6+ support)
- JavaScript must be enabled
- Cookies/local storage not required

## Troubleshooting

### Page is Blank
1. Check browser console (F12) for errors
2. Verify JavaScript is enabled
3. Try a different browser
4. Ensure file is not corrupted

### Suppressions Not Showing
1. Verify `--suppress_file` was used during scan
2. Check console: `window.__REPORT_DATA__.__metadata.suppressions`
3. Ensure suppressions.json has valid format

### Framework Data Missing
1. Ensure frameworks were generated during scan
2. Check console: `window.__REPORT_DATA__.framework_MSR`
3. Verify framework generation didn't fail

### Charts Not Rendering
1. Check browser console for errors
2. Ensure browser supports modern JavaScript
3. Try Chrome or Firefox (best support)

## Development

### Adding New Components
1. Create component in `src/components/`
2. Import in `App.jsx` or parent component
3. Add routing if needed
4. Update this README

### Modifying Data Structure
1. Update `dataLoader.js` utilities
2. Update component prop types
3. Update Python `OutputGenerator.py`
4. Test with real data

### Styling
- Use Cloudscape components when possible
- Follow Cloudscape design tokens
- Avoid custom CSS unless necessary
- Test responsive behavior

## Testing

### Manual Testing
See [BROWSER_TESTING_GUIDE.md](./BROWSER_TESTING_GUIDE.md) for comprehensive testing checklist.

### Quick Verification
```javascript
// Open browser console (F12) and run:
console.log('Data loaded:', !!window.__REPORT_DATA__);
console.log('Services:', Object.keys(window.__REPORT_DATA__).filter(k => !k.startsWith('_') && !k.startsWith('framework_')));
console.log('Frameworks:', Object.keys(window.__REPORT_DATA__).filter(k => k.startsWith('framework_')));
```

## Contributing

When contributing to the Cloudscape UI:

1. **Follow React best practices**
   - Functional components with hooks
   - Proper prop validation
   - Meaningful component names

2. **Use Cloudscape components**
   - Don't reinvent existing components
   - Follow Cloudscape design patterns
   - Use design tokens for styling

3. **Maintain accessibility**
   - Add ARIA labels where needed
   - Ensure keyboard navigation works
   - Test with screen reader

4. **Keep bundle size small**
   - Avoid large dependencies
   - Use code splitting if needed
   - Monitor build output size

5. **Test thoroughly**
   - Test with real AWS data
   - Test in multiple browsers
   - Test with file:// protocol
   - Test accessibility features

## License

Same as Service Screener main project.

## Support

For issues or questions:
1. Check [BROWSER_TESTING_GUIDE.md](./BROWSER_TESTING_GUIDE.md)
2. Check browser console for errors
3. Review this README
4. Open an issue in the main repository
