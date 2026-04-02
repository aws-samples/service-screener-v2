// Constants for Service Screener Cloudscape UI

// Criticality levels
export const CRITICALITY = {
  H: 'High',
  M: 'Medium',
  L: 'Low',
  I: 'Informational'
};

// Criticality colors for badges
export const CRITICALITY_COLORS = {
  H: 'red',
  M: 'orange',
  L: 'blue',
  I: 'grey'
};

// Category mappings (T excluded - internal use only)
export const CATEGORY_MAIN = {
  R: 'Reliability',
  S: 'Security',
  O: 'Ops Excellence',
  P: 'Performance',
  C: 'Cost Ops'
};

// Category colors - custom styles matching FindingsPage
export const CATEGORY_COLORS = {
  S: 'red',      // Security: Red
  C: 'blue',     // Cost Optimization: Blue  
  P: 'green',    // Performance Efficiency: Green
  R: 'magenta',  // Reliability: Magenta/Pink
  O: 'orange'    // Operational Excellence: Orange
};

// Category custom styles for badges
export const CATEGORY_STYLES = {
  S: { backgroundColor: '#d13212', color: 'white' }, // Security: Red
  C: { backgroundColor: '#0073bb', color: 'white' }, // Cost Optimization: Blue
  P: { backgroundColor: '#1d8102', color: 'white' }, // Performance Efficiency: Green
  R: { backgroundColor: '#f012be', color: 'white' }, // Reliability: Magenta/Pink
  O: { backgroundColor: '#ff851b', color: 'white' }  // Operational Excellence: Orange
};

// Compliance status
export const COMPLIANCE_STATUS = {
  0: 'Not Available',
  1: 'Compliant',
  2: 'Need Attention'
};

// Compliance status colors
export const COMPLIANCE_COLORS = {
  0: 'grey',
  1: 'green',
  2: 'red'
};

// Impact tags mapping
export const IMPACT_TAGS = {
  downtime: 'Downtime Risk',
  slowness: 'Performance Impact',
  additionalCost: 'Cost Impact',
  needFullTest: 'Requires Testing'
};
