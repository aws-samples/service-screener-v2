// Formatting utilities for Service Screener data

import { 
  CRITICALITY, 
  CRITICALITY_COLORS, 
  CATEGORY_MAIN, 
  CATEGORY_COLORS,
  CATEGORY_STYLES,
  COMPLIANCE_STATUS,
  COMPLIANCE_COLORS,
  IMPACT_TAGS
} from './constants';

/**
 * Format criticality level to human-readable text
 * @param {string} criticality - H, M, L, or I
 * @returns {string} Human-readable criticality
 */
export const formatCriticality = (criticality) => {
  return CRITICALITY[criticality] || criticality;
};

/**
 * Get color for criticality badge
 * @param {string} criticality - H, M, L, or I
 * @returns {string} Cloudscape badge color
 */
export const getCriticalityColor = (criticality) => {
  return CRITICALITY_COLORS[criticality] || 'grey';
};

/**
 * Format category code to human-readable text
 * @param {string} category - R, S, O, P, or C
 * @returns {string} Human-readable category
 */
export const formatCategory = (category) => {
  return CATEGORY_MAIN[category] || category;
};

/**
 * Get color for category badge
 * @param {string} category - R, S, O, P, or C
 * @returns {string} Cloudscape badge color
 */
export const getCategoryColor = (category) => {
  return CATEGORY_COLORS[category] || 'grey';
};

/**
 * Get custom style for category badge
 * @param {string} category - R, S, O, P, or C
 * @returns {Object} Style object with backgroundColor and color
 */
export const getCategoryStyle = (category) => {
  return CATEGORY_STYLES[category] || { backgroundColor: '#545b64', color: 'white' };
};

/**
 * Filter out internal categories (T) from category list
 * @param {Array<string>} categories - Array of category codes
 * @returns {Array<string>} Filtered categories excluding T
 */
export const filterUserCategories = (categories) => {
  return categories.filter(category => category !== 'T');
};

/**
 * Format compliance status code to human-readable text
 * @param {number} status - 0, 1, or 2
 * @returns {string} Human-readable compliance status
 */
export const formatComplianceStatus = (status) => {
  return COMPLIANCE_STATUS[status] || 'Unknown';
};

/**
 * Get color for compliance status badge
 * @param {number} status - 0, 1, or 2
 * @returns {string} Cloudscape badge color
 */
export const getComplianceColor = (status) => {
  return COMPLIANCE_COLORS[status] || 'grey';
};

/**
 * Get impact tags from finding data
 * @param {Object} finding - Finding object
 * @returns {Array<string>} Array of impact tag labels
 */
export const getImpactTags = (finding) => {
  const tags = [];
  
  if (finding.downtime > 0) tags.push(IMPACT_TAGS.downtime);
  if (finding.slowness > 0) tags.push(IMPACT_TAGS.slowness);
  if (finding.additionalCost > 0) tags.push(IMPACT_TAGS.additionalCost);
  if (finding.needFullTest > 0) tags.push(IMPACT_TAGS.needFullTest);
  
  return tags;
};

/**
 * Count total resources affected by a finding
 * @param {Object} affectedResources - Object with regions as keys and resource arrays as values
 * @returns {number} Total count of affected resources
 */
export const countAffectedResources = (affectedResources) => {
  if (!affectedResources) return 0;
  
  return Object.values(affectedResources).reduce((total, resources) => {
    return total + (Array.isArray(resources) ? resources.length : 0);
  }, 0);
};

/**
 * Extract service name from service key
 * @param {string} serviceKey - Service key from data (e.g., "cloudfront", "ec2")
 * @returns {string} Formatted service name
 */
export const formatServiceName = (serviceKey) => {
  return serviceKey.toUpperCase();
};

/**
 * Parse links from finding description
 * @param {Object} finding - Finding object with __links array
 * @returns {Array<Object>} Array of link objects with text and url
 */
export const parseLinks = (finding) => {
  if (!finding.__links || !Array.isArray(finding.__links)) {
    return [];
  }
  
  return finding.__links.map((link, index) => ({
    text: `Reference ${index + 1}`,
    url: link
  }));
};
