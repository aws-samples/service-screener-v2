// Data loading utilities for Service Screener

/**
 * Load report data from window.__REPORT_DATA__ or fetch from JSON file
 * This data is embedded in the HTML file during build or loaded dynamically
 * @returns {Promise<Object|null>} Report data or null if not available
 */
export const loadReportData = async () => {
  try {
    // First try to load from window.__REPORT_DATA__ (embedded data)
    if (typeof window !== 'undefined' && window.__REPORT_DATA__) {
      console.log('Report data loaded from window.__REPORT_DATA__');
      return window.__REPORT_DATA__;
    }
    
    // If not embedded, wait for it to be loaded (development mode)
    console.log('Waiting for report data to be loaded...');
    return new Promise((resolve, reject) => {
      // Check if data is available now
      if (window.__REPORT_DATA__) {
        resolve(window.__REPORT_DATA__);
        return;
      }
      
      // Wait for the reportDataReady event
      const timeout = setTimeout(() => {
        reject(new Error('Timeout waiting for report data'));
      }, 10000); // 10 second timeout
      
      window.addEventListener('reportDataReady', () => {
        clearTimeout(timeout);
        if (window.__REPORT_DATA__) {
          console.log('Report data loaded successfully');
          resolve(window.__REPORT_DATA__);
        } else {
          reject(new Error('Report data not available after event'));
        }
      }, { once: true });
    });
  } catch (error) {
    console.error('Error loading report data:', error);
    return null;
  }
};

/**
 * Discover available accounts from various sources
 * @returns {Array} Array of account objects with id and label
 */
export const discoverAccounts = () => {
  // In a real multi-account scenario, this would scan the directory structure
  // For now, return empty array as single-account is the default use case
  return [];
};

/**
 * Switch to a different account by navigating to its folder
 * @param {string} newAccountId - Target account ID
 */
export const switchAccount = (newAccountId) => {
  const currentPath = window.location.pathname;
  const currentHash = window.location.hash;
  
  // Pattern to match /aws/{12-digit-account}/
  const accountMatch = currentPath.match(/\/aws\/(\d{12})\//);
  
  if (accountMatch) {
    const currentAccountId = accountMatch[1];
    if (currentAccountId !== newAccountId) {
      // Replace account ID in path while preserving the rest
      const newPath = currentPath.replace(/\/aws\/\d{12}\//, `/aws/${newAccountId}/`);
      // Preserve hash for current page context
      window.location.href = newPath + currentHash;
    }
  } else {
    // Fallback: try to construct path to new account
    const pathParts = currentPath.split('/');
    const awsIndex = pathParts.findIndex(part => part === 'aws');
    
    if (awsIndex !== -1 && pathParts[awsIndex + 1]) {
      // Replace the account ID part
      pathParts[awsIndex + 1] = newAccountId;
      const newPath = pathParts.join('/');
      window.location.href = newPath + currentHash;
    } else {
      // Last resort: navigate to new account's index
      const protocol = window.location.protocol;
      const host = window.location.host;
      const basePath = currentPath.split('/').slice(0, -2).join('/'); // Remove filename and current account
      window.location.href = `${protocol}//${host}${basePath}/aws/${newAccountId}/index.html`;
    }
  }
};

/**
 * Extract account ID from report data or URL
 * @param {Object} data - Report data
 * @returns {string} Account ID or 'Unknown'
 */
export const getAccountId = (data) => {
  // First try to get from URL path (for multi-account scenarios)
  const currentPath = window.location.pathname;
  const accountMatch = currentPath.match(/\/aws\/(\d{12})\//);
  if (accountMatch) {
    return accountMatch[1];
  }
  
  // Account ID might be in metadata
  if (data && data.__metadata && data.__metadata.accountId) {
    return data.__metadata.accountId;
  }
  
  // Try to extract account ID from resource names
  // Look for patterns like "956288449190" in resource names
  for (const serviceName in data) {
    if (serviceName.startsWith('__') || serviceName.startsWith('framework_') || serviceName.startsWith('customPage_')) {
      continue;
    }
    
    const service = data[serviceName];
    if (service && service.detail) {
      for (const region in service.detail) {
        for (const resourceId in service.detail[region]) {
          // Extract account ID from resource names like "Bucket::aws-athena-query-results-ap-southeast-1-956288449190"
          const match = resourceId.match(/(\d{12})/);
          if (match) {
            return match[1];
          }
        }
      }
    }
  }
  
  return 'Unknown';
};

/**
 * Get list of all services from report data
 * @param {Object} data - Report data
 * @returns {Array<string>} Array of service names
 */
export const getServices = (data) => {
  if (!data) return [];
  
  // Filter out metadata, framework, and customPage keys
  return Object.keys(data).filter(key => 
    !key.startsWith('__') && 
    !key.startsWith('framework_') &&
    !key.startsWith('customPage_') &&
    typeof data[key] === 'object' &&
    data[key] !== null
  );
};

/**
 * Get list of all frameworks from report data
 * @param {Object} data - Report data
 * @returns {Array<string>} Array of framework names
 */
export const getFrameworks = (data) => {
  if (!data) return [];
  
  return Object.keys(data).filter(key => key.startsWith('framework_'));
};

/**
 * Get list of all custom pages from report data
 * @param {Object} data - Report data
 * @returns {Array<string>} Array of custom page names
 */
export const getCustomPages = (data) => {
  if (!data) return [];
  
  return Object.keys(data)
    .filter(key => key.startsWith('customPage_'))
    .map(key => key.replace('customPage_', ''));
};

/**
 * Get service data by service name
 * @param {Object} data - Report data
 * @param {string} serviceName - Service name
 * @returns {Object|null} Service data or null
 */
export const getServiceData = (data, serviceName) => {
  if (!data || !serviceName) return null;
  
  const serviceKey = serviceName.toLowerCase();
  return data[serviceKey] || null;
};

/**
 * Get framework data by framework name
 * @param {Object} data - Report data
 * @param {string} frameworkName - Framework name
 * @returns {Object|null} Framework data or null
 */
export const getFrameworkData = (data, frameworkName) => {
  if (!data || !frameworkName) return null;
  
  // Try exact match first
  const frameworkKey = frameworkName.startsWith('framework_') 
    ? frameworkName 
    : `framework_${frameworkName}`;
    
  if (data[frameworkKey]) {
    return data[frameworkKey];
  }
  
  // Try case-insensitive match
  const frameworkKeyUpper = frameworkName.startsWith('framework_')
    ? frameworkName.toUpperCase()
    : `framework_${frameworkName.toUpperCase()}`;
  
  if (data[frameworkKeyUpper]) {
    return data[frameworkKeyUpper];
  }
  
  // Try finding by case-insensitive search through all keys
  const lowerFrameworkName = frameworkName.toLowerCase().replace('framework_', '');
  const matchingKey = Object.keys(data).find(key => {
    if (!key.startsWith('framework_')) return false;
    const keyFrameworkName = key.replace('framework_', '').toLowerCase();
    return keyFrameworkName === lowerFrameworkName;
  });
  
  return matchingKey ? data[matchingKey] : null;
};

/**
 * Get all findings for a service
 * @param {Object} serviceData - Service data object
 * @returns {Array<Object>} Array of findings with metadata
 */
export const getServiceFindings = (serviceData) => {
  if (!serviceData || !serviceData.summary) return [];
  
  return Object.entries(serviceData.summary).map(([ruleName, finding]) => ({
    ruleName,
    ...finding
  }));
};

/**
 * Calculate dashboard statistics from report data
 * @param {Object} data - Report data
 * @returns {Object} Statistics object
 */
export const calculateDashboardStats = (data) => {
  const services = getServices(data);
  
  let totalFindings = 0;
  let highPriority = 0;
  let mediumPriority = 0;
  let lowPriority = 0;
  
  services.forEach(service => {
    const serviceData = data[service];
    if (serviceData && serviceData.summary) {
      Object.values(serviceData.summary).forEach(finding => {
        // Count affected resources instead of rules
        let resourceCount = 0;
        if (finding.__affectedResources) {
          // Sum up resources across all regions
          Object.values(finding.__affectedResources).forEach(resources => {
            if (Array.isArray(resources)) {
              resourceCount += resources.length;
            }
          });
        }
        
        // If no affected resources, count as 1 (the rule itself)
        if (resourceCount === 0) {
          resourceCount = 1;
        }
        
        totalFindings += resourceCount;
        
        switch (finding.criticality) {
          case 'H':
            highPriority += resourceCount;
            break;
          case 'M':
            mediumPriority += resourceCount;
            break;
          case 'L':
            lowPriority += resourceCount;
            break;
        }
      });
    }
  });
  
  return {
    totalServices: services.length,
    totalFindings,
    highPriority,
    mediumPriority,
    lowPriority
  };
};

/**
 * Get service statistics for dashboard cards
 * @param {Object} data - Report data
 * @returns {Array<Object>} Array of service statistics
 */
export const getServiceStats = (data) => {
  const services = getServices(data);
  
  return services.map(service => {
    const serviceData = data[service];
    const findings = getServiceFindings(serviceData);
    
    let totalResources = 0;
    let high = 0;
    let medium = 0;
    let low = 0;
    const categories = new Set();
    
    findings.forEach(finding => {
      // Count affected resources instead of rules
      let resourceCount = 0;
      if (finding.__affectedResources) {
        // Sum up resources across all regions
        Object.values(finding.__affectedResources).forEach(resources => {
          if (Array.isArray(resources)) {
            resourceCount += resources.length;
          }
        });
      }
      
      // If no affected resources, count as 1 (the rule itself)
      if (resourceCount === 0) {
        resourceCount = 1;
      }
      
      totalResources += resourceCount;
      
      switch (finding.criticality) {
        case 'H':
          high += resourceCount;
          break;
        case 'M':
          medium += resourceCount;
          break;
        case 'L':
          low += resourceCount;
          break;
      }
      
      if (finding.__categoryMain) {
        categories.add(finding.__categoryMain);
      }
    });
    
    return {
      serviceName: service,
      totalFindings: totalResources,
      high,
      medium,
      low,
      categories: Array.from(categories)
    };
  });
};

/**
 * Check if suppressions are active in the report
 * @param {Object} data - Report data
 * @returns {boolean} True if suppressions are active
 */
export const hasSuppressions = (data) => {
  if (!data || !data.__metadata || !data.__metadata.suppressions) return false;
  
  const suppressions = data.__metadata.suppressions;
  
  // Handle array format
  if (Array.isArray(suppressions)) {
    return suppressions.length > 0;
  }
  
  // Handle object format with serviceLevelSuppressions and resourceSuppressions
  if (typeof suppressions === 'object') {
    const hasServiceLevel = suppressions.serviceLevelSuppressions && 
                           suppressions.serviceLevelSuppressions.length > 0;
    const hasResourceLevel = suppressions.resourceSuppressions && 
                            suppressions.resourceSuppressions.length > 0;
    return hasServiceLevel || hasResourceLevel;
  }
  
  return false;
};

/**
 * Get suppression data from report
 * @param {Object} data - Report data
 * @returns {Object} Suppression data
 */
export const getSuppressions = (data) => {
  if (!data || !data.__metadata || !data.__metadata.suppressions) {
    return { serviceLevelSuppressions: [], resourceSuppressions: [] };
  }
  
  return data.__metadata.suppressions;
};

/**
 * Get category statistics with severity breakdown
 * @param {Object} data - Report data
 * @returns {Array<Object>} Array of category statistics
 */
export const getCategoryStats = (data) => {
  const services = getServices(data);
  const categoryMap = {};
  
  services.forEach(service => {
    const serviceData = data[service];
    if (serviceData && serviceData.summary) {
      Object.values(serviceData.summary).forEach(finding => {
        const category = finding.__categoryMain || 'Other';
        if (category === 'T') return;
        const severity = finding.criticality || 'I';
        
        // Count affected resources instead of rules
        let resourceCount = 0;
        if (finding.__affectedResources) {
          // Sum up resources across all regions
          Object.values(finding.__affectedResources).forEach(resources => {
            if (Array.isArray(resources)) {
              resourceCount += resources.length;
            }
          });
        }
        
        // If no affected resources, count as 1 (the rule itself)
        if (resourceCount === 0) {
          resourceCount = 1;
        }
        
        if (!categoryMap[category]) {
          categoryMap[category] = {
            category,
            total: 0,
            high: 0,
            medium: 0,
            low: 0,
            informational: 0
          };
        }
        
        categoryMap[category].total += resourceCount;
        
        switch (severity) {
          case 'H':
            categoryMap[category].high += resourceCount;
            break;
          case 'M':
            categoryMap[category].medium += resourceCount;
            break;
          case 'L':
            categoryMap[category].low += resourceCount;
            break;
          case 'I':
            categoryMap[category].informational += resourceCount;
            break;
        }
      });
    }
  });
  
  // Convert to array, filter out 'T' category, and sort by total (descending)
  return Object.values(categoryMap)
    .sort((a, b) => b.total - a.total);
};
