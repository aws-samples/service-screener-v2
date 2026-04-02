import React, { useState } from 'react';
import { useParams } from 'react-router-dom';
import {
  Container,
  Header,
  SpaceBetween,
  Grid,
  Box,
  ColumnLayout,
  Cards,
  Table,
  Badge,
  Link,
  Alert,
  BarChart,
  PieChart,
  Pagination,
  Button
} from '@cloudscape-design/components';
import EmptyState from './EmptyState';

// Helper function to render grouped findings
function renderGroupedFindings(groupedFindings, severityColor) {
  return (
    <SpaceBetween direction="vertical" size="m">
      {groupedFindings.map((categoryGroup, categoryIndex) => (
        <Box key={categoryIndex}>
          <Header variant="h3">{categoryGroup.category}</Header>
          <SpaceBetween direction="vertical" size="s">
            {categoryGroup.findingTypes.map((findingType, typeIndex) => (
              <Box key={typeIndex} padding={{ left: 'm' }}>
                <Link external href={findingType.docLink}>
                  {findingType.type}
                </Link>
                <Box margin={{ left: 'm', top: 'xs' }}>
                  {findingType.instances.map((instance, instanceIndex) => (
                    <Box key={instanceIndex} fontSize="body-s" color="text-body-secondary">
                      <span style={{ 
                        color: instance.failResolvedAfterXDays ? '#d13212' : 'inherit',
                        fontStyle: instance.isArchived ? 'italic' : 'normal'
                      }}>
                        {instance.failResolvedAfterXDays && '⚠️ '}
                        {instance.isArchived && '👁️ '}
                        {instance.region}: ({instance.count}), {instance.title} | 
                        <small> ({instance.days} days ago), {instance.id}</small>
                      </span>
                    </Box>
                  ))}
                </Box>
              </Box>
            ))}
          </SpaceBetween>
        </Box>
      ))}
    </SpaceBetween>
  );
}

export function GuardDutyDetail({ data }) {
  const [currentPageIndex, setCurrentPageIndex] = useState(1);
  const [visibleCategories, setVisibleCategories] = useState(new Set());
  const pageSize = 10;
  
  if (!data || !data.guardduty) {
    return <EmptyState title="No GuardDuty data available" />;
  }

  const guardDutyData = data.guardduty;
  
  // Get all available regions
  const availableRegions = Object.keys(guardDutyData.detail || {});
  
  if (availableRegions.length === 0) {
    return <EmptyState title="No GuardDuty regions available" />;
  }

  // Process the data for charts and tables (aggregate all regions)
  let processedData;
  try {
    processedData = processAllRegionsGuardDutyData(guardDutyData.detail);
    
    // Initialize visible categories to top 5 on first load
    React.useEffect(() => {
      if (processedData.categoryChart.length > 0 && visibleCategories.size === 0) {
        const top5 = new Set(processedData.categoryChart.slice(0, 5).map(c => c.title));
        setVisibleCategories(top5);
      }
    }, [processedData.categoryChart.length]);
  } catch (error) {
    console.error('Error processing GuardDuty data:', error);
    return <EmptyState title="Error processing GuardDuty data" description={error.message} />;
  }
  
  // Helper function to filter category data
  const getFilteredCategoryData = (categoryData, visibleSet) => {
    if (visibleSet.size === 0) {
      return categoryData.slice(0, 5); // Default to top 5 if nothing selected
    }
    return categoryData.filter(item => visibleSet.has(item.title));
  };

  return (
    <Container
      header={
        <Header
          variant="h1"
          description="Amazon GuardDuty findings, settings, and usage statistics"
        >
          GuardDuty Analysis - All Regions ({availableRegions.join(', ')})
        </Header>
      }
    >
      <SpaceBetween direction="vertical" size="l">
        {/* Severity Summary - Full Width Horizontal Bar */}
        {processedData.severityChart && processedData.severityChart.series && processedData.severityChart.series.length > 0 ? (
          <Grid gridDefinition={[{ colspan: 4 }, { colspan: 4 }, { colspan: 4 }]}>
            <Box textAlign="center" padding="m">
              <Box variant="h1" color="text-status-error">
                {processedData.severityChart.series[0].data[0]}
              </Box>
              <Box variant="h3" color="text-status-error">
                High Severity
              </Box>
            </Box>
            <Box textAlign="center" padding="m">
              <Box variant="h1" color="text-status-warning">
                {processedData.severityChart.series[0].data[1]}
              </Box>
              <Box variant="h3" color="text-status-warning">
                Medium Severity
              </Box>
            </Box>
            <Box textAlign="center" padding="m">
              <Box variant="h1" color="text-status-info">
                {processedData.severityChart.series[0].data[2]}
              </Box>
              <Box variant="h3" color="text-status-info">
                Low Severity
              </Box>
            </Box>
          </Grid>
        ) : (
          <EmptyState title="No findings data available" />
        )}

        {/* Category Chart - Full Width Section */}
        <Box>
          <Header 
            variant="h2"
            actions={
              processedData.categoryChart && processedData.categoryChart.length > 5 ? (
                <SpaceBetween direction="horizontal" size="xs">
                  <Button 
                    variant="link" 
                    onClick={() => {
                      const allCategories = new Set(processedData.categoryChart.slice(0, 5).map(c => c.title));
                      setVisibleCategories(allCategories);
                    }}
                  >
                    Show Top 5
                  </Button>
                  <Button 
                    variant="link" 
                    onClick={() => {
                      const allCategories = new Set(processedData.categoryChart.map(c => c.title));
                      setVisibleCategories(allCategories);
                    }}
                  >
                    Show All
                  </Button>
                </SpaceBetween>
              ) : null
            }
          >
            By Category
          </Header>
          {processedData.categoryChart && Array.isArray(processedData.categoryChart) && processedData.categoryChart.length > 0 ? (
            <PieChart
              data={getFilteredCategoryData(processedData.categoryChart, visibleCategories)}
              detailPopoverContent={(segment, sum) => [
                { key: "Findings", value: segment.value },
                { key: "Percentage", value: `${((segment.value / sum) * 100).toFixed(1)}%` }
              ]}
              segmentDescription={(segment, sum) =>
                `${segment.title}: ${segment.value} findings (${((segment.value / sum) * 100).toFixed(1)}%)`
              }
              height={300}
              hideFilter={true}
              legendTitle="Categories"
            />
          ) : (
            <EmptyState title="No findings data available" />
          )}
        </Box>

        {/* Settings Table */}
        {processedData.settingsTableByRegion && processedData.settingsTableByRegion.length > 0 ? (
          <Table
            columnDefinitions={[
                {
                  id: 'region',
                  header: 'Region',
                  cell: item => item?.region || 'Unknown'
                },
                {
                  id: 's3Protection',
                  header: 'S3 Protection',
                  cell: item => (
                    <span>
                      <Badge color={item?.s3Protection?.enabled ? 'green' : 'red'}>
                        {item?.s3Protection?.enabled ? '✓' : '✗'}
                      </Badge>
                      {' $' + (item?.s3Protection?.usage || 0).toFixed(4)}
                    </span>
                  )
                },
                {
                  id: 'eksProtection',
                  header: 'EKS Protection',
                  cell: item => (
                    <span>
                      <Badge color={item?.eksProtection?.enabled ? 'green' : 'red'}>
                        {item?.eksProtection?.enabled ? '✓' : '✗'}
                      </Badge>
                      {' $' + (item?.eksProtection?.usage || 0).toFixed(4)}
                    </span>
                  )
                },
                {
                  id: 'extendedThreatDetection',
                  header: 'Extended Threat Detection',
                  cell: item => (
                    <span>
                      <Badge color={item?.extendedThreatDetection?.enabled ? 'green' : 'red'}>
                        {item?.extendedThreatDetection?.enabled ? '✓' : '✗'}
                      </Badge>
                      {' $' + (item?.extendedThreatDetection?.usage || 0).toFixed(4)}
                    </span>
                  )
                },
                {
                  id: 'runtimeMonitoring',
                  header: 'Runtime Monitoring',
                  cell: item => (
                    <span>
                      <Badge color={item?.runtimeMonitoring?.enabled ? 'green' : 'red'}>
                        {item?.runtimeMonitoring?.enabled ? '✓' : '✗'}
                      </Badge>
                      {' $' + (item?.runtimeMonitoring?.usage || 0).toFixed(4)}
                    </span>
                  )
                },
                {
                  id: 'malwareProtection',
                  header: 'Malware Protection',
                  cell: item => (
                    <span>
                      <Badge color={item?.malwareProtection?.enabled ? 'green' : 'red'}>
                        {item?.malwareProtection?.enabled ? '✓' : '✗'}
                      </Badge>
                      {' $' + (item?.malwareProtection?.usage || 0).toFixed(4)}
                    </span>
                  )
                },
                {
                  id: 'rdsProtection',
                  header: 'RDS Protection',
                  cell: item => (
                    <span>
                      <Badge color={item?.rdsProtection?.enabled ? 'green' : 'red'}>
                        {item?.rdsProtection?.enabled ? '✓' : '✗'}
                      </Badge>
                      {' $' + (item?.rdsProtection?.usage || 0).toFixed(4)}
                    </span>
                  )
                },
                {
                  id: 'lambdaProtection',
                  header: 'Lambda Protection',
                  cell: item => (
                    <span>
                      <Badge color={item?.lambdaProtection?.enabled ? 'green' : 'red'}>
                        {item?.lambdaProtection?.enabled ? '✓' : '✗'}
                      </Badge>
                      {' $' + (item?.lambdaProtection?.usage || 0).toFixed(4)}
                    </span>
                  )
                },
                {
                  id: 'total',
                  header: 'Total',
                  cell: item => <strong>${(item?.total || 0).toFixed(4)}</strong>
                }
              ]}
              items={processedData.settingsTableByRegion}
              loadingText="Loading settings..."
              empty={<EmptyState title="No settings data available" />}
              header={
                <Header
                  variant="h2"
                  counter={`(${processedData.settingsTableByRegion.length})`}
                  description="GuardDuty data source configuration and usage by region"
                >
                  Current Settings
                </Header>
              }
            />
          ) : (
            <Box>
              <Header variant="h2">Current Settings</Header>
              <EmptyState title="No settings data available" />
            </Box>
          )}

        {/* Findings Sections - Split by Severity */}
        <Box>
          <Header variant="h1">All Findings</Header>
          
          {/* High Severity Findings */}
          {processedData.groupedFindings && processedData.groupedFindings.High && processedData.groupedFindings.High.length > 0 && (
            <Box margin={{ bottom: 'l' }}>
              <Header variant="h2" description={`${processedData.groupedFindings.High.length} finding types`}>
                High Severity
              </Header>
              {renderGroupedFindings(processedData.groupedFindings.High, 'red')}
            </Box>
          )}
          
          {/* Medium Severity Findings */}
          {processedData.groupedFindings && processedData.groupedFindings.Medium && processedData.groupedFindings.Medium.length > 0 && (
            <Box margin={{ bottom: 'l' }}>
              <Header variant="h2" description={`${processedData.groupedFindings.Medium.length} finding types`}>
                Medium Severity
              </Header>
              {renderGroupedFindings(processedData.groupedFindings.Medium, 'orange')}
            </Box>
          )}
          
          {/* Low Severity Findings */}
          {processedData.groupedFindings && processedData.groupedFindings.Low && processedData.groupedFindings.Low.length > 0 && (
            <Box margin={{ bottom: 'l' }}>
              <Header variant="h2" description={`${processedData.groupedFindings.Low.length} finding types`}>
                Low Severity
              </Header>
              {renderGroupedFindings(processedData.groupedFindings.Low, 'blue')}
            </Box>
          )}
          
          {(!processedData.groupedFindings || 
            (processedData.groupedFindings.High.length === 0 && 
             processedData.groupedFindings.Medium.length === 0 && 
             processedData.groupedFindings.Low.length === 0)) && (
            <EmptyState title="No security findings found" />
          )}
        </Box>

        {/* Compliance Alert */}
        {processedData.hasUnresolvedFindings && (
          <Alert
            statusIconAriaLabel="Warning"
            type="warning"
            header="Unresolved Security Findings"
          >
            You have security findings that have not been resolved within the recommended timeframe. 
            High severity findings should be resolved within 1 day, medium within 7 days, and low within 30 days.
          </Alert>
        )}
      </SpaceBetween>
    </Container>
  );
}

// Helper function to process GuardDuty data from all regions
function processAllRegionsGuardDutyData(allRegionsData) {
  const result = {
    severityChart: { series: [], categories: ['High', 'Medium', 'Low'] },
    categoryChart: [],
    settingsTable: [],
    settingsTableByRegion: [],
    findingsTable: [],
    groupedFindings: { High: [], Medium: [], Low: [] },
    hasUnresolvedFindings: false
  };

  // Validate input
  if (!allRegionsData || typeof allRegionsData !== 'object') {
    console.warn('Invalid allRegionsData provided to processAllRegionsGuardDutyData');
    return result;
  }

  const severityCountsByRegion = {};
  const categoryCounts = {};
  const findingsByCategory = { High: {}, Medium: {}, Low: {} };

  // Process each region
  Object.entries(allRegionsData).forEach(([region, regionData]) => {
    // Get the first detector in the region
    const detectorId = Object.keys(regionData)[0];
    const detector = regionData[detectorId];

    if (!detector) return;

    // Initialize region severity counts
    severityCountsByRegion[region] = { High: 0, Medium: 0, Low: 0 };

    // Process Settings for this region
    if (detector.Settings?.value) {
      const settings = detector.Settings.value.Settings;
      const usageData = detector.UsageStat?.value || [];
      const freeTrialData = detector.FreeTrial?.value || {};

      // Create usage lookup
      const usageLookup = {};
      usageData.forEach(usage => {
        usageLookup[usage.DataSource] = parseFloat(usage.Total.Amount);
      });

          // Create region settings row (AWS Console Protection Plans style)
      try {
        const regionSettings = {
          region: region,
          s3Protection: {
            enabled: settings?.S3Logs?.Status === 'ENABLED',
            usage: usageLookup['S3_LOGS'] || 0
          },
          eksProtection: {
            enabled: settings?.Kubernetes?.AuditLogs?.Status === 'ENABLED',
            usage: usageLookup['KUBERNETES_AUDIT_LOGS'] || 0
          },
          extendedThreatDetection: {
            // Maps to DNS Logs and CloudTrail (core threat detection)
            enabled: settings?.DNSLogs?.Status === 'ENABLED' || settings?.CloudTrail?.Status === 'ENABLED',
            usage: (usageLookup['DNS_LOGS'] || 0) + (usageLookup['CLOUD_TRAIL'] || 0)
          },
          runtimeMonitoring: {
            // Maps to VPC Flow Logs (network runtime monitoring)
            enabled: settings?.FlowLogs?.Status === 'ENABLED',
            usage: usageLookup['FLOW_LOGS'] || 0
          },
          malwareProtection: {
            enabled: settings?.MalwareProtection?.ScanEc2InstanceWithFindings?.EbsVolumes?.Status === 'ENABLED',
            usage: usageLookup['EC2_MALWARE_SCAN'] || 0
          },
          rdsProtection: {
            // RDS Protection (if available in settings)
            enabled: settings?.RdsLoginEvents?.Status === 'ENABLED',
            usage: usageLookup['RDS_LOGIN_EVENTS'] || 0
          },
          lambdaProtection: {
            // Lambda Protection (if available in settings)
            enabled: settings?.LambdaNetworkLogs?.Status === 'ENABLED',
            usage: usageLookup['LAMBDA_NETWORK_LOGS'] || 0
          },
          total: Object.values(usageLookup).reduce((sum, val) => sum + val, 0)
        };
        
        result.settingsTableByRegion.push(regionSettings);
      } catch (error) {
        console.warn('Error processing settings for region', region, error);
      }
    }

    // Process Findings for this region
    if (detector.Findings?.value) {
      const findings = detector.Findings.value;

      // Process each severity level
      Object.entries(findings).forEach(([severityCode, severityFindings]) => {
        const severityName = getSeverityName(severityCode);
        
        Object.entries(severityFindings).forEach(([findingType, findingData]) => {
          const category = getFindingCategory(findingType);
          
          // Initialize category in findings structure
          if (!findingsByCategory[severityName][category]) {
            findingsByCategory[severityName][category] = {};
          }
          if (!findingsByCategory[severityName][category][findingType]) {
            findingsByCategory[severityName][category][findingType] = {
              type: findingType,
              docLink: findingData.__,
              instances: []
            };
          }
          
          findingData.res_.forEach(finding => {
            // Add to grouped findings
            findingsByCategory[severityName][category][findingType].instances.push({
              id: finding.Id,
              count: finding.Count,
              title: finding.Title,
              region: finding.region,
              days: finding.days,
              failResolvedAfterXDays: finding.failResolvedAfterXDays,
              isArchived: finding.isArchived
            });

            // Count for charts
            severityCountsByRegion[region][severityName]++;
            categoryCounts[category] = (categoryCounts[category] || 0) + 1;

            // Check for unresolved findings
            if (finding.failResolvedAfterXDays) {
              result.hasUnresolvedFindings = true;
            }
          });
        });
      });
    }
  });

  // Create severity chart data (stacked by region)
  const regions = Object.keys(severityCountsByRegion);
  
  if (regions.length > 0) {
    // Create a single series with total counts across all regions
    const totalCounts = { High: 0, Medium: 0, Low: 0 };
    regions.forEach(region => {
      totalCounts.High += severityCountsByRegion[region]?.High || 0;
      totalCounts.Medium += severityCountsByRegion[region]?.Medium || 0;
      totalCounts.Low += severityCountsByRegion[region]?.Low || 0;
    });
    
    result.severityChart = {
      series: [{
        title: 'Findings',
        data: [totalCounts.High, totalCounts.Medium, totalCounts.Low]
      }],
      categories: ['High', 'Medium', 'Low']
    };
  } else {
    result.severityChart = {
      series: [],
      categories: ['High', 'Medium', 'Low']
    };
  }

  // Create category chart data (sorted by count, top 10)
  const sortedCategories = Object.entries(categoryCounts)
    .sort(([,a], [,b]) => b - a)
    .slice(0, 10);
  
  result.categoryChart = sortedCategories.map(([category, count]) => ({
    title: category,
    value: count
  }));

  // Convert grouped findings to array format
  ['High', 'Medium', 'Low'].forEach(severity => {
    result.groupedFindings[severity] = Object.entries(findingsByCategory[severity]).map(([category, findingTypes]) => ({
      category,
      findingTypes: Object.values(findingTypes)
    }));
  });

  return result;
}

// Helper functions
function getNestedValue(obj, path) {
  return path.split('.').reduce((current, key) => current?.[key], obj);
}

function getSeverityName(code) {
  const mapping = { '8': 'High', '5': 'Medium', '2': 'Low' };
  return mapping[code] || 'Unknown';
}

function getSeverityColor(severity) {
  const colors = { 'High': 'red', 'Medium': 'orange', 'Low': 'blue' };
  return colors[severity] || 'grey';
}

function getFindingCategory(findingType) {
  // Extract category from finding type (e.g., "Discovery:IAMUser/AnomalousBehavior" -> "IAMUser")
  const parts = findingType.split(':');
  if (parts.length > 1) {
    const secondPart = parts[1].split('/')[0];
    return secondPart;
  }
  return 'Other';
}

export default GuardDutyDetail;