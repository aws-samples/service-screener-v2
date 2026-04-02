import React, { useState, useEffect, useMemo } from 'react';
import { useParams } from 'react-router-dom';
import Container from '@cloudscape-design/components/container';
import Header from '@cloudscape-design/components/header';
import SpaceBetween from '@cloudscape-design/components/space-between';
import Box from '@cloudscape-design/components/box';
import Badge from '@cloudscape-design/components/badge';
import ExpandableSection from '@cloudscape-design/components/expandable-section';
import Link from '@cloudscape-design/components/link';
import ColumnLayout from '@cloudscape-design/components/column-layout';
import BarChart from '@cloudscape-design/components/bar-chart';
import PieChart from '@cloudscape-design/components/pie-chart';
import Select from '@cloudscape-design/components/select';
import TextFilter from '@cloudscape-design/components/text-filter';
import Grid from '@cloudscape-design/components/grid';
import Table from '@cloudscape-design/components/table';
import Button from '@cloudscape-design/components/button';
import Checkbox from '@cloudscape-design/components/checkbox';

import { 
  loadReportData,
  getServiceData, 
  getServiceFindings 
} from '../utils/dataLoader';
import { 
  formatServiceName,
  countAffectedResources,
  getImpactTags,
  parseLinks
} from '../utils/formatters';
import { renderHtml } from '../utils/htmlDecoder';

/**
 * ServiceDetail component - shows detailed findings for a specific service
 */
const ServiceDetail = () => {
  const { serviceName } = useParams();
  const [reportData, setReportData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [searchText, setSearchText] = useState('');
  const [severityFilter, setSeverityFilter] = useState({ label: 'All Severities', value: 'all' });
  const [categoryFilter, setCategoryFilter] = useState({ label: 'All Categories', value: 'all' });
  const [showQuickWins, setShowQuickWins] = useState(false);
  const [expandedFindings, setExpandedFindings] = useState(new Set());

  // Expand/Collapse All functions
  const expandAllFindings = () => {
    const allFindingIds = filteredFindings.map(finding => finding.ruleName);
    setExpandedFindings(new Set(allFindingIds));
  };

  const collapseAllFindings = () => {
    setExpandedFindings(new Set());
  };

  const toggleFinding = (findingId) => {
    const newExpanded = new Set(expandedFindings);
    if (newExpanded.has(findingId)) {
      newExpanded.delete(findingId);
    } else {
      newExpanded.add(findingId);
    }
    setExpandedFindings(newExpanded);
  };

  // Quick Win logic (formerly low-hanging fruit)
  const isQuickWin = (finding) => {
    return finding.downtime === 0 && 
           finding.additionalCost === 0 && 
           finding.needFullTest === 0;
  };

  // Impact indicators helper
  const getImpactIndicators = (finding) => {
    const indicators = [];
    
    if (finding.downtime !== 0) {
      indicators.push({
        type: 'downtime',
        label: 'Downtime Required',
        color: 'red',
        icon: '⏱️'
      });
    }
    
    if (finding.additionalCost === 1) {
      indicators.push({
        type: 'cost',
        label: 'Additional Cost',
        color: 'orange',
        icon: '💰'
      });
    } else if (finding.additionalCost === -1) {
      indicators.push({
        type: 'savings',
        label: 'Cost Savings',
        color: 'green',
        icon: '💰'
      });
    }
    
    if (finding.needFullTest !== 0) {
      const testLabel = finding.needFullTest === 1 ? 'Testing Required' : 'Testing Maybe Required';
      indicators.push({
        type: 'testing',
        label: testLabel,
        color: 'blue',
        icon: '🧪'
      });
    }
    
    if (finding.slowness !== 0) {
      indicators.push({
        type: 'performance',
        label: 'Performance Impact',
        color: 'purple',
        icon: '⚡'
      });
    }
    
    return indicators;
  };
  
  // Load report data
  useEffect(() => {
    const loadData = async () => {
      try {
        const data = await loadReportData();
        setReportData(data);
      } catch (error) {
        console.error('Failed to load report data:', error);
      } finally {
        setLoading(false);
      }
    };
    
    loadData();
  }, []);
  
  // Get service data
  const serviceData = useMemo(() => {
    return reportData ? getServiceData(reportData, serviceName) : null;
  }, [reportData, serviceName]);
  
  const findings = useMemo(() => {
    return serviceData ? getServiceFindings(serviceData) : [];
  }, [serviceData]);
  
  // Helper functions (defined before useMemo hooks that use them)
  const getCriticalityIcon = (criticality) => {
    switch (criticality) {
      case 'H': return '🔴';
      case 'M': return '🟡';
      case 'L': return '🔵';
      case 'I': return '⚪';
      default: return '⚫';
    }
  };
  
  const getSeverityCardStyle = (criticality) => {
    switch (criticality) {
      case 'H': 
        return {
          backgroundColor: '#d13212',
          color: '#16191f',
          headerTextColor: '#16191f',
          categoryBgColor: '#d13212',
          categoryTextColor: 'white'
        };
      case 'M': 
        return {
          backgroundColor: '#ff9900',
          color: '#16191f',
          headerTextColor: '#16191f',
          categoryBgColor: '#ff9900',
          categoryTextColor: 'white'
        };
      case 'L': 
        return {
          backgroundColor: '#0073bb',
          color: '#16191f',
          headerTextColor: '#16191f',
          categoryBgColor: '#0073bb',
          categoryTextColor: 'white'
        };
      case 'I': 
        return {
          backgroundColor: '#f2f3f3',
          color: '#16191f',
          headerTextColor: '#16191f',
          categoryBgColor: '#545b64',
          categoryTextColor: 'white'
        };
      default: 
        return {
          backgroundColor: '#f9f9f9',
          color: '#16191f',
          headerTextColor: '#16191f',
          categoryBgColor: '#545b64',
          categoryTextColor: 'white'
        };
    }
  };
  
  const getCategoryStyle = (category) => {
    const styles = {
      'S': { backgroundColor: '#d13212', color: 'white', label: 'Security' },
      'R': { backgroundColor: '#f012be', color: 'white', label: 'Reliability' },
      'C': { backgroundColor: '#0073bb', color: 'white', label: 'Cost Ops' },
      'P': { backgroundColor: '#1d8102', color: 'white', label: 'Performance' },
      'O': { backgroundColor: '#ff851b', color: 'white', label: 'Ops Excellence' }
    };
    return styles[category] || { backgroundColor: '#545b64', color: 'white', label: category };
  };
  
  // Calculate metrics
  const metrics = useMemo(() => {
    if (!serviceData) return null;
    
    const stats = serviceData.stats || {};
    const totalFindings = findings.length;
    const quickWinCount = findings.filter(finding => isQuickWin(finding)).length;
    
    const formatTime = (seconds) => {
      if (!seconds || seconds === 0) return '0s';
      return `${Math.round(parseFloat(seconds))}s`;
    };
    
    return {
      resources: stats.resources || 0,
      totalFindings,
      rulesExecuted: stats.rules || 0,
      uniqueRules: stats.checksCount || 0,  // Use checksCount from stats, not calculated from findings
      suppressed: stats.suppressed || 0,
      timespent: formatTime(stats.timespent),
      quickWins: quickWinCount
    };
  }, [serviceData, findings]);
  
  // Filter and sort findings
  const filteredFindings = useMemo(() => {
    let filtered = [...findings];
    
    // Apply search filter
    if (searchText) {
      const search = searchText.toLowerCase();
      filtered = filtered.filter(finding => 
        finding.ruleName?.toLowerCase().includes(search) ||
        finding.shortDesc?.toLowerCase().includes(search) ||
        finding['^description']?.toLowerCase().includes(search)
      );
    }
    
    // Apply severity filter
    if (severityFilter.value !== 'all') {
      filtered = filtered.filter(finding => finding.criticality === severityFilter.value);
    }
    
    // Apply category filter
    if (categoryFilter.value !== 'all') {
      filtered = filtered.filter(finding => finding.__categoryMain === categoryFilter.value);
    }
    
    // Apply quick wins filter
    if (showQuickWins) {
      filtered = filtered.filter(finding => isQuickWin(finding));
    }
    
    return filtered;
  }, [findings, searchText, severityFilter, categoryFilter, showQuickWins]);
  
  const sortedFindings = useMemo(() => {
    const criticalityOrder = { 'H': 0, 'M': 1, 'L': 2, 'I': 3 };
    return [...filteredFindings].sort((a, b) => {
      const orderA = criticalityOrder[a.criticality] ?? 4;
      const orderB = criticalityOrder[b.criticality] ?? 4;
      return orderA - orderB;
    });
  }, [filteredFindings]);
  
  // Chart data
  const chartData = useMemo(() => {
    if (!findings.length) return { severityChart: [], categoryChart: [] };
    
    // Group findings by region and severity for stacked bar chart
    const regionSeverityData = {};
    const categoryCounts = {};
    
    findings.forEach(finding => {
      // Extract regions from affected resources
      const affectedResources = finding.__affectedResources || {};
      const regions = Object.keys(affectedResources);
      
      // If no regions in affected resources, try to get from finding data
      if (regions.length === 0) {
        // Fallback: use a default region or extract from other fields
        regions.push('Global');
      }
      
      regions.forEach(region => {
        if (!regionSeverityData[region]) {
          regionSeverityData[region] = { 'H': 0, 'M': 0, 'L': 0, 'I': 0 };
        }
        
        // Count by severity for this region
        if (regionSeverityData[region].hasOwnProperty(finding.criticality)) {
          regionSeverityData[region][finding.criticality]++;
        }
      });
      
      // Count by category for pie chart
      const category = finding.__categoryMain;
      if (category) {
        categoryCounts[category] = (categoryCounts[category] || 0) + 1;
      }
    });
    
    // Create stacked bar chart data
    const regions = Object.keys(regionSeverityData).sort();
    const severityChart = regions.map(region => ({
      x: region,
      y: regionSeverityData[region]['H'] + regionSeverityData[region]['M'] + 
          regionSeverityData[region]['L'] + regionSeverityData[region]['I']
    }));
    
    // Create series data for stacked bars
    const stackedSeries = [
      {
        title: 'High',
        type: 'bar',
        data: regions.map(region => ({ x: region, y: regionSeverityData[region]['H'] })),
        color: '#d13212'
      },
      {
        title: 'Medium', 
        type: 'bar',
        data: regions.map(region => ({ x: region, y: regionSeverityData[region]['M'] })),
        color: '#ff9900'
      },
      {
        title: 'Low',
        type: 'bar', 
        data: regions.map(region => ({ x: region, y: regionSeverityData[region]['L'] })),
        color: '#0073bb'
      },
      {
        title: 'Info',
        type: 'bar',
        data: regions.map(region => ({ x: region, y: regionSeverityData[region]['I'] })),
        color: '#545b64'
      }
    ].filter(series => series.data.some(item => item.y > 0));
    
    const categoryChart = Object.entries(categoryCounts).map(([category, count]) => {
      const style = getCategoryStyle(category);
      return {
        title: style.label,
        value: count,
        color: style.backgroundColor
      };
    });
    
    // Calculate affected resources by severity
    const severityResources = { 'H': 0, 'M': 0, 'L': 0, 'I': 0 };
    findings.forEach(finding => {
      const severity = finding.criticality;
      if (severityResources.hasOwnProperty(severity)) {
        const resourceCount = countAffectedResources(finding.__affectedResources || {});
        severityResources[severity] += resourceCount;
      }
    });
    
    // Severity distribution table data
    const totalFindings = findings.length;
    const severityData = [
      {
        severity: 'High',
        icon: '🔴',
        count: Object.values(regionSeverityData).reduce((sum, region) => sum + region.H, 0),
        resources: severityResources.H,
        color: 'text-status-error',
        barColor: '#d13212'
      },
      {
        severity: 'Medium',
        icon: '🟡',
        count: Object.values(regionSeverityData).reduce((sum, region) => sum + region.M, 0),
        resources: severityResources.M,
        color: 'text-status-warning',
        barColor: '#ff9900'
      },
      {
        severity: 'Low',
        icon: '🔵',
        count: Object.values(regionSeverityData).reduce((sum, region) => sum + region.L, 0),
        resources: severityResources.L,
        color: 'text-status-info',
        barColor: '#0073bb'
      },
      {
        severity: 'Info',
        icon: '⚪',
        count: Object.values(regionSeverityData).reduce((sum, region) => sum + region.I, 0),
        resources: severityResources.I,
        color: 'text-status-inactive',
        barColor: '#545b64'
      }
    ].map(item => ({
      ...item,
      percentage: totalFindings > 0 ? ((item.count / totalFindings) * 100).toFixed(1) : '0.0'
    })).filter(item => item.count > 0); // Only show severities that have findings
    
    return { 
      severityChart, 
      categoryChart, 
      stackedSeries,
      regions,
      severityTable: severityData
    };
  }, [findings]);
  

  
  // Filter options
  const severityOptions = [
    { label: 'All Severities', value: 'all' },
    { label: 'High', value: 'H' },
    { label: 'Medium', value: 'M' },
    { label: 'Low', value: 'L' },
    { label: 'Informational', value: 'I' }
  ];
  
  const categoryOptions = useMemo(() => {
    const categories = new Set(findings.map(f => f.__categoryMain).filter(Boolean));
    const options = [{ label: 'All Categories', value: 'all' }];
    
    categories.forEach(category => {
      const style = getCategoryStyle(category);
      options.push({ label: style.label, value: category });
    });
    
    return options;
  }, [findings]);
  
  // Loading state
  if (loading) {
    return (
      <Box textAlign="center" padding={{ vertical: 'xxl' }}>
        <Box variant="h2" color="text-status-inactive">Loading...</Box>
        <Box variant="p" color="text-status-inactive">
          Loading service data for {formatServiceName(serviceName)}...
        </Box>
      </Box>
    );
  }
  
  // Service not found
  if (!serviceData) {
    return (
      <Box textAlign="center" padding={{ vertical: 'xxl' }}>
        <Box variant="h2" color="text-status-inactive">Service not found</Box>
        <Box variant="p" color="text-status-inactive">
          The service "{serviceName}" was not found in the report data.
        </Box>
      </Box>
    );
  }
  
  return (
    <SpaceBetween size="l">
      {/* Page Header */}
      <Header 
        variant="h1"
        description={`Detailed findings for ${formatServiceName(serviceName)}`}
      >
        {formatServiceName(serviceName)}
      </Header>
      
      {/* Stats Section */}
      <Container
        header={
          <Header variant="h2" description="Key metrics and statistics for this service">
            Stats
          </Header>
        }
      >
        <ColumnLayout columns={7} variant="default" minColumnWidth={120}>
          <Box padding="l" backgroundColor="background-container-content" borderRadius="s">
            <SpaceBetween size="xs">
              <Box variant="awsui-key-label">Resources</Box>
              <Box fontSize="display-l" fontWeight="bold" color="text-status-info">
                {metrics.resources}
              </Box>
            </SpaceBetween>
          </Box>
          
          <Box padding="l" backgroundColor="background-container-content" borderRadius="s">
            <SpaceBetween size="xs">
              <Box variant="awsui-key-label">Total Findings</Box>
              <Box fontSize="display-l" fontWeight="bold" color="text-status-warning">
                {metrics.totalFindings}
              </Box>
            </SpaceBetween>
          </Box>
          
          <Box padding="l" backgroundColor="background-container-content" borderRadius="s">
            <SpaceBetween size="xs">
              <Box variant="awsui-key-label">Rules Executed</Box>
              <Box fontSize="display-l" fontWeight="bold" color="text-status-success">
                {metrics.rulesExecuted}
              </Box>
            </SpaceBetween>
          </Box>
          
          <Box padding="l" backgroundColor="background-container-content" borderRadius="s">
            <SpaceBetween size="xs">
              <Box variant="awsui-key-label">Unique Rules</Box>
              <Box fontSize="display-l" fontWeight="bold" color="text-status-info">
                {metrics.uniqueRules}
              </Box>
            </SpaceBetween>
          </Box>
          
          <Box padding="l" backgroundColor="background-container-content" borderRadius="s">
            <SpaceBetween size="xs">
              <Box variant="awsui-key-label">Suppressed</Box>
              <Box fontSize="display-l" fontWeight="bold" color="text-status-inactive">
                {metrics.suppressed}
              </Box>
            </SpaceBetween>
          </Box>
          
          <Box padding="l" backgroundColor="background-container-content" borderRadius="s">
            <SpaceBetween size="xs">
              <Box variant="awsui-key-label">Quick Wins</Box>
              <Box fontSize="display-l" fontWeight="bold" color="text-status-success">
                {metrics.quickWins}
              </Box>
            </SpaceBetween>
          </Box>
          
          <Box padding="l" backgroundColor="background-container-content" borderRadius="s">
            <SpaceBetween size="xs">
              <Box variant="awsui-key-label">Time Spent</Box>
              <Box fontSize="display-l" fontWeight="bold">
                {metrics.timespent}
              </Box>
            </SpaceBetween>
          </Box>
        </ColumnLayout>
      </Container>
      
      {/* Charts Section - Expandable */}
      {findings.length > 0 && (
        <ExpandableSection
          headerText="Charts"
          variant="container"
          defaultExpanded={false}
          headerDescription="Visual breakdown of findings by severity and category"
        >
          <SpaceBetween size="l">
            {/* Full-width stacked bar chart for regions */}
            <div>
              <Box variant="h3" padding={{ bottom: 's' }}>Findings by Region and Severity</Box>
              <BarChart
                series={chartData.stackedSeries}
                xDomain={chartData.regions}
                yDomain={[0, Math.max(...chartData.severityChart.map(item => item.y), 1)]}
                xTitle="Region"
                yTitle="Count"
                height={400}
                stackedBars
                hideFilter
                legendTitle="Severity"
              />
            </div>
            
            {/* Second row: Pie chart + Top Rules */}
            <Grid
              gridDefinition={[
                { colspan: { default: 12, xs: 6 } },
                { colspan: { default: 12, xs: 6 } }
              ]}
            >
              <div>
                <Box variant="h3" padding={{ bottom: 's' }}>Findings by Category</Box>
                <PieChart
                  data={chartData.categoryChart}
                  detailPopoverContent={(datum) => [
                    { key: 'Category', value: datum.title },
                    { key: 'Findings', value: datum.value },
                    { key: 'Percentage', value: `${((datum.value / findings.length) * 100).toFixed(1)}%` }
                  ]}
                  segmentDescription={(datum) => `${datum.title}: ${datum.value} findings (${((datum.value / findings.length) * 100).toFixed(1)}%)`}
                  height={300}
                  hideFilter
                  hideLegend
                />
              </div>
              
              <div>
                <Box variant="h3" padding={{ bottom: 's' }}>Severity Distribution</Box>
                <Table
                  columnDefinitions={[
                    {
                      id: 'severity',
                      header: 'Severity',
                      cell: item => (
                        <SpaceBetween size="xs" direction="horizontal" alignItems="center">
                          <span style={{ fontSize: '16px' }}>{item.icon}</span>
                          <span style={{ fontWeight: '500' }}>{item.severity}</span>
                        </SpaceBetween>
                      ),
                      width: 120
                    },
                    {
                      id: 'count',
                      header: 'Findings',
                      cell: item => (
                        <Box fontSize="heading-s" fontWeight="bold" color={item.color}>
                          {item.count}
                        </Box>
                      ),
                      width: 70
                    },
                    {
                      id: 'resources',
                      header: 'Resources',
                      cell: item => (
                        <Box fontSize="body-m" color="text-body-secondary">
                          {item.resources}
                        </Box>
                      ),
                      width: 80
                    },
                    {
                      id: 'percentage',
                      header: '%',
                      cell: item => (
                        <Box fontSize="body-m">
                          {item.percentage}%
                        </Box>
                      ),
                      width: 60
                    },
                    {
                      id: 'bar',
                      header: 'Distribution',
                      cell: item => (
                        <div style={{ width: '100%', backgroundColor: '#f2f3f3', borderRadius: '4px', height: '8px', position: 'relative' }}>
                          <div
                            style={{
                              width: `${item.percentage}%`,
                              backgroundColor: item.barColor,
                              height: '100%',
                              borderRadius: '4px',
                              transition: 'width 0.3s ease'
                            }}
                          />
                        </div>
                      )
                    }
                  ]}
                  items={chartData.severityTable}
                  variant="borderless"
                  wrapLines
                />
              </div>
            </Grid>
          </SpaceBetween>
        </ExpandableSection>
      )}
      
      {/* Findings Section */}
      <Container
        header={
          <Header 
            variant="h2" 
            counter={`(${sortedFindings.length})`}
            description="Filter and expand findings to view detailed information"
            actions={
              <SpaceBetween direction="horizontal" size="xs">
                <Button 
                  variant="normal" 
                  onClick={expandAllFindings}
                  disabled={sortedFindings.length === 0}
                >
                  Expand All
                </Button>
                <Button 
                  variant="normal" 
                  onClick={collapseAllFindings}
                  disabled={sortedFindings.length === 0}
                >
                  Collapse All
                </Button>
              </SpaceBetween>
            }
          >
            Findings
          </Header>
        }
      >
        {/* Filters */}
        <SpaceBetween size="m">
          <Grid
            gridDefinition={[
              { colspan: { default: 12, xs: 6 } },
              { colspan: { default: 12, xs: 3 } },
              { colspan: { default: 12, xs: 3 } }
            ]}
          >
            <TextFilter
              filteringText={searchText}
              filteringPlaceholder="Search findings..."
              filteringAriaLabel="Filter findings"
              onChange={({ detail }) => setSearchText(detail.filteringText)}
            />
            
            <Select
              selectedOption={severityFilter}
              onChange={({ detail }) => setSeverityFilter(detail.selectedOption)}
              options={severityOptions}
              placeholder="Filter by severity"
            />
            
            <Select
              selectedOption={categoryFilter}
              onChange={({ detail }) => setCategoryFilter(detail.selectedOption)}
              options={categoryOptions}
              placeholder="Filter by category"
            />
          </Grid>
          
          {/* Quick Wins Filter */}
          <Checkbox
            checked={showQuickWins}
            onChange={({ detail }) => setShowQuickWins(detail.checked)}
          >
            Show quick wins only ({metrics?.quickWins || 0} available)
          </Checkbox>
          
          {/* Impact Indicators Legend */}
          <Container
            header={
              <Header variant="h3">
                Impact Indicators Legend
              </Header>
            }
          >
            <Grid
              gridDefinition={[
                { colspan: { default: 12, xs: 6, s: 4, m: 3, l: 2 } },
                { colspan: { default: 12, xs: 6, s: 4, m: 3, l: 2 } },
                { colspan: { default: 12, xs: 6, s: 4, m: 3, l: 2 } },
                { colspan: { default: 12, xs: 6, s: 4, m: 3, l: 2 } },
                { colspan: { default: 12, xs: 6, s: 4, m: 3, l: 2 } },
                { colspan: { default: 12, xs: 6, s: 4, m: 3, l: 2 } }
              ]}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span style={{
                  backgroundColor: '#d4edda',
                  color: '#155724',
                  padding: '4px 8px',
                  borderRadius: '4px',
                  fontSize: '12px',
                  fontWeight: '600'
                }}>
                  🍃 Quick Win
                </span>
                <Box variant="small">No downtime, cost, or testing required</Box>
              </div>
              
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span style={{
                  backgroundColor: '#f8d7da',
                  color: '#721c24',
                  padding: '4px 8px',
                  borderRadius: '4px',
                  fontSize: '12px',
                  fontWeight: '500'
                }}>
                  ⏱️
                </span>
                <Box variant="small">Requires service downtime</Box>
              </div>
              
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span style={{
                  backgroundColor: '#fff3cd',
                  color: '#856404',
                  padding: '4px 8px',
                  borderRadius: '4px',
                  fontSize: '12px',
                  fontWeight: '500'
                }}>
                  💰
                </span>
                <Box variant="small">Additional costs incurred</Box>
              </div>
              
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span style={{
                  backgroundColor: '#d4edda',
                  color: '#155724',
                  padding: '4px 8px',
                  borderRadius: '4px',
                  fontSize: '12px',
                  fontWeight: '500'
                }}>
                  💰
                </span>
                <Box variant="small">Potential cost savings</Box>
              </div>
              
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span style={{
                  backgroundColor: '#cce5ff',
                  color: '#004085',
                  padding: '4px 8px',
                  borderRadius: '4px',
                  fontSize: '12px',
                  fontWeight: '500'
                }}>
                  🧪
                </span>
                <Box variant="small">Testing required</Box>
              </div>
              
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span style={{
                  backgroundColor: '#e2d9f3',
                  color: '#5a2d82',
                  padding: '4px 8px',
                  borderRadius: '4px',
                  fontSize: '12px',
                  fontWeight: '500'
                }}>
                  ⚡
                </span>
                <Box variant="small">Performance impact</Box>
              </div>
            </Grid>
          </Container>
          
          {/* Findings List */}
          {sortedFindings.length === 0 ? (
            <Box textAlign="center" padding={{ vertical: 'l' }}>
              <Box variant="h3" color="text-status-inactive">No findings</Box>
              <Box variant="p" color="text-status-inactive">
                {searchText || severityFilter.value !== 'all' || categoryFilter.value !== 'all' || showQuickWins
                  ? 'No findings match your filter criteria.' 
                  : 'This service has no findings.'}
              </Box>
            </Box>
          ) : (
            <ColumnLayout columns={2} variant="default" minColumnWidth={300}>
              {sortedFindings.map(finding => {
                const categoryStyle = getCategoryStyle(finding.__categoryMain);
                const severityStyle = getSeverityCardStyle(finding.criticality);
                const impactIndicators = getImpactIndicators(finding);
                const isLHF = isQuickWin(finding);
                
                return (
                  <div
                    key={finding.ruleName}
                    style={{
                      backgroundColor: severityStyle.backgroundColor,
                      borderRadius: '8px',
                      overflow: 'hidden'
                    }}
                  >
                    <style>
                      {`
                        .awsui_main_2qdw9_1rr34_243:not(#\\ ) {
                          display: block !important;
                        }
                      `}
                    </style>
                    <ExpandableSection
                      headerText={
                        <div style={{ 
                          display: 'flex', 
                          alignItems: 'center', 
                          justifyContent: 'space-between',
                          width: '100%',
                          margin: 0,
                          padding: 0
                        }}>
                          <div style={{ display: 'flex', alignItems: 'center', flex: 1 }}>
                            <span style={{ 
                              fontWeight: '500',
                              color: severityStyle.headerTextColor,
                              marginRight: '8px'
                            }}>
                              {finding.ruleName}
                            </span>
                            
                            {/* Low-Hanging Fruit Badge */}
                            {isLHF && (
                              <span style={{
                                backgroundColor: '#d4edda',
                                color: '#155724',
                                padding: '2px 6px',
                                borderRadius: '4px',
                                fontSize: '10px',
                                fontWeight: '600',
                                marginRight: '4px'
                              }}>
                                🍃 Quick Win
                              </span>
                            )}
                            
                            {/* Impact Indicators */}
                            {impactIndicators.map((indicator, idx) => (
                              <span
                                key={idx}
                                style={{
                                  backgroundColor: indicator.color === 'red' ? '#f8d7da' : 
                                                 indicator.color === 'orange' ? '#fff3cd' :
                                                 indicator.color === 'green' ? '#d4edda' :
                                                 indicator.color === 'blue' ? '#cce5ff' : '#e2d9f3',
                                  color: indicator.color === 'red' ? '#721c24' : 
                                         indicator.color === 'orange' ? '#856404' :
                                         indicator.color === 'green' ? '#155724' :
                                         indicator.color === 'blue' ? '#004085' : '#5a2d82',
                                  padding: '2px 6px',
                                  borderRadius: '4px',
                                  fontSize: '10px',
                                  fontWeight: '500',
                                  marginRight: '4px',
                                  whiteSpace: 'nowrap'
                                }}
                                title={indicator.label}
                              >
                                {indicator.icon}
                              </span>
                            ))}
                          </div>
                          
                          <span style={{
                            backgroundColor: categoryStyle.backgroundColor,
                            color: categoryStyle.color,
                            padding: '4px 8px',
                            borderRadius: '4px',
                            fontSize: '11px',
                            fontWeight: '500',
                            whiteSpace: 'nowrap',
                            flexShrink: 0
                          }}>
                            {categoryStyle.label}
                          </span>
                        </div>
                      }
                      variant="container"
                      expanded={expandedFindings.has(finding.ruleName)}
                      onChange={({ detail }) => {
                        if (detail.expanded) {
                          setExpandedFindings(prev => new Set([...prev, finding.ruleName]));
                        } else {
                          setExpandedFindings(prev => {
                            const newSet = new Set(prev);
                            newSet.delete(finding.ruleName);
                            return newSet;
                          });
                        }
                      }}
                    >
                    <div style={{ color: severityStyle.color }}>
                      <SpaceBetween size="m">
                        <div>
                          <Box variant="awsui-key-label" color={severityStyle.color}>Description</Box>
                          <Box variant="p" color={severityStyle.color}>
                            <div dangerouslySetInnerHTML={renderHtml(finding['^description'] || finding.shortDesc)} />
                          </Box>
                        </div>
                        
                        {finding.__affectedResources && Object.keys(finding.__affectedResources).length > 0 && (
                          <div>
                            <Box variant="awsui-key-label" color={severityStyle.color}>
                              Affected Resources ({countAffectedResources(finding.__affectedResources)})
                            </Box>
                            <SpaceBetween size="xs">
                              {Object.entries(finding.__affectedResources).map(([region, resources]) => (
                                <div key={region}>
                                  <Box variant="small" fontWeight="bold" color={severityStyle.color}>{region}</Box>
                                  <Box variant="small" color={severityStyle.color} style={{ opacity: 0.8 }}>
                                    {Array.isArray(resources) ? resources.join(', ') : resources}
                                  </Box>
                                </div>
                              ))}
                            </SpaceBetween>
                          </div>
                        )}
                        
                        {finding.__links && finding.__links.length > 0 && (
                          <div>
                            <Box variant="awsui-key-label" color={severityStyle.color}>Documentation</Box>
                            <SpaceBetween size="xs">
                              {finding.__links.map((link, index) => {
                                // Parse HTML anchor tag to extract href and title
                                const parseLink = (htmlLink) => {
                                  const parser = new DOMParser();
                                  const doc = parser.parseFromString(htmlLink, 'text/html');
                                  const anchor = doc.querySelector('a');
                                  if (anchor) {
                                    const href = anchor.getAttribute('href');
                                    const title = anchor.textContent || anchor.innerText;
                                    
                                    // Extract domain from URL
                                    let domain = '';
                                    try {
                                      const url = new URL(href);
                                      domain = url.hostname;
                                      // Remove 'www.' prefix for cleaner display
                                      if (domain.startsWith('www.')) {
                                        domain = domain.substring(4);
                                      }
                                    } catch (e) {
                                      // If URL parsing fails, don't show domain
                                      domain = '';
                                    }
                                    
                                    return {
                                      href: href,
                                      title: domain ? `(${domain}) ${title}` : title
                                    };
                                  }
                                  // Fallback if not HTML anchor tag
                                  return {
                                    href: htmlLink,
                                    title: `Reference ${index + 1}`
                                  };
                                };
                                
                                const parsedLink = parseLink(link);
                                
                                return (
                                  <Link 
                                    key={index} 
                                    href={parsedLink.href} 
                                    external
                                    color={severityStyle.color}
                                  >
                                    {parsedLink.title}
                                  </Link>
                                );
                              })}
                            </SpaceBetween>
                          </div>
                        )}
                      </SpaceBetween>
                    </div>
                    </ExpandableSection>
                  </div>
                );
              })}
            </ColumnLayout>
          )}
        </SpaceBetween>
      </Container>
    </SpaceBetween>
  );
};

export default ServiceDetail;