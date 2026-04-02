import React, { useState, useEffect } from 'react';
import Container from '@cloudscape-design/components/container';
import Header from '@cloudscape-design/components/header';
import SpaceBetween from '@cloudscape-design/components/space-between';
import Alert from '@cloudscape-design/components/alert';
import Box from '@cloudscape-design/components/box';
import ColumnLayout from '@cloudscape-design/components/column-layout';
import StatusIndicator from '@cloudscape-design/components/status-indicator';
import Badge from '@cloudscape-design/components/badge';
import Button from '@cloudscape-design/components/button';
import Tabs from '@cloudscape-design/components/tabs';
import ExecutiveDashboard from './ExecutiveDashboard';

/**
 * KPI Card component for displaying cost optimization metrics
 */
const CostKPICard = ({ title, value, subtitle, variant = 'default', icon, onClick, clickable = false }) => {
  const content = (
    <SpaceBetween size="xs">
      <Box variant="awsui-key-label">{title}</Box>
      <Box 
        fontSize="display-l" 
        fontWeight="bold" 
        variant={variant}
      >
        {icon && <span style={{ marginRight: '8px' }}>{icon}</span>}
        {value}
      </Box>
      {subtitle && (
        <Box fontSize="body-s" color="text-body-secondary">
          {subtitle}
        </Box>
      )}
    </SpaceBetween>
  );
  
  if (clickable) {
    return (
      <Container>
        <div 
          onClick={onClick}
          style={{ cursor: 'pointer' }}
          role="button"
          tabIndex={0}
          onKeyPress={(e) => {
            if (e.key === 'Enter' || e.key === ' ') {
              onClick();
            }
          }}
        >
          {content}
        </div>
      </Container>
    );
  }
  
  return <Container>{content}</Container>;
};

/**
 * CostOptimizationPage component
 * Main page for displaying AWS cost optimization recommendations
 */
const CostOptimizationPage = ({ data }) => {
  const [cohData, setCohData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [activeTabId, setActiveTabId] = useState('executive');

  useEffect(() => {
    loadCOHData();
  }, [data]);

  const loadCOHData = async () => {
    try {
      setLoading(true);
      
      // Load COH data from the data prop (customPage_coh)
      const cohApiData = data?.customPage_coh;
      
      if (cohApiData && cohApiData.executive_summary) {
        // Transform the API data to match the expected format
        const transformedData = {
          executive_summary: cohApiData.executive_summary,
          recommendations: cohApiData.recommendations || [],
          error_messages: cohApiData.error_messages || [],
          data_collection_time: cohApiData.data_collection_time,
          // Add key_metrics for the UI
          key_metrics: {
            total_monthly_savings: cohApiData.executive_summary?.total_monthly_savings || 0,
            total_annual_savings: cohApiData.executive_summary?.total_annual_savings || 0,
            total_recommendations: cohApiData.executive_summary?.total_recommendations || 0,
            high_priority_count: cohApiData.executive_summary?.high_priority_count || 0,
            quick_wins_count: (cohApiData.recommendations || []).filter(r => 
              r.implementation_effort === 'low' && (r.monthly_savings || 0) > 0
            ).length
          }
        };
        
        setCohData(transformedData);
        setError(null);
      } else {
        throw new Error('Cost Optimization Hub data not available');
      }
    } catch (err) {
      console.error('Error loading COH data:', err);
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleExport = (format) => {
    // In a real implementation, this would trigger the export functionality
    console.log(`Exporting executive report in ${format} format`);
    
    // Mock export functionality
    const exportData = {
      timestamp: new Date().toISOString(),
      format: format,
      data: cohData
    };
    
    // For now, just log the export action
    alert(`Executive report export in ${format.toUpperCase()} format initiated. Check console for details.`);
    console.log('Export data:', exportData);
  };

  const handleDrillDown = (metricType) => {
    // In a real implementation, this would navigate to detailed views
    console.log(`Drilling down into ${metricType} details`);
    
    // For now, switch to the appropriate tab based on metric type
    if (metricType.includes('recommendation') || metricType.includes('priority')) {
      setActiveTabId('recommendations');
    } else if (metricType.includes('analytics') || metricType.includes('service')) {
      setActiveTabId('analytics');
    } else if (metricType === 'quick-wins') {
      // Navigate to recommendations tab for quick wins
      setActiveTabId('recommendations');
    } else {
      setActiveTabId('overview');
    }
  };

  if (loading) {
    return (
      <Container>
        <StatusIndicator type="loading">Loading Cost Optimization Hub data...</StatusIndicator>
      </Container>
    );
  }

  if (error || (cohData && cohData.error)) {
    const errorMessage = error || cohData?.error || 'Unknown error';
    
    return (
      <Container
        header={
          <Header variant="h1">
            Cost Optimization Hub
          </Header>
        }
      >
        <Alert type="warning" header="Cost Optimization Hub Unavailable">
          <Box variant="p">
            {errorMessage}
          </Box>
          <Box variant="p">
            <strong>Possible causes:</strong>
          </Box>
          <ul>
            <li>Cost Optimization Hub is not enabled in your AWS account</li>
            <li>Insufficient IAM permissions for cost optimization services</li>
            <li>No cost optimization recommendations are currently available</li>
          </ul>
          <Box variant="p">
            Please check your AWS configuration and try refreshing the data.
          </Box>
        </Alert>
      </Container>
    );
  }

  if (!cohData || !cohData.executive_summary) {
    return (
      <Container
        header={
          <Header variant="h1">
            Cost Optimization Hub
          </Header>
        }
      >
        <Alert type="info">
          No cost optimization data available. Please run a cost optimization scan to see recommendations.
        </Alert>
      </Container>
    );
  }

  const tabs = [
    {
      id: 'executive',
      label: 'Executive Dashboard',
      content: renderExecutiveDashboardTab()
    },
    {
      id: 'overview',
      label: 'Overview',
      content: renderOverviewTab()
    },
    {
      id: 'recommendations',
      label: 'Recommendations',
      content: renderRecommendationsTab()
    },
    {
      id: 'analytics',
      label: 'Analytics',
      content: renderAnalyticsTab()
    }
  ];

  return (
    <SpaceBetween size="l">
      <Container
        header={
          <Header
            variant="h1"
            description={
              <Box>
                AWS Cost Optimization Hub provides unified cost optimization recommendations across multiple AWS services. 
                It requires access to Cost Optimization Hub, Savings Plans Recommendations, and Compute Optimizer related permissions to pull information. 
                The report might look incomplete if some of these services are not available or properly configured.{' '}
                <a 
                  href="https://github.com/aws-samples/service-screener-v2/tree/main/utils/CustomPage/Pages/COH/README.md" 
                  target="_blank" 
                  rel="noopener noreferrer"
                  style={{ color: '#0073bb', textDecoration: 'underline' }}
                >
                  Read setup guide
                </a>
              </Box>
            }
          >
            <SpaceBetween size="xs" direction="horizontal" alignItems="center">
              Cost Optimization Hub
              <Badge color="red">Experimental</Badge>
            </SpaceBetween>
          </Header>
        }
      >
        {renderExecutiveSummary()}
      </Container>

      <Tabs
        activeTabId={activeTabId}
        onChange={({ detail }) => setActiveTabId(detail.activeTabId)}
        tabs={tabs}
      />
    </SpaceBetween>
  );

  function renderExecutiveDashboardTab() {
    return (
      <ExecutiveDashboard
        cohData={cohData}
        onExport={handleExport}
        onDrillDown={handleDrillDown}
      />
    );
  }

  function renderExecutiveSummary() {
    const summary = cohData.executive_summary;
    const keyMetrics = cohData.key_metrics || {};
    
    return (
      <SpaceBetween size="m">
        <Header variant="h2">Executive Summary</Header>
        
        <ColumnLayout columns={4} variant="text-grid">
          <CostKPICard
            title="Monthly Savings Potential"
            value={`$${keyMetrics.total_monthly_savings?.toLocaleString() || '0'}`}
            subtitle={`$${keyMetrics.total_annual_savings?.toLocaleString() || '0'}/year`}
            variant="h2"
            icon="💰"
          />
          
          <CostKPICard
            title="Total Recommendations"
            value={keyMetrics.total_recommendations || 0}
            subtitle="optimization opportunities"
            variant="h2"
            icon="💡"
          />
          
          <CostKPICard
            title="High Priority Actions"
            value={keyMetrics.high_priority_count || 0}
            subtitle="immediate attention required"
            variant="h2"
            icon="⚠️"
          />
          
          <CostKPICard
            title="Quick Wins"
            value={keyMetrics.quick_wins_count || 0}
            subtitle="low effort, high impact"
            variant="h2"
            icon="🚀"
          />
        </ColumnLayout>

        <ColumnLayout columns={1} variant="text-grid">
          <div>
            <Box variant="awsui-key-label">Last Updated</Box>
            <Box fontSize="body-m" color="text-body-secondary">
              {summary.data_freshness ? new Date(summary.data_freshness).toLocaleString() : 'Unknown'}
            </Box>
          </div>
        </ColumnLayout>
      </SpaceBetween>
    );
  }

  function renderOverviewTab() {
    return (
      <SpaceBetween size="l">
        <Container
          header={
            <Header variant="h2">
              Implementation Roadmap
            </Header>
          }
        >
          {renderImplementationRoadmap()}
        </Container>

        <Container
          header={
            <Header variant="h2">
              Top Savings Opportunities
            </Header>
          }
        >
          {renderTopOpportunities()}
        </Container>
      </SpaceBetween>
    );
  }

  function renderRecommendationsTab() {
    const recommendations = cohData.recommendations || [];
    
    if (recommendations.length === 0) {
      return (
        <Container
          header={
            <Header variant="h2">
              Cost Optimization Recommendations
            </Header>
          }
        >
          <Alert type="info">
            No recommendations available. This may indicate that your AWS resources are already well-optimized.
          </Alert>
        </Container>
      );
    }

    return (
      <SpaceBetween size="l">
        <Container
          header={
            <Header variant="h2">
              Cost Optimization Recommendations
            </Header>
          }
        >
          <Alert type="info" header="View All Recommendations">
            For complete details and to take action on recommendations, visit the{' '}
            <a 
              href="https://us-east-1.console.aws.amazon.com/costmanagement/home#/cost-optimization-hub/so" 
              target="_blank" 
              rel="noopener noreferrer"
              style={{ color: '#0073bb', textDecoration: 'underline' }}
            >
              AWS Cost Optimization Hub Console
            </a>
            . Note: This page currently shows Cost Optimization Hub recommendations only. 
            Compute Optimizer insights are not yet included.
          </Alert>
        </Container>

        <Container
          header={
            <Header 
              variant="h2"
              counter={`(${recommendations.length})`}
              description="Detailed cost optimization recommendations with implementation guidance"
            >
              Cost Optimization Recommendations
            </Header>
          }
        >
          <SpaceBetween size="m">
          {recommendations.map((rec, index) => (
            <Container key={index}>
              <SpaceBetween size="s">
                <SpaceBetween size="xs" direction="horizontal" alignItems="center">
                  <Header variant="h3">
                    {rec.title || 'Cost Optimization Recommendation'}
                  </Header>
                  <Badge 
                    color={rec.priority_level === 'high' ? 'red' : rec.priority_level === 'medium' ? 'blue' : 'green'}
                  >
                    {rec.priority_level?.toUpperCase() || 'MEDIUM'} PRIORITY
                  </Badge>
                  <Badge 
                    color={rec.implementation_effort === 'low' ? 'green' : rec.implementation_effort === 'medium' ? 'blue' : 'red'}
                  >
                    {rec.implementation_effort?.toUpperCase() || 'MEDIUM'} EFFORT
                  </Badge>
                </SpaceBetween>
                
                <Box variant="p">
                  {rec.description || rec.actionType || `${rec.resourceType || 'Resource'} optimization: ${rec.currentResourceSummary || 'Review current configuration'} → ${rec.recommendedResourceSummary || 'Apply recommended changes'}`}
                </Box>
                
                {/* Top Recommended Action and Resource Summary */}
                {(rec.topRecommendedAction || rec.recommendedResourceSummary) && (
                  <div>
                    <Box variant="awsui-key-label" margin={{ bottom: 'xs' }}>
                      Recommendation Details
                    </Box>
                    <ColumnLayout columns={2} variant="text-grid">
                      <div>
                        <Box variant="awsui-key-label" fontSize="body-s">Top Recommended Action</Box>
                        <Box fontSize="body-s" fontWeight="bold" color="text-status-info">
                          {rec.topRecommendedAction || rec.top_recommended_action || 'Optimize resource configuration'}
                        </Box>
                      </div>
                      <div>
                        <Box variant="awsui-key-label" fontSize="body-s">Recommended Resource Summary</Box>
                        <Box fontSize="body-s" color="text-status-success">
                          {rec.recommendedResourceSummary || rec.recommended_resource_summary || 'Review and optimize resource'}
                        </Box>
                      </div>
                    </ColumnLayout>
                  </div>
                )}
                
                <ColumnLayout columns={4} variant="text-grid">
                  <div>
                    <Box variant="awsui-key-label">Monthly Savings</Box>
                    <Box fontSize="heading-l" fontWeight="bold" color="text-status-success">
                      ${(rec.estimatedMonthlySavings || rec.monthly_savings || 0).toLocaleString()}
                    </Box>
                  </div>
                  <div>
                    <Box variant="awsui-key-label">Annual Savings</Box>
                    <Box fontSize="heading-l" fontWeight="bold" color="text-status-success">
                      ${(rec.annual_savings || (rec.estimatedMonthlySavings || rec.monthly_savings || 0) * 12).toLocaleString()}
                    </Box>
                  </div>
                  <div>
                    <Box variant="awsui-key-label">Savings Percentage</Box>
                    <Box fontSize="heading-l" fontWeight="bold" color="text-status-success">
                      {rec.estimatedSavingsPercentage || rec.estimated_savings_percentage || '0'}%
                    </Box>
                  </div>
                  <div>
                    <Box variant="awsui-key-label">Implementation Effort</Box>
                    <Badge 
                      color={rec.implementationEffort === 'LOW' || rec.implementationEffort === 'VERY_LOW' || rec.implementation_effort === 'Low' ? 'green' : 
                             rec.implementationEffort === 'MEDIUM' || rec.implementation_effort === 'Medium' ? 'blue' : 'red'}
                    >
                      {rec.implementationEffort || rec.implementation_effort || 'MEDIUM'}
                    </Badge>
                  </div>
                </ColumnLayout>

                {/* Resource Information */}
                <div>
                  <Box variant="awsui-key-label" margin={{ bottom: 'xs' }}>
                    Resource Details
                  </Box>
                  <ColumnLayout columns={3} variant="text-grid">
                    <div>
                      <Box variant="awsui-key-label" fontSize="body-s">Resource Type</Box>
                      <Box fontSize="body-s" fontWeight="bold">
                        {rec.resourceType || rec.resource_type || (rec.resources && rec.resources[0]?.resourceType) || (rec.affected_resources && rec.affected_resources[0]?.type) || 'Not specified'}
                      </Box>
                    </div>
                    <div>
                      <Box variant="awsui-key-label" fontSize="body-s">Resource ID</Box>
                      <Box fontSize="body-s" fontWeight="bold">
                        {rec.resourceId || rec.resource_id || (rec.resources && rec.resources[0]?.resourceId) || (rec.affected_resources && rec.affected_resources[0]?.id) || 'Not specified'}
                      </Box>
                    </div>
                    <div>
                      <Box variant="awsui-key-label" fontSize="body-s">Region</Box>
                      <Box fontSize="body-s">
                        {rec.region || rec._region || (rec.resources && rec.resources[0]?.region) || (rec.affected_resources && rec.affected_resources[0]?.region) || 'Not specified'}
                      </Box>
                    </div>
                  </ColumnLayout>
                </div>

                {/* Current vs Recommended Configuration */}
                {(rec.currentResourceSummary || rec.recommendedResourceSummary || rec.current_resource_summary || rec.recommended_resource_summary) && (
                  <div>
                    <Box variant="awsui-key-label" margin={{ bottom: 'xs' }}>
                      Configuration Changes
                    </Box>
                    <ColumnLayout columns={2} variant="text-grid">
                      <div>
                        <Box variant="awsui-key-label" fontSize="body-s">Current</Box>
                        <Box fontSize="body-s" color="text-body-secondary">
                          {rec.currentResourceSummary || rec.current_resource_summary || rec.current_configuration || 'Current configuration'}
                        </Box>
                      </div>
                      <div>
                        <Box variant="awsui-key-label" fontSize="body-s">Recommended</Box>
                        <Box fontSize="body-s" color="text-status-success">
                          {rec.recommendedResourceSummary || rec.recommended_resource_summary || rec.recommended_configuration || 'Recommended configuration'}
                        </Box>
                      </div>
                    </ColumnLayout>
                  </div>
                )}

                {/* Implementation Details */}
                {(rec.is_resource_restart_needed || rec.is_rollback_possible) && (
                  <div>
                    <Box variant="awsui-key-label" margin={{ bottom: 'xs' }}>
                      Implementation Details
                    </Box>
                    <ColumnLayout columns={2} variant="text-grid">
                      {rec.is_resource_restart_needed !== undefined && (
                        <div>
                          <Box variant="awsui-key-label" fontSize="body-s">Restart Required</Box>
                          <Badge color={rec.is_resource_restart_needed === 'Yes' ? 'red' : 'green'}>
                            {rec.is_resource_restart_needed || 'No'}
                          </Badge>
                        </div>
                      )}
                      {rec.is_rollback_possible !== undefined && (
                        <div>
                          <Box variant="awsui-key-label" fontSize="body-s">Rollback Possible</Box>
                          <Badge color={rec.is_rollback_possible === 'Yes' ? 'green' : 'red'}>
                            {rec.is_rollback_possible || 'No'}
                          </Badge>
                        </div>
                      )}
                    </ColumnLayout>
                  </div>
                )}

              </SpaceBetween>
            </Container>
          ))}
        </SpaceBetween>
      </Container>
      </SpaceBetween>
    );
  }

  function renderAnalyticsTab() {
    const recommendations = cohData.recommendations || [];
    const keyMetrics = cohData.key_metrics || {};
    
    // Calculate analytics data from recommendations
    const serviceBreakdown = {};
    const priorityBreakdown = { high: 0, medium: 0, low: 0 };
    const effortBreakdown = { low: 0, medium: 0, high: 0 };
    let totalSavings = 0;

    recommendations.forEach(rec => {
      // Service breakdown
      const service = rec.service || 'other';
      if (!serviceBreakdown[service]) {
        serviceBreakdown[service] = { count: 0, savings: 0 };
      }
      serviceBreakdown[service].count += 1;
      serviceBreakdown[service].savings += rec.monthly_savings || 0;
      
      // Priority breakdown
      const priority = rec.priority_level || 'medium';
      priorityBreakdown[priority] = (priorityBreakdown[priority] || 0) + 1;
      
      // Effort breakdown
      const effort = rec.implementation_effort || 'medium';
      effortBreakdown[effort] = (effortBreakdown[effort] || 0) + 1;
      
      totalSavings += rec.monthly_savings || 0;
    });

    return (
      <SpaceBetween size="l">
        <Container
          header={
            <Header variant="h2">
              Cost Analytics & Insights
            </Header>
          }
        >
          <Alert type="info" header="Analytics Overview">
            Cost optimization insights based on {recommendations.length} recommendations 
            with ${totalSavings.toLocaleString()} monthly savings potential.
          </Alert>
        </Container>

        <ColumnLayout columns={2} variant="default">
          {/* Service Breakdown */}
          <Container
            header={
              <Header variant="h3">
                Savings by Service
              </Header>
            }
          >
            <SpaceBetween size="s">
              {Object.entries(serviceBreakdown)
                .sort(([,a], [,b]) => b.savings - a.savings)
                .map(([service, data]) => (
                <div key={service}>
                  <SpaceBetween size="xs" direction="horizontal" alignItems="center">
                    <Box fontSize="body-m" fontWeight="bold">
                      {service.toUpperCase()}
                    </Box>
                    <div style={{ flex: 1 }}>
                      <Box fontSize="body-s" color="text-body-secondary">
                        {data.count} recommendations • ${data.savings.toLocaleString()}/month
                      </Box>
                    </div>
                  </SpaceBetween>
                  <div style={{ 
                    width: '100%', 
                    height: '8px', 
                    backgroundColor: '#e9ecef', 
                    borderRadius: '4px',
                    marginTop: '4px'
                  }}>
                    <div style={{
                      width: `${totalSavings > 0 ? (data.savings / totalSavings) * 100 : 0}%`,
                      height: '100%',
                      backgroundColor: '#0073bb',
                      borderRadius: '4px'
                    }} />
                  </div>
                </div>
              ))}
            </SpaceBetween>
          </Container>

          {/* Priority Distribution */}
          <Container
            header={
              <Header variant="h3">
                Priority Distribution
              </Header>
            }
          >
            <SpaceBetween size="s">
              {Object.entries(priorityBreakdown).map(([priority, count]) => {
                const percentage = recommendations.length > 0 ? (count / recommendations.length) * 100 : 0;
                const color = priority === 'high' ? '#d13212' : priority === 'medium' ? '#0073bb' : '#037f0c';
                
                return (
                  <div key={priority}>
                    <SpaceBetween size="xs" direction="horizontal" alignItems="center">
                      <Box fontSize="body-m">
                        {priority.charAt(0).toUpperCase() + priority.slice(1)} Priority
                      </Box>
                      <Box fontSize="body-s" color="text-body-secondary">
                        {count} ({percentage.toFixed(1)}%)
                      </Box>
                    </SpaceBetween>
                    <div style={{ 
                      width: '100%', 
                      height: '8px', 
                      backgroundColor: '#e9ecef', 
                      borderRadius: '4px',
                      marginTop: '4px'
                    }}>
                      <div style={{
                        width: `${percentage}%`,
                        height: '100%',
                        backgroundColor: color,
                        borderRadius: '4px'
                      }} />
                    </div>
                  </div>
                );
              })}
            </SpaceBetween>
          </Container>
        </ColumnLayout>

        {/* Implementation Effort Analysis */}
        <Container
          header={
            <Header variant="h3">
              Implementation Effort Analysis
            </Header>
          }
        >
          <ColumnLayout columns={3} variant="text-grid">
            {Object.entries(effortBreakdown).map(([effort, count]) => {
              const percentage = recommendations.length > 0 ? (count / recommendations.length) * 100 : 0;
              const color = effort === 'low' ? 'text-status-success' : effort === 'medium' ? 'text-status-info' : 'text-status-error';
              const icon = effort === 'low' ? '🟢' : effort === 'medium' ? '🟡' : '🔴';
              
              return (
                <div key={effort}>
                  <Box variant="awsui-key-label">
                    {icon} {effort.charAt(0).toUpperCase() + effort.slice(1)} Effort
                  </Box>
                  <Box fontSize="heading-l" fontWeight="bold" color={color}>
                    {count}
                  </Box>
                  <Box fontSize="body-s" color="text-body-secondary">
                    {percentage.toFixed(1)}% of recommendations
                  </Box>
                </div>
              );
            })}
          </ColumnLayout>
        </Container>

        {/* ROI Analysis */}
        <Container
          header={
            <Header variant="h3">
              ROI Analysis
            </Header>
          }
        >
          <ColumnLayout columns={3} variant="text-grid">
            <div>
              <Box variant="awsui-key-label">Potential Monthly Savings</Box>
              <Box fontSize="heading-l" fontWeight="bold" color="text-status-success">
                ${keyMetrics.total_monthly_savings?.toLocaleString() || '0'}
              </Box>
              <Box fontSize="body-s" color="text-body-secondary">
                Across all recommendations
              </Box>
            </div>
            <div>
              <Box variant="awsui-key-label">Average Savings per Recommendation</Box>
              <Box fontSize="heading-l" fontWeight="bold" color="text-status-success">
                ${recommendations.length > 0 ? Math.round((keyMetrics.total_monthly_savings || 0) / recommendations.length).toLocaleString() : '0'}
              </Box>
              <Box fontSize="body-s" color="text-body-secondary">
                Monthly savings per recommendation
              </Box>
            </div>
            <div>
              <Box variant="awsui-key-label">Quick Wins Available</Box>
              <Box fontSize="heading-l" fontWeight="bold" color="text-status-success">
                {keyMetrics.quick_wins_count || 0}
              </Box>
              <Box fontSize="body-s" color="text-body-secondary">
                Low effort, high impact opportunities
              </Box>
            </div>
          </ColumnLayout>
        </Container>
      </SpaceBetween>
    );
  }

  function renderImplementationRoadmap() {
    const recommendations = cohData.recommendations || [];
    
    if (recommendations.length === 0) {
      return (
        <Box textAlign="center" color="inherit">
          <b>No recommendations available</b>
          <Box padding={{ bottom: 's' }} variant="p" color="inherit">
            Implementation roadmap will be generated when cost optimization recommendations are available.
          </Box>
        </Box>
      );
    }

    // Generate roadmap phases based on recommendations
    const phases = [
      {
        phase: "Phase 1: Quick Wins",
        timeline: "0-30 days",
        recommendations: recommendations.filter(r => 
          r.implementation_effort === 'low' && (r.monthly_savings || 0) > 0
        ),
        description: "Low effort, immediate impact optimizations"
      },
      {
        phase: "Phase 2: Medium Impact",
        timeline: "1-3 months", 
        recommendations: recommendations.filter(r => 
          r.implementation_effort === 'medium'
        ),
        description: "Moderate effort optimizations with significant savings"
      },
      {
        phase: "Phase 3: Strategic Initiatives",
        timeline: "3-6 months",
        recommendations: recommendations.filter(r => 
          r.implementation_effort === 'high'
        ),
        description: "High effort, long-term optimization projects"
      }
    ];

    // Always show all phases, even if empty, to provide complete roadmap view
    return (
      <SpaceBetween size="m">
        {phases.map((phase, index) => {
          const expectedSavings = phase.recommendations.reduce((sum, rec) => sum + (rec.monthly_savings || 0), 0);
          const hasRecommendations = phase.recommendations.length > 0;
          
          return (
            <Container key={index}>
              <SpaceBetween size="s">
                <SpaceBetween size="s" direction="horizontal" alignItems="center">
                  <Header variant="h3">
                    {phase.phase}
                  </Header>
                  <Badge color="blue">
                    {phase.timeline}
                  </Badge>
                </SpaceBetween>
                
                <Box variant="p" color="text-body-secondary">
                  {phase.description}
                </Box>
                
                {hasRecommendations ? (
                  <>
                    <ColumnLayout columns={3} variant="text-grid">
                      <div>
                        <Box variant="awsui-key-label">Expected Savings</Box>
                        <Box fontSize="heading-m" fontWeight="bold" color="text-status-success">
                          ${expectedSavings.toLocaleString()}/month
                        </Box>
                      </div>
                      <div>
                        <Box variant="awsui-key-label">Recommendations</Box>
                        <Box fontSize="heading-m" fontWeight="bold">
                          {phase.recommendations.length} items
                        </Box>
                      </div>
                      <div>
                        <Box variant="awsui-key-label">Implementation Status</Box>
                        <Badge color="grey">Ready to Start</Badge>
                      </div>
                    </ColumnLayout>

                    <div>
                      <Box variant="awsui-key-label" margin={{ bottom: 'xs' }}>
                        Key Recommendations
                      </Box>
                      <ul>
                        {phase.recommendations.slice(0, 3).map((rec, recIndex) => (
                          <li key={recIndex}>
                            {rec.title || 'Cost Optimization Recommendation'} 
                            <span style={{ color: '#5f6b7a', fontSize: '0.9em' }}>
                              {' '}(${(rec.monthly_savings || 0).toLocaleString()}/month)
                            </span>
                          </li>
                        ))}
                        {phase.recommendations.length > 3 && (
                          <li>
                            <Button 
                              variant="link" 
                              onClick={() => setActiveTabId('recommendations')}
                              ariaLabel={`View ${phase.recommendations.length - 3} more recommendations`}
                            >
                              ...and {phase.recommendations.length - 3} more recommendations
                            </Button>
                          </li>
                        )}
                      </ul>
                    </div>
                  </>
                ) : (
                  <Alert type="info" header={`No ${phase.phase.toLowerCase()} recommendations available`}>
                    This phase will be populated when recommendations matching the criteria become available.
                  </Alert>
                )}
              </SpaceBetween>
            </Container>
          );
        })}
      </SpaceBetween>
    );
  }

  function renderTopOpportunities() {
    const topCategories = cohData.executive_summary?.top_categories || [];
    
    if (topCategories.length === 0) {
      return (
        <SpaceBetween size="s">
          <Alert type="info" header="Data Source Information">
            Top savings opportunities are derived from Cost Optimization Hub recommendations, 
            Compute Optimizer suggestions, and Savings Plans analysis. Data may be limited if 
            these services are not fully configured.
          </Alert>
          <Box textAlign="center" color="inherit">
            <b>No opportunities identified</b>
            <Box padding={{ bottom: 's' }} variant="p" color="inherit">
              Top savings opportunities will appear here when recommendations are available.
            </Box>
          </Box>
        </SpaceBetween>
      );
    }

    return (
      <SpaceBetween size="m">
        <Alert type="info" header="Data Source Information">
          These opportunities are aggregated from AWS Cost Optimization Hub, Compute Optimizer, 
          and Savings Plans recommendations. Savings estimates are based on current usage patterns.
        </Alert>
        {topCategories.map((category, index) => (
          <Container key={index}>
            <SpaceBetween size="s" direction="horizontal">
              <div style={{ flex: 1 }}>
                <Header variant="h4">
                  {category.category?.charAt(0).toUpperCase() + category.category?.slice(1) || 'Unknown Category'}
                </Header>
                <Box fontSize="body-s" color="text-body-secondary">
                  {getCategoryDescription(category.category)}
                </Box>
              </div>
              <div>
                <Box fontSize="heading-l" fontWeight="bold" color="text-status-success">
                  ${category.savings?.toLocaleString() || '0'}/month
                </Box>
              </div>
            </SpaceBetween>
          </Container>
        ))}
      </SpaceBetween>
    );
  }
};

// Helper function to get category descriptions
function getCategoryDescription(category) {
  const descriptions = {
    'compute': 'Optimize EC2 instances, Auto Scaling, and compute resources',
    'storage': 'Optimize S3, EBS, and other storage services',
    'database': 'Optimize RDS, DynamoDB, and database configurations',
    'commitment': 'Leverage Reserved Instances and Savings Plans',
    'general': 'General cost optimization opportunities'
  };
  
  return descriptions[category] || 'Cost optimization opportunities';
}

export default CostOptimizationPage;