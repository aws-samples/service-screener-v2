import React, { useState } from 'react';
import Container from '@cloudscape-design/components/container';
import Header from '@cloudscape-design/components/header';
import SpaceBetween from '@cloudscape-design/components/space-between';
import Box from '@cloudscape-design/components/box';
import ColumnLayout from '@cloudscape-design/components/column-layout';
import Badge from '@cloudscape-design/components/badge';
import Button from '@cloudscape-design/components/button';
import Cards from '@cloudscape-design/components/cards';
import ProgressBar from '@cloudscape-design/components/progress-bar';
import StatusIndicator from '@cloudscape-design/components/status-indicator';
import Alert from '@cloudscape-design/components/alert';
import Modal from '@cloudscape-design/components/modal';
import Table from '@cloudscape-design/components/table';

/**
 * Enhanced KPI Card component with trend indicators and drill-down capability
 */
const EnhancedKPICard = ({ 
  title, 
  value, 
  subtitle, 
  variant = 'default', 
  icon, 
  trend, 
  trendValue,
  onClick, 
  clickable = false,
  status = 'success'
}) => {
  const getTrendIcon = (trend) => {
    switch (trend) {
      case 'up': return '📈';
      case 'down': return '📉';
      case 'stable': return '➡️';
      default: return '';
    }
  };

  const getTrendColor = (trend) => {
    switch (trend) {
      case 'up': return 'text-status-success';
      case 'down': return 'text-status-error';
      case 'stable': return 'text-status-info';
      default: return 'text-body-secondary';
    }
  };

  const content = (
    <SpaceBetween size="xs">
      <Box variant="awsui-key-label">{title}</Box>
      <SpaceBetween size="xs" direction="horizontal" alignItems="center">
        <Box 
          fontSize="display-l" 
          fontWeight="bold" 
          variant={variant}
        >
          {icon && <span style={{ marginRight: '8px' }}>{icon}</span>}
          {value}
        </Box>
        {trend && (
          <Box fontSize="body-s" color={getTrendColor(trend)}>
            {getTrendIcon(trend)} {trendValue}
          </Box>
        )}
      </SpaceBetween>
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
          style={{ cursor: 'pointer', transition: 'all 0.2s' }}
          role="button"
          tabIndex={0}
          onKeyPress={(e) => {
            if (e.key === 'Enter' || e.key === ' ') {
              onClick();
            }
          }}
          onMouseEnter={(e) => {
            e.currentTarget.style.transform = 'translateY(-2px)';
            e.currentTarget.style.boxShadow = '0 4px 12px rgba(0,0,0,0.15)';
          }}
          onMouseLeave={(e) => {
            e.currentTarget.style.transform = 'translateY(0)';
            e.currentTarget.style.boxShadow = '';
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
 * Priority Breakdown Card component
 */
const PriorityBreakdownCard = ({ priorities, onPriorityClick }) => {
  const total = Object.values(priorities).reduce((sum, count) => sum + count, 0);
  
  const priorityConfig = {
    high: { color: 'red', label: 'High Priority', icon: '🔴' },
    medium: { color: 'blue', label: 'Medium Priority', icon: '🟡' },
    low: { color: 'green', label: 'Low Priority', icon: '🟢' }
  };

  return (
    <Container
      header={
        <Header variant="h3">
          Priority Breakdown
        </Header>
      }
    >
      <SpaceBetween size="s">
        {Object.entries(priorities).map(([priority, count]) => {
          const config = priorityConfig[priority];
          const percentage = total > 0 ? ((count / total) * 100).toFixed(1) : 0;
          
          return (
            <div 
              key={priority}
              style={{ cursor: 'pointer' }}
              onClick={() => onPriorityClick && onPriorityClick(priority)}
              role="button"
              tabIndex={0}
            >
              <SpaceBetween size="xs" direction="horizontal" alignItems="center">
                <Box fontSize="body-m">
                  {config.icon} {config.label}
                </Box>
                <div style={{ flex: 1 }}>
                  <ProgressBar
                    value={parseFloat(percentage)}
                    variant={config.color === 'red' ? 'error' : config.color === 'blue' ? 'in-progress' : 'success'}
                    description={`${count} recommendations (${percentage}%)`}
                  />
                </div>
              </SpaceBetween>
            </div>
          );
        })}
      </SpaceBetween>
    </Container>
  );
};

/**
 * Service Impact Cards component
 */
const ServiceImpactCards = ({ serviceData, onServiceClick }) => {
  const cardDefinition = {
    header: item => (
      <Header
        variant="h3"
        actions={
          <Button 
            variant="primary" 
            size="small"
            onClick={() => onServiceClick && onServiceClick(item.service)}
          >
            View Details
          </Button>
        }
      >
        {item.service.toUpperCase()}
      </Header>
    ),
    sections: [
      {
        id: 'savings',
        header: 'Monthly Savings Potential',
        content: item => (
          <Box fontSize="heading-l" fontWeight="bold" color="text-status-success">
            ${item.monthlySavings.toLocaleString()}
          </Box>
        )
      },
      {
        id: 'recommendations',
        header: 'Recommendations',
        content: item => (
          <SpaceBetween size="xs">
            <Box fontSize="heading-m" fontWeight="bold">
              {item.recommendationCount}
            </Box>
            <SpaceBetween size="xs" direction="horizontal">
              <Badge color="red">{item.highPriority} High</Badge>
              <Badge color="grey">{item.mediumPriority} Medium</Badge>
              <Badge color="green">{item.lowPriority} Low</Badge>
            </SpaceBetween>
          </SpaceBetween>
        )
      },
      {
        id: 'effort',
        header: 'Implementation Effort',
        content: item => (
          <StatusIndicator type={item.effort === 'low' ? 'success' : item.effort === 'medium' ? 'pending' : 'error'}>
            {item.effort.charAt(0).toUpperCase() + item.effort.slice(1)} Effort
          </StatusIndicator>
        )
      }
    ]
  };

  return (
    <Cards
      cardDefinition={cardDefinition}
      items={serviceData}
      loadingText="Loading service data"
      empty={
        <Box textAlign="center" color="inherit">
          <b>No service data</b>
          <Box padding={{ bottom: 's' }} variant="p" color="inherit">
            No service impact data available.
          </Box>
        </Box>
      }
      header={
        <Header
          variant="h2"
          counter={`(${serviceData.length})`}
          description="Services with the highest cost optimization potential"
        >
          Service Impact Analysis
        </Header>
      }
    />
  );
};

/**
 * Executive Dashboard component
 * Enhanced dashboard with metrics, trends, and interactive elements
 */
const ExecutiveDashboard = ({ cohData, onExport, onDrillDown }) => {
  const [showExportModal, setShowExportModal] = useState(false);
  const [selectedMetric, setSelectedMetric] = useState(null);

  if (!cohData) {
    return (
      <Alert type="warning">
        No Cost Optimization Hub data available for executive dashboard.
      </Alert>
    );
  }

  const keyMetrics = cohData.key_metrics || {};
  const executiveSummary = cohData.executive_summary || {};

  // Mock trend data (in real implementation, this would come from historical data)
  const trendData = {
    savings: { trend: 'up', value: '+12%' },
    recommendations: { trend: 'stable', value: '0%' },
    priority: { trend: 'down', value: '-8%' },
    quality: { trend: 'up', value: '+5%' }
  };

  // Calculate real service data from actual recommendations
  const calculateServiceData = () => {
    const recommendations = cohData.recommendations || [];
    const serviceBreakdown = {};
    
    // Process each recommendation to build service breakdown
    recommendations.forEach(rec => {
      const service = rec.service || 'other';
      if (!serviceBreakdown[service]) {
        serviceBreakdown[service] = {
          service: service,
          monthlySavings: 0,
          recommendationCount: 0,
          highPriority: 0,
          mediumPriority: 0,
          lowPriority: 0,
          effort: 'medium'
        };
      }
      
      serviceBreakdown[service].monthlySavings += rec.monthly_savings || 0;
      serviceBreakdown[service].recommendationCount += 1;
      
      // Count by priority
      const priority = rec.priority_level || 'medium';
      if (priority === 'high') serviceBreakdown[service].highPriority += 1;
      else if (priority === 'medium') serviceBreakdown[service].mediumPriority += 1;
      else serviceBreakdown[service].lowPriority += 1;
      
      // Set effort level (use most common or highest effort)
      const effort = rec.implementation_effort || 'medium';
      if (effort === 'high' || serviceBreakdown[service].effort !== 'high') {
        serviceBreakdown[service].effort = effort;
      }
    });
    
    // Convert to array and sort by savings (highest first)
    return Object.values(serviceBreakdown)
      .sort((a, b) => b.monthlySavings - a.monthlySavings)
      .slice(0, 10); // Limit to top 10 services
  };

  const serviceData = calculateServiceData();

  const priorities = {
    high: (() => {
      const recommendations = cohData.recommendations || [];
      return recommendations.filter(r => r.priority_level === 'high').length;
    })(),
    medium: (() => {
      const recommendations = cohData.recommendations || [];
      return recommendations.filter(r => r.priority_level === 'medium').length;
    })(),
    low: (() => {
      const recommendations = cohData.recommendations || [];
      return recommendations.filter(r => r.priority_level === 'low').length;
    })()
  };

  const handleMetricClick = (metricType) => {
    setSelectedMetric(metricType);
    if (onDrillDown) {
      onDrillDown(metricType);
    }
  };

  const handleExport = (format) => {
    setShowExportModal(false);
    if (onExport) {
      onExport(format);
    }
  };

  return (
    <SpaceBetween size="l">
      {/* Header with Export Actions */}
      <Container
        header={
          <Header
            variant="h1"
            description="Executive-level cost optimization insights and key performance indicators"
          >
            Executive Dashboard
          </Header>
        }
      >
        <Alert type="info" header="Real-time Cost Optimization Insights">
          This dashboard provides executive-level visibility into your AWS cost optimization opportunities. 
          Click on any metric to drill down into detailed recommendations.
        </Alert>
      </Container>

      {/* Enhanced KPI Cards */}
      <Container
        header={
          <Header variant="h2">
            Key Performance Indicators
          </Header>
        }
      >
        <ColumnLayout columns={3} variant="text-grid">
          <EnhancedKPICard
            title="Monthly Savings Potential"
            value={`$${keyMetrics.total_monthly_savings?.toLocaleString() || '0'}`}
            subtitle={`$${keyMetrics.total_annual_savings?.toLocaleString() || '0'}/year`}
            variant="h2"
            icon="💰"
            trend={trendData.savings.trend}
            trendValue={trendData.savings.value}
            clickable={true}
            onClick={() => handleMetricClick('savings')}
          />
          
          <EnhancedKPICard
            title="Total Recommendations"
            value={keyMetrics.total_recommendations || 0}
            subtitle="optimization opportunities"
            variant="h2"
            icon="💡"
            trend={trendData.recommendations.trend}
            trendValue={trendData.recommendations.value}
            clickable={true}
            onClick={() => handleMetricClick('recommendations')}
          />
          
          <EnhancedKPICard
            title="High Priority Actions"
            value={keyMetrics.high_priority_count || 0}
            subtitle="immediate attention required"
            variant="h2"
            icon="⚠️"
            trend={trendData.priority.trend}
            trendValue={trendData.priority.value}
            clickable={true}
            onClick={() => handleMetricClick('priority')}
          />
        </ColumnLayout>
      </Container>

      {/* Priority Breakdown and Service Impact */}
      <ColumnLayout columns={2} variant="default">
        <PriorityBreakdownCard
          priorities={priorities}
          onPriorityClick={(priority) => handleMetricClick(`priority-${priority}`)}
        />
        
        <Container
          header={
            <Header variant="h3">
              Quick Wins Summary
            </Header>
          }
        >
          <SpaceBetween size="m">
            <Box>
              <Box variant="awsui-key-label">Available Quick Wins</Box>
              <Box fontSize="heading-l" fontWeight="bold" color="text-status-success">
                {keyMetrics.quick_wins_count || 0}
              </Box>
              <Box fontSize="body-s" color="text-body-secondary">
                Low effort, high impact opportunities
              </Box>
            </Box>
            
            <Box>
              <Box variant="awsui-key-label">Potential Quick Win Savings</Box>
              <Box fontSize="heading-l" fontWeight="bold" color="text-status-success">
                ${(() => {
                  // Calculate actual quick wins savings (same logic as Phase 1)
                  const recommendations = cohData.recommendations || [];
                  const quickWinSavings = recommendations
                    .filter(r => r.implementation_effort === 'low' && (r.monthly_savings || 0) > 0)
                    .reduce((sum, rec) => sum + (rec.monthly_savings || 0), 0);
                  return quickWinSavings.toLocaleString();
                })()}
              </Box>
              <Box fontSize="body-s" color="text-body-secondary">
                Monthly savings from Phase 1 quick wins
              </Box>
            </Box>

            <Button 
              variant="primary" 
              fullWidth
              onClick={() => handleMetricClick('quick-wins')}
            >
              View Quick Wins
            </Button>
          </SpaceBetween>
        </Container>
      </ColumnLayout>

      {/* Service Impact Analysis */}
      <ServiceImpactCards
        serviceData={serviceData}
        onServiceClick={(service) => handleMetricClick(`service-${service}`)}
      />

      {/* Export Modal */}
      <Modal
        visible={showExportModal}
        onDismiss={() => setShowExportModal(false)}
        header="Export Executive Report"
        footer={
          <Box float="right">
            <SpaceBetween direction="horizontal" size="xs">
              <Button variant="link" onClick={() => setShowExportModal(false)}>
                Cancel
              </Button>
            </SpaceBetween>
          </Box>
        }
      >
        <SpaceBetween size="m">
          <Box variant="p">
            Choose the format for your executive cost optimization report:
          </Box>
          
          <SpaceBetween size="s">
            <Button 
              variant="primary" 
              fullWidth
              onClick={() => handleExport('pdf')}
            >
              📄 Executive PDF Report
            </Button>
            <Button 
              variant="normal" 
              fullWidth
              onClick={() => handleExport('excel')}
            >
              📊 Excel Spreadsheet
            </Button>
            <Button 
              variant="normal" 
              fullWidth
              onClick={() => handleExport('csv')}
            >
              📋 CSV Data Export
            </Button>
          </SpaceBetween>
        </SpaceBetween>
      </Modal>
    </SpaceBetween>
  );
};

export default ExecutiveDashboard;