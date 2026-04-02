import React, { useState, useEffect } from 'react';
import Container from '@cloudscape-design/components/container';
import Header from '@cloudscape-design/components/header';
import SpaceBetween from '@cloudscape-design/components/space-between';
import Alert from '@cloudscape-design/components/alert';
import Tabs from '@cloudscape-design/components/tabs';
import Table from '@cloudscape-design/components/table';
import Box from '@cloudscape-design/components/box';
import Badge from '@cloudscape-design/components/badge';
import ColumnLayout from '@cloudscape-design/components/column-layout';
import StatusIndicator from '@cloudscape-design/components/status-indicator';

/**
 * TrustedAdvisorPage component
 * Displays AWS Trusted Advisor recommendations organized by pillars
 */
const TrustedAdvisorPage = () => {
  const [taData, setTaData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [activeTabId, setActiveTabId] = useState('');

  useEffect(() => {
    loadTAData();
  }, []);

  const loadTAData = async () => {
    try {
      setLoading(true);
      
      // Load TA data from embedded window.__TA_DATA__
      if (typeof window !== 'undefined' && window.__TA_DATA__) {
        const data = window.__TA_DATA__;
        setTaData(data);
        
        // Set first pillar as active tab
        if (data.pillars && Object.keys(data.pillars).length > 0) {
          setActiveTabId(Object.keys(data.pillars)[0]);
        }
        
        setError(null);
      } else {
        throw new Error('TA data not available in embedded data');
      }
    } catch (err) {
      console.error('Error loading TA data:', err);
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <Container>
        <StatusIndicator type="loading">Loading Trusted Advisor data...</StatusIndicator>
      </Container>
    );
  }

  if (error || (taData && taData.error)) {
    const errorMessage = error || taData?.error || 'Unknown error';
    
    return (
      <Container
        header={
          <Header variant="h1">
            Trusted Advisor
          </Header>
        }
      >
        <Alert type="warning" header="Trusted Advisor Unavailable">
          <Box variant="p">
            {errorMessage}
          </Box>
          {errorMessage.includes('support level') && (
            <Box variant="p">
              <strong>Note:</strong> AWS Trusted Advisor requires a Business or Enterprise Support plan. 
              Please upgrade your support plan to access these recommendations.
            </Box>
          )}
        </Alert>
      </Container>
    );
  }

  if (!taData || !taData.pillars || Object.keys(taData.pillars).length === 0) {
    return (
      <Container
        header={
          <Header variant="h1">
            Trusted Advisor
          </Header>
        }
      >
        <Alert type="info">
          No Trusted Advisor data available.
        </Alert>
      </Container>
    );
  }

  // Create tabs for each pillar
  const tabs = Object.entries(taData.pillars).map(([pillarName, pillarData]) => ({
    id: pillarName,
    label: formatPillarName(pillarName),
    content: renderPillarContent(pillarName, pillarData)
  }));

  return (
    <SpaceBetween size="l">
      <Container
        header={
          <Header
            variant="h1"
            description="AWS Trusted Advisor provides recommendations to help you follow AWS best practices"
            info={
              <Box variant="p">
                <strong>Note:</strong> This page shows data from the Trusted Advisor API only. 
                For the complete Trusted Advisor experience with all optimization recommendations, 
                visit the <a href="https://us-east-1.console.aws.amazon.com/trustedadvisor/home?region=us-east-1#/dashboard" target="_blank" rel="noopener noreferrer">
                  AWS Console Trusted Advisor
                </a>.
              </Box>
            }
          >
            Trusted Advisor
          </Header>
        }
      >
        {renderSummaryCards()}
      </Container>

      <Tabs
        activeTabId={activeTabId}
        onChange={({ detail }) => setActiveTabId(detail.activeTabId)}
        tabs={tabs}
      />
    </SpaceBetween>
  );

  function renderSummaryCards() {
    const totalCounts = { Error: 0, Warning: 0, OK: 0 };
    let totalSavings = 0;

    // Calculate totals across all pillars
    Object.values(taData.pillars).forEach(pillarData => {
      if (pillarData.totals) {
        totalCounts.Error += pillarData.totals.Error || 0;
        totalCounts.Warning += pillarData.totals.Warning || 0;
        totalCounts.OK += pillarData.totals.OK || 0;
      }
      
      // Calculate cost savings from cost optimization pillar
      if (pillarData.rows) {
        pillarData.rows.forEach(row => {
          if (row['Estimated Monthly Savings']) {
            const savings = parseFloat(row['Estimated Monthly Savings'].replace(/[$,]/g, ''));
            if (!isNaN(savings)) {
              totalSavings += savings;
            }
          }
        });
      }
    });

    return (
      <ColumnLayout columns={4} variant="text-grid">
        <div>
          <Box variant="awsui-key-label">Total Resources Checked</Box>
          <Box variant="h2" color="text-status-info">
            {totalCounts.Error + totalCounts.Warning + totalCounts.OK}
          </Box>
        </div>
        <div>
          <Box variant="awsui-key-label">Resources with Issues</Box>
          <Box variant="h2" color="text-status-error">
            {totalCounts.Error}
          </Box>
        </div>
        <div>
          <Box variant="awsui-key-label">Resources with Warnings</Box>
          <Box variant="h2" color="text-status-warning">
            {totalCounts.Warning}
          </Box>
        </div>
        <div>
          <Box variant="awsui-key-label">Estimated Monthly Savings</Box>
          <Box variant="h2" color="text-status-success">
            ${totalSavings.toFixed(2)}
          </Box>
        </div>
      </ColumnLayout>
    );
  }

  function renderPillarContent(pillarName, pillarData) {
    if (!pillarData.rows || pillarData.rows.length === 0) {
      return (
        <Container>
          <Box textAlign="center" color="inherit">
            <b>No recommendations</b>
            <Box padding={{ bottom: 's' }} variant="p" color="inherit">
              No {formatPillarName(pillarName)} recommendations available.
            </Box>
          </Box>
        </Container>
      );
    }

    // Create column definitions based on headers
    const columnDefinitions = pillarData.headers.map(header => ({
      id: header,
      header: header,
      cell: item => renderCell(header, item[header]),
      sortingField: header,
      width: getColumnWidth(header)
    }));

    return (
      <Container
        header={
          <Header
            variant="h2"
            counter={`(${pillarData.rows.length})`}
            description={getPillarDescription(pillarName)}
          >
            {formatPillarName(pillarName)} Recommendations
          </Header>
        }
      >
        <SpaceBetween size="m">
          {pillarData.totals && renderPillarSummary(pillarData.totals)}
          
          <Table
            columnDefinitions={columnDefinitions}
            items={pillarData.rows}
            loadingText="Loading recommendations"
            empty={
              <Box textAlign="center" color="inherit">
                <b>No recommendations</b>
                <Box padding={{ bottom: 's' }} variant="p" color="inherit">
                  No recommendations to display.
                </Box>
              </Box>
            }
            sortingDisabled={false}
            variant="embedded"
          />
        </SpaceBetween>
      </Container>
    );
  }

  function renderPillarSummary(totals) {
    return (
      <ColumnLayout columns={3} variant="text-grid">
        <div>
          <Badge color="red">{totals.Error || 0} Errors</Badge>
        </div>
        <div>
          <Badge color="grey">{totals.Warning || 0} Warnings</Badge>
        </div>
        <div>
          <Badge color="green">{totals.OK || 0} OK</Badge>
        </div>
      </ColumnLayout>
    );
  }

  function renderCell(header, value) {
    if (!value) return '-';

    // Handle status badges (contains HTML)
    if (typeof value === 'string' && value.includes('<span class=\'badge')) {
      // Extract status from HTML
      const statusMatch = value.match(/badge-(\w+).*?>(\w+)</);
      if (statusMatch) {
        const [, badgeType, status] = statusMatch;
        const color = badgeType === 'danger' ? 'red' : 
                     badgeType === 'warning' ? 'grey' : 'green';
        
        // Extract the text after the badge
        const textMatch = value.match(/<\/span>\s*(.+?)(?:\s*<i>|$)/);
        const text = textMatch ? textMatch[1] : '';
        
        return (
          <SpaceBetween size="xs" direction="vertical">
            <Badge color={color}>{status}</Badge>
            <Box fontSize="body-s">{text}</Box>
          </SpaceBetween>
        );
      }
    }

    // Handle monetary values
    if (header.includes('Savings') && typeof value === 'string' && value.startsWith('$')) {
      return (
        <Box color="text-status-success" fontWeight="bold">
          {value}
        </Box>
      );
    }

    // Handle percentage values
    if (header.includes('Percent') && typeof value === 'string' && value.includes('%')) {
      return (
        <Box color="text-status-info">
          {value}
        </Box>
      );
    }

    // Handle dates
    if (header.includes('Updated') && typeof value === 'string' && value.includes('UTC')) {
      return (
        <Box fontSize="body-s" color="text-body-secondary">
          {value}
        </Box>
      );
    }

    return value;
  }

  function getColumnWidth(header) {
    switch (header) {
      case 'Services':
        return 120;
      case '# Error':
      case '# Warning':
      case '# OK':
        return 80;
      case 'Last Updated':
        return 180;
      case 'Estimated Monthly Savings':
        return 150;
      case 'Estimated Percent Savings':
        return 120;
      default:
        return undefined;
    }
  }
};

// Helper functions
function formatPillarName(pillarName) {
  return pillarName
    .toLowerCase()
    .split('_')
    .map(word => word.charAt(0).toUpperCase() + word.slice(1))
    .join(' ');
}

function getPillarDescription(pillarName) {
  const descriptions = {
    'COST_OPTIMIZING': 'Recommendations to help you reduce costs and optimize spending',
    'SECURITY': 'Security recommendations to help protect your AWS resources',
    'PERFORMANCE': 'Performance recommendations to improve application efficiency',
    'FAULT_TOLERANCE': 'Recommendations to improve system reliability and availability',
    'SERVICE_LIMITS': 'Service limit recommendations to prevent resource constraints',
    'OPERATIONAL_EXCELLENCE': 'Operational recommendations to improve management and monitoring'
  };
  
  return descriptions[pillarName] || 'AWS Trusted Advisor recommendations';
}

export default TrustedAdvisorPage;