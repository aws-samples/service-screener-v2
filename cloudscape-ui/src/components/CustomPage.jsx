import React from 'react';
import { useParams } from 'react-router-dom';
import Container from '@cloudscape-design/components/container';
import Header from '@cloudscape-design/components/header';
import Box from '@cloudscape-design/components/box';
import Alert from '@cloudscape-design/components/alert';
import Table from '@cloudscape-design/components/table';
import SpaceBetween from '@cloudscape-design/components/space-between';
import FindingsPage from './FindingsPage';
import TrustedAdvisorPage from './TrustedAdvisorPage';
import CostOptimizationPage from './CostOptimizationPage';
import SankeyDiagram from './SankeyDiagram';

/**
 * CustomPage component
 * Displays custom pages like Findings, Modernize, TA
 */
const CustomPage = ({ data }) => {
  const { pageName } = useParams();
  
  if (!data || !pageName) {
    return (
      <Container>
        <Alert type="error">
          Invalid page data
        </Alert>
      </Container>
    );
  }
  
  // Format page title
  const pageTitle = pageName === 'ta' ? 'Trusted Advisor' :
                   pageName === 'coh' ? 'Cost Optimization Hub' :
                   pageName.charAt(0).toUpperCase() + pageName.slice(1);
  
  // Handle TA page separately (loads from ta.json)
  if (pageName === 'ta') {
    return <TrustedAdvisorPage />;
  }
  
  // Handle Cost Optimization Hub page
  if (pageName === 'coh') {
    return <CostOptimizationPage data={data} />;
  }
  
  // Handle Findings page (uses data from api-full.json)
  if (pageName === 'findings') {
    return <FindingsPage data={data} />;
  }
  
  // For other pages, check if data exists
  const pageKey = `customPage_${pageName}`;
  const pageData = data[pageKey];
  
  if (!pageData) {
    return (
      <Container>
        <Alert type="warning">
          Page "{pageName}" not found in report data
        </Alert>
      </Container>
    );
  }
  
  // Render based on page type
  if (pageName === 'modernize') {
    return renderModernizePage(pageData, pageTitle);
  }
  
  // Default rendering for unknown page types
  return (
    <Container header={<Header variant="h1">{pageTitle}</Header>}>
      <Box variant="p">
        Custom page data available. Specific rendering not yet implemented.
      </Box>
      <Box variant="code">
        <pre>{JSON.stringify(pageData, null, 2)}</pre>
      </Box>
    </Container>
  );
};



/**
 * Render Modernize page with Sankey diagrams
 */
const renderModernizePage = (pageData, pageTitle) => {
  // Check if we have Sankey data
  const computesData = pageData?.Computes;
  const databasesData = pageData?.Databases;
  
  return (
    <SpaceBetween size="l">
      <Container header={<Header variant="h1">{pageTitle}</Header>}>
        <Box variant="p">
          <strong>Modernization Pathways</strong> - These diagrams show potential modernization paths 
          for your AWS resources. The thickness of each flow indicates the number of resources 
          that could benefit from that modernization approach.
        </Box>
        <Alert type="info" header="Beta Feature">
          This modernization analysis is in beta. Recommendations are based on resource 
          configurations and may require additional validation before implementation.
        </Alert>
      </Container>
      
      {computesData && (
        <SankeyDiagram 
          title="Compute Modernization" 
          data={computesData}
          height={500}
        />
      )}
      
      {databasesData && (
        <SankeyDiagram 
          title="Database Modernization" 
          data={databasesData}
          height={400}
        />
      )}
      
      {/* Summary information */}
      <Container header={<Header variant="h2">Modernization Summary</Header>}>
        <SpaceBetween size="m">
          {computesData && (
            <Box>
              <Box variant="h3">Compute Resources</Box>
              <Box variant="p">
                {(() => {
                  // Count modernization pathways (links that end with modernization targets)
                  const modernizationPathways = computesData.links?.filter(link => {
                    const targetNode = computesData.nodes?.[link.target];
                    return targetNode && targetNode.startsWith('_');
                  }).length || 0;
                  
                  // Count actual AWS resources (nodes that don't start with '_' and are leaf sources)
                  const sourceResourceIndices = new Set();
                  const targetResourceIndices = new Set();
                  
                  computesData.links?.forEach(link => {
                    sourceResourceIndices.add(link.source);
                    targetResourceIndices.add(link.target);
                  });
                  
                  // Find nodes that are only sources (never targets) - these are the root AWS resources
                  const rootResourceIndices = [...sourceResourceIndices].filter(index => 
                    !targetResourceIndices.has(index)
                  );
                  
                  const resourceCount = rootResourceIndices.length;
                  const resourceText = resourceCount === 1 ? 'resource' : 'resources';
                  const pathwayText = modernizationPathways === 1 ? 'pathway' : 'pathways';
                  
                  return `Found ${resourceCount} compute ${resourceText} with ${modernizationPathways} modernization ${pathwayText}.`;
                })()}
              </Box>
            </Box>
          )}
          
          {databasesData && (
            <Box>
              <Box variant="h3">Database Resources</Box>
              <Box variant="p">
                {(() => {
                  // Count modernization pathways (links that end with modernization targets)
                  const modernizationPathways = databasesData.links?.filter(link => {
                    const targetNode = databasesData.nodes?.[link.target];
                    return targetNode && targetNode.startsWith('_');
                  }).length || 0;
                  
                  // Count actual AWS resources (nodes that don't start with '_' and are leaf sources)
                  const sourceResourceIndices = new Set();
                  const targetResourceIndices = new Set();
                  
                  databasesData.links?.forEach(link => {
                    sourceResourceIndices.add(link.source);
                    targetResourceIndices.add(link.target);
                  });
                  
                  // Find nodes that are only sources (never targets) - these are the root AWS resources
                  const rootResourceIndices = [...sourceResourceIndices].filter(index => 
                    !targetResourceIndices.has(index)
                  );
                  
                  const resourceCount = rootResourceIndices.length;
                  const resourceText = resourceCount === 1 ? 'resource' : 'resources';
                  const pathwayText = modernizationPathways === 1 ? 'pathway' : 'pathways';
                  
                  return `Found ${resourceCount} database ${resourceText} with ${modernizationPathways} modernization ${pathwayText}.`;
                })()}
              </Box>
            </Box>
          )}
          
          <Box variant="p" color="text-body-secondary">
            <strong>Next Steps:</strong> Review the modernization pathways above and consider 
            implementing changes that align with your business objectives. Each pathway shows 
            the potential impact based on your current resource usage.
          </Box>
        </SpaceBetween>
      </Container>
    </SpaceBetween>
  );
};

/**
 * Render Trusted Advisor page
 */
const renderTAPage = (pageData, pageTitle) => {
  const ec2Data = pageData.ec2instance || {};
  const instances = ec2Data.items || [];
  
  return (
    <SpaceBetween size="l">
      <Container header={<Header variant="h1">{pageTitle}</Header>}>
        <Box variant="p">
          Trusted Advisor recommendations for EC2 instances: {ec2Data.total || 0}
        </Box>
      </Container>
      
      <Container header={<Header variant="h2">EC2 Recommendations</Header>}>
        <Table
          columnDefinitions={[
            {
              id: 'id',
              header: 'Instance ID',
              cell: item => item.id || '-'
            },
            {
              id: 'platform',
              header: 'Platform',
              cell: item => item.platform || '-'
            },
            {
              id: 'instanceType',
              header: 'Instance Type',
              cell: item => item.instanceType || '-'
            },
            {
              id: 'keyTags',
              header: 'Key Tags',
              cell: item => item.keyTags ? item.keyTags.join(', ') : '-'
            }
          ]}
          items={instances}
          loadingText="Loading recommendations"
          empty={
            <Box textAlign="center" color="inherit">
              <b>No recommendations</b>
              <Box padding={{ bottom: 's' }} variant="p" color="inherit">
                No Trusted Advisor recommendations to display.
              </Box>
            </Box>
          }
          sortingDisabled={false}
          variant="embedded"
        />
      </Container>
    </SpaceBetween>
  );
};

export default CustomPage;
