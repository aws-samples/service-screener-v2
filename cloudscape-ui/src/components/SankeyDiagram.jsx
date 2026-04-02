import React from 'react';
import { Sankey, ResponsiveContainer, Tooltip } from 'recharts';
import Container from '@cloudscape-design/components/container';
import Header from '@cloudscape-design/components/header';
import Box from '@cloudscape-design/components/box';
import Alert from '@cloudscape-design/components/alert';

/**
 * SankeyDiagram component
 * Renders a Sankey diagram using Recharts
 */
const SankeyDiagram = ({ title, data, height = 400 }) => {
  // Enhanced validation and error handling
  if (!data) {
    return (
      <Container header={<Header variant="h2">{title}</Header>}>
        <Alert type="info">
          No data provided for {title.toLowerCase()}.
        </Alert>
      </Container>
    );
  }

  if (!data.nodes || !data.links) {
    return (
      <Container header={<Header variant="h2">{title}</Header>}>
        <Alert type="info">
          No modernization data available for {title.toLowerCase()}.
        </Alert>
      </Container>
    );
  }

  // Check if we have empty data
  if (!Array.isArray(data.nodes) || !Array.isArray(data.links) || 
      data.nodes.length === 0 || data.links.length === 0) {
    return (
      <Container header={<Header variant="h2">{title}</Header>}>
        <Alert type="info">
          No modernization paths found for {title.toLowerCase()}.
        </Alert>
      </Container>
    );
  }

  try {
    // Transform data for Recharts Sankey with additional validation
    const sankeyData = {
      nodes: data.nodes.map((node, index) => {
        if (typeof node !== 'string') {
          console.warn(`Invalid node at index ${index}:`, node);
          return { id: index, name: `Node ${index}` };
        }
        return {
          id: index,
          name: node
        };
      }),
      links: data.links.map((link, index) => {
        if (!link || typeof link.source !== 'number' || typeof link.target !== 'number' || typeof link.value !== 'number') {
          console.warn(`Invalid link at index ${index}:`, link);
          return { source: 0, target: 0, value: 0 };
        }
        // Ensure source and target are within valid range
        const maxNodeIndex = data.nodes.length - 1;
        return {
          source: Math.max(0, Math.min(link.source, maxNodeIndex)),
          target: Math.max(0, Math.min(link.target, maxNodeIndex)),
          value: Math.max(0, link.value)
        };
      })
    };

    // Custom tooltip with error handling
    const CustomTooltip = ({ active, payload }) => {
      if (!active || !payload || !payload.length) {
        return null;
      }

      try {
        const data = payload[0].payload;
        if (data.source !== undefined && data.target !== undefined) {
          // Link tooltip
          const sourceNode = sankeyData.nodes[data.source];
          const targetNode = sankeyData.nodes[data.target];
          return (
            <Box
              padding="s"
              backgroundColor="white"
              borderRadius="4px"
              boxShadow="0 2px 8px rgba(0,0,0,0.15)"
            >
              <Box variant="strong">{sourceNode?.name || 'Unknown'} → {targetNode?.name || 'Unknown'}</Box>
              <Box variant="p">Resources: {data.value || 0}</Box>
            </Box>
          );
        } else if (data.name) {
          // Node tooltip
          return (
            <Box
              padding="s"
              backgroundColor="white"
              borderRadius="4px"
              boxShadow="0 2px 8px rgba(0,0,0,0.15)"
            >
              <Box variant="strong">{data.name}</Box>
              <Box variant="p">Value: {data.value || 'N/A'}</Box>
            </Box>
          );
        }
      } catch (error) {
        console.error('Error in CustomTooltip:', error);
      }
      return null;
    };

    return (
      <Container header={<Header variant="h2">{title}</Header>}>
        <Box padding={{ bottom: 'm' }}>
          <Box variant="p" color="text-body-secondary">
            This diagram shows the modernization pathway for {title.toLowerCase()}, 
            with flow indicating the number of resources that can be modernized.
          </Box>
        </Box>
        
        <div style={{ width: '100%', height: `${height}px` }}>
          <ResponsiveContainer width="100%" height="100%">
            <Sankey
              data={sankeyData}
              nodeWidth={15}
              nodePadding={10}
              margin={{ top: 20, right: 80, bottom: 20, left: 80 }}
              node={(nodeProps) => {
                const { x, y, width, height, payload } = nodeProps;
                return (
                  <g>
                    {/* Node rectangle */}
                    <rect
                      x={x}
                      y={y}
                      width={width}
                      height={height}
                      fill="#0073bb"
                      stroke="#005a9f"
                      strokeWidth={1}
                    />
                    {/* Node label */}
                    <text
                      x={x < 200 ? x + width + 6 : x - 6}
                      y={y + height / 2}
                      textAnchor={x < 200 ? "start" : "end"}
                      dominantBaseline="middle"
                      fontSize="12"
                      fill="#232f3e"
                      fontFamily="Amazon Ember, Helvetica, Arial, sans-serif"
                    >
                      {payload.name}
                    </text>
                  </g>
                );
              }}
            >
              <Tooltip content={<CustomTooltip />} />
            </Sankey>
          </ResponsiveContainer>
        </div>
        
        <Box padding={{ top: 'm' }}>
          <Box variant="small" color="text-body-secondary">
            <strong>Legend:</strong> Boxes represent resource types, arrows show modernization paths, 
            and thickness indicates the number of resources.
          </Box>
        </Box>
      </Container>
    );
  } catch (error) {
    console.error('Error rendering Sankey diagram:', error);
    return (
      <Container header={<Header variant="h2">{title}</Header>}>
        <Alert type="error" header="Rendering Error">
          <Box variant="p">
            Unable to render the modernization diagram due to a data processing error.
          </Box>
          <Box variant="p">
            <strong>Error:</strong> {error.message}
          </Box>
          <Box variant="p">
            Please check the browser console for more details or try refreshing the page.
          </Box>
        </Alert>
      </Container>
    );
  }
};

export default SankeyDiagram;