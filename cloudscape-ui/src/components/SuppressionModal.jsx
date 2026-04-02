import { useMemo } from 'react';
import Modal from '@cloudscape-design/components/modal';
import Box from '@cloudscape-design/components/box';
import SpaceBetween from '@cloudscape-design/components/space-between';
import Table from '@cloudscape-design/components/table';
import Header from '@cloudscape-design/components/header';
import Badge from '@cloudscape-design/components/badge';
import ColumnLayout from '@cloudscape-design/components/column-layout';

import { getSuppressions } from '../utils/dataLoader';

/**
 * SuppressionModal component - displays active suppressions
 * Requirements: 8.1, 8.2, 8.3, 8.4
 */
const SuppressionModal = ({ data, visible, onDismiss }) => {
  // Get suppression data
  const suppressionData = useMemo(() => {
    return getSuppressions(data);
  }, [data]);

  // Parse suppression data into service-level and resource-specific
  const { serviceLevelSuppressions, resourceSuppressions } = useMemo(() => {
    const serviceLevelList = [];
    const resourceList = [];

    if (!suppressionData) {
      return { serviceLevelSuppressions: [], resourceSuppressions: [] };
    }

    // Handle different suppression data formats
    if (Array.isArray(suppressionData)) {
      // Array format
      suppressionData.forEach((suppression, index) => {
        if (suppression.resources && suppression.resources.length > 0) {
          resourceList.push({
            id: index,
            service: suppression.service || 'Unknown',
            ruleName: suppression.rule || suppression.ruleName || 'Unknown',
            resources: suppression.resources.join(', ')
          });
        } else {
          serviceLevelList.push({
            id: index,
            service: suppression.service || 'Unknown',
            ruleName: suppression.rule || suppression.ruleName || 'Unknown',
            description: suppression.description || suppression.reason || 'No description provided'
          });
        }
      });
    } else if (typeof suppressionData === 'object') {
      // Object format with serviceLevelSuppressions and resourceSuppressions
      if (suppressionData.serviceLevelSuppressions) {
        suppressionData.serviceLevelSuppressions.forEach((suppression, index) => {
          serviceLevelList.push({
            id: index,
            service: suppression.service || 'Unknown',
            ruleName: suppression.rule || suppression.ruleName || 'Unknown',
            description: suppression.description || suppression.reason || 'No description provided'
          });
        });
      }

      if (suppressionData.resourceSuppressions) {
        suppressionData.resourceSuppressions.forEach((suppression, index) => {
          resourceList.push({
            id: index,
            service: suppression.service || 'Unknown',
            ruleName: suppression.rule || suppression.ruleName || 'Unknown',
            resources: Array.isArray(suppression.resources) 
              ? suppression.resources.join(', ')
              : suppression.resources || 'Unknown'
          });
        });
      }
    }

    return {
      serviceLevelSuppressions: serviceLevelList,
      resourceSuppressions: resourceList
    };
  }, [suppressionData]);

  // Calculate summary statistics
  const summaryStats = useMemo(() => {
    return {
      totalSuppressions: serviceLevelSuppressions.length + resourceSuppressions.length,
      serviceLevelCount: serviceLevelSuppressions.length,
      resourceSpecificCount: resourceSuppressions.length
    };
  }, [serviceLevelSuppressions, resourceSuppressions]);

  // Service-level suppressions column definitions
  const serviceLevelColumns = [
    {
      id: 'service',
      header: 'Service',
      cell: item => item.service.toUpperCase(),
      width: 150
    },
    {
      id: 'ruleName',
      header: 'Rule Name',
      cell: item => item.ruleName,
      width: 200
    },
    {
      id: 'description',
      header: 'Description',
      cell: item => item.description
    }
  ];

  // Resource-specific suppressions column definitions
  const resourceColumns = [
    {
      id: 'service',
      header: 'Service',
      cell: item => item.service.toUpperCase(),
      width: 150
    },
    {
      id: 'ruleName',
      header: 'Rule Name',
      cell: item => item.ruleName,
      width: 200
    },
    {
      id: 'resources',
      header: 'Affected Resources',
      cell: item => (
        <Box fontSize="body-s">
          {item.resources}
        </Box>
      )
    }
  ];

  return (
    <Modal
      visible={visible}
      onDismiss={onDismiss}
      header="Active Suppressions"
      size="large"
    >
      <SpaceBetween size="l">
        {/* Summary statistics */}
        <Box>
          <Box variant="h3" padding={{ bottom: 's' }}>
            Summary
          </Box>
          <ColumnLayout columns={3} variant="text-grid">
            <div>
              <Box variant="awsui-key-label">Total Suppressions</Box>
              <Box fontSize="display-l" fontWeight="bold">
                {summaryStats.totalSuppressions}
              </Box>
            </div>
            <div>
              <Box variant="awsui-key-label">Service-Level</Box>
              <Box fontSize="display-l" fontWeight="bold" color="text-status-info">
                {summaryStats.serviceLevelCount}
              </Box>
            </div>
            <div>
              <Box variant="awsui-key-label">Resource-Specific</Box>
              <Box fontSize="display-l" fontWeight="bold" color="text-status-warning">
                {summaryStats.resourceSpecificCount}
              </Box>
            </div>
          </ColumnLayout>
        </Box>

        {/* Service-level suppressions table */}
        {serviceLevelSuppressions.length > 0 && (
          <Table
            columnDefinitions={serviceLevelColumns}
            items={serviceLevelSuppressions}
            header={
              <Header
                variant="h3"
                counter={`(${serviceLevelSuppressions.length})`}
              >
                Service-Level Suppressions
              </Header>
            }
            empty={
              <Box textAlign="center" color="inherit">
                <Box variant="p" color="inherit">
                  No service-level suppressions
                </Box>
              </Box>
            }
            wrapLines
          />
        )}

        {/* Resource-specific suppressions table */}
        {resourceSuppressions.length > 0 && (
          <Table
            columnDefinitions={resourceColumns}
            items={resourceSuppressions}
            header={
              <Header
                variant="h3"
                counter={`(${resourceSuppressions.length})`}
              >
                Resource-Specific Suppressions
              </Header>
            }
            empty={
              <Box textAlign="center" color="inherit">
                <Box variant="p" color="inherit">
                  No resource-specific suppressions
                </Box>
              </Box>
            }
            wrapLines
          />
        )}

        {/* No suppressions message */}
        {summaryStats.totalSuppressions === 0 && (
          <Box textAlign="center" padding={{ vertical: 'l' }}>
            <Badge color="green">No Active Suppressions</Badge>
            <Box variant="p" padding={{ top: 's' }} color="text-status-inactive">
              All checks are currently active.
            </Box>
          </Box>
        )}
      </SpaceBetween>
    </Modal>
  );
};

export default SuppressionModal;
