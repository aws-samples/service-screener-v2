import React, { useState, useMemo } from 'react';
import Table from '@cloudscape-design/components/table';
import Header from '@cloudscape-design/components/header';
import SpaceBetween from '@cloudscape-design/components/space-between';
import Box from '@cloudscape-design/components/box';
import Badge from '@cloudscape-design/components/badge';
import Button from '@cloudscape-design/components/button';
import ButtonDropdown from '@cloudscape-design/components/button-dropdown';
import TextFilter from '@cloudscape-design/components/text-filter';
import Pagination from '@cloudscape-design/components/pagination';
import CollectionPreferences from '@cloudscape-design/components/collection-preferences';
import PropertyFilter from '@cloudscape-design/components/property-filter';
import Modal from '@cloudscape-design/components/modal';
import StatusIndicator from '@cloudscape-design/components/status-indicator';
import ColumnLayout from '@cloudscape-design/components/column-layout';
import ProgressBar from '@cloudscape-design/components/progress-bar';
import Link from '@cloudscape-design/components/link';

/**
 * RecommendationTable component
 * Sortable, filterable table for cost optimization recommendations with bulk actions
 */
const RecommendationTable = ({ 
  recommendations = [], 
  onRecommendationSelect,
  onBulkAction,
  onStatusUpdate,
  loading = false 
}) => {
  const [selectedItems, setSelectedItems] = useState([]);
  const [filteringText, setFilteringText] = useState('');
  const [currentPageIndex, setCurrentPageIndex] = useState(1);
  const [pageSize, setPageSize] = useState(25);
  const [sortingColumn, setSortingColumn] = useState({ sortingField: 'priority_score', sortingDescending: true });
  const [preferences, setPreferences] = useState({
    pageSize: 25,
    visibleContent: ['id', 'title', 'service', 'category', 'monthly_savings', 'priority_level', 'implementation_effort', 'status', 'actions'],
    wrapLines: false
  });
  const [propertyFiltering, setPropertyFiltering] = useState({
    tokens: [],
    operation: 'and'
  });
  const [showDetailsModal, setShowDetailsModal] = useState(false);
  const [selectedRecommendation, setSelectedRecommendation] = useState(null);

  // Property filter options
  const filteringProperties = [
    {
      key: 'service',
      operators: ['=', '!='],
      propertyLabel: 'Service',
      groupValuesLabel: 'Service values'
    },
    {
      key: 'category',
      operators: ['=', '!='],
      propertyLabel: 'Category',
      groupValuesLabel: 'Category values'
    },
    {
      key: 'priority_level',
      operators: ['=', '!='],
      propertyLabel: 'Priority',
      groupValuesLabel: 'Priority values'
    },
    {
      key: 'implementation_effort',
      operators: ['=', '!='],
      propertyLabel: 'Implementation Effort',
      groupValuesLabel: 'Effort values'
    },
    {
      key: 'status',
      operators: ['=', '!='],
      propertyLabel: 'Status',
      groupValuesLabel: 'Status values'
    },
    {
      key: 'monthly_savings',
      operators: ['>', '<', '=', '!=', '>=', '<='],
      propertyLabel: 'Monthly Savings',
      groupValuesLabel: 'Savings values'
    }
  ];

  // Column definitions
  const columnDefinitions = [
    {
      id: 'id',
      header: 'ID',
      cell: item => (
        <Link 
          onFollow={() => handleViewDetails(item)}
          variant="primary"
        >
          {item.id?.substring(0, 8) || 'N/A'}...
        </Link>
      ),
      sortingField: 'id',
      isRowHeader: true,
      width: 100
    },
    {
      id: 'title',
      header: 'Recommendation',
      cell: item => (
        <SpaceBetween size="xs">
          <Box fontWeight="bold">
            {item.title || 'Cost Optimization Recommendation'}
          </Box>
          <Box fontSize="body-s" color="text-body-secondary">
            {item.description?.substring(0, 100) || 'No description available'}
            {item.description?.length > 100 && '...'}
          </Box>
        </SpaceBetween>
      ),
      sortingField: 'title',
      width: 300
    },
    {
      id: 'service',
      header: 'Service',
      cell: item => (
        <Badge color="blue">
          {item.service?.toUpperCase() || 'UNKNOWN'}
        </Badge>
      ),
      sortingField: 'service',
      width: 100
    },
    {
      id: 'category',
      header: 'Category',
      cell: item => {
        const categoryColors = {
          'compute': 'green',
          'storage': 'blue',
          'database': 'red',
          'commitment': 'grey',
          'network': 'purple'
        };
        return (
          <Badge color={categoryColors[item.category] || 'grey'}>
            {item.category?.toUpperCase() || 'OTHER'}
          </Badge>
        );
      },
      sortingField: 'category',
      width: 120
    },
    {
      id: 'monthly_savings',
      header: 'Monthly Savings',
      cell: item => (
        <SpaceBetween size="xs">
          <Box fontSize="heading-s" fontWeight="bold" color="text-status-success">
            ${(item.monthly_savings || 0).toLocaleString()}
          </Box>
          <Box fontSize="body-s" color="text-body-secondary">
            ${((item.monthly_savings || 0) * 12).toLocaleString()}/year
          </Box>
        </SpaceBetween>
      ),
      sortingField: 'monthly_savings',
      width: 140
    },
    {
      id: 'priority_level',
      header: 'Priority',
      cell: item => {
        const priorityConfig = {
          'high': { color: 'red', icon: '🔴' },
          'medium': { color: 'blue', icon: '🟡' },
          'low': { color: 'green', icon: '🟢' }
        };
        const config = priorityConfig[item.priority_level] || priorityConfig['medium'];
        
        return (
          <SpaceBetween size="xs" direction="horizontal" alignItems="center">
            <span>{config.icon}</span>
            <Badge color={config.color}>
              {item.priority_level?.toUpperCase() || 'MEDIUM'}
            </Badge>
            <Box fontSize="body-s" color="text-body-secondary">
              {Math.round(item.priority_score || 0)}
            </Box>
          </SpaceBetween>
        );
      },
      sortingField: 'priority_score',
      width: 120
    },
    {
      id: 'implementation_effort',
      header: 'Effort',
      cell: item => {
        const effortConfig = {
          'low': { color: 'green', progress: 25 },
          'medium': { color: 'blue', progress: 50 },
          'high': { color: 'red', progress: 75 }
        };
        const config = effortConfig[item.implementation_effort] || effortConfig['medium'];
        
        return (
          <SpaceBetween size="xs">
            <Badge color={config.color}>
              {item.implementation_effort?.toUpperCase() || 'MEDIUM'}
            </Badge>
            <ProgressBar
              value={config.progress}
              variant={config.color === 'red' ? 'error' : config.color === 'blue' ? 'in-progress' : 'success'}
              size="small"
            />
          </SpaceBetween>
        );
      },
      sortingField: 'implementation_effort',
      width: 120
    },
    {
      id: 'status',
      header: 'Status',
      cell: item => {
        const statusConfig = {
          'new': { type: 'pending', color: 'blue' },
          'in_progress': { type: 'in-progress', color: 'blue' },
          'completed': { type: 'success', color: 'green' },
          'dismissed': { type: 'stopped', color: 'grey' },
          'failed': { type: 'error', color: 'red' }
        };
        const config = statusConfig[item.status] || statusConfig['new'];
        
        return (
          <StatusIndicator type={config.type}>
            {item.status?.replace('_', ' ').toUpperCase() || 'NEW'}
          </StatusIndicator>
        );
      },
      sortingField: 'status',
      width: 120
    },
    {
      id: 'actions',
      header: 'Actions',
      cell: item => (
        <SpaceBetween size="xs" direction="horizontal">
          <Button 
            variant="link" 
            size="small"
            onClick={() => handleViewDetails(item)}
          >
            View Details
          </Button>
          <ButtonDropdown
            variant="icon"
            ariaLabel="More actions"
            items={[
              {
                id: 'mark_in_progress',
                text: 'Mark In Progress',
                disabled: item.status === 'in_progress'
              },
              {
                id: 'mark_completed',
                text: 'Mark Completed',
                disabled: item.status === 'completed'
              },
              {
                id: 'dismiss',
                text: 'Dismiss',
                disabled: item.status === 'dismissed'
              },
              { id: 'divider', itemType: 'divider' },
              {
                id: 'export_details',
                text: 'Export Details'
              }
            ]}
            onItemClick={({ detail }) => handleItemAction(item, detail.id)}
          />
        </SpaceBetween>
      ),
      width: 150
    }
  ];

  // Filter and sort recommendations
  const { items, filteredItemsCount, collectionProps } = useMemo(() => {
    let filteredItems = recommendations;

    // Apply text filtering
    if (filteringText) {
      filteredItems = filteredItems.filter(item =>
        item.title?.toLowerCase().includes(filteringText.toLowerCase()) ||
        item.description?.toLowerCase().includes(filteringText.toLowerCase()) ||
        item.service?.toLowerCase().includes(filteringText.toLowerCase()) ||
        item.category?.toLowerCase().includes(filteringText.toLowerCase())
      );
    }

    // Apply property filtering
    if (propertyFiltering.tokens.length > 0) {
      filteredItems = filteredItems.filter(item => {
        return propertyFiltering.tokens.every(token => {
          const { propertyKey, operator, value } = token;
          const itemValue = item[propertyKey];
          
          switch (operator) {
            case '=':
              return String(itemValue).toLowerCase() === String(value).toLowerCase();
            case '!=':
              return String(itemValue).toLowerCase() !== String(value).toLowerCase();
            case '>':
              return Number(itemValue) > Number(value);
            case '<':
              return Number(itemValue) < Number(value);
            case '>=':
              return Number(itemValue) >= Number(value);
            case '<=':
              return Number(itemValue) <= Number(value);
            default:
              return true;
          }
        });
      });
    }

    // Apply sorting
    if (sortingColumn.sortingField) {
      filteredItems = [...filteredItems].sort((a, b) => {
        const aVal = a[sortingColumn.sortingField];
        const bVal = b[sortingColumn.sortingField];
        
        let comparison = 0;
        if (typeof aVal === 'number' && typeof bVal === 'number') {
          comparison = aVal - bVal;
        } else {
          comparison = String(aVal || '').localeCompare(String(bVal || ''));
        }
        
        return sortingColumn.sortingDescending ? -comparison : comparison;
      });
    }

    // Apply pagination
    const startIndex = (currentPageIndex - 1) * pageSize;
    const endIndex = startIndex + pageSize;
    const paginatedItems = filteredItems.slice(startIndex, endIndex);

    return {
      items: paginatedItems,
      filteredItemsCount: filteredItems.length,
      collectionProps: {
        totalItemsCount: recommendations.length
      }
    };
  }, [recommendations, filteringText, propertyFiltering, sortingColumn, currentPageIndex, pageSize]);

  const handleViewDetails = (recommendation) => {
    setSelectedRecommendation(recommendation);
    setShowDetailsModal(true);
    if (onRecommendationSelect) {
      onRecommendationSelect(recommendation);
    }
  };

  const handleItemAction = (item, actionId) => {
    switch (actionId) {
      case 'mark_in_progress':
      case 'mark_completed':
      case 'dismiss':
        if (onStatusUpdate) {
          const newStatus = actionId.replace('mark_', '');
          onStatusUpdate(item.id, newStatus);
        }
        break;
      case 'export_details':
        // Export individual recommendation details
        const exportData = {
          recommendation: item,
          timestamp: new Date().toISOString()
        };
        console.log('Exporting recommendation details:', exportData);
        break;
      default:
        break;
    }
  };

  const handleBulkAction = (actionId) => {
    if (onBulkAction && selectedItems.length > 0) {
      onBulkAction(actionId, selectedItems);
    }
  };

  const getBulkActionItems = () => {
    if (selectedItems.length === 0) return [];
    
    return [
      {
        id: 'mark_in_progress',
        text: `Mark ${selectedItems.length} as In Progress`,
        disabled: selectedItems.every(item => item.status === 'in_progress')
      },
      {
        id: 'mark_completed',
        text: `Mark ${selectedItems.length} as Completed`,
        disabled: selectedItems.every(item => item.status === 'completed')
      },
      {
        id: 'dismiss',
        text: `Dismiss ${selectedItems.length} recommendations`,
        disabled: selectedItems.every(item => item.status === 'dismissed')
      },
      { id: 'divider', itemType: 'divider' },
      {
        id: 'export_selected',
        text: `Export ${selectedItems.length} recommendations`
      }
    ];
  };

  return (
    <SpaceBetween size="l">
      <Table
        {...collectionProps}
        columnDefinitions={columnDefinitions}
        items={items}
        loading={loading}
        loadingText="Loading recommendations..."
        selectionType="multi"
        selectedItems={selectedItems}
        onSelectionChange={({ detail }) => setSelectedItems(detail.selectedItems)}
        ariaLabels={{
          selectionGroupLabel: "Items selection",
          allItemsSelectionLabel: ({ selectedItems }) =>
            `${selectedItems.length} ${selectedItems.length === 1 ? "item" : "items"} selected`,
          itemSelectionLabel: ({ selectedItems }, item) => {
            const isItemSelected = selectedItems.filter(i => i.id === item.id).length;
            return `${item.title} is ${isItemSelected ? "" : "not"} selected`;
          }
        }}
        sortingColumn={sortingColumn}
        onSortingChange={({ detail }) => setSortingColumn(detail)}
        header={
          <Header
            variant="h2"
            counter={`(${filteredItemsCount})`}
            description="Cost optimization recommendations with implementation guidance and priority scoring"
            actions={
              <SpaceBetween size="xs" direction="horizontal">
                {selectedItems.length > 0 && (
                  <ButtonDropdown
                    variant="primary"
                    items={getBulkActionItems()}
                    onItemClick={({ detail }) => handleBulkAction(detail.id)}
                  >
                    Actions ({selectedItems.length})
                  </ButtonDropdown>
                )}
                <Button
                  variant="primary"
                  onClick={() => {
                    // Export all visible recommendations
                    const exportData = {
                      recommendations: items,
                      filters: { text: filteringText, properties: propertyFiltering },
                      timestamp: new Date().toISOString()
                    };
                    console.log('Exporting recommendations:', exportData);
                  }}
                >
                  Export Table
                </Button>
              </SpaceBetween>
            }
          >
            Cost Optimization Recommendations
          </Header>
        }
        filter={
          <SpaceBetween size="s">
            <TextFilter
              filteringText={filteringText}
              onFilteringTextChange={({ detail }) => setFilteringText(detail.filteringText)}
              filteringAriaLabel="Filter recommendations"
              filteringPlaceholder="Search recommendations..."
              countText={`${filteredItemsCount} ${filteredItemsCount === 1 ? 'match' : 'matches'}`}
            />
            <PropertyFilter
              query={propertyFiltering}
              onChange={({ detail }) => setPropertyFiltering(detail)}
              filteringProperties={filteringProperties}
              filteringAriaLabel="Filter recommendations by properties"
              filteringPlaceholder="Filter by service, category, priority..."
              expandToViewport={true}
            />
          </SpaceBetween>
        }
        pagination={
          <Pagination
            currentPageIndex={currentPageIndex}
            pagesCount={Math.ceil(filteredItemsCount / pageSize)}
            onCurrentPageIndexChange={({ detail }) => setCurrentPageIndex(detail.currentPageIndex)}
            ariaLabels={{
              nextPageLabel: "Next page",
              previousPageLabel: "Previous page",
              pageLabel: pageNumber => `Page ${pageNumber} of all pages`
            }}
          />
        }
        preferences={
          <CollectionPreferences
            title="Preferences"
            confirmLabel="Confirm"
            cancelLabel="Cancel"
            preferences={preferences}
            onConfirm={({ detail }) => setPreferences(detail)}
            pageSizePreference={{
              title: "Page size",
              options: [
                { value: 10, label: "10 recommendations" },
                { value: 25, label: "25 recommendations" },
                { value: 50, label: "50 recommendations" },
                { value: 100, label: "100 recommendations" }
              ]
            }}
            visibleContentPreference={{
              title: "Select visible columns",
              options: [
                {
                  label: "Recommendation properties",
                  options: [
                    { id: "id", label: "ID" },
                    { id: "title", label: "Recommendation" },
                    { id: "service", label: "Service" },
                    { id: "category", label: "Category" }
                  ]
                },
                {
                  label: "Financial metrics",
                  options: [
                    { id: "monthly_savings", label: "Monthly Savings" }
                  ]
                },
                {
                  label: "Implementation details",
                  options: [
                    { id: "priority_level", label: "Priority" },
                    { id: "implementation_effort", label: "Effort" },
                    { id: "status", label: "Status" }
                  ]
                },
                {
                  label: "Actions",
                  options: [
                    { id: "actions", label: "Actions" }
                  ]
                }
              ]
            }}
            wrapLinesPreference={{
              label: "Wrap lines",
              description: "Check to see all the text and wrap the lines"
            }}
          />
        }
        empty={
          <Box textAlign="center" color="inherit">
            <b>No recommendations</b>
            <Box padding={{ bottom: "s" }} variant="p" color="inherit">
              No cost optimization recommendations found.
            </Box>
          </Box>
        }
      />

      {/* Recommendation Details Modal */}
      <Modal
        visible={showDetailsModal}
        onDismiss={() => setShowDetailsModal(false)}
        header={selectedRecommendation?.title || 'Recommendation Details'}
        size="large"
        footer={
          <Box float="right">
            <SpaceBetween direction="horizontal" size="xs">
              <Button variant="link" onClick={() => setShowDetailsModal(false)}>
                Close
              </Button>
              <Button 
                variant="primary"
                onClick={() => {
                  // Export this specific recommendation
                  console.log('Exporting recommendation:', selectedRecommendation);
                  setShowDetailsModal(false);
                }}
              >
                Export Details
              </Button>
            </SpaceBetween>
          </Box>
        }
      >
        {selectedRecommendation && (
          <SpaceBetween size="l">
            {/* Basic Information */}
            <ColumnLayout columns={3} variant="text-grid">
              <div>
                <Box variant="awsui-key-label">Service</Box>
                <Badge color="blue">
                  {selectedRecommendation.service?.toUpperCase() || 'UNKNOWN'}
                </Badge>
              </div>
              <div>
                <Box variant="awsui-key-label">Category</Box>
                <Badge color="green">
                  {selectedRecommendation.category?.toUpperCase() || 'OTHER'}
                </Badge>
              </div>
              <div>
                <Box variant="awsui-key-label">Priority</Box>
                <Badge color={selectedRecommendation.priority_level === 'high' ? 'red' : 'blue'}>
                  {selectedRecommendation.priority_level?.toUpperCase() || 'MEDIUM'}
                </Badge>
              </div>
            </ColumnLayout>

            {/* Financial Impact */}
            <ColumnLayout columns={2} variant="text-grid">
              <div>
                <Box variant="awsui-key-label">Monthly Savings</Box>
                <Box fontSize="heading-l" fontWeight="bold" color="text-status-success">
                  ${(selectedRecommendation.monthly_savings || 0).toLocaleString()}
                </Box>
              </div>
              <div>
                <Box variant="awsui-key-label">Annual Savings</Box>
                <Box fontSize="heading-l" fontWeight="bold" color="text-status-success">
                  ${((selectedRecommendation.monthly_savings || 0) * 12).toLocaleString()}
                </Box>
              </div>
            </ColumnLayout>

            {/* Description */}
            <div>
              <Box variant="awsui-key-label">Description</Box>
              <Box variant="p">
                {selectedRecommendation.description || 'No description available'}
              </Box>
            </div>

            {/* Implementation Steps */}
            {selectedRecommendation.implementation_steps && selectedRecommendation.implementation_steps.length > 0 && (
              <div>
                <Box variant="awsui-key-label">Implementation Steps</Box>
                <ol>
                  {selectedRecommendation.implementation_steps.map((step, index) => (
                    <li key={index}>
                      <Box variant="p">{step}</Box>
                    </li>
                  ))}
                </ol>
              </div>
            )}

            {/* Required Permissions */}
            {selectedRecommendation.required_permissions && selectedRecommendation.required_permissions.length > 0 && (
              <div>
                <Box variant="awsui-key-label">Required Permissions</Box>
                <SpaceBetween size="xs" direction="horizontal">
                  {selectedRecommendation.required_permissions.map((permission, index) => (
                    <Badge key={index} color="grey">
                      {permission}
                    </Badge>
                  ))}
                </SpaceBetween>
              </div>
            )}

            {/* Potential Risks */}
            {selectedRecommendation.potential_risks && selectedRecommendation.potential_risks.length > 0 && (
              <div>
                <Box variant="awsui-key-label">Potential Risks</Box>
                <ul>
                  {selectedRecommendation.potential_risks.map((risk, index) => (
                    <li key={index}>
                      <Box variant="p" color="text-status-warning">{risk}</Box>
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {/* Affected Resources */}
            {selectedRecommendation.affected_resources && selectedRecommendation.affected_resources.length > 0 && (
              <div>
                <Box variant="awsui-key-label">Affected Resources ({selectedRecommendation.affected_resources.length})</Box>
                <SpaceBetween size="xs">
                  {selectedRecommendation.affected_resources.slice(0, 5).map((resource, index) => (
                    <Box key={index} variant="code">
                      {resource.type}: {resource.id}
                    </Box>
                  ))}
                  {selectedRecommendation.affected_resources.length > 5 && (
                    <Box variant="p" color="text-body-secondary">
                      ...and {selectedRecommendation.affected_resources.length - 5} more resources
                    </Box>
                  )}
                </SpaceBetween>
              </div>
            )}
          </SpaceBetween>
        )}
      </Modal>
    </SpaceBetween>
  );
};

export default RecommendationTable;