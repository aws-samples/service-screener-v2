import React, { useState, useEffect, useMemo } from 'react';
import { useSearchParams } from 'react-router-dom';
import Container from '@cloudscape-design/components/container';
import Header from '@cloudscape-design/components/header';
import SpaceBetween from '@cloudscape-design/components/space-between';
import Tabs from '@cloudscape-design/components/tabs';
import Table from '@cloudscape-design/components/table';
import Box from '@cloudscape-design/components/box';
import TextFilter from '@cloudscape-design/components/text-filter';
import PropertyFilter from '@cloudscape-design/components/property-filter';
import Pagination from '@cloudscape-design/components/pagination';
import CollectionPreferences from '@cloudscape-design/components/collection-preferences';
import Badge from '@cloudscape-design/components/badge';
import Button from '@cloudscape-design/components/button';

/**
 * FindingsPage component
 * Displays all findings with search, filter, and tabs for active/suppressed
 * Supports deep linking from dashboard with URL parameters
 */
const FindingsPage = ({ data }) => {
  const [searchParams, setSearchParams] = useSearchParams();
  const [activeTabId, setActiveTabId] = useState('active');
  const [filteringText, setFilteringText] = useState('');
  const [currentPageIndex, setCurrentPageIndex] = useState(1);
  const [pageSize, setPageSize] = useState(20);
  const [sortingColumn, setSortingColumn] = useState({ sortingField: 'Severity' });
  const [isDescending, setIsDescending] = useState(true);
  const [propertyFilterQuery, setPropertyFilterQuery] = useState({ tokens: [], operation: 'and' });
  
  // Get findings data
  const findingsData = data?.customPage_findings || {};
  const activeFindings = findingsData.findings || [];
  const suppressedFindings = findingsData.suppressed || [];
  
  // Apply URL parameters on mount
  useEffect(() => {
    const type = searchParams.get('type');
    const severity = searchParams.get('severity');
    const service = searchParams.get('service');
    
    const tokens = [];
    if (type) {
      tokens.push({ propertyKey: 'Type', value: type, operator: ':' });
    }
    if (severity) {
      tokens.push({ propertyKey: 'Severity', value: severity, operator: ':' });
    }
    if (service) {
      tokens.push({ propertyKey: 'service', value: service, operator: ':' });
    }
    
    if (tokens.length > 0) {
      setPropertyFilterQuery({ tokens, operation: 'and' });
    }
  }, [searchParams]);
  
  // Column definitions
  const columnDefinitions = [
    {
      id: 'service',
      header: 'Service',
      cell: item => item.service || '-',
      sortingField: 'service',
      width: 120
    },
    {
      id: 'region',
      header: 'Region',
      cell: item => item.Region || '-',
      sortingField: 'Region',
      width: 150
    },
    {
      id: 'check',
      header: 'Check',
      cell: item => item.Check || '-',
      sortingField: 'Check',
      width: 200
    },
    {
      id: 'type',
      header: 'Type',
      cell: item => {
        const typeStyle = getTypeStyle(item.Type);
        return (
          <span
            style={{
              display: 'inline-block',
              padding: '2px 8px',
              borderRadius: '4px',
              fontSize: '12px',
              fontWeight: '500',
              ...typeStyle
            }}
          >
            {item.Type || '-'}
          </span>
        );
      },
      sortingField: 'Type',
      width: 150
    },
    {
      id: 'resourceId',
      header: 'Resource ID',
      cell: item => (
        <Box fontSize="body-s" color="text-body-secondary">
          {item.ResourceID || '-'}
        </Box>
      ),
      sortingField: 'ResourceID',
      width: 300
    },
    {
      id: 'severity',
      header: 'Severity',
      cell: item => (
        <Badge color={getSeverityColor(item.Severity)}>
          {item.Severity || '-'}
        </Badge>
      ),
      sortingField: 'Severity',
      width: 120
    }
  ];
  
  // Property filter properties
  const filteringProperties = [
    {
      key: 'service',
      propertyLabel: 'Service',
      groupValuesLabel: 'Service values',
      operators: [':', '!:', '=', '!=']
    },
    {
      key: 'Region',
      propertyLabel: 'Region',
      groupValuesLabel: 'Region values',
      operators: [':', '!:', '=', '!=']
    },
    {
      key: 'Check',
      propertyLabel: 'Check',
      groupValuesLabel: 'Check values',
      operators: [':', '!:', '=', '!=']
    },
    {
      key: 'Type',
      propertyLabel: 'Type',
      groupValuesLabel: 'Type values',
      operators: [':', '!:', '=', '!=']
    },
    {
      key: 'Severity',
      propertyLabel: 'Severity',
      groupValuesLabel: 'Severity values',
      operators: [':', '!:', '=', '!=']
    }
  ];
  
  // Get current items based on active tab
  const currentItems = activeTabId === 'active' ? activeFindings : suppressedFindings;
  
  // Filter items
  const filteredItems = useMemo(() => {
    let items = [...currentItems];
    
    // Apply property filter
    if (propertyFilterQuery.tokens.length > 0) {
      items = items.filter(item => {
        return propertyFilterQuery.tokens.every(token => {
          const value = item[token.propertyKey];
          const tokenValue = token.value.toLowerCase();
          const itemValue = (value || '').toString().toLowerCase();
          
          switch (token.operator) {
            case ':':
              return itemValue.includes(tokenValue);
            case '!:':
              return !itemValue.includes(tokenValue);
            case '=':
              return itemValue === tokenValue;
            case '!=':
              return itemValue !== tokenValue;
            default:
              return true;
          }
        });
      });
    }
    
    // Apply text filter
    if (filteringText) {
      const searchText = filteringText.toLowerCase();
      items = items.filter(item => {
        return Object.values(item).some(value => 
          (value || '').toString().toLowerCase().includes(searchText)
        );
      });
    }
    
    return items;
  }, [currentItems, propertyFilterQuery, filteringText]);
  
  // Sort items
  const sortedItems = useMemo(() => {
    if (!sortingColumn.sortingField) return filteredItems;
    
    return [...filteredItems].sort((a, b) => {
      const aValue = a[sortingColumn.sortingField] || '';
      const bValue = b[sortingColumn.sortingField] || '';
      
      // Handle severity sorting with custom order
      if (sortingColumn.sortingField === 'Severity') {
        const severityOrder = { 'High': 4, 'Medium': 3, 'Low': 2, 'Informational': 1 };
        const aOrder = severityOrder[aValue] || 0;
        const bOrder = severityOrder[bValue] || 0;
        return isDescending ? bOrder - aOrder : aOrder - bOrder;
      }
      
      // Default string comparison
      const comparison = aValue.toString().localeCompare(bValue.toString());
      return isDescending ? -comparison : comparison;
    });
  }, [filteredItems, sortingColumn, isDescending]);
  
  // Paginate items
  const paginatedItems = useMemo(() => {
    const startIndex = (currentPageIndex - 1) * pageSize;
    return sortedItems.slice(startIndex, startIndex + pageSize);
  }, [sortedItems, currentPageIndex, pageSize]);
  
  // Handle sorting
  const handleSortingChange = (event) => {
    const { sortingColumn: newSortingColumn, isDescending: newIsDescending } = event.detail;
    setSortingColumn(newSortingColumn);
    setIsDescending(newIsDescending);
  };
  
  return (
    <SpaceBetween size="l">
      <Container
        header={
          <Header
            variant="h1"
            description="View and search all findings across your AWS resources"
          >
            Findings
          </Header>
        }
      >
        <SpaceBetween size="m">
          <Box variant="p">
            Total active findings: <strong>{activeFindings.length}</strong> | 
            Suppressed findings: <strong>{suppressedFindings.length}</strong>
          </Box>
        </SpaceBetween>
      </Container>
      
      <Tabs
        activeTabId={activeTabId}
        onChange={({ detail }) => {
          setActiveTabId(detail.activeTabId);
          setCurrentPageIndex(1);
        }}
        tabs={[
          {
            id: 'active',
            label: `Active Findings (${activeFindings.length})`,
            content: null
          },
          {
            id: 'suppressed',
            label: `Suppressed Findings (${suppressedFindings.length})`,
            content: null
          }
        ]}
      />
      
      <Table
        columnDefinitions={columnDefinitions}
        items={paginatedItems}
        loading={false}
        loadingText="Loading findings"
        sortingColumn={sortingColumn}
        sortingDescending={isDescending}
        onSortingChange={handleSortingChange}
        header={
          <Header
            counter={`(${filteredItems.length})`}
            description={activeTabId === 'active' ? 'Active findings' : 'Suppressed findings'}
          >
            {activeTabId === 'active' ? 'Active Findings' : 'Suppressed Findings'}
          </Header>
        }
        filter={
          <SpaceBetween size="xs" direction="horizontal">
            <div style={{ flex: 1 }}>
              <SpaceBetween size="xs" direction="vertical">
                <PropertyFilter
                  query={propertyFilterQuery}
                  onChange={({ detail }) => {
                    setPropertyFilterQuery(detail);
                    setCurrentPageIndex(1);
                  }}
                  filteringProperties={filteringProperties}
                  filteringPlaceholder="Filter findings"
                  filteringAriaLabel="Filter findings"
                  customControl={
                    (propertyFilterQuery.tokens.length > 0 || filteringText) && (
                      <Button
                        onClick={() => {
                          setPropertyFilterQuery({ tokens: [], operation: 'and' });
                          setFilteringText('');
                          setCurrentPageIndex(1);
                        }}
                        variant="normal"
                        ariaLabel="Clear all filters"
                      >
                        ✕ Clear filters
                      </Button>
                    )
                  }
                />
                <TextFilter
                  filteringText={filteringText}
                  onChange={({ detail }) => {
                    setFilteringText(detail.filteringText);
                    setCurrentPageIndex(1);
                  }}
                  filteringPlaceholder="Search all fields"
                  filteringAriaLabel="Search findings"
                />
              </SpaceBetween>
            </div>
          </SpaceBetween>
        }
        pagination={
          <Pagination
            currentPageIndex={currentPageIndex}
            pagesCount={Math.ceil(filteredItems.length / pageSize)}
            onChange={({ detail }) => setCurrentPageIndex(detail.currentPageIndex)}
            ariaLabels={{
              nextPageLabel: 'Next page',
              previousPageLabel: 'Previous page',
              pageLabel: pageNumber => `Page ${pageNumber}`
            }}
          />
        }
        preferences={
          <CollectionPreferences
            title="Preferences"
            confirmLabel="Confirm"
            cancelLabel="Cancel"
            preferences={{
              pageSize: pageSize
            }}
            pageSizePreference={{
              title: 'Page size',
              options: [
                { value: 10, label: '10 findings' },
                { value: 20, label: '20 findings' },
                { value: 50, label: '50 findings' },
                { value: 100, label: '100 findings' }
              ]
            }}
            onConfirm={({ detail }) => {
              setPageSize(detail.pageSize);
              setCurrentPageIndex(1);
            }}
          />
        }
        empty={
          <Box textAlign="center" color="inherit">
            <b>No findings</b>
            <Box padding={{ bottom: 's' }} variant="p" color="inherit">
              No findings match the current filters.
            </Box>
          </Box>
        }
        variant="full-page"
        stickyHeader={true}
      />
    </SpaceBetween>
  );
};

// Helper functions
const getSeverityColor = (severity) => {
  switch (severity?.toLowerCase()) {
    case 'high':
      return 'red';
    case 'medium':
      return 'blue';
    case 'low':
      return 'green';
    case 'informational':
      return 'grey';
    default:
      return 'grey';
  }
};

const getTypeStyle = (type) => {
  switch (type?.toLowerCase()) {
    case 'security':
      return { backgroundColor: '#d13212', color: 'white' }; // Red
    case 'cost optimization':
    case 'cost ops':
      return { backgroundColor: '#0073bb', color: 'white' }; // Blue
    case 'performance efficiency':
    case 'performance':
      return { backgroundColor: '#1d8102', color: 'white' }; // Green
    case 'reliability':
      return { backgroundColor: '#f012be', color: 'white' }; // Magenta/Pink
    case 'operational excellence':
    case 'operation excellence':
    case 'ops excellence':
      return { backgroundColor: '#ff851b', color: 'white' }; // Orange
    default:
      return { backgroundColor: '#545b64', color: 'white' }; // Grey
  }
};

export default FindingsPage;
