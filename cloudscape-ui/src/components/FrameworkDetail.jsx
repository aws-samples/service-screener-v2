import { useState, useMemo } from 'react';
import { useParams } from 'react-router-dom';
import Container from '@cloudscape-design/components/container';
import Header from '@cloudscape-design/components/header';
import SpaceBetween from '@cloudscape-design/components/space-between';
import Box from '@cloudscape-design/components/box';
import PieChart from '@cloudscape-design/components/pie-chart';
import BarChart from '@cloudscape-design/components/bar-chart';
import ColumnLayout from '@cloudscape-design/components/column-layout';
import Badge from '@cloudscape-design/components/badge';
import Link from '@cloudscape-design/components/link';
import Table from '@cloudscape-design/components/table';
import TextFilter from '@cloudscape-design/components/text-filter';
import Button from '@cloudscape-design/components/button';
import Pagination from '@cloudscape-design/components/pagination';
import Tabs from '@cloudscape-design/components/tabs';

import ProgressBar from '@cloudscape-design/components/progress-bar';
import StatusIndicator from '@cloudscape-design/components/status-indicator';

import { getFrameworkData } from '../utils/dataLoader';
import { renderHtml, decodeHtml } from '../utils/htmlDecoder';

/**
 * Parse framework description HTML into React elements with Cloudscape StatusIndicator
 * Replaces invisible Font Awesome icons + Bootstrap classes with native Cloudscape components
 */
const DescriptionRenderer = ({ html }) => {
  if (!html) return null;
  const decoded = decodeHtml(html);

  // Extract the h4 title if present
  const titleMatch = decoded.match(/<h4>(.*?)<\/h4>/i);
  const title = titleMatch ? titleMatch[1] : null;

  // Parse each <dt> block into structured items
  const items = [];
  // Match both pass and fail patterns
  const dtRegex = /<dt\s+class='text-(danger|success)'>\s*<i\s+class='fas fa-(?:times|check)'><\/i>\s*\[([^\]]+)\](.*?)<\/dt>([\s\S]*?)(?=<dt |<\/dl>|$)/gi;
  let match;
  while ((match = dtRegex.exec(decoded)) !== null) {
    const status = match[1] === 'success' ? 'pass' : 'fail';
    const checkId = match[2];
    // Clean up the label text after checkId (e.g., " - Enable MFA on root user</i>")
    const label = (match[3] || '').replace(/<\/?i>/gi, '').replace(/^\s*-\s*/, '').trim();
    // Extract affected resources from <ul><li> blocks
    const resourceHtml = match[4] || '';
    const resources = [];
    const liRegex = /<li>(.*?)<\/li>/gi;
    let liMatch;
    while ((liMatch = liRegex.exec(resourceHtml)) !== null) {
      resources.push(liMatch[1]);
    }
    items.push({ status, checkId, label, resources });
  }

  // If no structured items found, fall back to raw HTML
  if (items.length === 0) {
    return <div dangerouslySetInnerHTML={{ __html: decoded.replace(/<i\s+class='fas[^']*'><\/i>/gi, '') }} />;
  }

  return (
    <SpaceBetween size="xxs">
      {title && <Box variant="small" fontWeight="bold">{title.replace(/&amp;/g, '&')}</Box>}
      {items.map((item, i) => (
        <div key={i} style={{ padding: '2px 0' }}>
          <StatusIndicator type={item.status === 'pass' ? 'success' : 'error'}>
            <Box variant="code" display="inline">{item.checkId}</Box>
            {item.label && <span> — {item.label}</span>}
          </StatusIndicator>
          {item.resources.length > 0 && (
            <Box padding={{ left: 'l' }} color="text-body-secondary" fontSize="body-s">
              {item.resources.map((r, j) => (
                <div key={j} dangerouslySetInnerHTML={{ __html: r }} />
              ))}
            </Box>
          )}
        </div>
      ))}
    </SpaceBetween>
  );
};

/**
 * FrameworkDetail component - displays compliance framework reports
 * Requirements: 6.1, 6.2, 6.3, 6.4, 6.5
 */
const FrameworkDetail = ({ data }) => {
  const { frameworkName } = useParams();
  
  // Get framework data
  const frameworkData = getFrameworkData(data, frameworkName);
  
  // Table state
  const [filteringText, setFilteringText] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  const [sortingColumn, setSortingColumn] = useState({ sortingField: 'category' });
  const [sortingDescending, setSortingDescending] = useState(false);
  const [currentPageIndex, setCurrentPageIndex] = useState(1);
  const pageSize = 50;
  
  // If framework not found
  if (!frameworkData) {
    return (
      <Container>
        <Box textAlign="center" padding={{ vertical: 'xxl' }}>
          <Box variant="h2" color="text-status-error">
            Framework Not Found
          </Box>
          <Box variant="p" color="text-status-inactive">
            The framework "{frameworkName}" was not found in this report.
          </Box>
        </Box>
      </Container>
    );
  }

  const { metadata, summary, details } = frameworkData;
  
  // Calculate summary statistics
  const summaryStats = useMemo(() => {
    if (!summary || !summary.mcn) {
      return { notAvailable: 0, compliant: 0, needAttention: 0, total: 0 };
    }
    
    const [notAvailable, compliant, needAttention] = summary.mcn;
    return {
      notAvailable,
      compliant,
      needAttention,
      total: notAvailable + compliant + needAttention
    };
  }, [summary]);

  // Prepare pie chart data
  const pieChartData = useMemo(() => {
    return [
      { title: 'Not Available', value: summaryStats.notAvailable, color: '#17a2b8' },
      { title: 'Compliant', value: summaryStats.compliant, color: '#28a745' },
      { title: 'Need Attention', value: summaryStats.needAttention, color: '#dc3545' }
    ].filter(item => item.value > 0);
  }, [summaryStats]);

  // Prepare bar chart data
  const barChartData = useMemo(() => {
    if (!summary || !summary.stats) return [];
    
    return Object.entries(summary.stats).map(([category, values]) => ({
      x: category,
      y: values[0] + values[1] + values[2], // Total
      notAvailable: values[0],
      compliant: values[1],
      needAttention: values[2]
    }));
  }, [summary]);

  // Compliance percentage per category
  const categoryCompliance = useMemo(() => {
    if (!summary || !summary.stats) return [];
    return Object.entries(summary.stats).map(([category, values]) => {
      const [na, compliant, needAttention] = values;
      const assessed = compliant + needAttention;
      const pct = assessed > 0 ? Math.round((compliant / assessed) * 100) : null;
      return { category, na, compliant, needAttention, total: na + compliant + needAttention, assessed, pct };
    });
  }, [summary]);

  // Prepare table data from details array
  // Details format: [Category, Rule ID, Compliance Status, Description, Reference]
  const tableItems = useMemo(() => {
    if (!details || !Array.isArray(details)) return [];
    
    return details.map((row, index) => ({
      id: index,
      category: row[0] || '',
      ruleId: row[1] || '',
      complianceStatus: row[2], // 0 = Not Available, 1 = Compliant, -1 = Need Attention
      description: row[3] || '',
      reference: row[4] || ''
    }));
  }, [details]);

  // Filter table items
  const filteredItems = useMemo(() => {
    let items = tableItems;
    
    // Status filter
    if (statusFilter === 'needAttention') {
      items = items.filter(item => item.complianceStatus === -1);
    } else if (statusFilter === 'compliant') {
      items = items.filter(item => item.complianceStatus === 1);
    } else if (statusFilter === 'notAvailable') {
      items = items.filter(item => item.complianceStatus === 0);
    }
    
    // Text filter
    if (filteringText) {
      const lowerFilter = filteringText.toLowerCase();
      items = items.filter(item => 
        item.category.toLowerCase().includes(lowerFilter) ||
        item.ruleId.toLowerCase().includes(lowerFilter) ||
        item.description.toLowerCase().includes(lowerFilter)
      );
    }
    
    return items;
  }, [tableItems, filteringText, statusFilter]);

  // Sort table items
  const sortedItems = useMemo(() => {
    const items = [...filteredItems];
    
    if (!sortingColumn.sortingField) return items;
    
    items.sort((a, b) => {
      let aVal = a[sortingColumn.sortingField];
      let bVal = b[sortingColumn.sortingField];
      
      // Handle compliance status sorting
      if (sortingColumn.sortingField === 'complianceStatus') {
        aVal = aVal === 1 ? 2 : aVal === -1 ? 0 : 1; // Sort: Need Attention, Not Available, Compliant
        bVal = bVal === 1 ? 2 : bVal === -1 ? 0 : 1;
      }
      
      if (typeof aVal === 'string') {
        return sortingDescending 
          ? bVal.localeCompare(aVal)
          : aVal.localeCompare(bVal);
      }
      
      return sortingDescending ? bVal - aVal : aVal - bVal;
    });
    
    return items;
  }, [filteredItems, sortingColumn, sortingDescending]);

  // Paginate items
  const paginatedItems = useMemo(() => {
    const startIndex = (currentPageIndex - 1) * pageSize;
    return sortedItems.slice(startIndex, startIndex + pageSize);
  }, [sortedItems, currentPageIndex]);

  // Get compliance status badge
  const getComplianceBadge = (status) => {
    if (status === 1) {
      return <Badge color="green">Compliant</Badge>;
    } else if (status === -1) {
      return <Badge color="red">Need Attention</Badge>;
    } else {
      return <Badge color="blue">Not Available</Badge>;
    }
  };

  // Export to CSV
  const exportToCSV = () => {
    const headers = ['Category', 'Rule ID', 'Compliance Status', 'Description', 'Reference'];
    const csvRows = [headers.join(',')];
    
    sortedItems.forEach(item => {
      const status = item.complianceStatus === 1 ? 'Compliant' 
        : item.complianceStatus === -1 ? 'Need Attention' 
        : 'Not Available';
      
      const row = [
        `"${item.category.replace(/"/g, '""')}"`,
        `"${item.ruleId.replace(/"/g, '""')}"`,
        `"${status}"`,
        `"${item.description.replace(/<[^>]*>/g, '').replace(/"/g, '""')}"`, // Strip HTML
        `"${item.reference.replace(/<[^>]*>/g, '').replace(/"/g, '""')}"` // Strip HTML
      ];
      csvRows.push(row.join(','));
    });
    
    const csvContent = csvRows.join('\n');
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const link = document.createElement('a');
    const url = URL.createObjectURL(blob);
    
    link.setAttribute('href', url);
    link.setAttribute('download', `${frameworkName}_compliance.csv`);
    link.style.visibility = 'hidden';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  // Table column definitions
  const columnDefinitions = [
    {
      id: 'category',
      header: 'Category',
      cell: item => item.category,
      sortingField: 'category',
      width: 150
    },
    {
      id: 'ruleId',
      header: 'Rule ID',
      cell: item => item.ruleId,
      sortingField: 'ruleId',
      width: 120
    },
    {
      id: 'complianceStatus',
      header: 'Compliance Status',
      cell: item => getComplianceBadge(item.complianceStatus),
      sortingField: 'complianceStatus',
      width: 150
    },
    {
      id: 'description',
      header: 'Description',
      cell: item => <DescriptionRenderer html={item.description} />,
      width: 400
    },
    {
      id: 'reference',
      header: 'Reference',
      cell: item => (
        <Box>
          <div dangerouslySetInnerHTML={renderHtml(item.reference)} />
        </Box>
      ),
      width: 200
    }
  ];

  return (
    <SpaceBetween size="l">
      <Header 
        variant="h1"
        description={metadata?.description || 'Framework compliance report'}
      >
        {metadata?.fullname || frameworkName.toUpperCase()}
      </Header>
      
      {/* Framework metadata */}
      <Container
        header={
          <Header variant="h2">
            Framework Information
          </Header>
        }
      >
        <SpaceBetween size="m">
          <Box>
            <Box variant="awsui-key-label">Framework</Box>
            <Box>{metadata?.fullname || frameworkName}</Box>
          </Box>
          <Box>
            <Box variant="awsui-key-label">Short Name</Box>
            <Box>{metadata?.shortname || frameworkName}</Box>
          </Box>
          {metadata?._ && (
            <Box>
              <Box variant="awsui-key-label">Reference</Box>
              <Link href={metadata._} external>
                Read more
              </Link>
            </Box>
          )}
        </SpaceBetween>
      </Container>

      {/* Summary statistics */}
      <Container
        header={
          <Header 
            variant="h2"
            description={`Total: ${summaryStats.total} controls`}
          >
            Compliance Summary
          </Header>
        }
      >
        <ColumnLayout columns={3} variant="text-grid">
          <div>
            <Box variant="awsui-key-label">Not Available</Box>
            <Box fontSize="display-l" fontWeight="bold" color="text-status-info">
              {summaryStats.notAvailable}
            </Box>
          </div>
          <div>
            <Box variant="awsui-key-label">Compliant</Box>
            <Box fontSize="display-l" fontWeight="bold" color="text-status-success">
              {summaryStats.compliant}
            </Box>
          </div>
          <div>
            <Box variant="awsui-key-label">Need Attention</Box>
            <Box fontSize="display-l" fontWeight="bold" color="text-status-error">
              {summaryStats.needAttention}
            </Box>
          </div>
        </ColumnLayout>
      </Container>

      {/* Pie chart */}
      <Container
        header={
          <Header variant="h2">
            Compliance Status Distribution
          </Header>
        }
      >
        <PieChart
          data={pieChartData}
          detailPopoverContent={(datum) => [
            { key: 'Status', value: datum.title },
            { key: 'Count', value: datum.value },
            { 
              key: 'Percentage', 
              value: `${((datum.value / summaryStats.total) * 100).toFixed(1)}%` 
            }
          ]}
          segmentDescription={(datum, sum) => 
            `${datum.value} controls, ${((datum.value / sum) * 100).toFixed(1)}%`
          }
          ariaLabel="Compliance status distribution"
          ariaDescription="Pie chart showing the distribution of compliance statuses"
          hideFilter
          size="medium"
          variant="donut"
          innerMetricDescription="controls"
          innerMetricValue={summaryStats.total.toString()}
        />
      </Container>

      {/* Bar chart */}
      <Container
        header={
          <Header variant="h2">
            Compliance Breakdown by Category
          </Header>
        }
      >
        <BarChart
          series={[
            {
              title: 'Not Available',
              type: 'bar',
              data: barChartData.map(d => ({ x: d.x, y: d.notAvailable })),
              color: '#17a2b8'
            },
            {
              title: 'Compliant',
              type: 'bar',
              data: barChartData.map(d => ({ x: d.x, y: d.compliant })),
              color: '#28a745'
            },
            {
              title: 'Need Attention',
              type: 'bar',
              data: barChartData.map(d => ({ x: d.x, y: d.needAttention })),
              color: '#dc3545'
            }
          ]}
          xDomain={barChartData.map(d => d.x)}
          yDomain={[0, Math.max(...barChartData.map(d => d.y))]}
          xTitle="Category"
          yTitle="Number of Controls"
          ariaLabel="Compliance breakdown by category"
          ariaDescription="Bar chart showing compliance status breakdown by category"
          height={300}
          stackedBars
          hideFilter
        />
      </Container>

      {/* Compliance percentage per category */}
      {categoryCompliance.length > 0 && (
        <Container
          header={
            <Header
              variant="h2"
              description="Percentage based on assessed controls (excludes Not Available)"
            >
              Compliance Rate by Category
            </Header>
          }
        >
          <ColumnLayout columns={2}>
            {categoryCompliance.map(c => (
              <ProgressBar
                key={c.category}
                value={c.pct ?? 0}
                label={c.category}
                description={
                  <span>
                    <span style={{color:'#037f0c',fontWeight:600}}>{c.compliant} compliant</span>
                    {', '}
                    <span style={{color:'#d91515',fontWeight:600}}>{c.needAttention} need attention</span>
                    {c.na > 0 && <>{', '}<span style={{color:'#0972d3',fontWeight:600}}>{c.na} not available</span></>}
                  </span>
                }
                status={c.pct === null ? 'error' : 'success'}
                resultText={c.pct === null ? 'No assessed controls' : `${c.pct}% compliant (${c.compliant}/${c.assessed})`}
              />
            ))}
          </ColumnLayout>
        </Container>
      )}

      {/* Compliance details table */}
      <Table
        columnDefinitions={columnDefinitions}
        items={paginatedItems}
        sortingColumn={sortingColumn}
        sortingDescending={sortingDescending}
        onSortingChange={({ detail }) => {
          setSortingColumn({ sortingField: detail.sortingColumn.sortingField });
          setSortingDescending(detail.isDescending);
        }}
        header={
          <Header
            variant="h2"
            counter={`(${sortedItems.length})`}
            actions={
              <Button
                iconName="download"
                onClick={exportToCSV}
                disabled={sortedItems.length === 0}
              >
                Export to CSV
              </Button>
            }
          >
            Compliance Details
          </Header>
        }
        filter={
          <SpaceBetween size="xs">
            <Tabs
              activeTabId={statusFilter}
              onChange={({ detail }) => {
                setStatusFilter(detail.activeTabId);
                setCurrentPageIndex(1);
              }}
              tabs={[
                { id: 'all', label: `All (${tableItems.length})` },
                { id: 'needAttention', label: `Need Attention (${tableItems.filter(i => i.complianceStatus === -1).length})` },
                { id: 'compliant', label: `Compliant (${tableItems.filter(i => i.complianceStatus === 1).length})` },
                { id: 'notAvailable', label: `Not Available (${tableItems.filter(i => i.complianceStatus === 0).length})` },
              ]}
            />
            <TextFilter
              filteringText={filteringText}
              filteringPlaceholder="Find controls"
              filteringAriaLabel="Filter controls"
              onChange={({ detail }) => {
                setFilteringText(detail.filteringText);
                setCurrentPageIndex(1);
              }}
            />
          </SpaceBetween>
        }
        pagination={
          <Pagination
            currentPageIndex={currentPageIndex}
            pagesCount={Math.ceil(sortedItems.length / pageSize)}
            onChange={({ detail }) => setCurrentPageIndex(detail.currentPageIndex)}
            ariaLabels={{
              nextPageLabel: 'Next page',
              previousPageLabel: 'Previous page',
              pageLabel: pageNumber => `Page ${pageNumber}`
            }}
          />
        }
        empty={
          <Box textAlign="center" color="inherit">
            <Box variant="p" color="inherit">
              No controls found
            </Box>
          </Box>
        }
        wrapLines
      />
    </SpaceBetween>
  );
};

export default FrameworkDetail;
