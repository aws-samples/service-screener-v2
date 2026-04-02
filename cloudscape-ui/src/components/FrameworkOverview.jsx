import { useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import Container from '@cloudscape-design/components/container';
import Header from '@cloudscape-design/components/header';
import SpaceBetween from '@cloudscape-design/components/space-between';
import Box from '@cloudscape-design/components/box';
import ColumnLayout from '@cloudscape-design/components/column-layout';
import PieChart from '@cloudscape-design/components/pie-chart';
import Table from '@cloudscape-design/components/table';
import Link from '@cloudscape-design/components/link';
import ProgressBar from '@cloudscape-design/components/progress-bar';
import Badge from '@cloudscape-design/components/badge';
import BarChart from '@cloudscape-design/components/bar-chart';

import { getFrameworkData } from '../utils/dataLoader';

const FrameworkOverview = ({ data, frameworks = [] }) => {
  const navigate = useNavigate();

  const frameworkStats = useMemo(() => {
    return frameworks.map(fwKey => {
      const name = fwKey.replace('framework_', '');
      const fw = getFrameworkData(data, name);
      if (!fw || !fw.summary || !fw.summary.mcn) {
        return { name, na: 0, compliant: 0, needAttention: 0, total: 0, assessed: 0, pct: null };
      }
      const [na, compliant, needAttention] = fw.summary.mcn;
      const assessed = compliant + needAttention;
      const pct = assessed > 0 ? Math.round((compliant / assessed) * 100) : null;
      const fullname = fw.metadata?.fullname || name;
      return { name, fullname, na, compliant, needAttention, total: na + compliant + needAttention, assessed, pct };
    }).sort((a, b) => a.name.localeCompare(b.name));
  }, [data, frameworks]);

  // Aggregate totals
  const totals = useMemo(() => {
    const t = { na: 0, compliant: 0, needAttention: 0, total: 0, assessed: 0 };
    frameworkStats.forEach(f => {
      t.na += f.na; t.compliant += f.compliant; t.needAttention += f.needAttention;
      t.total += f.total; t.assessed += f.assessed;
    });
    t.pct = t.assessed > 0 ? Math.round((t.compliant / t.assessed) * 100) : 0;
    return t;
  }, [frameworkStats]);

  if (frameworks.length === 0) {
    return (
      <Container>
        <Box textAlign="center" padding={{ vertical: 'xxl' }}>
          <Box variant="h2">No Frameworks</Box>
          <Box variant="p" color="text-status-inactive">No framework data found in this report.</Box>
        </Box>
      </Container>
    );
  }

  return (
    <SpaceBetween size="l">
      <Header variant="h1" description="Compliance posture across all frameworks">
        Framework Overview
      </Header>

      {/* Aggregate summary */}
      <Container header={<Header variant="h2">Overall Compliance</Header>}>
        <ColumnLayout columns={4} variant="text-grid">
          <div>
            <Box variant="awsui-key-label">Frameworks</Box>
            <Box fontSize="display-l" fontWeight="bold">{frameworkStats.length}</Box>
          </div>
          <div>
            <Box variant="awsui-key-label">Total Controls</Box>
            <Box fontSize="display-l" fontWeight="bold">{totals.total}</Box>
          </div>
          <div>
            <Box variant="awsui-key-label">Overall Compliance</Box>
            <Box fontSize="display-l" fontWeight="bold" color="text-status-success">{totals.pct}%</Box>
          </div>
          <div>
            <Box variant="awsui-key-label">Need Attention</Box>
            <Box fontSize="display-l" fontWeight="bold" color="text-status-error">{totals.needAttention}</Box>
          </div>
        </ColumnLayout>
      </Container>

      {/* Comparison bar chart */}
      <Container header={<Header variant="h2">Framework Comparison</Header>}>
        <BarChart
          series={[
            {
              title: 'Compliant',
              type: 'bar',
              data: frameworkStats.map(f => ({ x: f.name, y: f.compliant })),
              color: '#28a745'
            },
            {
              title: 'Need Attention',
              type: 'bar',
              data: frameworkStats.map(f => ({ x: f.name, y: f.needAttention })),
              color: '#dc3545'
            },
            {
              title: 'Not Available',
              type: 'bar',
              data: frameworkStats.map(f => ({ x: f.name, y: f.na })),
              color: '#17a2b8'
            }
          ]}
          xDomain={frameworkStats.map(f => f.name)}
          yDomain={[0, Math.max(...frameworkStats.map(f => f.total))]}
          xTitle="Framework"
          yTitle="Number of Controls"
          ariaLabel="Framework compliance comparison"
          height={300}
          stackedBars
          hideFilter
        />
      </Container>

      {/* Compliance rate per framework */}
      <Container
        header={
          <Header variant="h2" description="Percentage based on assessed controls (excludes Not Available)">
            Compliance Rate
          </Header>
        }
      >
        <ColumnLayout columns={2}>
          {frameworkStats.map(f => (
            <ProgressBar
              key={f.name}
              value={f.pct ?? 0}
              label={f.name}
              description={
                <span>
                  <span style={{color:'#037f0c',fontWeight:600}}>{f.compliant} compliant</span>
                  {', '}
                  <span style={{color:'#d91515',fontWeight:600}}>{f.needAttention} need attention</span>
                  {f.na > 0 && <>{', '}<span style={{color:'#0972d3',fontWeight:600}}>{f.na} not available</span></>}
                </span>
              }
              status={f.pct === null ? 'error' : 'success'}
              resultText={f.pct === null ? 'No assessed controls' : `${f.pct}% (${f.compliant}/${f.assessed})`}
            />
          ))}
        </ColumnLayout>
      </Container>

      {/* Detail table */}
      <Table
        columnDefinitions={[
          {
            id: 'name',
            header: 'Framework',
            cell: item => (
              <Link onFollow={() => navigate(`/framework/${item.name.toLowerCase()}`)}>
                {item.name}
              </Link>
            ),
            sortingField: 'name',
          },
          {
            id: 'fullname',
            header: 'Full Name',
            cell: item => item.fullname,
          },
          {
            id: 'pct',
            header: 'Compliance %',
            cell: item => item.pct !== null
              ? <Badge color={item.pct >= 80 ? 'green' : item.pct >= 50 ? 'blue' : 'red'}>{item.pct}%</Badge>
              : <Badge color="grey">N/A</Badge>,
            sortingField: 'pct',
          },
          {
            id: 'compliant',
            header: 'Compliant',
            cell: item => <Box color="text-status-success">{item.compliant}</Box>,
            sortingField: 'compliant',
          },
          {
            id: 'needAttention',
            header: 'Need Attention',
            cell: item => <Box color="text-status-error">{item.needAttention}</Box>,
            sortingField: 'needAttention',
          },
          {
            id: 'na',
            header: 'Not Available',
            cell: item => <Box color="text-status-info">{item.na}</Box>,
            sortingField: 'na',
          },
          {
            id: 'total',
            header: 'Total',
            cell: item => item.total,
            sortingField: 'total',
          },
        ]}
        items={frameworkStats}
        header={<Header variant="h2" counter={`(${frameworkStats.length})`}>Framework Details</Header>}
        sortingDisabled={false}
        wrapLines
      />
    </SpaceBetween>
  );
};

export default FrameworkOverview;
