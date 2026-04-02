import React from 'react';
import { useNavigate } from 'react-router-dom';
import Container from '@cloudscape-design/components/container';
import Header from '@cloudscape-design/components/header';
import SpaceBetween from '@cloudscape-design/components/space-between';
import Grid from '@cloudscape-design/components/grid';
import Box from '@cloudscape-design/components/box';
import Badge from '@cloudscape-design/components/badge';
import Button from '@cloudscape-design/components/button';
import ColumnLayout from '@cloudscape-design/components/column-layout';

import { 
  calculateDashboardStats, 
  getServiceStats,
  getCategoryStats 
} from '../utils/dataLoader';
import { 
  formatServiceName, 
  formatCategory, 
  getCategoryColor,
  getCategoryStyle,
  filterUserCategories
} from '../utils/formatters';
import EmptyState from './EmptyState';
import CategoryCard from './CategoryCard';
import ContentEnrichment from './ContentEnrichment';

/**
 * KPI Card component for displaying key metrics
 */
const KPICard = ({ title, value, variant = 'default', onClick, clickable = false }) => {
  const content = (
    <SpaceBetween size="xs">
      <Box variant="awsui-key-label">{title}</Box>
      <Box 
        fontSize="display-l" 
        fontWeight="bold" 
        variant={variant}
      >
        {value}
      </Box>
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
 * Service Card component for displaying service summary
 */
const ServiceCard = ({ service, onClick, onCategoryClick }) => {
  const { serviceName, totalFindings, high, medium, low, categories } = service;
  
  return (
    <Container
      header={
        <Header
          variant="h3"
          actions={
            <Button 
              onClick={() => onClick(serviceName)} 
              iconName="arrow-right"
              ariaLabel={`View details for ${formatServiceName(serviceName)}`}
            >
              View Details
            </Button>
          }
        >
          {formatServiceName(serviceName)}
        </Header>
      }
    >
      <SpaceBetween size="m">
        <ColumnLayout columns={4} variant="text-grid">
          <div>
            <Box variant="awsui-key-label">Total Findings</Box>
            <Box fontSize="heading-l" fontWeight="bold">
              {totalFindings}
            </Box>
          </div>
          <div>
            <Box variant="awsui-key-label">High Priority</Box>
            <Box fontSize="heading-l" fontWeight="bold" color="text-status-error">
              {high}
            </Box>
          </div>
          <div>
            <Box variant="awsui-key-label">Medium Priority</Box>
            <Box fontSize="heading-l" fontWeight="bold" color="text-status-warning">
              {medium}
            </Box>
          </div>
          <div>
            <Box variant="awsui-key-label">Low Priority</Box>
            <Box fontSize="heading-l" fontWeight="bold" color="text-status-info">
              {low}
            </Box>
          </div>
        </ColumnLayout>
        
        {categories.length > 0 && (
          <div>
            <Box variant="awsui-key-label" margin={{ bottom: 'xs' }}>
              Affected Categories
            </Box>
            <SpaceBetween size="xs" direction="horizontal">
              {filterUserCategories(categories).map(category => {
                const categoryStyle = getCategoryStyle(category);
                return (
                  <div 
                    key={category}
                    style={{ cursor: 'pointer' }}
                    onClick={() => onCategoryClick(category)}
                    role="button"
                    tabIndex={0}
                  >
                    <span
                      style={{
                        display: 'inline-block',
                        padding: '2px 8px',
                        borderRadius: '4px',
                        fontSize: '12px',
                        fontWeight: '500',
                        ...categoryStyle
                      }}
                    >
                      {formatCategory(category)}
                    </span>
                  </div>
                );
              })}
            </SpaceBetween>
          </div>
        )}
      </SpaceBetween>
    </Container>
  );
};

/**
 * Dashboard component - main landing page
 * Displays KPI cards and service summary cards
 */
const Dashboard = ({ data }) => {
  const navigate = useNavigate();
  
  // Calculate statistics
  const stats = calculateDashboardStats(data);
  const serviceStats = getServiceStats(data);
  const categoryStats = getCategoryStats(data);
  
  const handleServiceClick = (serviceName) => {
    navigate(`/service/${serviceName.toLowerCase()}`);
  };
  
  const handleFindingsClick = (severity = null) => {
    if (severity) {
      // Map severity code to full name for deep-link
      const severityNameMap = {
        'H': 'High',
        'M': 'Medium',
        'L': 'Low',
        'I': 'Informational'
      };
      const fullSeverityName = severityNameMap[severity] || severity;
      navigate(`/page/findings?severity=${fullSeverityName}`);
    } else {
      navigate(`/page/findings`);
    }
  };
  
  const handleCategoryClick = (category, severity = null) => {
    // Navigate to findings with full category name and optional severity filter
    const params = new URLSearchParams();
    
    // Map category code to full name for deep-link
    const categoryNameMap = {
      'S': 'Security',
      'R': 'Reliability',
      'C': 'Cost',
      'P': 'Performance',
      'O': 'Operation'
    };
    
    // Map severity code to full name for deep-link
    const severityNameMap = {
      'H': 'High',
      'M': 'Medium',
      'L': 'Low',
      'I': 'Informational'
    };
    
    const fullCategoryName = categoryNameMap[category] || category;
    params.append('type', fullCategoryName);
    
    if (severity) {
      const fullSeverityName = severityNameMap[severity] || severity;
      params.append('severity', fullSeverityName);
    }
    navigate(`/page/findings?${params.toString()}`);
  };
  
  return (
    <SpaceBetween size="l">
      <Header variant="h1" description="AWS Well-Architected Assessment Report">
        Service Screener Dashboard
      </Header>
      
      {/* Category Cards - Main KPI Section - Always show all 5 Well-Architected Pillars */}
      <div>
        <Header variant="h2" description="Click on cards to filter findings by category and severity" />
        
        {(() => {
          const categoryOrder = ['S', 'R', 'C', 'P', 'O'];
          const orderedCategories = [];
          
          // Ensure all 5 pillars are shown, even if they have 0 findings
          // Filter out 'T' category
          categoryOrder.forEach(catCode => {
            const cat = categoryStats.find(c => c.category === catCode);
            if (cat) {
              orderedCategories.push(cat);
            } else {
              // Create empty category if no findings exist
              orderedCategories.push({
                category: catCode,
                total: 0,
                high: 0,
                medium: 0,
                low: 0,
                informational: 0
              });
            }
          });
          
          // Split into Security (first row) and other 4 pillars (second row)
          const securityCategory = orderedCategories.find(cat => cat.category === 'S');
          const otherCategories = orderedCategories.filter(cat => cat.category !== 'S');
          
          return (
            <SpaceBetween size="l">
              {/* Row 1: Security - Full Width */}
              {securityCategory && (
                <CategoryCard
                  key={securityCategory.category}
                  category={securityCategory}
                  onClick={handleCategoryClick}
                />
              )}
              
              {/* Row 2: Other 4 Pillars */}
              <ColumnLayout columns={4} variant="default" minColumnWidth={200}>
                {otherCategories.map(cat => (
                  <CategoryCard
                    key={cat.category}
                    category={cat}
                    onClick={handleCategoryClick}
                  />
                ))}
              </ColumnLayout>
            </SpaceBetween>
          );
        })()}
      </div>
      
      {/* Content Enrichment Section */}
      <ContentEnrichment data={data} />
      
      {/* Service Cards */}
      <Container
        header={
          <Header variant="h2" description="Click on a service to view detailed findings">
            Services Overview
          </Header>
        }
      >
        {serviceStats.length === 0 ? (
          <EmptyState
            title="No services found"
            description="No service data available in this report."
            icon="search"
          />
        ) : (
          <ColumnLayout columns={2} variant="default" minColumnWidth={300}>
            {serviceStats.map(service => (
              <ServiceCard 
                key={service.serviceName} 
                service={service}
                onClick={handleServiceClick}
                onCategoryClick={handleCategoryClick}
              />
            ))}
          </ColumnLayout>
        )}
      </Container>
    </SpaceBetween>
  );
};

export default Dashboard;
