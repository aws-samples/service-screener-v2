import React from 'react';
import Container from '@cloudscape-design/components/container';
import Header from '@cloudscape-design/components/header';
import SpaceBetween from '@cloudscape-design/components/space-between';
import Box from '@cloudscape-design/components/box';
import ColumnLayout from '@cloudscape-design/components/column-layout';
import { formatCategory, getCategoryColor } from '../utils/formatters';

/**
 * CategoryCard component - displays category breakdown with severity icons
 * Matches the legacy AdminLTE dashboard category cards
 */
const CategoryCard = ({ category, onClick }) => {
  const { category: categoryCode, total, high, medium, low, informational } = category;
  
  const handleCardClick = () => {
    onClick(categoryCode);
  };
  
  const handleSeverityClick = (severity, event) => {
    event.stopPropagation(); // Prevent card click
    onClick(categoryCode, severity);
  };
  
  // Get category display info
  const categoryName = formatCategory(categoryCode);
  const categoryColor = getCategoryColor(categoryCode);
  
  // Determine if this is the Security card (should be larger/featured)
  const isSecurity = categoryCode === 'S';
  
  return (
    <Container>
      <div 
        onClick={handleCardClick}
        style={{ 
          cursor: 'pointer',
          transition: 'all 0.2s ease',
        }}
        role="button"
        tabIndex={0}
        onKeyPress={(e) => {
          if (e.key === 'Enter' || e.key === ' ') {
            handleCardClick();
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
        <SpaceBetween size="m">
          {/* Category Header */}
          <div style={{ textAlign: 'center' }}>
            <Box 
              fontSize={isSecurity ? "display-l" : "heading-xl"} 
              fontWeight="bold"
              color={categoryColor === 'red' ? 'text-status-error' : 
                     categoryColor === 'blue' ? 'text-status-info' :
                     categoryColor === 'green' ? 'text-status-success' :
                     categoryColor === 'orange' ? 'text-status-warning' : 'inherit'}
            >
              {total}
            </Box>
            <Box 
              variant={isSecurity ? "h2" : "h3"} 
              color="text-body-secondary"
              margin={{ top: 'xs' }}
            >
              {categoryName}
            </Box>
          </div>
          
          {/* Severity Breakdown Icons */}
          {total > 0 && (
            <div style={{ 
              display: 'flex', 
              justifyContent: 'center', 
              gap: '12px',
              paddingTop: '8px',
              borderTop: '1px solid #e9ebed'
            }}>
              {/* High Severity */}
              {high > 0 && (
                <div 
                  onClick={(e) => handleSeverityClick('H', e)}
                  style={{ 
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '4px',
                    padding: '4px 8px',
                    borderRadius: '4px',
                    transition: 'background-color 0.2s ease'
                  }}
                  onMouseEnter={(e) => {
                    e.currentTarget.style.backgroundColor = '#ffeaea';
                  }}
                  onMouseLeave={(e) => {
                    e.currentTarget.style.backgroundColor = 'transparent';
                  }}
                  title={`${high} High severity findings`}
                >
                  <span style={{ fontSize: '16px' }}>🚫</span>
                  <Box fontSize="body-s" fontWeight="bold" color="text-status-error">
                    {high}
                  </Box>
                </div>
              )}
              
              {/* Medium Severity */}
              {medium > 0 && (
                <div 
                  onClick={(e) => handleSeverityClick('M', e)}
                  style={{ 
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '4px',
                    padding: '4px 8px',
                    borderRadius: '4px',
                    transition: 'background-color 0.2s ease'
                  }}
                  onMouseEnter={(e) => {
                    e.currentTarget.style.backgroundColor = '#fff8e1';
                  }}
                  onMouseLeave={(e) => {
                    e.currentTarget.style.backgroundColor = 'transparent';
                  }}
                  title={`${medium} Medium severity findings`}
                >
                  <span style={{ fontSize: '16px' }}>⚠️</span>
                  <Box fontSize="body-s" fontWeight="bold" color="text-status-warning">
                    {medium}
                  </Box>
                </div>
              )}
              
              {/* Low Severity */}
              {low > 0 && (
                <div 
                  onClick={(e) => handleSeverityClick('L', e)}
                  style={{ 
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '4px',
                    padding: '4px 8px',
                    borderRadius: '4px',
                    transition: 'background-color 0.2s ease'
                  }}
                  onMouseEnter={(e) => {
                    e.currentTarget.style.backgroundColor = '#e3f2fd';
                  }}
                  onMouseLeave={(e) => {
                    e.currentTarget.style.backgroundColor = 'transparent';
                  }}
                  title={`${low} Low severity findings`}
                >
                  <span style={{ fontSize: '16px' }}>👁️</span>
                  <Box fontSize="body-s" fontWeight="bold" color="text-status-info">
                    {low}
                  </Box>
                </div>
              )}
              
              {/* Informational */}
              {informational > 0 && (
                <div 
                  onClick={(e) => handleSeverityClick('I', e)}
                  style={{ 
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '4px',
                    padding: '4px 8px',
                    borderRadius: '4px',
                    transition: 'background-color 0.2s ease'
                  }}
                  onMouseEnter={(e) => {
                    e.currentTarget.style.backgroundColor = '#f5f5f5';
                  }}
                  onMouseLeave={(e) => {
                    e.currentTarget.style.backgroundColor = 'transparent';
                  }}
                  title={`${informational} Informational findings`}
                >
                  <span style={{ fontSize: '16px' }}>ℹ️</span>
                  <Box fontSize="body-s" fontWeight="bold" color="text-body-secondary">
                    {informational}
                  </Box>
                </div>
              )}
            </div>
          )}
          
          {/* Empty State */}
          {total === 0 && (
            <div style={{ 
              textAlign: 'center',
              padding: '8px',
              borderTop: '1px solid #e9ebed'
            }}>
              <Box fontSize="body-s" color="text-status-success">
                ✅ No findings
              </Box>
            </div>
          )}
        </SpaceBetween>
      </div>
    </Container>
  );
};

export default CategoryCard;