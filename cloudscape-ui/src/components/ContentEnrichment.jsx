import React, { useState, useEffect } from 'react';
import Container from '@cloudscape-design/components/container';
import Header from '@cloudscape-design/components/header';
import SpaceBetween from '@cloudscape-design/components/space-between';
import Tabs from '@cloudscape-design/components/tabs';
import Box from '@cloudscape-design/components/box';
import Badge from '@cloudscape-design/components/badge';
import Link from '@cloudscape-design/components/link';
import Spinner from '@cloudscape-design/components/spinner';
import Alert from '@cloudscape-design/components/alert';
import ColumnLayout from '@cloudscape-design/components/column-layout';
import Button from '@cloudscape-design/components/button';
import ExpandableSection from '@cloudscape-design/components/expandable-section';
import Grid from '@cloudscape-design/components/grid';
import LazyImage from './LazyImage';

/**
 * Content Enrichment Component for Cloudscape UI
 * Displays AWS best practices, security insights, and AI/ML content
 * based on detected services in the scan
 * 
 * Features responsive design for mobile, tablet, and desktop layouts
 * Includes touch-friendly interactions with appropriate target sizes
 */
const ContentEnrichment = ({ data }) => {
  const [contentData, setContentData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [expanded, setExpanded] = useState(false);
  const [viewportSize, setViewportSize] = useState('desktop');
  const [touchStartY, setTouchStartY] = useState(null);
  const [contentLoadingProgress, setContentLoadingProgress] = useState(0);
  const [isContentRendering, setIsContentRendering] = useState(false);

  // Touch interaction handlers
  const handleTouchStart = (e) => {
    setTouchStartY(e.touches[0].clientY);
  };

  const handleTouchMove = (e) => {
    if (!touchStartY) return;
    
    const touchEndY = e.touches[0].clientY;
    const deltaY = touchStartY - touchEndY;
    
    // Smooth scrolling behavior for touch devices
    if (Math.abs(deltaY) > 10) {
      e.currentTarget.style.scrollBehavior = 'smooth';
    }
  };

  const handleTouchEnd = () => {
    setTouchStartY(null);
  };

  // Enhanced button click handler with touch feedback
  const handleButtonClick = (callback, feedbackElement) => {
    return (e) => {
      // Add visual feedback for touch interactions
      if (feedbackElement && 'ontouchstart' in window) {
        feedbackElement.style.transform = 'scale(0.95)';
        feedbackElement.style.transition = 'transform 0.1s ease';
        
        setTimeout(() => {
          feedbackElement.style.transform = 'scale(1)';
        }, 100);
      }
      
      callback(e);
    };
  };

  // Responsive breakpoints
  const getViewportSize = () => {
    if (typeof window === 'undefined') return 'desktop';
    const width = window.innerWidth;
    if (width < 768) return 'mobile';
    if (width < 1024) return 'tablet';
    return 'desktop';
  };

  useEffect(() => {
    const handleResize = () => {
      setViewportSize(getViewportSize());
    };

    // Set initial viewport size
    setViewportSize(getViewportSize());

    // Add resize listener
    window.addEventListener('resize', handleResize);
    return () => window.removeEventListener('resize', handleResize);
  }, []);

  useEffect(() => {
    const loadContentEnrichmentData = () => {
      try {
        // Load content enrichment data from window object
        if (typeof window !== 'undefined' && window.__CONTENT_ENRICHMENT_DATA__) {
          setContentData(window.__CONTENT_ENRICHMENT_DATA__);
          setLoading(false);
        } else {
          // No content enrichment data available
          setContentData(null);
          setLoading(false);
        }
      } catch (err) {
        console.error('Error loading content enrichment data:', err);
        setError('Failed to load content enrichment data');
        setLoading(false);
      }
    };

    loadContentEnrichmentData();
  }, []);

  // Responsive configuration with touch-friendly settings
  const getResponsiveConfig = () => {
    switch (viewportSize) {
      case 'mobile':
        return {
          columns: 1,
          spacing: 's',
          itemsPerPage: 5,
          showFullMetadata: false,
          compactBadges: true,
          stackActions: true,
          touchTargetSize: 48, // Minimum 48px for touch targets
          scrollPadding: 16,
          tapHighlight: true
        };
      case 'tablet':
        return {
          columns: 2,
          spacing: 'm',
          itemsPerPage: 8,
          showFullMetadata: true,
          compactBadges: false,
          stackActions: false,
          touchTargetSize: 44, // Minimum 44px for touch targets
          scrollPadding: 20,
          tapHighlight: true
        };
      default: // desktop
        return {
          columns: 3,
          spacing: 'l',
          itemsPerPage: 12,
          showFullMetadata: true,
          compactBadges: false,
          stackActions: false,
          touchTargetSize: 32, // Smaller targets acceptable for mouse
          scrollPadding: 24,
          tapHighlight: false
        };
    }
  };

  const responsiveConfig = getResponsiveConfig();

  useEffect(() => {
    const loadContentEnrichmentData = () => {
      try {
        // Load content enrichment data from window object
        if (typeof window !== 'undefined' && window.__CONTENT_ENRICHMENT_DATA__) {
          setContentData(window.__CONTENT_ENRICHMENT_DATA__);
          setLoading(false);
        } else {
          // No content enrichment data available
          setContentData(null);
          setLoading(false);
        }
      } catch (err) {
        console.error('Error loading content enrichment data:', err);
        setError('Failed to load content enrichment data');
        setLoading(false);
      }
    };

    loadContentEnrichmentData();
  }, []);

  // Loading state
  if (loading) {
    return (
      <Container>
        <Box textAlign="center" padding="l">
          <Spinner size="normal" />
          <Box variant="p" padding={{ top: 's' }}>
            Loading AWS insights...
          </Box>
        </Box>
      </Container>
    );
  }

  // Error state
  if (error) {
    return (
      <Container>
        <Alert type="warning" header="Content Enrichment Unavailable">
          {error}
        </Alert>
      </Container>
    );
  }

  // No content enrichment data
  if (!contentData || !contentData.contentData) {
    return (
      <Container>
        <Alert type="info" header="Content Enrichment">
          Content enrichment is not available for this report. 
          Run the scan with <code>--beta 1</code> to include AWS best practices and security insights.
        </Alert>
      </Container>
    );
  }

  // Prepare tab data (removed Bookmarks tab)
  const categories = [
    {
      id: 'security-reliability',
      label: 'Security & Reliability',
      icon: '🛡️',
      items: contentData?.contentData?.['security-reliability'] || []
    },
    {
      id: 'ai-ml-genai',
      label: 'AI/ML & GenAI',
      icon: '🤖',
      items: contentData?.contentData?.['ai-ml-genai'] || []
    },
    {
      id: 'best-practices',
      label: 'Best Practices',
      icon: '⭐',
      items: contentData?.contentData?.['best-practices'] || []
    }
  ];

  const totalItems = categories.reduce((sum, cat) => sum + cat.items.length, 0);

  // Format detected services for display
  const detectedServices = contentData.metadata?.detectedServices || [];
  const fetchTime = contentData.metadata?.fetchTime ? 
    new Date(contentData.metadata.fetchTime).toLocaleString() : 'Unknown';

  // Summary information
  const summaryInfo = `Personalized AWS insights based on your detected services. ${totalItems} relevant items found.`;
  const metadataInfo = `Content fetched: ${fetchTime} | Detected services: ${detectedServices.join(', ')}`;

  // If not expanded, show responsive summary view with touch-friendly interactions
  if (!expanded) {
    return (
      <Container
        header={
          <Header
            variant="h2"
            description={summaryInfo}
            actions={
              <Button 
                variant="primary" 
                onClick={handleButtonClick(() => setExpanded(true))}
                size={viewportSize === 'mobile' ? 'normal' : 'normal'}
                style={{
                  minHeight: responsiveConfig.touchTargetSize,
                  minWidth: responsiveConfig.touchTargetSize,
                  padding: viewportSize === 'mobile' ? '12px 20px' : '8px 16px',
                  fontSize: viewportSize === 'mobile' ? '14px' : '14px',
                  borderRadius: '8px',
                  transition: 'all 0.2s ease'
                }}
                onTouchStart={(e) => {
                  if (responsiveConfig.tapHighlight) {
                    e.currentTarget.style.transform = 'scale(0.95)';
                  }
                }}
                onTouchEnd={(e) => {
                  if (responsiveConfig.tapHighlight) {
                    setTimeout(() => {
                      e.currentTarget.style.transform = 'scale(1)';
                    }, 150);
                  }
                }}
              >
                ▼ {viewportSize === 'mobile' ? 'View' : 'View Details'}
              </Button>
            }
          >
            {viewportSize === 'mobile' ? 
              '🔍 AWS Insights' : 
              '🔍 AWS Best Practices & Security Insights'
            }
          </Header>
        }
      >
        <SpaceBetween size="m">
          {responsiveConfig.showFullMetadata && (
            <Box variant="small" color="text-body-secondary">
              {metadataInfo}
            </Box>
          )}
          
          {/* Responsive summary badges with touch-friendly spacing */}
          <div style={{
            display: 'flex',
            flexDirection: viewportSize === 'mobile' ? 'column' : 'row',
            flexWrap: 'wrap',
            gap: viewportSize === 'mobile' ? '8px' : '12px'
          }}>
            {categories.map(category => (
              <Badge 
                key={category.id} 
                color="blue"
                style={{
                  minHeight: viewportSize === 'mobile' ? '36px' : '28px',
                  padding: viewportSize === 'mobile' ? '8px 16px' : '6px 12px',
                  fontSize: viewportSize === 'mobile' ? '13px' : '12px',
                  borderRadius: '6px'
                }}
              >
                {category.icon} {viewportSize === 'mobile' ? 
                  `${category.label.split(' ')[0]}: ${category.items.length}` : // Shortened on mobile
                  `${category.label}: ${category.items.length} items`
                }
              </Badge>
            ))}
          </div>
        </SpaceBetween>
      </Container>
    );
  }

  // Render content item with responsive design, touch-friendly interactions, and lazy-loaded images
  const renderContentItem = (item) => {
    const relevanceScore = Math.round((item.relevance_score || 0) * 100);
    const relevanceColor = relevanceScore >= 80 ? 'green' : relevanceScore >= 60 ? 'blue' : 'grey';
    
    // Extract images from content if available
    const contentImages = item.images || [];
    const hasImages = contentImages.length > 0;
    
    return (
      <Container 
        key={item.id}
        style={{
          // Touch-friendly container with proper spacing
          minHeight: responsiveConfig.touchTargetSize,
          cursor: responsiveConfig.tapHighlight ? 'pointer' : 'default',
          transition: 'all 0.2s ease',
          // Add touch feedback
          WebkitTapHighlightColor: responsiveConfig.tapHighlight ? 'rgba(0, 123, 255, 0.1)' : 'transparent'
        }}
        onTouchStart={handleTouchStart}
        onTouchMove={handleTouchMove}
        onTouchEnd={handleTouchEnd}
      >
        <SpaceBetween size="xs">
          {/* Images section with lazy loading */}
          {hasImages && (
            <div style={{ marginBottom: '12px' }}>
              {contentImages.slice(0, 1).map((image, index) => (
                <LazyImage
                  key={`${item.id}-image-${index}`}
                  src={image.src}
                  alt={image.alt || `Image for ${item.title}`}
                  responsiveSources={image.responsive_sources}
                  loadingStrategy={image.loading_strategy || (index === 0 ? 'eager' : 'lazy')}
                  rootMargin={image.intersection_observer_config?.root_margin || '50px'}
                  threshold={image.intersection_observer_config?.threshold || 0.1}
                  fallbackSrc={image.error_handling?.fallback_src}
                  maxRetries={image.error_handling?.retry_config?.max_retries || 2}
                  skeletonHeight={viewportSize === 'mobile' ? 150 : 200}
                  style={{
                    width: '100%',
                    maxHeight: viewportSize === 'mobile' ? '150px' : '200px',
                    objectFit: 'cover',
                    borderRadius: '6px'
                  }}
                  onLoad={(metrics) => {
                    // Track image load performance
                    console.debug(`Image loaded for ${item.title}:`, metrics);
                  }}
                  onError={(errorInfo) => {
                    console.warn(`Image failed for ${item.title}:`, errorInfo);
                  }}
                />
              ))}
              
              {/* Show additional images count if more than 1 */}
              {contentImages.length > 1 && (
                <Box variant="small" color="text-body-secondary" margin={{ top: 'xs' }}>
                  +{contentImages.length - 1} more images
                </Box>
              )}
            </div>
          )}

          {/* Title and badges - responsive layout with touch targets */}
          <div style={{ 
            display: 'flex', 
            flexDirection: responsiveConfig.stackActions ? 'column' : 'row',
            justifyContent: 'space-between', 
            alignItems: responsiveConfig.stackActions ? 'flex-start' : 'flex-start',
            gap: responsiveConfig.stackActions ? '8px' : '16px'
          }}>
            <Box variant="h4" margin={{ bottom: 'xs' }}>
              <Link 
                external 
                href={item.url} 
                target="_blank"
                // Security attributes for external links
                rel="noopener noreferrer nofollow"
                style={{
                  fontSize: viewportSize === 'mobile' ? '14px' : '16px',
                  lineHeight: viewportSize === 'mobile' ? '1.4' : '1.5',
                  // Ensure touch target is large enough
                  minHeight: responsiveConfig.touchTargetSize,
                  display: 'inline-block',
                  padding: viewportSize === 'mobile' ? '8px 0' : '4px 0',
                  textDecoration: 'none',
                  borderRadius: '4px',
                  // Touch feedback
                  transition: 'background-color 0.15s ease'
                }}
                onTouchStart={(e) => {
                  if (responsiveConfig.tapHighlight) {
                    e.currentTarget.style.backgroundColor = 'rgba(0, 123, 255, 0.05)';
                  }
                }}
                onTouchEnd={(e) => {
                  if (responsiveConfig.tapHighlight) {
                    setTimeout(() => {
                      e.currentTarget.style.backgroundColor = 'transparent';
                    }, 150);
                  }
                }}
                // Additional security validation
                onClick={(e) => {
                  // Validate URL before opening (security check)
                  try {
                    const url = new URL(item.url);
                    // Only allow HTTPS URLs from trusted domains
                    if (url.protocol !== 'https:') {
                      e.preventDefault();
                      console.warn('Blocked non-HTTPS URL:', item.url);
                      return false;
                    }
                    
                    // Check against trusted domains (should match Python validation)
                    const trustedDomains = ['aws.amazon.com', 'amazon.com', 'docs.aws.amazon.com'];
                    const domain = url.hostname.toLowerCase();
                    const isTrusted = trustedDomains.some(trusted => 
                      domain === trusted || domain.endsWith(`.${trusted}`)
                    );
                    
                    if (!isTrusted) {
                      e.preventDefault();
                      console.warn('Blocked URL from untrusted domain:', item.url);
                      return false;
                    }
                  } catch (error) {
                    e.preventDefault();
                    console.warn('Blocked invalid URL:', item.url);
                    return false;
                  }
                }}
              >
                {item.title}
              </Link>
            </Box>
            
            {/* Responsive badge layout with touch-friendly spacing */}
            <div style={{
              display: 'flex',
              flexWrap: 'wrap',
              gap: viewportSize === 'mobile' ? '6px' : '4px',
              alignItems: 'center',
              minHeight: responsiveConfig.touchTargetSize / 2 // Ensure adequate touch area
            }}>
              {item.is_new && (
                <Badge 
                  color="green"
                  style={{
                    minHeight: viewportSize === 'mobile' ? '32px' : '24px',
                    padding: viewportSize === 'mobile' ? '6px 12px' : '4px 8px'
                  }}
                >
                  New
                </Badge>
              )}
              {item.is_archived && (
                <Badge 
                  color="grey"
                  style={{
                    minHeight: viewportSize === 'mobile' ? '32px' : '24px',
                    padding: viewportSize === 'mobile' ? '6px 12px' : '4px 8px'
                  }}
                >
                  Archived
                </Badge>
              )}
              {item.difficulty && (
                <Badge 
                  color="blue"
                  style={{
                    minHeight: viewportSize === 'mobile' ? '32px' : '24px',
                    padding: viewportSize === 'mobile' ? '6px 12px' : '4px 8px'
                  }}
                >
                  {responsiveConfig.compactBadges ? 
                    item.difficulty.charAt(0) : // Show only first letter on mobile
                    item.difficulty
                  }
                </Badge>
              )}
              <Badge 
                color={relevanceColor}
                style={{
                  minHeight: viewportSize === 'mobile' ? '32px' : '24px',
                  padding: viewportSize === 'mobile' ? '6px 12px' : '4px 8px'
                }}
              >
                {responsiveConfig.compactBadges ? 
                  `${relevanceScore}%` : 
                  `${relevanceScore}% match`
                }
              </Badge>
            </div>
          </div>
          
          {/* Summary with responsive text size and touch-friendly padding */}
          <Box 
            variant="p" 
            color="text-body-secondary"
            style={{
              fontSize: viewportSize === 'mobile' ? '13px' : '14px',
              lineHeight: '1.5',
              padding: viewportSize === 'mobile' ? '8px 0' : '4px 0'
            }}
          >
            {viewportSize === 'mobile' && item.summary.length > 120 ? 
              `${item.summary.substring(0, 120)}...` : 
              item.summary
            }
          </Box>
          
          {/* Metadata and tags - responsive layout with touch spacing */}
          <div style={{ 
            display: 'flex', 
            flexDirection: responsiveConfig.stackActions ? 'column' : 'row',
            justifyContent: 'space-between', 
            alignItems: responsiveConfig.stackActions ? 'flex-start' : 'center',
            gap: responsiveConfig.stackActions ? '8px' : '16px',
            paddingTop: '8px'
          }}>
            {responsiveConfig.showFullMetadata && (
              <Box 
                variant="small" 
                color="text-body-secondary"
                style={{ 
                  fontSize: viewportSize === 'mobile' ? '11px' : '12px',
                  minHeight: viewportSize === 'mobile' ? '24px' : 'auto',
                  display: 'flex',
                  alignItems: 'center'
                }}
              >
                📅 {new Date(item.publish_date).toLocaleDateString()} | 
                🏷️ {viewportSize === 'mobile' ? 
                  item.source.split(' ')[0] : // Show only first word on mobile
                  item.source
                }
              </Box>
            )}
            
            {item.tags && item.tags.length > 0 && (
              <div style={{
                display: 'flex',
                flexWrap: 'wrap',
                gap: viewportSize === 'mobile' ? '6px' : '4px',
                minHeight: viewportSize === 'mobile' ? '32px' : 'auto',
                alignItems: 'center'
              }}>
                {item.tags.slice(0, viewportSize === 'mobile' ? 2 : 3).map(tag => (
                  <Badge 
                    key={tag} 
                    color="grey"
                    style={{ 
                      fontSize: viewportSize === 'mobile' ? '10px' : '11px',
                      minHeight: viewportSize === 'mobile' ? '28px' : '20px',
                      padding: viewportSize === 'mobile' ? '4px 8px' : '2px 6px'
                    }}
                  >
                    {tag}
                  </Badge>
                ))}
                {item.tags.length > (viewportSize === 'mobile' ? 2 : 3) && (
                  <Badge 
                    color="grey"
                    style={{ 
                      minHeight: viewportSize === 'mobile' ? '28px' : '20px',
                      padding: viewportSize === 'mobile' ? '4px 8px' : '2px 6px'
                    }}
                  >
                    +{item.tags.length - (viewportSize === 'mobile' ? 2 : 3)}
                  </Badge>
                )}
              </div>
            )}
          </div>
        </SpaceBetween>
      </Container>
    );
  };

  // Render category content with responsive grid and touch-friendly interactions
  const renderCategoryContent = (category) => {
    if (category.items.length === 0) {
      return (
        <Box textAlign="center" padding="l">
          <Box variant="h3" color="text-body-secondary">
            No content available
          </Box>
          <Box variant="p" color="text-body-secondary">
            No {category.label.toLowerCase()} content found for your detected services.
          </Box>
        </Box>
      );
    }

    // Use responsive grid layout with touch-friendly scrolling
    if (viewportSize === 'mobile') {
      // Mobile: Single column, stacked layout with smooth scrolling
      return (
        <div
          style={{
            overflowY: 'auto',
            maxHeight: '70vh',
            scrollBehavior: 'smooth',
            padding: `0 ${responsiveConfig.scrollPadding}px`,
            // Add momentum scrolling for iOS
            WebkitOverflowScrolling: 'touch'
          }}
          onTouchStart={handleTouchStart}
          onTouchMove={handleTouchMove}
          onTouchEnd={handleTouchEnd}
        >
          <SpaceBetween size={responsiveConfig.spacing}>
            {category.items.slice(0, responsiveConfig.itemsPerPage).map(renderContentItem)}
            {category.items.length > responsiveConfig.itemsPerPage && (
              <Box textAlign="center" padding="s">
                <Button 
                  variant="link"
                  style={{
                    minHeight: responsiveConfig.touchTargetSize,
                    padding: '12px 24px',
                    fontSize: '14px',
                    borderRadius: '8px',
                    transition: 'all 0.2s ease'
                  }}
                  onTouchStart={(e) => {
                    e.currentTarget.style.backgroundColor = 'rgba(0, 123, 255, 0.1)';
                  }}
                  onTouchEnd={(e) => {
                    setTimeout(() => {
                      e.currentTarget.style.backgroundColor = 'transparent';
                    }, 150);
                  }}
                >
                  Load more ({category.items.length - responsiveConfig.itemsPerPage} remaining)
                </Button>
              </Box>
            )}
          </SpaceBetween>
        </div>
      );
    } else {
      // Tablet and Desktop: Use Grid component with touch-friendly scrolling
      const gridItems = category.items.slice(0, responsiveConfig.itemsPerPage).map(item => ({
        content: renderContentItem(item)
      }));

      return (
        <div
          style={{
            overflowY: 'auto',
            maxHeight: '80vh',
            scrollBehavior: 'smooth',
            padding: `0 ${responsiveConfig.scrollPadding}px`,
            WebkitOverflowScrolling: 'touch'
          }}
        >
          <SpaceBetween size={responsiveConfig.spacing}>
            <Grid
              gridDefinition={
                viewportSize === 'tablet' ? 
                  [{ colspan: 6 }, { colspan: 6 }] : // 2 columns on tablet
                  [{ colspan: 4 }, { colspan: 4 }, { colspan: 4 }] // 3 columns on desktop
              }
            >
              {gridItems.map((gridItem, index) => (
                <div key={index}>
                  {gridItem.content}
                </div>
              ))}
            </Grid>
            
            {category.items.length > responsiveConfig.itemsPerPage && (
              <Box textAlign="center" padding="s">
                <Button 
                  variant="link"
                  style={{
                    minHeight: responsiveConfig.touchTargetSize,
                    padding: viewportSize === 'tablet' ? '10px 20px' : '8px 16px',
                    fontSize: '14px',
                    borderRadius: '6px',
                    transition: 'all 0.2s ease'
                  }}
                  onTouchStart={(e) => {
                    if (responsiveConfig.tapHighlight) {
                      e.currentTarget.style.backgroundColor = 'rgba(0, 123, 255, 0.1)';
                    }
                  }}
                  onTouchEnd={(e) => {
                    if (responsiveConfig.tapHighlight) {
                      setTimeout(() => {
                        e.currentTarget.style.backgroundColor = 'transparent';
                      }, 150);
                    }
                  }}
                >
                  Load more ({category.items.length - responsiveConfig.itemsPerPage} remaining)
                </Button>
              </Box>
            )}
          </SpaceBetween>
        </div>
      );
    }
  };

  // Prepare responsive tabs for Cloudscape Tabs component
  const tabs = categories.map(category => ({
    id: category.id,
    label: (
      <div style={{
        display: 'flex',
        alignItems: 'center',
        gap: '4px',
        fontSize: viewportSize === 'mobile' ? '13px' : '14px'
      }}>
        <span>
          {category.icon} {viewportSize === 'mobile' ? 
            category.label.split(' ')[0] : // Show only first word on mobile
            category.label
          }
        </span>
        <Badge color="grey">{category.items.length}</Badge>
      </div>
    ),
    content: renderCategoryContent(category)
  }));

  // Responsive expanded view with full content and touch-friendly interactions
  return (
    <Container
      header={
        <Header
          variant="h2"
          description={viewportSize === 'mobile' ? 
            `${totalItems} relevant items found.` : 
            summaryInfo
          }
          actions={
            <Button 
              variant="normal" 
              onClick={handleButtonClick(() => setExpanded(false))}
              size={viewportSize === 'mobile' ? 'normal' : 'normal'}
              style={{
                minHeight: responsiveConfig.touchTargetSize,
                minWidth: responsiveConfig.touchTargetSize,
                padding: viewportSize === 'mobile' ? '12px 20px' : '8px 16px',
                fontSize: viewportSize === 'mobile' ? '14px' : '14px',
                borderRadius: '8px',
                transition: 'all 0.2s ease'
              }}
              onTouchStart={(e) => {
                if (responsiveConfig.tapHighlight) {
                  e.currentTarget.style.transform = 'scale(0.95)';
                }
              }}
              onTouchEnd={(e) => {
                if (responsiveConfig.tapHighlight) {
                  setTimeout(() => {
                    e.currentTarget.style.transform = 'scale(1)';
                  }, 150);
                }
              }}
            >
              ▲ {viewportSize === 'mobile' ? 'Hide' : 'Collapse'}
            </Button>
          }
        >
          {viewportSize === 'mobile' ? 
            '🔍 AWS Insights' : 
            '🔍 AWS Best Practices & Security Insights'
          }
        </Header>
      }
    >
      <SpaceBetween size={responsiveConfig.spacing}>
        {/* Responsive metadata info */}
        {responsiveConfig.showFullMetadata && (
          <Box 
            variant="small" 
            color="text-body-secondary"
            style={{ 
              fontSize: viewportSize === 'mobile' ? '11px' : '12px',
              padding: viewportSize === 'mobile' ? '8px 0' : '4px 0'
            }}
          >
            {metadataInfo}
          </Box>
        )}
        
        {/* Responsive content tabs with touch-friendly scrolling */}
        <div style={{
          // Add horizontal scrolling for tabs on mobile if needed
          overflowX: viewportSize === 'mobile' ? 'auto' : 'visible',
          WebkitOverflowScrolling: 'touch',
          scrollBehavior: 'smooth'
        }}>
          <Tabs 
            tabs={tabs}
            variant={viewportSize === 'mobile' ? 'default' : 'default'}
          />
        </div>
      </SpaceBetween>
    </Container>
  );
};

export default ContentEnrichment;