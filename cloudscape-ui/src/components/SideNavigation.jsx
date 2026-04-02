import React from 'react';
import SideNavigation from '@cloudscape-design/components/side-navigation';
import { useLocation, useNavigate } from 'react-router-dom';
import { formatServiceName } from '../utils/formatters';

/**
 * SideNavigation component for Service Screener
 * Displays navigation links for Dashboard, Services, Pages, and Frameworks
 */
const ServiceScreenerSideNav = ({ services = [], frameworks = [], customPages = [], data = null }) => {
  const location = useLocation();
  const navigate = useNavigate();
  
  // Build navigation items
  const items = [
    {
      type: 'link',
      text: 'Dashboard',
      href: '#/'
    },
    {
      type: 'divider'
    }
  ];
  
  // Add custom pages section if custom pages exist (MOVED TO FIRST)
  const customPagesFromData = customPages || [];
  
  // Always include standard custom pages that should be available
  const standardCustomPages = ['findings', 'modernize', 'ta', 'coh'];
  const allCustomPages = [...new Set([...customPagesFromData, ...standardCustomPages])];
  
  if (allCustomPages.length > 0) {
    // Sort custom pages alphabetically by display name
    const sortedCustomPages = allCustomPages.sort((a, b) => {
      const nameA = a === 'ta' ? 'Trusted Advisor' : 
                    a === 'coh' ? 'Cost Optimization Hub' :
                    a === 'findings' ? 'Cross-Service Findings' :
                    a === 'modernize' ? 'Modernization Recommendations' :
                    a.charAt(0).toUpperCase() + a.slice(1);
      const nameB = b === 'ta' ? 'Trusted Advisor' : 
                    b === 'coh' ? 'Cost Optimization Hub' :
                    b === 'findings' ? 'Cross-Service Findings' :
                    b === 'modernize' ? 'Modernization Recommendations' :
                    b.charAt(0).toUpperCase() + b.slice(1);
      return nameA.localeCompare(nameB);
    });
    
    items.push({
      type: 'section',
      text: 'Pages',
      items: sortedCustomPages.map(page => {
        // Format page name with proper titles
        const pageName = page === 'ta' ? 'Trusted Advisor' : 
                        page === 'coh' ? 'Cost Optimization Hub' :
                        page === 'findings' ? 'Cross-Service Findings' :
                        page === 'modernize' ? 'Modernization Recommendations' :
                        page.charAt(0).toUpperCase() + page.slice(1);
        return {
          type: 'link',
          text: pageName,
          href: `#/page/${page.toLowerCase()}`
        };
      })
    });
    
    items.push({
      type: 'divider'
    });
  }
  
  // Add frameworks section if frameworks exist (MOVED TO SECOND)
  if (frameworks.length > 0) {
    // Sort frameworks alphabetically
    const sortedFrameworks = [...frameworks].sort((a, b) => {
      const nameA = a.replace('framework_', '').toUpperCase();
      const nameB = b.replace('framework_', '').toUpperCase();
      return nameA.localeCompare(nameB);
    });
    
    items.push({
      type: 'section',
      text: 'Frameworks',
      items: [
        {
          type: 'link',
          text: '📊 Overview',
          href: '#/framework/overview'
        },
        ...sortedFrameworks.map(framework => {
          const frameworkName = framework.replace('framework_', '');
          return {
            type: 'link',
            text: frameworkName.toUpperCase(),
            href: `#/framework/${frameworkName.toLowerCase()}`
          };
        })
      ]
    });
    
    items.push({
      type: 'divider'
    });
  }
  
  // Add services section (MOVED TO THIRD)
  if (services.length > 0) {
    // Sort services alphabetically
    const sortedServices = [...services].sort((a, b) => {
      return formatServiceName(a).localeCompare(formatServiceName(b));
    });
    
    items.push({
      type: 'section',
      text: 'Services',
      items: sortedServices.map(service => {
        // Special handling for GuardDuty - single consolidated view for all regions
        if (service.toLowerCase() === 'guardduty') {
          return {
            type: 'link',
            text: formatServiceName(service),
            href: `#/service/guardduty`
          };
        }
        
        // Regular service link
        return {
          type: 'link',
          text: formatServiceName(service),
          href: `#/service/${service.toLowerCase()}`
        };
      })
    });
  }
  
  // Add "Others" section with GitHub star link
  items.push({
    type: 'divider'
  });
  
  items.push({
    type: 'section',
    text: 'Others',
    items: [
      {
        type: 'link',
        text: '⭐ Give us a Star ⭐',
        href: 'https://github.com/aws-samples/service-screener-v2',
        external: true
      },
      {
        type: 'link',
        text: 'Raise Issues',
        href: 'https://github.com/aws-samples/service-screener-v2/issues',
        external: true
      }
    ]
  });
  
  // Determine active href based on current location
  const getActiveHref = () => {
    const hash = location.hash || window.location.hash;
    
    // Remove leading # if present
    const path = hash.startsWith('#') ? hash : `#${hash}`;
    
    // If at root, return dashboard
    if (path === '#' || path === '#/') {
      return '#/';
    }
    
    return path;
  };
  
  const handleFollow = (event) => {
    event.preventDefault();
    
    const href = event.detail.href;
    
    // Handle external links
    if (href.startsWith('http')) {
      window.open(href, '_blank', 'noopener,noreferrer');
      return;
    }
    
    // Handle internal navigation
    // Extract path from href (remove #)
    const path = href.startsWith('#') ? href.substring(1) : href;
    
    navigate(path);
  };
  
  return (
    <SideNavigation
      activeHref={getActiveHref()}
      items={items}
      onFollow={handleFollow}
      header={{
        text: 'Navigation',
        href: '#/'
      }}
    />
  );
};

export default ServiceScreenerSideNav;
