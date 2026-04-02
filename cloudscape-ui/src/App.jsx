import React, { useState, useEffect } from 'react';
import { HashRouter, Routes, Route } from 'react-router-dom';
import AppLayout from '@cloudscape-design/components/app-layout';
import Alert from '@cloudscape-design/components/alert';
import Spinner from '@cloudscape-design/components/spinner';
import Box from '@cloudscape-design/components/box';
import '@cloudscape-design/global-styles/index.css';

import ServiceScreenerTopNav from './components/TopNavigation';
import ServiceScreenerSideNav from './components/SideNavigation';
import Dashboard from './components/Dashboard';
import ServiceDetail from './components/ServiceDetail';
import FrameworkDetail from './components/FrameworkDetail';
import FrameworkOverview from './components/FrameworkOverview';
import CustomPage from './components/CustomPage';
import GuardDutyDetail from './components/GuardDutyDetail';
import SuppressionModal from './components/SuppressionModal';
import SkipToContent from './components/SkipToContent';
import ErrorBoundary from './components/ErrorBoundary';

import { 
  loadReportData, 
  getAccountId, 
  discoverAccounts,
  switchAccount,
  getServices, 
  getFrameworks,
  getCustomPages,
  hasSuppressions 
} from './utils/dataLoader';

/**
 * Main App component
 * Handles data loading, routing, and layout
 */
function App() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [accountId, setAccountId] = useState('Unknown');
  const [availableAccounts, setAvailableAccounts] = useState([]);
  const [services, setServices] = useState([]);
  const [frameworks, setFrameworks] = useState([]);
  const [customPages, setCustomPages] = useState([]);
  const [showSuppressionModal, setShowSuppressionModal] = useState(false);
  
  // Load data on mount
  useEffect(() => {
    const loadData = async () => {
      try {
        const reportData = await loadReportData();
        
        if (!reportData) {
          setError('Failed to load report data. Please ensure the file is not corrupted.');
          setLoading(false);
          return;
        }
        
        setData(reportData);
        setAccountId(getAccountId(reportData));
        setAvailableAccounts(discoverAccounts());
        setServices(getServices(reportData));
        setFrameworks(getFrameworks(reportData));
        setCustomPages(getCustomPages(reportData));
        setLoading(false);
      } catch (err) {
        console.error('Error loading data:', err);
        setError(`Error loading report data: ${err.message}`);
        setLoading(false);
      }
    };
    
    loadData();
  }, []);
  
  // Update account ID when URL changes (for account switching)
  useEffect(() => {
    const updateAccountId = () => {
      if (data) {
        const newAccountId = getAccountId(data);
        setAccountId(newAccountId);
      }
    };
    
    // Listen for URL changes (including hash changes)
    window.addEventListener('popstate', updateAccountId);
    window.addEventListener('hashchange', updateAccountId);
    
    return () => {
      window.removeEventListener('popstate', updateAccountId);
      window.removeEventListener('hashchange', updateAccountId);
    };
  }, [data]);
  
  // Handle suppression modal
  const handleSuppressionClick = () => {
    setShowSuppressionModal(true);
  };
  
  // Loading state
  if (loading) {
    return (
      <Box textAlign="center" padding={{ vertical: 'xxl' }}>
        <Spinner size="large" />
        <Box variant="h2" padding={{ top: 'm' }}>
          Loading Service Screener Report...
        </Box>
      </Box>
    );
  }
  
  // Error state
  if (error || !data) {
    return (
      <Box padding="l">
        <Alert
          type="error"
          header="Data Loading Failed"
        >
          <Box variant="p">
            {error || 'Unable to load report data. Please check:'}
          </Box>
          <ul>
            <li>File is not corrupted</li>
            <li>Browser console for errors</li>
            <li>File:// protocol is supported in your browser</li>
          </ul>
          <Box variant="p">
            If the problem persists, please try opening the file in a different browser 
            or contact support.
          </Box>
        </Alert>
      </Box>
    );
  }
  
  // Main app with routing
  return (
    <ErrorBoundary>
      <HashRouter>
        <SkipToContent />
        <ServiceScreenerTopNav 
          accountId={accountId}
          availableAccounts={availableAccounts}
          onAccountSwitch={switchAccount}
          hasSuppressions={hasSuppressions(data)}
          onSuppressionClick={handleSuppressionClick}
        />
        
        <AppLayout
          navigation={
            <ServiceScreenerSideNav 
              services={services}
              frameworks={frameworks}
              customPages={customPages}
              data={data}
            />
          }
          content={
            <div id="main-content" tabIndex="-1">
              <Routes>
                <Route path="/" element={<Dashboard data={data} />} />
                <Route 
                  path="/service/guardduty" 
                  element={
                    data?.guardduty?.detail ? (
                      <GuardDutyDetail data={data} />
                    ) : (
                      <ServiceDetail data={data} />
                    )
                  } 
                />
                <Route path="/service/:serviceName" element={<ServiceDetail data={data} />} />
                <Route path="/framework/overview" element={<FrameworkOverview data={data} frameworks={frameworks} />} />
                <Route path="/framework/:frameworkName" element={<FrameworkDetail data={data} />} />
                <Route path="/page/:pageName" element={<CustomPage data={data} />} />
              </Routes>
            </div>
          }
          toolsHide={true}
          navigationWidth={280}
          contentType="default"
          ariaLabels={{
            navigation: 'Side navigation',
            navigationClose: 'Close navigation',
            navigationToggle: 'Open navigation',
            notifications: 'Notifications',
            tools: 'Help panel',
            toolsClose: 'Close help panel',
            toolsToggle: 'Open help panel'
          }}
        />
        
        {/* Suppression Modal */}
        <SuppressionModal
          data={data}
          visible={showSuppressionModal}
          onDismiss={() => setShowSuppressionModal(false)}
        />
      </HashRouter>
    </ErrorBoundary>
  );
}

export default App;
