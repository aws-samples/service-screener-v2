import React, { useState } from 'react';
import Container from '@cloudscape-design/components/container';
import Header from '@cloudscape-design/components/header';
import SpaceBetween from '@cloudscape-design/components/space-between';
import Box from '@cloudscape-design/components/box';
import ColumnLayout from '@cloudscape-design/components/column-layout';
import Badge from '@cloudscape-design/components/badge';
import Button from '@cloudscape-design/components/button';
import ButtonDropdown from '@cloudscape-design/components/button-dropdown';
import StatusIndicator from '@cloudscape-design/components/status-indicator';
import ProgressBar from '@cloudscape-design/components/progress-bar';
import Alert from '@cloudscape-design/components/alert';
import Tabs from '@cloudscape-design/components/tabs';
import Table from '@cloudscape-design/components/table';
import TextContent from '@cloudscape-design/components/text-content';
import ExpandableSection from '@cloudscape-design/components/expandable-section';
import Link from '@cloudscape-design/components/link';
import Modal from '@cloudscape-design/components/modal';
import Textarea from '@cloudscape-design/components/textarea';
import FormField from '@cloudscape-design/components/form-field';

/**
 * RecommendationDetails component
 * Detailed view of a cost optimization recommendation with implementation tracking
 */
const RecommendationDetails = ({ 
  recommendation, 
  onStatusUpdate, 
  onAddNote, 
  onUpdateProgress,
  onExport,
  relatedFindings = [],
  implementationHistory = []
}) => {
  const [activeTabId, setActiveTabId] = useState('overview');
  const [showNotesModal, setShowNotesModal] = useState(false);
  const [newNote, setNewNote] = useState('');
  const [showProgressModal, setShowProgressModal] = useState(false);
  const [progressUpdate, setProgressUpdate] = useState('');

  if (!recommendation) {
    return (
      <Container>
        <Alert type="info">
          No recommendation selected. Please select a recommendation to view details.
        </Alert>
      </Container>
    );
  }

  const handleStatusChange = (newStatus) => {
    if (onStatusUpdate) {
      onStatusUpdate(recommendation.id, newStatus);
    }
  };

  const handleAddNote = () => {
    if (onAddNote && newNote.trim()) {
      onAddNote(recommendation.id, newNote.trim());
      setNewNote('');
      setShowNotesModal(false);
    }
  };

  const handleProgressUpdate = () => {
    if (onUpdateProgress && progressUpdate.trim()) {
      onUpdateProgress(recommendation.id, progressUpdate.trim());
      setProgressUpdate('');
      setShowProgressModal(false);
    }
  };

  const getStatusConfig = (status) => {
    const configs = {
      'new': { type: 'pending', color: 'blue', label: 'New' },
      'in_progress': { type: 'in-progress', color: 'blue', label: 'In Progress' },
      'completed': { type: 'success', color: 'green', label: 'Completed' },
      'dismissed': { type: 'stopped', color: 'grey', label: 'Dismissed' },
      'failed': { type: 'error', color: 'red', label: 'Failed' }
    };
    return configs[status] || configs['new'];
  };

  const getPriorityConfig = (priority) => {
    const configs = {
      'high': { color: 'red', icon: '🔴', urgency: 'Immediate attention required' },
      'medium': { color: 'blue', icon: '🟡', urgency: 'Should be addressed soon' },
      'low': { color: 'green', icon: '🟢', urgency: 'Can be scheduled for later' }
    };
    return configs[priority] || configs['medium'];
  };

  const getEffortConfig = (effort) => {
    const configs = {
      'low': { color: 'green', progress: 25, description: 'Quick implementation, minimal resources' },
      'medium': { color: 'blue', progress: 50, description: 'Moderate effort, some planning required' },
      'high': { color: 'red', progress: 75, description: 'Significant effort, careful planning needed' }
    };
    return configs[effort] || configs['medium'];
  };

  const statusConfig = getStatusConfig(recommendation.status);
  const priorityConfig = getPriorityConfig(recommendation.priority_level);
  const effortConfig = getEffortConfig(recommendation.implementation_effort);

  const tabs = [
    {
      id: 'overview',
      label: 'Overview',
      content: renderOverviewTab()
    },
    {
      id: 'implementation',
      label: 'Implementation',
      content: renderImplementationTab()
    },
    {
      id: 'resources',
      label: 'Affected Resources',
      content: renderResourcesTab()
    },
    {
      id: 'analysis',
      label: 'Risk Analysis',
      content: renderAnalysisTab()
    },
    {
      id: 'tracking',
      label: 'Progress Tracking',
      content: renderTrackingTab()
    }
  ];

  return (
    <SpaceBetween size="l">
      {/* Header with Actions */}
      <Container
        header={
          <Header
            variant="h1"
            description={recommendation.description || 'Cost optimization recommendation details'}
            actions={
              <SpaceBetween size="xs" direction="horizontal">
                <ButtonDropdown
                  variant="normal"
                  items={[
                    {
                      id: 'mark_in_progress',
                      text: 'Mark In Progress',
                      disabled: recommendation.status === 'in_progress'
                    },
                    {
                      id: 'mark_completed',
                      text: 'Mark Completed',
                      disabled: recommendation.status === 'completed'
                    },
                    {
                      id: 'dismiss',
                      text: 'Dismiss',
                      disabled: recommendation.status === 'dismissed'
                    },
                    { id: 'divider', itemType: 'divider' },
                    {
                      id: 'add_note',
                      text: 'Add Note'
                    },
                    {
                      id: 'update_progress',
                      text: 'Update Progress'
                    }
                  ]}
                  onItemClick={({ detail }) => {
                    switch (detail.id) {
                      case 'mark_in_progress':
                        handleStatusChange('in_progress');
                        break;
                      case 'mark_completed':
                        handleStatusChange('completed');
                        break;
                      case 'dismiss':
                        handleStatusChange('dismissed');
                        break;
                      case 'add_note':
                        setShowNotesModal(true);
                        break;
                      case 'update_progress':
                        setShowProgressModal(true);
                        break;
                    }
                  }}
                >
                  Actions
                </ButtonDropdown>
                <Button 
                  variant="primary"
                  onClick={() => onExport && onExport(recommendation)}
                >
                  Export Details
                </Button>
              </SpaceBetween>
            }
          >
            {recommendation.title || 'Cost Optimization Recommendation'}
          </Header>
        }
      >
        {/* Key Metrics Summary */}
        <ColumnLayout columns={4} variant="text-grid">
          <div>
            <Box variant="awsui-key-label">Monthly Savings</Box>
            <Box fontSize="heading-l" fontWeight="bold" color="text-status-success">
              ${(recommendation.monthly_savings || 0).toLocaleString()}
            </Box>
            <Box fontSize="body-s" color="text-body-secondary">
              ${((recommendation.monthly_savings || 0) * 12).toLocaleString()}/year
            </Box>
          </div>
          
          <div>
            <Box variant="awsui-key-label">Priority</Box>
            <SpaceBetween size="xs" direction="horizontal" alignItems="center">
              <span>{priorityConfig.icon}</span>
              <Badge color={priorityConfig.color}>
                {recommendation.priority_level?.toUpperCase() || 'MEDIUM'}
              </Badge>
            </SpaceBetween>
            <Box fontSize="body-s" color="text-body-secondary">
              Score: {Math.round(recommendation.priority_score || 0)}
            </Box>
          </div>
          
          <div>
            <Box variant="awsui-key-label">Implementation Effort</Box>
            <Badge color={effortConfig.color}>
              {recommendation.implementation_effort?.toUpperCase() || 'MEDIUM'}
            </Badge>
            <ProgressBar
              value={effortConfig.progress}
              variant={effortConfig.color === 'red' ? 'error' : effortConfig.color === 'blue' ? 'in-progress' : 'success'}
              size="small"
            />
          </div>
          
          <div>
            <Box variant="awsui-key-label">Status</Box>
            <StatusIndicator type={statusConfig.type}>
              {statusConfig.label}
            </StatusIndicator>
            <Box fontSize="body-s" color="text-body-secondary">
              Last updated: {new Date(recommendation.last_updated).toLocaleDateString()}
            </Box>
          </div>
        </ColumnLayout>
      </Container>

      {/* Detailed Tabs */}
      <Tabs
        activeTabId={activeTabId}
        onChange={({ detail }) => setActiveTabId(detail.activeTabId)}
        tabs={tabs}
      />

      {/* Add Note Modal */}
      <Modal
        visible={showNotesModal}
        onDismiss={() => setShowNotesModal(false)}
        header="Add Implementation Note"
        footer={
          <Box float="right">
            <SpaceBetween direction="horizontal" size="xs">
              <Button variant="link" onClick={() => setShowNotesModal(false)}>
                Cancel
              </Button>
              <Button 
                variant="primary" 
                onClick={handleAddNote}
                disabled={!newNote.trim()}
              >
                Add Note
              </Button>
            </SpaceBetween>
          </Box>
        }
      >
        <FormField
          label="Note"
          description="Add a note about implementation progress, challenges, or decisions"
        >
          <Textarea
            value={newNote}
            onChange={({ detail }) => setNewNote(detail.value)}
            placeholder="Enter your implementation note..."
            rows={4}
          />
        </FormField>
      </Modal>

      {/* Progress Update Modal */}
      <Modal
        visible={showProgressModal}
        onDismiss={() => setShowProgressModal(false)}
        header="Update Implementation Progress"
        footer={
          <Box float="right">
            <SpaceBetween direction="horizontal" size="xs">
              <Button variant="link" onClick={() => setShowProgressModal(false)}>
                Cancel
              </Button>
              <Button 
                variant="primary" 
                onClick={handleProgressUpdate}
                disabled={!progressUpdate.trim()}
              >
                Update Progress
              </Button>
            </SpaceBetween>
          </Box>
        }
      >
        <FormField
          label="Progress Update"
          description="Describe the current implementation progress and any blockers"
        >
          <Textarea
            value={progressUpdate}
            onChange={({ detail }) => setProgressUpdate(detail.value)}
            placeholder="Describe implementation progress, completed steps, next actions..."
            rows={4}
          />
        </FormField>
      </Modal>
    </SpaceBetween>
  );

  function renderOverviewTab() {
    return (
      <SpaceBetween size="l">
        {/* Service and Category Information */}
        <Container
          header={
            <Header variant="h3">
              Service Information
            </Header>
          }
        >
          <ColumnLayout columns={3} variant="text-grid">
            <div>
              <Box variant="awsui-key-label">Service</Box>
              <Badge color="blue">
                {recommendation.service?.toUpperCase() || 'UNKNOWN'}
              </Badge>
            </div>
            <div>
              <Box variant="awsui-key-label">Category</Box>
              <Badge color="green">
                {recommendation.category?.toUpperCase() || 'OTHER'}
              </Badge>
            </div>
            <div>
              <Box variant="awsui-key-label">Source</Box>
              <Badge color="grey">
                {recommendation.source?.toUpperCase() || 'SYSTEM'}
              </Badge>
            </div>
          </ColumnLayout>
        </Container>

        {/* Financial Impact */}
        <Container
          header={
            <Header variant="h3">
              Financial Impact
            </Header>
          }
        >
          <ColumnLayout columns={2} variant="text-grid">
            <div>
              <Box variant="awsui-key-label">Monthly Savings</Box>
              <Box fontSize="display-l" fontWeight="bold" color="text-status-success">
                ${(recommendation.monthly_savings || 0).toLocaleString()}
              </Box>
              <Box fontSize="body-s" color="text-body-secondary">
                Estimated monthly cost reduction
              </Box>
            </div>
            <div>
              <Box variant="awsui-key-label">Annual Savings</Box>
              <Box fontSize="display-l" fontWeight="bold" color="text-status-success">
                ${((recommendation.monthly_savings || 0) * 12).toLocaleString()}
              </Box>
              <Box fontSize="body-s" color="text-body-secondary">
                Total annual cost reduction
              </Box>
            </div>
          </ColumnLayout>

          {recommendation.confidence_level && (
            <div>
              <Box variant="awsui-key-label">Confidence Level</Box>
              <Badge color={recommendation.confidence_level === 'high' ? 'green' : 'blue'}>
                {recommendation.confidence_level?.toUpperCase()} CONFIDENCE
              </Badge>
              <Box fontSize="body-s" color="text-body-secondary">
                Reliability of savings estimate
              </Box>
            </div>
          )}
        </Container>

        {/* Description */}
        <Container
          header={
            <Header variant="h3">
              Recommendation Description
            </Header>
          }
        >
          <TextContent>
            <p>{recommendation.description || 'No detailed description available for this recommendation.'}</p>
          </TextContent>
        </Container>

        {/* Priority and Effort Details */}
        <ColumnLayout columns={2} variant="default">
          <Container
            header={
              <Header variant="h3">
                Priority Assessment
              </Header>
            }
          >
            <SpaceBetween size="s">
              <div>
                <SpaceBetween size="xs" direction="horizontal" alignItems="center">
                  <span>{priorityConfig.icon}</span>
                  <Badge color={priorityConfig.color}>
                    {recommendation.priority_level?.toUpperCase() || 'MEDIUM'} PRIORITY
                  </Badge>
                </SpaceBetween>
                <Box fontSize="body-s" color="text-body-secondary">
                  {priorityConfig.urgency}
                </Box>
              </div>
              
              <div>
                <Box variant="awsui-key-label">Priority Score</Box>
                <Box fontSize="heading-l" fontWeight="bold">
                  {Math.round(recommendation.priority_score || 0)}/100
                </Box>
                <ProgressBar
                  value={recommendation.priority_score || 0}
                  variant={recommendation.priority_level === 'high' ? 'error' : 'in-progress'}
                />
              </div>
            </SpaceBetween>
          </Container>

          <Container
            header={
              <Header variant="h3">
                Implementation Effort
              </Header>
            }
          >
            <SpaceBetween size="s">
              <div>
                <Badge color={effortConfig.color}>
                  {recommendation.implementation_effort?.toUpperCase() || 'MEDIUM'} EFFORT
                </Badge>
                <Box fontSize="body-s" color="text-body-secondary">
                  {effortConfig.description}
                </Box>
              </div>
              
              <div>
                <Box variant="awsui-key-label">Effort Level</Box>
                <ProgressBar
                  value={effortConfig.progress}
                  variant={effortConfig.color === 'red' ? 'error' : effortConfig.color === 'blue' ? 'in-progress' : 'success'}
                  description={`${effortConfig.progress}% effort required`}
                />
              </div>
            </SpaceBetween>
          </Container>
        </ColumnLayout>
      </SpaceBetween>
    );
  }

  function renderImplementationTab() {
    return (
      <SpaceBetween size="l">
        {/* Implementation Steps */}
        <Container
          header={
            <Header variant="h3">
              Implementation Steps
            </Header>
          }
        >
          {recommendation.implementation_steps && recommendation.implementation_steps.length > 0 ? (
            <ol>
              {recommendation.implementation_steps.map((step, index) => (
                <li key={index}>
                  <Box variant="p" margin={{ bottom: 's' }}>
                    {step}
                  </Box>
                </li>
              ))}
            </ol>
          ) : (
            <Alert type="info">
              No specific implementation steps provided. Please refer to AWS documentation for detailed guidance.
            </Alert>
          )}
        </Container>

        {/* Required Permissions */}
        <Container
          header={
            <Header variant="h3">
              Required Permissions
            </Header>
          }
        >
          {recommendation.required_permissions && recommendation.required_permissions.length > 0 ? (
            <SpaceBetween size="xs" direction="horizontal">
              {recommendation.required_permissions.map((permission, index) => (
                <Badge key={index} color="grey">
                  {permission}
                </Badge>
              ))}
            </SpaceBetween>
          ) : (
            <Alert type="info">
              No specific permissions listed. Ensure you have appropriate access to modify the affected resources.
            </Alert>
          )}
        </Container>

        {/* Implementation Guidance */}
        <Container
          header={
            <Header variant="h3">
              Implementation Guidance
            </Header>
          }
        >
          <SpaceBetween size="m">
            <ExpandableSection headerText="Pre-implementation Checklist">
              <ul>
                <li>Review all affected resources and their current configurations</li>
                <li>Ensure you have necessary permissions and access</li>
                <li>Plan for potential downtime or service interruption</li>
                <li>Create backups of current configurations if applicable</li>
                <li>Test changes in a non-production environment first</li>
                <li>Notify stakeholders of planned changes</li>
              </ul>
            </ExpandableSection>

            <ExpandableSection headerText="Best Practices">
              <ul>
                <li>Implement changes during maintenance windows</li>
                <li>Monitor resources closely after implementation</li>
                <li>Document all changes made</li>
                <li>Validate that expected savings are realized</li>
                <li>Set up alerts for any performance degradation</li>
              </ul>
            </ExpandableSection>

            <ExpandableSection headerText="Rollback Plan">
              <TextContent>
                <p>
                  Always have a rollback plan ready before implementing changes. 
                  Document the current state and ensure you can revert changes if needed.
                </p>
                <p>
                  For most AWS services, you can revert to previous configurations through 
                  the AWS Console, CLI, or Infrastructure as Code tools.
                </p>
              </TextContent>
            </ExpandableSection>
          </SpaceBetween>
        </Container>
      </SpaceBetween>
    );
  }

  function renderResourcesTab() {
    const resources = recommendation.affected_resources || [];
    
    const resourceColumns = [
      {
        id: 'type',
        header: 'Resource Type',
        cell: item => (
          <Badge color="blue">
            {item.type || 'UNKNOWN'}
          </Badge>
        ),
        sortingField: 'type'
      },
      {
        id: 'id',
        header: 'Resource ID',
        cell: item => (
          <Box variant="code">
            {item.id || 'N/A'}
          </Box>
        ),
        sortingField: 'id'
      },
      {
        id: 'region',
        header: 'Region',
        cell: item => (
          <Badge color="grey">
            {item.region || recommendation._region || 'N/A'}
          </Badge>
        ),
        sortingField: 'region'
      },
      {
        id: 'current_config',
        header: 'Current Configuration',
        cell: item => (
          <Box fontSize="body-s">
            {item.current_configuration || 'Not specified'}
          </Box>
        )
      },
      {
        id: 'recommended_config',
        header: 'Recommended Configuration',
        cell: item => (
          <Box fontSize="body-s" color="text-status-info">
            {item.recommended_configuration || 'See implementation steps'}
          </Box>
        )
      }
    ];

    return (
      <SpaceBetween size="l">
        <Container
          header={
            <Header 
              variant="h3"
              counter={`(${resources.length})`}
              description="Resources that will be affected by this optimization"
            >
              Affected Resources
            </Header>
          }
        >
          {resources.length > 0 ? (
            <Table
              columnDefinitions={resourceColumns}
              items={resources}
              sortingDisabled={false}
              empty={
                <Box textAlign="center" color="inherit">
                  <b>No resources specified</b>
                  <Box padding={{ bottom: "s" }} variant="p" color="inherit">
                    Resource details not available for this recommendation.
                  </Box>
                </Box>
              }
            />
          ) : (
            <Alert type="info">
              No specific resources listed. This recommendation may apply to multiple resources 
              or the affected resources will be identified during implementation.
            </Alert>
          )}
        </Container>

        {/* Resource Impact Summary */}
        <Container
          header={
            <Header variant="h3">
              Resource Impact Summary
            </Header>
          }
        >
          <ColumnLayout columns={3} variant="text-grid">
            <div>
              <Box variant="awsui-key-label">Total Resources</Box>
              <Box fontSize="heading-l" fontWeight="bold">
                {recommendation.resource_count || resources.length || 0}
              </Box>
            </div>
            <div>
              <Box variant="awsui-key-label">Savings per Resource</Box>
              <Box fontSize="heading-l" fontWeight="bold" color="text-status-success">
                ${recommendation.resource_count > 0 ? 
                  Math.round((recommendation.monthly_savings || 0) / recommendation.resource_count).toLocaleString() : 
                  (recommendation.monthly_savings || 0).toLocaleString()}
              </Box>
            </div>
            <div>
              <Box variant="awsui-key-label">Implementation Scope</Box>
              <Badge color={resources.length > 10 ? 'red' : resources.length > 5 ? 'blue' : 'green'}>
                {resources.length > 10 ? 'LARGE' : resources.length > 5 ? 'MEDIUM' : 'SMALL'} SCOPE
              </Badge>
            </div>
          </ColumnLayout>
        </Container>
      </SpaceBetween>
    );
  }

  function renderAnalysisTab() {
    const risks = recommendation.potential_risks || [];
    
    return (
      <SpaceBetween size="l">
        {/* Risk Assessment */}
        <Container
          header={
            <Header variant="h3">
              Risk Assessment
            </Header>
          }
        >
          {risks.length > 0 ? (
            <SpaceBetween size="s">
              {risks.map((risk, index) => (
                <Alert key={index} type="warning" header={`Risk ${index + 1}`}>
                  {risk}
                </Alert>
              ))}
            </SpaceBetween>
          ) : (
            <Alert type="success">
              No specific risks identified for this recommendation. However, always test changes 
              in a non-production environment first.
            </Alert>
          )}
        </Container>

        {/* Mitigation Strategies */}
        <Container
          header={
            <Header variant="h3">
              Risk Mitigation Strategies
            </Header>
          }
        >
          <SpaceBetween size="m">
            <ExpandableSection headerText="General Mitigation Approaches">
              <ul>
                <li><strong>Testing:</strong> Always test changes in development/staging environments</li>
                <li><strong>Monitoring:</strong> Set up comprehensive monitoring before and after changes</li>
                <li><strong>Gradual Rollout:</strong> Implement changes incrementally when possible</li>
                <li><strong>Backup Strategy:</strong> Ensure you can restore previous configurations</li>
                <li><strong>Communication:</strong> Keep stakeholders informed of changes and potential impacts</li>
              </ul>
            </ExpandableSection>

            <ExpandableSection headerText="Service-Specific Considerations">
              <TextContent>
                <p>
                  Consider the specific characteristics of the {recommendation.service?.toUpperCase()} service 
                  when implementing this optimization:
                </p>
                <ul>
                  <li>Review service-specific best practices and limitations</li>
                  <li>Check for any service dependencies that might be affected</li>
                  <li>Understand the service's change management requirements</li>
                  <li>Consider regional or availability zone implications</li>
                </ul>
              </TextContent>
            </ExpandableSection>
          </SpaceBetween>
        </Container>

        {/* Business Impact Analysis */}
        <Container
          header={
            <Header variant="h3">
              Business Impact Analysis
            </Header>
          }
        >
          <ColumnLayout columns={2} variant="text-grid">
            <div>
              <Box variant="awsui-key-label">Positive Impacts</Box>
              <ul>
                <li>Cost reduction of ${(recommendation.monthly_savings || 0).toLocaleString()}/month</li>
                <li>Improved resource efficiency</li>
                <li>Better alignment with actual usage patterns</li>
                <li>Potential performance improvements</li>
              </ul>
            </div>
            <div>
              <Box variant="awsui-key-label">Potential Concerns</Box>
              <ul>
                <li>Temporary service disruption during implementation</li>
                <li>Need for configuration changes</li>
                <li>Monitoring and validation requirements</li>
                <li>Staff time for implementation and testing</li>
              </ul>
            </div>
          </ColumnLayout>
        </Container>
      </SpaceBetween>
    );
  }

  function renderTrackingTab() {
    return (
      <SpaceBetween size="l">
        {/* Current Status */}
        <Container
          header={
            <Header variant="h3">
              Implementation Status
            </Header>
          }
        >
          <ColumnLayout columns={2} variant="text-grid">
            <div>
              <Box variant="awsui-key-label">Current Status</Box>
              <StatusIndicator type={statusConfig.type}>
                {statusConfig.label}
              </StatusIndicator>
              <Box fontSize="body-s" color="text-body-secondary">
                Last updated: {new Date(recommendation.last_updated).toLocaleString()}
              </Box>
            </div>
            <div>
              <Box variant="awsui-key-label">Created Date</Box>
              <Box fontSize="body-m">
                {new Date(recommendation.created_date).toLocaleDateString()}
              </Box>
              <Box fontSize="body-s" color="text-body-secondary">
                Age: {Math.floor((new Date() - new Date(recommendation.created_date)) / (1000 * 60 * 60 * 24))} days
              </Box>
            </div>
          </ColumnLayout>
        </Container>

        {/* Implementation History */}
        <Container
          header={
            <Header 
              variant="h3"
              counter={implementationHistory.length > 0 ? `(${implementationHistory.length})` : ''}
            >
              Implementation History
            </Header>
          }
        >
          {implementationHistory.length > 0 ? (
            <SpaceBetween size="s">
              {implementationHistory.map((entry, index) => (
                <Container key={index}>
                  <SpaceBetween size="xs">
                    <SpaceBetween size="xs" direction="horizontal" alignItems="center">
                      <Badge color="blue">
                        {entry.action?.toUpperCase() || 'UPDATE'}
                      </Badge>
                      <Box fontSize="body-s" color="text-body-secondary">
                        {new Date(entry.timestamp).toLocaleString()}
                      </Box>
                      {entry.user && (
                        <Box fontSize="body-s" color="text-body-secondary">
                          by {entry.user}
                        </Box>
                      )}
                    </SpaceBetween>
                    <Box variant="p">
                      {entry.description || entry.note || 'Status updated'}
                    </Box>
                  </SpaceBetween>
                </Container>
              ))}
            </SpaceBetween>
          ) : (
            <Alert type="info">
              No implementation history available. Updates will appear here as you track progress.
            </Alert>
          )}
        </Container>

        {/* Related Service Screener Findings */}
        {relatedFindings.length > 0 && (
          <Container
            header={
              <Header 
                variant="h3"
                counter={`(${relatedFindings.length})`}
                description="Related security and compliance findings that may be relevant"
              >
                Related Service Screener Findings
              </Header>
            }
          >
            <SpaceBetween size="s">
              {relatedFindings.map((finding, index) => (
                <Container key={index}>
                  <SpaceBetween size="xs">
                    <SpaceBetween size="xs" direction="horizontal" alignItems="center">
                      <Badge color={finding.severity === 'HIGH' ? 'red' : finding.severity === 'MEDIUM' ? 'blue' : 'green'}>
                        {finding.severity} SEVERITY
                      </Badge>
                      <Badge color="grey">
                        {finding.service?.toUpperCase()}
                      </Badge>
                    </SpaceBetween>
                    <Box fontWeight="bold">
                      {finding.title || 'Security Finding'}
                    </Box>
                    <Box variant="p" fontSize="body-s">
                      {finding.description || 'No description available'}
                    </Box>
                    {finding.resource_id && (
                      <Box variant="code" fontSize="body-s">
                        Resource: {finding.resource_id}
                      </Box>
                    )}
                  </SpaceBetween>
                </Container>
              ))}
            </SpaceBetween>
          </Container>
        )}

        {/* Quick Actions */}
        <Container
          header={
            <Header variant="h3">
              Quick Actions
            </Header>
          }
        >
          <SpaceBetween size="s" direction="horizontal">
            <Button 
              variant="primary"
              onClick={() => setShowProgressModal(true)}
            >
              Update Progress
            </Button>
            <Button 
              variant="normal"
              onClick={() => setShowNotesModal(true)}
            >
              Add Note
            </Button>
            <Button 
              variant="normal"
              onClick={() => onExport && onExport(recommendation)}
            >
              Export Details
            </Button>
            <Link 
              external
              href={`https://console.aws.amazon.com/${recommendation.service}`}
            >
              Open AWS Console
            </Link>
          </SpaceBetween>
        </Container>
      </SpaceBetween>
    );
  }
};

export default RecommendationDetails;