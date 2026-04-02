import React from 'react';
import Box from '@cloudscape-design/components/box';
import SpaceBetween from '@cloudscape-design/components/space-between';
import Icon from '@cloudscape-design/components/icon';

/**
 * EmptyState component
 * Displays a user-friendly message when no data is available
 */
const EmptyState = ({ 
  title = 'No data available',
  description = 'There is no data to display at this time.',
  icon = 'status-info',
  iconColor = 'text-status-inactive'
}) => {
  return (
    <Box textAlign="center" padding={{ vertical: 'xxl' }}>
      <SpaceBetween size="m">
        <Box>
          <Icon name={icon} size="big" variant={iconColor} />
        </Box>
        <Box variant="h3" color="text-status-inactive">
          {title}
        </Box>
        <Box variant="p" color="text-status-inactive">
          {description}
        </Box>
      </SpaceBetween>
    </Box>
  );
};

export default EmptyState;
