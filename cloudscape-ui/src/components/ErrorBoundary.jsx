import React from 'react';
import Alert from '@cloudscape-design/components/alert';
import Box from '@cloudscape-design/components/box';
import Button from '@cloudscape-design/components/button';
import SpaceBetween from '@cloudscape-design/components/space-between';

/**
 * ErrorBoundary component
 * Catches React errors and displays a user-friendly error message
 */
class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { 
      hasError: false,
      error: null,
      errorInfo: null
    };
  }

  static getDerivedStateFromError(error) {
    // Update state so the next render will show the fallback UI
    return { hasError: true };
  }

  componentDidCatch(error, errorInfo) {
    // Log error details to console
    console.error('ErrorBoundary caught an error:', error, errorInfo);
    
    this.setState({
      error,
      errorInfo
    });
  }

  handleReset = () => {
    this.setState({ 
      hasError: false,
      error: null,
      errorInfo: null
    });
    
    // Reload the page to reset the app
    window.location.reload();
  };

  render() {
    if (this.state.hasError) {
      return (
        <Box padding="l">
          <Alert
            type="error"
            header="Something went wrong"
            action={
              <Button onClick={this.handleReset}>
                Reload Page
              </Button>
            }
          >
            <SpaceBetween size="m">
              <Box variant="p">
                An unexpected error occurred while rendering the application. 
                This could be due to corrupted data or a browser compatibility issue.
              </Box>
              
              {this.state.error && (
                <Box variant="code">
                  {this.state.error.toString()}
                </Box>
              )}
              
              <Box variant="p">
                <strong>What you can do:</strong>
              </Box>
              <ul>
                <li>Click "Reload Page" to restart the application</li>
                <li>Try opening the file in a different browser</li>
                <li>Check the browser console for more details</li>
                <li>Ensure the report file is not corrupted</li>
              </ul>
              
              {process.env.NODE_ENV === 'development' && this.state.errorInfo && (
                <details style={{ whiteSpace: 'pre-wrap', marginTop: '1rem' }}>
                  <summary>Error Details (Development Only)</summary>
                  <Box variant="code" margin={{ top: 's' }}>
                    {this.state.errorInfo.componentStack}
                  </Box>
                </details>
              )}
            </SpaceBetween>
          </Alert>
        </Box>
      );
    }

    return this.props.children;
  }
}

export default ErrorBoundary;
