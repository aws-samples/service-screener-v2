import boto3
import botocore
import constants as _C

from services.Evaluator import Evaluator

class CloudwatchDashboards(Evaluator):
    """
    Driver for CloudWatch Dashboards checks
    Handles dashboard configuration validation including cross-account setup and vended dashboards
    """
    
    def __init__(self, dashboard, cwClient):
        """
        Initialize dashboard driver
        
        Args:
            dashboard: Dashboard dict from list_dashboards()
            cwClient: CloudWatch boto3 client
        
        Validates: Requirements 15.3, 15.4
        """
        super().__init__()
        self.init()
        
        self.dashboard = dashboard
        self.cwClient = cwClient
        
        try:
            self._resourceName = dashboard.get('DashboardName', 'unknown')
        except Exception as e:
            self._resourceName = 'unknown'
            print(f"Error getting dashboard name: {str(e)}")
        
        return
    
    def _checkCrossAccountConfiguration(self):
        """
        Check if dashboard contains cross-account metrics
        
        Cross-account dashboards provide centralized visibility across multiple AWS accounts,
        which is essential for multi-account environments. This check identifies whether
        dashboards leverage cross-account metric capabilities.
        
        Validates: Requirements 4.1, 4.2, 4.3, 4.4
        """
        try:
            # Retrieve dashboard body
            response = self.cwClient.get_dashboard(
                DashboardName=self.dashboard['DashboardName']
            )
            
            # Parse dashboard JSON
            import json
            dashboard_body = json.loads(response['DashboardBody'])
            
            # Check for cross-account metrics
            has_cross_account = False
            widgets = dashboard_body.get('widgets', [])
            
            for widget in widgets:
                properties = widget.get('properties', {})
                metrics = properties.get('metrics', [])
                
                # Check each metric for accountId property
                for metric in metrics:
                    if isinstance(metric, list):
                        # Metrics can be arrays with dimensions dict at the end
                        for item in metric:
                            if isinstance(item, dict):
                                if 'accountId' in item or 'region' in item:
                                    has_cross_account = True
                                    break
                    elif isinstance(metric, dict):
                        if 'accountId' in metric or 'region' in metric:
                            has_cross_account = True
                            break
                
                if has_cross_account:
                    break
            
            # Flag if no cross-account metrics found
            if not has_cross_account:
                self.results['missingCrossAccountDashboards'] = [-1, 
                    f"Dashboard does not contain cross-account metrics. Consider configuring cross-account dashboards for multi-account visibility."]
        
        except botocore.exceptions.ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'ResourceNotFoundException':
                print(f"Dashboard not found: {self._resourceName}")
            elif error_code == 'AccessDeniedException':
                print(f"Access denied for dashboard: {self._resourceName}")
            else:
                print(f"API error checking dashboard {self._resourceName}: {str(e)}")
        except json.JSONDecodeError as e:
            print(f"Error parsing dashboard JSON for {self._resourceName}: {str(e)}")
        except Exception as e:
            print(f"Error checking cross-account configuration for {self._resourceName}: {str(e)}")
    
    def _checkVendedDashboards(self):
        """
        Check if vended dashboards exist for supported log types
        
        Vended dashboards are pre-built CloudWatch dashboards automatically generated
        for specific log types (VPC Flow Logs, CloudTrail, WAF). This check identifies
        opportunities to leverage these pre-built visualizations.
        
        Validates: Requirements 13.1, 13.2, 13.3, 13.4
        """
        try:
            dashboard_name = self.dashboard.get('DashboardName', '').lower()
            
            # Check if dashboard name matches vended dashboard patterns
            is_vended = False
            supported_log_types = []
            
            # VPC Flow Logs vended dashboard patterns
            if 'vpc' in dashboard_name or 'flowlogs' in dashboard_name or 'flow-logs' in dashboard_name:
                is_vended = True
                supported_log_types.append('VPC Flow Logs')
            
            # CloudTrail vended dashboard patterns
            if 'cloudtrail' in dashboard_name or 'trail' in dashboard_name:
                is_vended = True
                supported_log_types.append('CloudTrail')
            
            # WAF vended dashboard patterns
            if 'waf' in dashboard_name:
                is_vended = True
                supported_log_types.append('WAF')
            
            # Flag if dashboard doesn't match vended patterns (informational)
            if not is_vended:
                self.results['missingVendedDashboards'] = [-1, 
                    f"Dashboard does not appear to be a vended dashboard. Consider using pre-built vended dashboards for VPC Flow Logs, CloudTrail, or WAF logs for enhanced visualizations."]
            
        except Exception as e:
            print(f"Error checking vended dashboards for {self._resourceName}: {str(e)}")
