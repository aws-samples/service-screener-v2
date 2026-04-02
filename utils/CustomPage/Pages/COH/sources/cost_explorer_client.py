"""
AWS Cost Explorer Client

Specialized client for accessing AWS Cost Explorer rightsizing recommendations
and cost analysis data.
"""

import time
from datetime import datetime, timedelta
from botocore.exceptions import ClientError

from .base_client import BaseOptimizationClient
from utils.Tools import _pr, _warn


class CostExplorerClient(BaseOptimizationClient):
    """
    Enhanced client for AWS Cost Explorer API
    
    Provides access to rightsizing recommendations, reserved instance analysis,
    and cost optimization insights from Cost Explorer.
    """
    
    def __init__(self, session=None, retry_config=None):
        super().__init__('ce', session, retry_config)
        # Cost Explorer is global service, always use us-east-1
        self.default_region = 'us-east-1'
        
    def get_rightsizing_recommendations(self, service='AmazonEC2', lookback_days=30, recommendation_target='SAME_INSTANCE_FAMILY'):
        """
        Get EC2 rightsizing recommendations with enhanced configuration options
        
        Args:
            service: AWS service to analyze (default: AmazonEC2)
            lookback_days: Number of days to look back for usage analysis
            recommendation_target: Rightsizing target (SAME_INSTANCE_FAMILY, CROSS_INSTANCE_FAMILY)
            
        Returns:
            List of rightsizing recommendations with enhanced metadata
        """
        try:
            client = self._get_client(self.default_region)
            
            def _get_rightsizing():
                response = client.get_rightsizing_recommendation(
                    Service=service,
                    Configuration={
                        'BenefitsConsidered': True,
                        'RecommendationTarget': recommendation_target
                    }
                )
                
                recommendations = response.get('RightsizingRecommendations', [])
                
                # Enrich recommendations with additional metadata
                for rec in recommendations:
                    self._add_metadata(rec, self.default_region, {
                        '_service': service,
                        '_lookback_days': lookback_days,
                        '_recommendation_target': recommendation_target
                    })
                    
                    # Calculate additional metrics
                    current_instance = rec.get('CurrentInstance', {})
                    if current_instance:
                        rec['_current_monthly_cost'] = float(current_instance.get('MonthlyCost', 0))
                        rec['_utilization_average'] = self._calculate_average_utilization(current_instance)
                
                return recommendations
            
            return self._retry_with_backoff(_get_rightsizing)
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            error_message = e.response['Error']['Message']
            if error_code == 'AccessDeniedException':
                if 'opt-in only feature' in error_message:
                    _pr("[INFO] Cost Explorer Rightsizing is an opt-in feature and not enabled for this account")
                    _pr("[INFO] To enable: AWS Console → Cost Explorer → Preferences → Enable Rightsizing Recommendations")
                    _pr("[INFO] Skipping Cost Explorer rightsizing recommendations")
                    return []
                else:
                    _warn("[PERMISSION ERROR] Insufficient permissions for Cost Explorer rightsizing")
                    _warn("[PERMISSION ERROR] Required IAM permission: ce:GetRightsizingRecommendation")
                    return []
            elif error_code == 'ValidationException':
                _warn(f"[VALIDATION ERROR] Invalid parameters for rightsizing recommendations: {error_message}")
                return []
            else:
                _warn(f"[API ERROR] Error getting rightsizing recommendations: {str(e)}")
                return []
        except Exception as e:
            _warn(f"[UNEXPECTED ERROR] Unexpected error in Cost Explorer rightsizing: {str(e)}")
            return []
    
    def get_reserved_instance_coverage(self, lookback_days=30, group_by_service=True):
        """
        Get Reserved Instance coverage analysis with enhanced grouping options
        
        Args:
            lookback_days: Number of days to analyze
            group_by_service: Whether to group results by AWS service
            
        Returns:
            List of RI coverage data with enhanced analysis
        """
        try:
            client = self._get_client(self.default_region)
            
            end_date = datetime.now().strftime('%Y-%m-%d')
            start_date = (datetime.now() - timedelta(days=lookback_days)).strftime('%Y-%m-%d')
            
            def _get_ri_coverage():
                request_params = {
                    'TimePeriod': {
                        'Start': start_date,
                        'End': end_date
                    },
                    'Granularity': 'MONTHLY'
                }
                
                if group_by_service:
                    request_params['GroupBy'] = [
                        {
                            'Type': 'DIMENSION',
                            'Key': 'SERVICE'
                        }
                    ]
                
                response = client.get_reservation_coverage(**request_params)
                
                coverage_data = response.get('CoveragesByTime', [])
                
                # Enrich coverage data with metadata
                for coverage in coverage_data:
                    self._add_metadata(coverage, self.default_region, {
                        '_lookback_days': lookback_days,
                        '_group_by_service': group_by_service,
                        '_analysis_type': 'ri_coverage'
                    })
                
                return coverage_data
            
            return self._retry_with_backoff(_get_ri_coverage)
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'AccessDeniedException':
                _warn("Insufficient permissions for Cost Explorer RI coverage. Required: ce:GetReservationCoverage")
                return []
            elif error_code == 'ValidationException':
                _warn(f"Invalid parameters for RI coverage analysis: {e.response['Error']['Message']}")
                return []
            else:
                _warn(f"Error getting RI coverage: {str(e)}")
                return []
        except Exception as e:
            _warn(f"Unexpected error in Cost Explorer RI coverage: {str(e)}")
            return []
    
    def get_cost_and_usage(self, start_date, end_date, granularity='MONTHLY', metrics=None, group_by=None):
        """
        Get cost and usage data with flexible grouping and metrics
        
        Args:
            start_date: Start date for analysis (YYYY-MM-DD)
            end_date: End date for analysis (YYYY-MM-DD)
            granularity: Data granularity (DAILY, MONTHLY)
            metrics: List of metrics to retrieve
            group_by: Optional grouping dimensions
            
        Returns:
            Cost and usage data with metadata
        """
        try:
            client = self._get_client(self.default_region)
            
            def _get_cost_usage():
                request_params = {
                    'TimePeriod': {
                        'Start': start_date,
                        'End': end_date
                    },
                    'Granularity': granularity,
                    'Metrics': metrics or ['BlendedCost', 'UsageQuantity']
                }
                
                if group_by:
                    request_params['GroupBy'] = group_by
                
                response = client.get_cost_and_usage(**request_params)
                
                results = response.get('ResultsByTime', [])
                
                # Add metadata to results
                for result in results:
                    self._add_metadata(result, self.default_region, {
                        '_granularity': granularity,
                        '_metrics': metrics or ['BlendedCost', 'UsageQuantity'],
                        '_analysis_type': 'cost_usage'
                    })
                
                return results
            
            return self._retry_with_backoff(_get_cost_usage)
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'AccessDeniedException':
                _warn("Insufficient permissions for Cost Explorer cost/usage data. Required: ce:GetCostAndUsage")
                return []
            else:
                _warn(f"Error getting cost and usage data: {str(e)}")
                return []
        except Exception as e:
            _warn(f"Unexpected error in Cost Explorer cost/usage: {str(e)}")
            return []
    
    def _calculate_average_utilization(self, instance_data):
        """
        Calculate average utilization from instance data
        
        Args:
            instance_data: Instance utilization data
            
        Returns:
            Average utilization percentage
        """
        try:
            utilization = instance_data.get('Utilization', {})
            
            # Get CPU utilization metrics
            cpu_max = float(utilization.get('MaxCpuUtilizationPercentage', 0))
            cpu_avg = float(utilization.get('AverageCpuUtilizationPercentage', 0))
            
            # Calculate weighted average (favor average over max)
            if cpu_avg > 0:
                return cpu_avg
            elif cpu_max > 0:
                return cpu_max * 0.7  # Assume average is 70% of max
            else:
                return 0.0
                
        except (ValueError, TypeError):
            return 0.0
    
    def test_connectivity(self):
        """
        Test connectivity and permissions for Cost Explorer
        
        Returns:
            Dictionary with test results
        """
        test_result = {
            'service': 'cost-explorer',
            'region': self.default_region,
            'accessible': False,
            'permissions_ok': False,
            'error': None,
            'tested_at': datetime.now().isoformat()
        }
        
        try:
            client = self._get_client(self.default_region)
            if not client:
                test_result['error'] = "Failed to create client"
                return test_result
            
            # Test with minimal API call
            end_date = datetime.now().strftime('%Y-%m-%d')
            start_date = (datetime.now() - timedelta(days=7)).strftime('%Y-%m-%d')
            
            response = client.get_cost_and_usage(
                TimePeriod={'Start': start_date, 'End': end_date},
                Granularity='MONTHLY',
                Metrics=['BlendedCost']
            )
            
            test_result['accessible'] = True
            test_result['permissions_ok'] = True
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            test_result['accessible'] = True  # We can reach the service
            
            if error_code == 'AccessDeniedException':
                test_result['error'] = "Insufficient permissions"
            else:
                test_result['error'] = f"API Error: {error_code}"
        except Exception as e:
            test_result['error'] = f"Connection error: {str(e)}"
        
        return test_result