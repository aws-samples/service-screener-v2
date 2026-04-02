"""
AWS Savings Plans Client

Specialized client for accessing AWS Savings Plans recommendations
and utilization analysis.
"""

from datetime import datetime, timedelta
from botocore.exceptions import ClientError

from .base_client import BaseOptimizationClient
from utils.Tools import _pr, _warn


class SavingsPlansClient(BaseOptimizationClient):
    """
    Enhanced client for AWS Savings Plans API
    
    Provides access to Savings Plans recommendations, utilization analysis,
    and commitment optimization insights.
    """
    
    def __init__(self, session=None, retry_config=None):
        # Use Cost Explorer service for Savings Plans recommendations
        # Set more conservative retry config for savings plans to reduce noise
        if retry_config is None:
            retry_config = {
                'max_attempts': 1,  # Only try once for savings plans
                'backoff_factor': 1,
                'initial_delay': 1
            }
        super().__init__('ce', session, retry_config)
        # Savings Plans is global service, always use us-east-1
        self.default_region = 'us-east-1'
        
    def get_savings_plans_purchase_recommendations(self, lookback_days=30, term_years=1, payment_option='NO_UPFRONT'):
        """
        Get Savings Plans purchase recommendations
        
        Args:
            lookback_days: Number of days to analyze (7, 30, or 60 - will be mapped to AWS enum)
            term_years: Savings Plans term length (1 or 3 years - will be mapped to AWS enum)
            payment_option: Payment option (NO_UPFRONT, PARTIAL_UPFRONT, ALL_UPFRONT)
            
        Returns:
            List of Savings Plans purchase recommendations
        """
        try:
            # Use Cost Explorer client for Savings Plans recommendations
            client = self._get_client(self.default_region)  # Use the CE client we initialized
            
            def _get_sp_recommendations():
                # Map parameters to AWS API enum values
                if term_years == 1:
                    term_param = 'ONE_YEAR'
                elif term_years == 3:
                    term_param = 'THREE_YEARS'
                else:
                    _warn(f"Invalid term_years {term_years}, using ONE_YEAR")
                    term_param = 'ONE_YEAR'
                
                # Map lookback days to valid enum values
                if lookback_days <= 7:
                    lookback_param = 'SEVEN_DAYS'
                elif lookback_days <= 30:
                    lookback_param = 'THIRTY_DAYS'
                elif lookback_days <= 60:
                    lookback_param = 'SIXTY_DAYS'
                else:
                    _warn(f"Invalid lookback_days {lookback_days}, using THIRTY_DAYS")
                    lookback_param = 'THIRTY_DAYS'
                
                response = client.get_savings_plans_purchase_recommendation(
                    SavingsPlansType='COMPUTE_SP',
                    TermInYears=term_param,
                    PaymentOption=payment_option,
                    LookbackPeriodInDays=lookback_param
                )
                
                recommendations = response.get('SavingsPlansRecommendations', [])
                
                # Enrich recommendations with metadata
                for rec in recommendations:
                    self._add_metadata(rec, self.default_region, {
                        '_lookback_days': lookback_days,
                        '_term_years': term_years,
                        '_payment_option': payment_option,
                        '_recommendation_type': 'savings_plans_purchase'
                    })
                
                return recommendations
            
            return self._retry_with_backoff(_get_sp_recommendations)
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            error_message = e.response['Error']['Message']
            if error_code == 'AccessDeniedException':
                if 'opt-in' in error_message.lower() or 'not enabled' in error_message.lower():
                    _pr("[INFO] Savings Plans recommendations may require opt-in or have no suitable recommendations")
                    _pr("[INFO] This is normal if: 1) No consistent usage patterns, 2) Already have optimal coverage, 3) Account is new")
                    _pr("[INFO] Skipping Savings Plans recommendations")
                else:
                    _warn("[PERMISSION ERROR] Insufficient permissions for Savings Plans recommendations")
                    _warn("[PERMISSION ERROR] Required IAM permission: ce:GetSavingsPlansPurchaseRecommendation")
                return []
            elif error_code == 'ValidationException':
                _warn(f"[VALIDATION ERROR] Invalid parameters for Savings Plans recommendations: {error_message}")
                return []
            else:
                _warn(f"[API ERROR] Error getting Savings Plans recommendations: {str(e)}")
                return []
        except Exception as e:
            _warn(f"[UNEXPECTED ERROR] Unexpected error in Savings Plans recommendations: {str(e)}")
            return []
    
    def get_savings_plans_utilization(self, start_date=None, end_date=None, granularity='MONTHLY'):
        """
        Get Savings Plans utilization data
        
        Args:
            start_date: Start date for analysis (defaults to 30 days ago)
            end_date: End date for analysis (defaults to today)
            granularity: Data granularity (DAILY, MONTHLY)
            
        Returns:
            Savings Plans utilization data
        """
        try:
            # Use Cost Explorer client for utilization data
            client = self._get_client(self.default_region)
            
            # Set default date range if not provided
            if not end_date:
                end_date = datetime.now().strftime('%Y-%m-%d')
            if not start_date:
                start_date = (datetime.now() - timedelta(days=30)).strftime('%Y-%m-%d')
            
            def _get_sp_utilization():
                response = client.get_savings_plans_utilization(
                    TimePeriod={
                        'Start': start_date,
                        'End': end_date
                    },
                    Granularity=granularity
                )
                
                utilization_data = response.get('SavingsPlansUtilizationsByTime', [])
                
                # Add metadata to utilization data
                for data in utilization_data:
                    self._add_metadata(data, self.default_region, {
                        '_granularity': granularity,
                        '_analysis_type': 'savings_plans_utilization'
                    })
                
                return utilization_data
            
            return self._retry_with_backoff(_get_sp_utilization)
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'AccessDeniedException':
                _warn("Insufficient permissions for Savings Plans utilization. Required: ce:GetSavingsPlansUtilization")
                return []
            else:
                _warn(f"Error getting Savings Plans utilization: {str(e)}")
                return []
        except Exception as e:
            _warn(f"Unexpected error in Savings Plans utilization: {str(e)}")
            return []
    
    def get_savings_plans_coverage(self, start_date=None, end_date=None, granularity='MONTHLY'):
        """
        Get Savings Plans coverage data
        
        Args:
            start_date: Start date for analysis (defaults to 30 days ago)
            end_date: End date for analysis (defaults to today)
            granularity: Data granularity (DAILY, MONTHLY)
            
        Returns:
            Savings Plans coverage data
        """
        try:
            # Use Cost Explorer client for coverage data
            client = self._get_client('ce')
            
            # Set default date range if not provided
            if not end_date:
                end_date = datetime.now().strftime('%Y-%m-%d')
            if not start_date:
                start_date = (datetime.now() - timedelta(days=30)).strftime('%Y-%m-%d')
            
            def _get_sp_coverage():
                response = client.get_savings_plans_coverage(
                    TimePeriod={
                        'Start': start_date,
                        'End': end_date
                    },
                    Granularity=granularity
                )
                
                coverage_data = response.get('SavingsPlansCoverages', [])
                
                # Add metadata to coverage data
                for data in coverage_data:
                    self._add_metadata(data, self.default_region, {
                        '_granularity': granularity,
                        '_analysis_type': 'savings_plans_coverage'
                    })
                
                return coverage_data
            
            return self._retry_with_backoff(_get_sp_coverage)
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'AccessDeniedException':
                _warn("Insufficient permissions for Savings Plans coverage. Required: ce:GetSavingsPlansCoverage")
                return []
            else:
                _warn(f"Error getting Savings Plans coverage: {str(e)}")
                return []
        except Exception as e:
            _warn(f"Unexpected error in Savings Plans coverage: {str(e)}")
            return []
    
    def analyze_savings_opportunities(self, current_usage_data=None):
        """
        Analyze potential savings opportunities from Savings Plans
        
        Args:
            current_usage_data: Optional current usage data for analysis
            
        Returns:
            Analysis of savings opportunities
        """
        try:
            # Get recommendations for different configurations
            recommendations = []
            
            # 1-year plans with different payment options
            for payment_option in ['NO_UPFRONT', 'PARTIAL_UPFRONT', 'ALL_UPFRONT']:
                recs = self.get_savings_plans_purchase_recommendations(
                    term_years=1,
                    payment_option=payment_option
                )
                recommendations.extend(recs)
            
            # 3-year plans (typically better savings)
            for payment_option in ['NO_UPFRONT', 'PARTIAL_UPFRONT', 'ALL_UPFRONT']:
                recs = self.get_savings_plans_purchase_recommendations(
                    term_years=3,
                    payment_option=payment_option
                )
                recommendations.extend(recs)
            
            # Analyze and rank recommendations
            analysis = {
                'total_recommendations': len(recommendations),
                'potential_annual_savings': 0.0,
                'best_recommendation': None,
                'recommendations_by_term': {'1_year': [], '3_year': []},
                'analysis_timestamp': datetime.now().isoformat()
            }
            
            best_savings = 0.0
            
            for rec in recommendations:
                # Extract savings information
                savings = float(rec.get('EstimatedMonthlySavings', 0)) * 12
                analysis['potential_annual_savings'] += savings
                
                # Track best recommendation
                if savings > best_savings:
                    best_savings = savings
                    analysis['best_recommendation'] = rec
                
                # Group by term
                term_years = rec.get('_term_years', 1)
                if term_years == 1:
                    analysis['recommendations_by_term']['1_year'].append(rec)
                else:
                    analysis['recommendations_by_term']['3_year'].append(rec)
            
            return analysis
            
        except Exception as e:
            _warn(f"Error analyzing Savings Plans opportunities: {str(e)}")
            return {
                'total_recommendations': 0,
                'potential_annual_savings': 0.0,
                'best_recommendation': None,
                'recommendations_by_term': {'1_year': [], '3_year': []},
                'error': str(e),
                'analysis_timestamp': datetime.now().isoformat()
            }
    
    def test_connectivity(self):
        """
        Test connectivity and permissions for Savings Plans
        
        Returns:
            Dictionary with test results
        """
        test_result = {
            'service': 'savings-plans',
            'region': self.default_region,
            'accessible': False,
            'permissions_ok': False,
            'error': None,
            'tested_at': datetime.now().isoformat()
        }
        
        try:
            # Test with Cost Explorer client (handles SP APIs)
            client = self._get_client('ce')
            if not client:
                test_result['error'] = "Failed to create client"
                return test_result
            
            # Test with minimal API call
            response = client.get_savings_plans_purchase_recommendation(
                SavingsPlansType='COMPUTE_SP',
                TermInYears='ONE_YEAR',
                PaymentOption='NO_UPFRONT',
                LookbackPeriodInDays='7'
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