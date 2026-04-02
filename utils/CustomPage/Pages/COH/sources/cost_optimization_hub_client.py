"""
AWS Cost Optimization Hub Client

Specialized client for accessing AWS Cost Optimization Hub recommendations
with multi-region support and intelligent error handling.
"""

from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from botocore.exceptions import ClientError

from .base_client import BaseOptimizationClient
from utils.Tools import _pr, _warn


class CostOptimizationHubClient(BaseOptimizationClient):
    """
    Enhanced client for AWS Cost Optimization Hub API
    
    Provides comprehensive access to Cost Optimization Hub recommendations with
    multi-region support, intelligent error handling, and retry logic.
    """
    
    def __init__(self, session=None, retry_config=None):
        super().__init__('cost-optimization-hub', session, retry_config)
        self.supported_regions = [
            'us-east-1'  # COH is global service, us-east-1 provides all recommendations
        ]
        
    def list_recommendations(self, region='us-east-1', max_results=100, filters=None):
        """
        List cost optimization recommendations with advanced filtering
        
        Args:
            region: AWS region to query
            max_results: Maximum number of recommendations to return
            filters: Optional filters for recommendations
            
        Returns:
            List of recommendation dictionaries with enhanced fields
        """
        if region not in self.supported_regions:
            _warn(f"Cost Optimization Hub not supported in region {region}")
            return []
        
        try:
            client = self._get_client(region)
            if not client:
                return []
            
            def _list_recommendations():
                recommendations = []
                
                # Build request parameters
                request_params = {
                    'maxResults': min(max_results, 100)  # API limit is 100 per request
                }
                
                # Add filters if provided
                if filters:
                    if 'implementationEfforts' in filters:
                        request_params['filter'] = {
                            'implementationEfforts': filters['implementationEfforts']
                        }
                    if 'restartNeeded' in filters:
                        if 'filter' not in request_params:
                            request_params['filter'] = {}
                        request_params['filter']['restartNeeded'] = filters['restartNeeded']
                
                # Use paginator for large result sets
                paginator = client.get_paginator('list_recommendations')
                page_count = 0
                
                for page in paginator.paginate(
                    **request_params,
                    PaginationConfig={'MaxItems': max_results}
                ):
                    page_count += 1
                    items = page.get('items', [])
                    
                    # Process each recommendation to extract additional fields
                    for rec in items:
                        self._add_metadata(rec, region, {'_page': page_count})
                        self._enhance_recommendation_data(rec)
                    
                    recommendations.extend(items)
                
                return recommendations
            
            return self._retry_with_backoff(_list_recommendations)
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'OptInRequiredException':
                _warn(f"Cost Optimization Hub not enabled in region {region}. Enable it in AWS Console.")
                return []
            elif error_code in ['AccessDeniedException', 'UnauthorizedOperation']:
                _warn(f"Insufficient permissions for Cost Optimization Hub in {region}. Required: cost-optimization-hub:ListRecommendations")
                return []
            elif error_code == 'ValidationException':
                _warn(f"Invalid request parameters for Cost Optimization Hub in {region}: {e.response['Error']['Message']}")
                return []
            else:
                _warn(f"Error accessing Cost Optimization Hub in {region}: {str(e)}")
                return []
        except Exception as e:
            _warn(f"Unexpected error in Cost Optimization Hub for {region}: {str(e)}")
            return []
    
    def get_recommendation(self, recommendation_id, region='us-east-1'):
        """
        Get detailed recommendation information
        
        Args:
            recommendation_id: Unique identifier for the recommendation
            region: AWS region where the recommendation exists
            
        Returns:
            Dictionary with detailed recommendation data
        """
        if region not in self.supported_regions:
            _warn(f"Cost Optimization Hub not supported in region {region}")
            return {}
        
        try:
            client = self._get_client(region)
            if not client:
                return {}
            
            def _get_recommendation():
                response = client.get_recommendation(recommendationId=recommendation_id)
                recommendation = response.get('recommendation', {})
                
                # Add metadata
                self._add_metadata(recommendation, region)
                
                return recommendation
            
            return self._retry_with_backoff(_get_recommendation)
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'ResourceNotFoundException':
                _warn(f"Recommendation {recommendation_id} not found in region {region}")
                return {}
            elif error_code in ['AccessDeniedException', 'UnauthorizedOperation']:
                _warn(f"Insufficient permissions to get recommendation details in {region}")
                return {}
            else:
                _warn(f"Error getting recommendation {recommendation_id}: {str(e)}")
                return {}
        except Exception as e:
            _warn(f"Unexpected error getting recommendation {recommendation_id}: {str(e)}")
            return {}
    
    def list_recommendations_multi_region(self, regions=None, max_results_per_region=100, filters=None):
        """
        Collect recommendations from multiple regions in parallel
        
        Args:
            regions: List of regions to query (defaults to all supported regions)
            max_results_per_region: Maximum recommendations per region
            filters: Optional filters to apply
            
        Returns:
            Dictionary mapping regions to their recommendations
        """
        if regions is None:
            regions = self.supported_regions
        
        # Filter to only supported regions
        valid_regions = [r for r in regions if r in self.supported_regions]
        
        if not valid_regions:
            _warn("No valid regions specified for Cost Optimization Hub")
            return {}
        
        results = {}
        
        # Use ThreadPoolExecutor for parallel collection
        with ThreadPoolExecutor(max_workers=min(len(valid_regions), 5)) as executor:
            # Submit tasks for each region
            future_to_region = {
                executor.submit(
                    self.list_recommendations, 
                    region, 
                    max_results_per_region, 
                    filters
                ): region 
                for region in valid_regions
            }
            
            # Collect results as they complete
            for future in as_completed(future_to_region):
                region = future_to_region[future]
                try:
                    recommendations = future.result(timeout=30)  # 30 second timeout per region
                    results[region] = recommendations
                    if recommendations:
                        _pr(f"Collected {len(recommendations)} recommendations from {region}")
                except Exception as e:
                    _warn(f"Failed to collect recommendations from {region}: {str(e)}")
                    results[region] = []
        
        return results
    
    def get_recommendation_summary(self, region='us-east-1'):
        """
        Get summary statistics for recommendations in a region
        
        Args:
            region: AWS region to analyze
            
        Returns:
            Dictionary with summary statistics
        """
        try:
            recommendations = self.list_recommendations(region, max_results=1000)
            
            if not recommendations:
                return {
                    'total_count': 0,
                    'total_monthly_savings': 0.0,
                    'categories': {},
                    'implementation_efforts': {},
                    'region': region
                }
            
            # Calculate summary statistics
            total_savings = sum(float(rec.get('estimatedMonthlySavings', 0)) for rec in recommendations)
            
            # Group by category
            categories = {}
            for rec in recommendations:
                category = rec.get('category', 'unknown')
                if category not in categories:
                    categories[category] = {'count': 0, 'savings': 0.0}
                categories[category]['count'] += 1
                categories[category]['savings'] += float(rec.get('estimatedMonthlySavings', 0))
            
            # Group by implementation effort
            efforts = {}
            for rec in recommendations:
                effort = rec.get('implementationEffort', 'unknown')
                if effort not in efforts:
                    efforts[effort] = {'count': 0, 'savings': 0.0}
                efforts[effort]['count'] += 1
                efforts[effort]['savings'] += float(rec.get('estimatedMonthlySavings', 0))
            
            return {
                'total_count': len(recommendations),
                'total_monthly_savings': total_savings,
                'categories': categories,
                'implementation_efforts': efforts,
                'region': region,
                'generated_at': datetime.now().isoformat()
            }
            
        except Exception as e:
            _warn(f"Error generating recommendation summary for {region}: {str(e)}")
            return {
                'total_count': 0,
                'total_monthly_savings': 0.0,
                'categories': {},
                'implementation_efforts': {},
                'region': region,
                'error': str(e)
            }
    
    def validate_region_support(self, region):
        """
        Validate if Cost Optimization Hub is supported in the given region
        
        Args:
            region: AWS region to validate
            
        Returns:
            Boolean indicating support status
        """
        return region in self.supported_regions
    
    def get_supported_regions(self):
        """
        Get list of regions where Cost Optimization Hub is available
        
        Returns:
            List of supported region names
        """
        return self.supported_regions.copy()
    
    def test_connectivity(self, region='us-east-1'):
        """
        Test connectivity and permissions for Cost Optimization Hub
        
        Args:
            region: AWS region to test
            
        Returns:
            Dictionary with test results
        """
        test_result = {
            'region': region,
            'supported': region in self.supported_regions,
            'accessible': False,
            'permissions_ok': False,
            'error': None,
            'tested_at': datetime.now().isoformat()
        }
        
        if not test_result['supported']:
            test_result['error'] = f"Cost Optimization Hub not supported in {region}"
            return test_result
        
        try:
            client = self._get_client(region)
            if not client:
                test_result['error'] = "Failed to create client"
                return test_result
            
            # Test with minimal API call
            response = client.list_recommendations(maxResults=1)
            test_result['accessible'] = True
            test_result['permissions_ok'] = True
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            test_result['accessible'] = True  # We can reach the service
            
            if error_code == 'OptInRequiredException':
                test_result['error'] = "Cost Optimization Hub not enabled"
            elif error_code in ['AccessDeniedException', 'UnauthorizedOperation']:
                test_result['error'] = "Insufficient permissions"
            else:
                test_result['error'] = f"API Error: {error_code}"
        except Exception as e:
            test_result['error'] = f"Connection error: {str(e)}"
        
        return test_result
    
    def _enhance_recommendation_data(self, recommendation):
        """
        Enhance recommendation data with additional fields extracted from AWS COH API
        
        Args:
            recommendation: Raw recommendation dictionary from AWS API
        """
        try:
            # Extract top recommended action from actionType or category
            action_type = recommendation.get('actionType', '')
            category = recommendation.get('category', '')
            source = recommendation.get('source', '')
            
            # Map actionType to user-friendly top recommended action
            top_action = self._extract_top_recommended_action(action_type, category, source)
            recommendation['topRecommendedAction'] = top_action
            
            # Extract recommended resource summary from description and resources
            resource_summary = self._extract_recommended_resource_summary(recommendation)
            recommendation['recommendedResourceSummary'] = resource_summary
            
            # Extract current resource summary
            current_summary = self._extract_current_resource_summary(recommendation)
            recommendation['currentResourceSummary'] = current_summary
            
        except Exception as e:
            _warn(f"Error enhancing recommendation data: {str(e)}")
            # Set default values if extraction fails
            recommendation['topRecommendedAction'] = recommendation.get('actionType', 'Optimize resource configuration')
            recommendation['recommendedResourceSummary'] = recommendation.get('description', 'Review and optimize resource')
            recommendation['currentResourceSummary'] = 'Current configuration'
    
    def _extract_top_recommended_action(self, action_type, category, source):
        """
        Extract user-friendly top recommended action from AWS API fields
        
        Args:
            action_type: Action type from AWS API
            category: Category from AWS API  
            source: Source service from AWS API
            
        Returns:
            User-friendly top recommended action string
        """
        # Map common action types to user-friendly actions
        action_mapping = {
            'Terminate': 'Delete idle or unused resources',
            'Stop': 'Stop idle or unused resources', 
            'Rightsize': 'Migrate to Graviton' if 'graviton' in action_type.lower() else 'Rightsize instance',
            'ModifyDBInstance': 'Migrate to Graviton',
            'PurchaseReservedInstances': 'Purchase Reserved Instances',
            'PurchaseSavingsPlans': 'Purchase Savings Plans',
            'MigrateToGraviton': 'Migrate to Graviton',
            'Upgrade': 'Upgrade to newer generation',
            'Delete': 'Delete idle or unused resources'
        }
        
        # Check for exact matches first
        for key, value in action_mapping.items():
            if key.lower() in action_type.lower():
                return value
        
        # Check category-based mapping
        if category.lower() == 'compute':
            if 'graviton' in action_type.lower() or 'arm' in action_type.lower():
                return 'Migrate to Graviton'
            elif 'rightsize' in action_type.lower() or 'resize' in action_type.lower():
                return 'Rightsize instance'
        elif category.lower() == 'storage':
            if 'delete' in action_type.lower() or 'terminate' in action_type.lower():
                return 'Delete idle or unused resources'
        
        # Default fallback
        return action_type if action_type else 'Optimize resource configuration'
    
    def _extract_recommended_resource_summary(self, recommendation):
        """
        Extract recommended resource summary from AWS API response
        
        Args:
            recommendation: Raw recommendation dictionary
            
        Returns:
            Recommended resource summary string
        """
        try:
            action_type = recommendation.get('actionType', '').lower()
            category = recommendation.get('category', '').lower()
            resources = recommendation.get('resources', [])
            
            # For EBS volumes - deletion recommendations
            if category == 'storage' and 'delete' in action_type:
                if any('volume' in str(res).lower() for res in resources):
                    return "Detach volume from instance, create a snapshot and delete."
            
            # For EC2 instances - Graviton migration
            if category == 'compute' and ('graviton' in action_type or 'rightsize' in action_type):
                # Try to extract target instance type from description or other fields
                description = recommendation.get('description', '')
                if 't4g.' in description:
                    return "t4g.micro"
                elif 'm6g.' in description:
                    return "m6g.large"
                elif 'graviton' in description.lower():
                    return "Migrate to Graviton-based instance type"
                else:
                    return "Optimize instance type for better performance and cost"
            
            # For Reserved Instances
            if 'reserved' in action_type:
                return "Purchase Reserved Instances for predictable workloads"
            
            # For Savings Plans
            if 'savings' in action_type:
                return "Purchase Savings Plans for flexible compute usage"
            
            # Default extraction from description
            description = recommendation.get('description', '')
            if description:
                # Try to extract actionable summary from description
                if len(description) > 100:
                    # Take first sentence or first 100 characters
                    sentences = description.split('.')
                    if sentences:
                        return sentences[0].strip() + '.'
                return description
            
            return "Review and optimize resource configuration"
            
        except Exception as e:
            _warn(f"Error extracting recommended resource summary: {str(e)}")
            return "Review and optimize resource configuration"
    
    def _extract_current_resource_summary(self, recommendation):
        """
        Extract current resource summary from AWS API response
        
        Args:
            recommendation: Raw recommendation dictionary
            
        Returns:
            Current resource summary string
        """
        try:
            resources = recommendation.get('resources', [])
            if not resources:
                return "Current configuration"
            
            # Extract resource IDs and types
            resource_summaries = []
            for resource in resources[:3]:  # Limit to first 3 resources
                if isinstance(resource, dict):
                    resource_id = resource.get('resourceId', resource.get('arn', ''))
                    resource_type = resource.get('resourceType', '')
                    
                    if resource_id:
                        # Extract meaningful part of resource ID
                        if resource_id.startswith('arn:'):
                            # Extract from ARN
                            parts = resource_id.split(':')
                            if len(parts) >= 6:
                                resource_summaries.append(parts[-1])
                        else:
                            resource_summaries.append(resource_id)
                elif isinstance(resource, str):
                    resource_summaries.append(resource)
            
            if resource_summaries:
                return ', '.join(resource_summaries)
            
            return "Current configuration"
            
        except Exception as e:
            _warn(f"Error extracting current resource summary: {str(e)}")
            return "Current configuration"