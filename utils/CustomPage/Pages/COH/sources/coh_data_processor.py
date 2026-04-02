"""
COH Data Processor

Specialized processor for transforming and normalizing Cost Optimization Hub
recommendation data from various sources into a unified format.
"""

from datetime import datetime
from typing import Dict, List, Optional, Any
from utils.Tools import _pr, _warn


class COHDataProcessor:
    """
    Processes and normalizes COH recommendation data from multiple sources
    """
    
    def __init__(self):
        self.action_type_mapping = {
            # Storage actions
            'Terminate': 'Delete idle or unused resources',
            'Delete': 'Delete idle or unused resources',
            'Stop': 'Stop idle or unused resources',
            
            # Compute actions
            'Rightsize': 'Rightsize instance',
            'ModifyDBInstance': 'Migrate to Graviton',
            'MigrateToGraviton': 'Migrate to Graviton',
            'Upgrade': 'Upgrade to newer generation',
            
            # Cost optimization actions
            'PurchaseReservedInstances': 'Purchase Reserved Instances',
            'PurchaseSavingsPlans': 'Purchase Savings Plans',
            
            # General actions
            'Optimize': 'Optimize resource configuration'
        }
        
        self.resource_type_mapping = {
            'AWS::EC2::Volume': 'EBS volume',
            'AWS::EC2::Instance': 'EC2 Instance',
            'AWS::RDS::DBInstance': 'RDS Instance',
            'AWS::S3::Bucket': 'S3 Bucket',
            'AWS::Lambda::Function': 'Lambda Function'
        }
    
    def normalize_coh_recommendation(self, raw_recommendation: Dict) -> Dict:
        """
        Normalize a raw COH recommendation into the expected format
        
        Args:
            raw_recommendation: Raw recommendation from AWS COH API
            
        Returns:
            Normalized recommendation dictionary
        """
        try:
            # Extract basic fields
            recommendation_id = raw_recommendation.get('recommendationId', f"coh_{int(datetime.now().timestamp())}")
            action_type = raw_recommendation.get('actionType', '')
            category = raw_recommendation.get('category', '')
            source = raw_recommendation.get('source', '')
            
            # Extract enhanced fields
            top_action = self._extract_top_recommended_action(action_type, category, source)
            recommended_summary = self._extract_recommended_resource_summary(raw_recommendation)
            current_summary = self._extract_current_resource_summary(raw_recommendation)
            
            # Extract financial information
            monthly_savings = float(raw_recommendation.get('estimatedMonthlySavings', 0))
            monthly_cost = float(raw_recommendation.get('estimatedMonthlyCost', monthly_savings))
            savings_percentage = self._calculate_savings_percentage(monthly_savings, monthly_cost)
            
            # Extract resource information
            resources = raw_recommendation.get('resources', [])
            affected_resources = self._normalize_affected_resources(resources)
            
            # Build normalized recommendation
            normalized = {
                'id': recommendation_id,
                'source': 'coh',
                'category': self._normalize_category(category),
                'service': source.lower() if source else 'aws',
                'title': raw_recommendation.get('name', top_action),
                'description': raw_recommendation.get('description', top_action),
                
                # Enhanced fields from AWS Console
                'topRecommendedAction': top_action,
                'recommendedResourceSummary': recommended_summary,
                'currentResourceSummary': current_summary,
                
                # Financial information
                'estimatedMonthlySavings': monthly_savings,
                'estimatedMonthlyCost': monthly_cost,
                'estimatedSavingsPercentage': savings_percentage,
                'annualSavings': monthly_savings * 12,
                
                # Implementation details
                'implementationEffort': self._normalize_effort(raw_recommendation.get('implementationEffort', 'MEDIUM')),
                'restartRequired': raw_recommendation.get('restartNeeded', False),
                'rollbackPossible': raw_recommendation.get('rollbackPossible', True),
                
                # Resource information
                'affectedResources': affected_resources,
                'resourceCount': len(affected_resources),
                'resourceType': self._extract_resource_type(resources),
                
                # Metadata
                'region': raw_recommendation.get('_region', 'us-east-1'),
                'accountId': raw_recommendation.get('_account_id', ''),
                'lastUpdated': datetime.now().isoformat(),
                'status': 'new'
            }
            
            return normalized
            
        except Exception as e:
            _warn(f"Error normalizing COH recommendation: {str(e)}")
            return self._create_fallback_recommendation(raw_recommendation)
    
    def _extract_top_recommended_action(self, action_type: str, category: str, source: str) -> str:
        """Extract user-friendly top recommended action"""
        if not action_type:
            return 'Optimize resource configuration'
        
        # Check direct mapping first
        for key, value in self.action_type_mapping.items():
            if key.lower() in action_type.lower():
                # Special case for Graviton migration
                if key == 'Rightsize' and ('graviton' in action_type.lower() or 'arm' in action_type.lower()):
                    return 'Migrate to Graviton'
                return value
        
        # Category-based inference
        if category.lower() == 'compute':
            if any(keyword in action_type.lower() for keyword in ['graviton', 'arm', 'migrate']):
                return 'Migrate to Graviton'
            elif any(keyword in action_type.lower() for keyword in ['rightsize', 'resize', 'modify']):
                return 'Rightsize instance'
        elif category.lower() == 'storage':
            if any(keyword in action_type.lower() for keyword in ['delete', 'terminate', 'remove']):
                return 'Delete idle or unused resources'
        
        # Return cleaned action type as fallback
        return action_type.replace('_', ' ').title()
    
    def _extract_recommended_resource_summary(self, recommendation: Dict) -> str:
        """Extract recommended resource summary"""
        try:
            action_type = recommendation.get('actionType', '').lower()
            category = recommendation.get('category', '').lower()
            description = recommendation.get('description', '')
            resources = recommendation.get('resources', [])
            
            # EBS Volume deletion
            if category == 'storage' and any(keyword in action_type for keyword in ['delete', 'terminate']):
                if any('volume' in str(res).lower() for res in resources):
                    return "Detach volume from instance, create a snapshot and delete."
            
            # EC2 Graviton migration
            if category == 'compute':
                if 'graviton' in action_type or 'graviton' in description.lower():
                    # Try to extract target instance type
                    if 't4g.micro' in description:
                        return "t4g.micro"
                    elif 't4g.' in description:
                        return "t4g.medium"
                    elif 'm6g.' in description:
                        return "m6g.large"
                    elif 'c6g.' in description:
                        return "c6g.large"
                    else:
                        return "Migrate to Graviton-based instance type"
                elif 'rightsize' in action_type:
                    return "Optimize instance type for better performance and cost"
            
            # Reserved Instances
            if 'reserved' in action_type:
                return "Purchase Reserved Instances for predictable workloads"
            
            # Savings Plans
            if 'savings' in action_type:
                return "Purchase Savings Plans for flexible compute usage"
            
            # Extract from description
            if description:
                # Look for actionable phrases
                sentences = description.split('.')
                for sentence in sentences:
                    sentence = sentence.strip()
                    if any(keyword in sentence.lower() for keyword in ['recommend', 'should', 'consider', 'migrate', 'upgrade']):
                        return sentence + '.' if not sentence.endswith('.') else sentence
                
                # Return first sentence if no actionable phrase found
                if sentences:
                    return sentences[0].strip() + '.'
            
            return "Review and optimize resource configuration"
            
        except Exception as e:
            _warn(f"Error extracting recommended resource summary: {str(e)}")
            return "Review and optimize resource configuration"
    
    def _extract_current_resource_summary(self, recommendation: Dict) -> str:
        """Extract current resource summary"""
        try:
            resources = recommendation.get('resources', [])
            if not resources:
                return "Current configuration"
            
            # Extract resource identifiers
            resource_ids = []
            for resource in resources[:3]:  # Limit to first 3
                if isinstance(resource, dict):
                    # Try different fields for resource ID
                    resource_id = (
                        resource.get('resourceId') or 
                        resource.get('arn') or 
                        resource.get('id') or
                        resource.get('resourceArn', '')
                    )
                    
                    if resource_id:
                        # Clean up ARN to get just the resource ID
                        if resource_id.startswith('arn:'):
                            parts = resource_id.split(':')
                            if len(parts) >= 6:
                                # Get the resource part (last part after the last :)
                                resource_part = parts[-1]
                                # If it contains /, get the part after the last /
                                if '/' in resource_part:
                                    resource_ids.append(resource_part.split('/')[-1])
                                else:
                                    resource_ids.append(resource_part)
                        else:
                            resource_ids.append(resource_id)
                elif isinstance(resource, str):
                    resource_ids.append(resource)
            
            if resource_ids:
                return ', '.join(resource_ids)
            
            return "Current configuration"
            
        except Exception as e:
            _warn(f"Error extracting current resource summary: {str(e)}")
            return "Current configuration"
    
    def _normalize_affected_resources(self, resources: List) -> List[Dict]:
        """Normalize affected resources list"""
        normalized_resources = []
        
        for resource in resources:
            try:
                if isinstance(resource, dict):
                    # Extract resource information
                    resource_id = (
                        resource.get('resourceId') or 
                        resource.get('arn') or 
                        resource.get('id') or
                        resource.get('resourceArn', '')
                    )
                    
                    resource_type = resource.get('resourceType', 'Unknown')
                    region = resource.get('region', resource.get('_region', 'us-east-1'))
                    
                    normalized_resources.append({
                        'id': resource_id,
                        'type': self.resource_type_mapping.get(resource_type, resource_type),
                        'region': region,
                        'arn': resource.get('arn', resource_id)
                    })
                elif isinstance(resource, str):
                    # Handle string resources (likely ARNs or IDs)
                    normalized_resources.append({
                        'id': resource,
                        'type': 'Unknown',
                        'region': 'us-east-1',
                        'arn': resource
                    })
            except Exception as e:
                _warn(f"Error normalizing resource: {str(e)}")
                continue
        
        return normalized_resources
    
    def _extract_resource_type(self, resources: List) -> str:
        """Extract the primary resource type from resources list"""
        if not resources:
            return "Unknown"
        
        # Get the first resource type
        first_resource = resources[0]
        if isinstance(first_resource, dict):
            resource_type = first_resource.get('resourceType', 'Unknown')
            return self.resource_type_mapping.get(resource_type, resource_type)
        
        return "Unknown"
    
    def _calculate_savings_percentage(self, monthly_savings: float, monthly_cost: float) -> int:
        """Calculate savings percentage"""
        if monthly_cost <= 0:
            return 100 if monthly_savings > 0 else 0
        
        percentage = (monthly_savings / monthly_cost) * 100
        return min(100, max(0, int(round(percentage))))
    
    def _normalize_category(self, category: str) -> str:
        """Normalize category name"""
        category_mapping = {
            'compute': 'compute',
            'storage': 'storage', 
            'database': 'database',
            'networking': 'networking',
            'cost_optimization': 'general'
        }
        return category_mapping.get(category.lower(), 'general')
    
    def _normalize_effort(self, effort: str) -> str:
        """Normalize implementation effort"""
        effort_mapping = {
            'VERY_LOW': 'Low',
            'LOW': 'Low',
            'MEDIUM': 'Medium',
            'HIGH': 'High',
            'VERY_HIGH': 'Very high'
        }
        return effort_mapping.get(effort.upper(), 'Medium')
    
    def _create_fallback_recommendation(self, raw_recommendation: Dict) -> Dict:
        """Create a fallback recommendation when normalization fails"""
        return {
            'id': f"coh_fallback_{int(datetime.now().timestamp())}",
            'source': 'coh',
            'category': 'general',
            'service': 'aws',
            'title': 'Cost Optimization Recommendation',
            'description': 'Review and optimize resource configuration',
            'topRecommendedAction': 'Optimize resource configuration',
            'recommendedResourceSummary': 'Review and optimize resource',
            'currentResourceSummary': 'Current configuration',
            'estimatedMonthlySavings': 0.0,
            'estimatedMonthlyCost': 0.0,
            'estimatedSavingsPercentage': 0,
            'annualSavings': 0.0,
            'implementationEffort': 'Medium',
            'restartRequired': False,
            'rollbackPossible': True,
            'affectedResources': [],
            'resourceCount': 0,
            'resourceType': 'Unknown',
            'region': 'us-east-1',
            'accountId': '',
            'lastUpdated': datetime.now().isoformat(),
            'status': 'new'
        }