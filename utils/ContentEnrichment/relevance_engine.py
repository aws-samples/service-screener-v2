"""
Relevance Engine

Calculates content relevance scores based on user context and detected AWS services.
Implements content prioritization algorithms and service-based filtering.
"""

from typing import List, Dict, Any, Set
from datetime import datetime, timedelta
import math

from utils.Tools import _pr, _warn
from .base_interfaces import RelevanceScorer
from .models import ContentItem, UserContext, ContentCategory, AI_ML_SERVICE_TAGS


class RelevanceEngine(RelevanceScorer):
    """
    Calculates content relevance and prioritizes content based on user context
    """
    
    def __init__(self):
        """Initialize the relevance engine"""
        self.service_weights = self._initialize_service_weights()
        self.category_weights = self._initialize_category_weights()
    
    def _initialize_service_weights(self) -> Dict[str, float]:
        """
        Initialize service-specific weights for relevance scoring
        
        Returns:
            Dictionary mapping service names to weight multipliers
        """
        return {
            # High-impact services (commonly used, high relevance)
            'ec2': 1.0,
            's3': 1.0,
            'rds': 0.9,
            'lambda': 0.9,
            'iam': 0.8,
            'vpc': 0.8,
            
            # AI/ML services (high relevance for AI content)
            'sagemaker': 1.2,
            'bedrock': 1.2,
            'comprehend': 1.1,
            'textract': 1.1,
            'rekognition': 1.1,
            
            # Security services (high relevance for security content)
            'guardduty': 1.1,
            'securityhub': 1.1,
            'inspector': 1.0,
            'macie': 1.0,
            
            # Cost optimization services
            'cost-explorer': 1.1,
            'budgets': 1.0,
            'trusted-advisor': 1.0,
            
            # Default weight for other services
            'default': 0.7
        }
    
    def _initialize_category_weights(self) -> Dict[str, Dict[str, float]]:
        """
        Initialize category-specific weights based on service types
        
        Returns:
            Dictionary mapping categories to service type weights
        """
        return {
            ContentCategory.SECURITY_RELIABILITY.value: {
                'security_services': 1.5,
                'compute_services': 1.2,
                'storage_services': 1.1,
                'networking_services': 1.3,
                'default': 1.0
            },
            ContentCategory.AI_ML_GENAI.value: {
                'ai_ml_services': 1.8,
                'compute_services': 1.2,
                'storage_services': 1.1,
                'default': 0.8
            },
            ContentCategory.BEST_PRACTICES.value: {
                'compute_services': 1.3,
                'storage_services': 1.2,
                'database_services': 1.2,
                'networking_services': 1.1,
                'default': 1.0
            }
        }
    
    def calculate_relevance(self, content_item: ContentItem, user_context: UserContext) -> float:
        """
        Calculate relevance score for content based on user context
        
        Args:
            content_item: Content item to score
            user_context: User's AWS environment context
            
        Returns:
            Relevance score between 0.0 and 1.0
        """
        try:
            # Base score components
            service_match_score = self._calculate_service_match_score(content_item, user_context)
            content_freshness_score = self._calculate_freshness_score(content_item)
            category_relevance_score = self._calculate_category_relevance(content_item, user_context)
            tag_match_score = self._calculate_tag_match_score(content_item, user_context)
            
            # Weighted combination of scores
            relevance_score = (
                service_match_score * 0.4 +      # Service matching is most important
                category_relevance_score * 0.25 + # Category relevance
                tag_match_score * 0.2 +          # Tag matching
                content_freshness_score * 0.15   # Content freshness
            )
            
            # Apply content-specific boosts
            relevance_score = self._apply_content_boosts(content_item, relevance_score)
            
            # Ensure score is within bounds
            return max(0.0, min(1.0, relevance_score))
            
        except Exception as e:
            _warn(f"Error calculating relevance for content {content_item.id}: {str(e)}")
            return 0.5  # Default moderate relevance
    
    def _calculate_service_match_score(self, content_item: ContentItem, user_context: UserContext) -> float:
        """
        Calculate score based on how well content matches detected services
        
        Args:
            content_item: Content item to score
            user_context: User context with detected services
            
        Returns:
            Service match score between 0.0 and 1.0
        """
        if not user_context.detected_services:
            return 0.5  # Neutral score if no services detected
        
        detected_services_lower = [service.lower() for service in user_context.detected_services]
        content_text = f"{content_item.title} {content_item.summary}".lower()
        content_tags_lower = [tag.lower() for tag in content_item.tags]
        
        matches = 0
        total_weight = 0
        
        for service in detected_services_lower:
            service_weight = self.service_weights.get(service, self.service_weights['default'])
            total_weight += service_weight
            
            # Check for service mentions in content
            if (service in content_text or 
                service in content_tags_lower or
                any(service in tag for tag in content_tags_lower)):
                matches += service_weight
        
        if total_weight == 0:
            return 0.5
        
        return min(1.0, matches / total_weight)
    
    def _calculate_freshness_score(self, content_item: ContentItem) -> float:
        """
        Calculate score based on content freshness (Task 5.4: Enhanced with archival logic)
        
        Args:
            content_item: Content item to score
            
        Returns:
            Freshness score between 0.0 and 1.0
        """
        try:
            now = datetime.now()
            age_days = (now - content_item.publish_date).days
            
            # Task 5.4: Apply archival penalty for content older than 30 days
            if content_item.is_archived:
                # Archived content gets significantly lower freshness score
                if age_days <= 90:
                    return 0.3  # Recent archived content
                elif age_days <= 180:
                    return 0.2  # Older archived content
                else:
                    return 0.1  # Very old archived content
            
            # Scoring based on age for non-archived content
            if age_days <= 7:
                return 1.0  # Very fresh content
            elif age_days <= 30:
                return 0.8  # Recent content
            elif age_days <= 90:
                return 0.6  # Moderately recent
            elif age_days <= 180:
                return 0.4  # Older content
            else:
                return 0.2  # Old content
                
        except Exception:
            return 0.5  # Default if date parsing fails
    
    def _calculate_category_relevance(self, content_item: ContentItem, user_context: UserContext) -> float:
        """
        Calculate relevance based on content category and user's service profile
        
        Args:
            content_item: Content item to score
            user_context: User context
            
        Returns:
            Category relevance score between 0.0 and 1.0
        """
        if not user_context.detected_services:
            return 0.7  # Default relevance
        
        # Categorize detected services
        service_profile = self._categorize_user_services(user_context.detected_services)
        category_weights = self.category_weights.get(content_item.category, {})
        
        # Calculate weighted relevance based on service profile
        relevance = 0.0
        total_weight = 0.0
        
        for service_type, count in service_profile.items():
            weight = category_weights.get(service_type, category_weights.get('default', 1.0))
            relevance += weight * count
            total_weight += count
        
        if total_weight == 0:
            return 0.7
        
        normalized_relevance = relevance / total_weight
        return min(1.0, normalized_relevance)
    
    def _calculate_tag_match_score(self, content_item: ContentItem, user_context: UserContext) -> float:
        """
        Calculate score based on tag matching with user context
        
        Args:
            content_item: Content item to score
            user_context: User context
            
        Returns:
            Tag match score between 0.0 and 1.0
        """
        if not content_item.tags or not user_context.detected_services:
            return 0.5
        
        detected_services_set = set(service.lower() for service in user_context.detected_services)
        content_tags_set = set(tag.lower() for tag in content_item.tags)
        
        # Calculate intersection
        matching_tags = detected_services_set.intersection(content_tags_set)
        
        if not content_tags_set:
            return 0.5
        
        # Score based on percentage of matching tags
        match_ratio = len(matching_tags) / len(content_tags_set)
        return min(1.0, match_ratio * 2)  # Boost the score for good matches
    
    def _apply_content_boosts(self, content_item: ContentItem, base_score: float) -> float:
        """
        Apply content-specific boosts to the relevance score (Task 5.4: Enhanced with archival penalty)
        
        Args:
            content_item: Content item
            base_score: Base relevance score
            
        Returns:
            Boosted relevance score
        """
        boosted_score = base_score
        
        # Task 5.4: Apply penalty for archived content
        if content_item.is_archived:
            boosted_score *= 0.7  # Reduce score for archived content
        
        # Boost for new content
        if content_item.is_new:
            boosted_score *= 1.2
        
        # Boost for security content (always important)
        if content_item.category == ContentCategory.SECURITY_RELIABILITY.value:
            boosted_score *= 1.1
        
        # Boost for easy-to-implement best practices
        if (content_item.category == ContentCategory.BEST_PRACTICES.value and 
            content_item.difficulty == 'Easy'):
            boosted_score *= 1.15
        
        # Boost for high-value tags
        high_value_tags = ['security', 'cost-optimization', 'performance', 'reliability']
        if any(tag.lower() in high_value_tags for tag in content_item.tags):
            boosted_score *= 1.1
        
        return boosted_score
    
    def _categorize_user_services(self, detected_services: List[str]) -> Dict[str, int]:
        """
        Categorize detected services into service types
        
        Args:
            detected_services: List of detected AWS services
            
        Returns:
            Dictionary mapping service types to counts
        """
        service_categories = {
            'compute_services': ['ec2', 'lambda', 'ecs', 'eks', 'fargate', 'batch'],
            'storage_services': ['s3', 'ebs', 'efs', 'fsx'],
            'database_services': ['rds', 'dynamodb', 'redshift', 'documentdb', 'neptune'],
            'networking_services': ['vpc', 'cloudfront', 'route53', 'elb', 'api-gateway'],
            'security_services': ['iam', 'guardduty', 'securityhub', 'inspector', 'macie'],
            'ai_ml_services': AI_ML_SERVICE_TAGS
        }
        
        service_profile = {}
        detected_lower = [service.lower() for service in detected_services]
        
        for category, services in service_categories.items():
            count = sum(1 for service in services if service in detected_lower)
            if count > 0:
                service_profile[category] = count
        
        return service_profile
    
    def prioritize_content(self, content_items: List[ContentItem], user_context: UserContext) -> List[ContentItem]:
        """
        Sort content items by relevance for the user
        
        Args:
            content_items: List of content items to prioritize
            user_context: User's AWS environment context
            
        Returns:
            Sorted list of content items (highest relevance first)
        """
        try:
            # Calculate relevance scores for all items
            scored_items = []
            for item in content_items:
                relevance_score = self.calculate_relevance(item, user_context)
                # Update the item's relevance score
                item.relevance_score = relevance_score
                scored_items.append(item)
            
            # Sort by relevance score (descending) and then by publication date (descending)
            sorted_items = sorted(
                scored_items,
                key=lambda x: (x.relevance_score, x.publish_date),
                reverse=True
            )
            
            _pr(f"Prioritized {len(sorted_items)} content items by relevance")
            return sorted_items
            
        except Exception as e:
            _warn(f"Error prioritizing content: {str(e)}")
            # Return original list if prioritization fails
            return content_items
    
    def filter_by_relevance_threshold(self, content_items: List[ContentItem], 
                                    threshold: float = 0.3) -> List[ContentItem]:
        """
        Filter content items by minimum relevance threshold
        
        Args:
            content_items: List of content items to filter
            threshold: Minimum relevance score (0.0 to 1.0)
            
        Returns:
            Filtered list of content items above threshold
        """
        filtered_items = [item for item in content_items if item.relevance_score >= threshold]
        
        _pr(f"Filtered {len(content_items)} items to {len(filtered_items)} "
            f"items above relevance threshold {threshold}")
        
        return filtered_items
    
    def get_top_content_by_category(self, content_items: List[ContentItem], 
                                  max_per_category: int = 5) -> Dict[str, List[ContentItem]]:
        """
        Get top content items for each category
        
        Args:
            content_items: List of content items
            max_per_category: Maximum items per category
            
        Returns:
            Dictionary mapping categories to top content items
        """
        categorized_content = {}
        
        # Group by category
        for item in content_items:
            if item.category not in categorized_content:
                categorized_content[item.category] = []
            categorized_content[item.category].append(item)
        
        # Get top items for each category
        top_content = {}
        for category, items in categorized_content.items():
            # Sort by relevance score and take top items
            sorted_items = sorted(items, key=lambda x: x.relevance_score, reverse=True)
            top_content[category] = sorted_items[:max_per_category]
        
        return top_content
    
    def match_content_to_findings(self, content_items: List[ContentItem], 
                                scan_findings: List[Dict[str, Any]]) -> List[ContentItem]:
        """
        Match content to specific scan findings for contextual relevance
        
        Args:
            content_items: List of content items
            scan_findings: List of scan findings from Service Screener
            
        Returns:
            List of content items relevant to scan findings
        """
        if not scan_findings:
            return content_items
        
        # Extract keywords from findings
        finding_keywords = set()
        for finding in scan_findings:
            # Extract service names and issue types from findings
            if 'service' in finding:
                finding_keywords.add(finding['service'].lower())
            if 'category' in finding:
                finding_keywords.add(finding['category'].lower())
            if 'description' in finding:
                # Extract key terms from description
                description_words = finding['description'].lower().split()
                finding_keywords.update(word for word in description_words if len(word) > 3)
        
        # Score content based on finding relevance
        relevant_content = []
        for item in content_items:
            content_text = f"{item.title} {item.summary}".lower()
            content_words = set(content_text.split())
            
            # Calculate overlap with finding keywords
            overlap = len(finding_keywords.intersection(content_words))
            if overlap > 0:
                # Boost relevance score based on finding match
                item.relevance_score = min(1.0, item.relevance_score + (overlap * 0.1))
                relevant_content.append(item)
        
        return relevant_content