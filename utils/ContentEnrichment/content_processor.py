"""
Content Processor

Validates, sanitizes, and processes content from RSS feeds. Implements HTML
sanitization using bleach library and content categorization logic.
"""

import re
import html
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta

try:
    import bleach
    BLEACH_AVAILABLE = True
except ImportError:
    BLEACH_AVAILABLE = False
    import warnings
    warnings.warn("bleach library not available, using basic HTML sanitization")

from utils.Tools import _pr, _warn
from .base_interfaces import ContentValidator, ContentCategorizer, ContentValidationError
from .models import ContentItem, ContentCategory, WELL_ARCHITECTED_PILLARS, AI_ML_SERVICE_TAGS


class ContentProcessor(ContentValidator, ContentCategorizer):
    """
    Processes and validates content with HTML sanitization and categorization
    """
    
    # Allowed HTML tags for content sanitization
    ALLOWED_TAGS = [
        'p', 'br', 'strong', 'em', 'u', 'i', 'b',
        'ul', 'ol', 'li', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
        'blockquote', 'code', 'pre'
    ]
    
    # Allowed HTML attributes
    ALLOWED_ATTRIBUTES = {
        '*': ['class'],
        'a': ['href', 'title', 'rel', 'target'],
        'img': ['src', 'alt', 'title', 'width', 'height']
    }
    
    def __init__(self):
        """Initialize the content processor"""
        self.validation_stats = {
            'total_processed': 0,
            'validation_failures': 0,
            'sanitization_applied': 0
        }
    
    def process_content_batch(self, content_items: List[ContentItem]) -> List[ContentItem]:
        """
        Process a batch of content items with validation and sanitization
        
        Args:
            content_items: List of content items to process
            
        Returns:
            List of processed and validated content items
        """
        processed_items = []
        
        for item in content_items:
            try:
                if self.validate_content_item(item):
                    processed_item = self.process_single_item(item)
                    if processed_item:
                        processed_items.append(processed_item)
                        self.validation_stats['total_processed'] += 1
                else:
                    self.validation_stats['validation_failures'] += 1
                    _warn(f"Content validation failed for item: {item.id}")
            except Exception as e:
                self.validation_stats['validation_failures'] += 1
                _warn(f"Error processing content item {item.id}: {str(e)}")
        
        _pr(f"Content processing complete. Processed: {len(processed_items)}, "
            f"Failed: {self.validation_stats['validation_failures']}")
        
        return processed_items
    
    def process_single_item(self, content_item: ContentItem) -> Optional[ContentItem]:
        """
        Process a single content item
        
        Args:
            content_item: Content item to process
            
        Returns:
            Processed content item or None if processing fails
        """
        try:
            # Sanitize HTML content
            sanitized_title = self.sanitize_html(content_item.title)
            sanitized_summary = self.sanitize_html(content_item.summary)
            
            # Update content item with sanitized content
            processed_item = ContentItem(
                id=content_item.id,
                title=sanitized_title,
                summary=sanitized_summary,
                url=content_item.url,
                publish_date=content_item.publish_date,
                category=content_item.category,
                source=content_item.source,
                tags=content_item.tags,
                relevance_score=content_item.relevance_score,
                is_new=content_item.is_new,
                is_archived=content_item.is_archived,  # Task 5.4: Include archival status
                difficulty=content_item.difficulty
            )
            
            # Re-categorize content based on processed content
            updated_category = self.categorize_content(processed_item)
            processed_item.category = updated_category
            
            # Extract additional service tags
            additional_tags = self.extract_service_tags(processed_item)
            processed_item.tags = list(set(processed_item.tags + additional_tags))
            
            # Update difficulty for best practices
            if processed_item.category == ContentCategory.BEST_PRACTICES.value:
                processed_item.difficulty = self.extract_difficulty_level(processed_item)
            
            return processed_item
            
        except Exception as e:
            _warn(f"Error processing content item: {str(e)}")
            return None
    
    def validate_content_item(self, content_item: ContentItem) -> bool:
        """
        Validate a ContentItem object
        
        Args:
            content_item: Content item to validate
            
        Returns:
            True if content is valid, False otherwise
        """
        try:
            # Check required fields
            if not content_item.id or not content_item.title or not content_item.url:
                return False
            
            # Validate URL format
            if not self._is_valid_url(content_item.url):
                return False
            
            # Check content length limits
            if len(content_item.title) > 500 or len(content_item.summary) > 2000:
                return False
            
            # Validate publication date (not too far in future)
            if content_item.publish_date > datetime.now() + timedelta(days=1):
                return False
            
            # Validate category
            valid_categories = [cat.value for cat in ContentCategory]
            if content_item.category not in valid_categories:
                return False
            
            return True
            
        except Exception as e:
            _warn(f"Error validating content: {str(e)}")
            return False
    
    def validate_content(self, raw_content: Dict[str, Any]) -> bool:
        """
        Validate raw content dictionary from RSS feed
        
        Args:
            raw_content: Raw content dictionary
            
        Returns:
            True if content is valid, False otherwise
        """
        try:
            # Check required fields
            required_fields = ['title', 'link']
            for field in required_fields:
                if field not in raw_content or not raw_content[field]:
                    return False
            
            # Validate URL
            if not self._is_valid_url(raw_content['link']):
                return False
            
            # Check for reasonable content length
            title = raw_content.get('title', '')
            if len(title) < 5 or len(title) > 500:
                return False
            
            return True
            
        except Exception as e:
            _warn(f"Error validating raw content: {str(e)}")
            return False
    
    def sanitize_html(self, html_content: str) -> str:
        """
        Sanitize HTML content to remove potentially dangerous elements
        
        Args:
            html_content: Raw HTML content
            
        Returns:
            Sanitized HTML content
        """
        if not html_content:
            return ""
        
        try:
            if BLEACH_AVAILABLE:
                # Use bleach for comprehensive sanitization
                sanitized = bleach.clean(
                    html_content,
                    tags=self.ALLOWED_TAGS,
                    attributes=self.ALLOWED_ATTRIBUTES,
                    strip=True
                )
                self.validation_stats['sanitization_applied'] += 1
                return sanitized
            else:
                # Fallback to basic HTML sanitization
                return self._basic_html_sanitize(html_content)
                
        except Exception as e:
            _warn(f"Error sanitizing HTML content: {str(e)}")
            # Return escaped content as fallback
            return html.escape(html_content)
    
    def _basic_html_sanitize(self, html_content: str) -> str:
        """
        Basic HTML sanitization when bleach is not available
        
        Args:
            html_content: Raw HTML content
            
        Returns:
            Sanitized content
        """
        # Remove script and style tags completely
        html_content = re.sub(r'<script[^>]*>.*?</script>', '', html_content, flags=re.DOTALL | re.IGNORECASE)
        html_content = re.sub(r'<style[^>]*>.*?</style>', '', html_content, flags=re.DOTALL | re.IGNORECASE)
        
        # Remove potentially dangerous attributes
        html_content = re.sub(r'on\w+\s*=\s*["\'][^"\']*["\']', '', html_content, flags=re.IGNORECASE)
        html_content = re.sub(r'javascript:', '', html_content, flags=re.IGNORECASE)
        
        # Remove most HTML tags, keeping only basic formatting
        allowed_pattern = r'</?(?:' + '|'.join(self.ALLOWED_TAGS) + r')(?:\s[^>]*)?>|<br\s*/?>'
        html_content = re.sub(r'<(?!/?(?:' + '|'.join(self.ALLOWED_TAGS) + r')\b)[^>]*>', '', html_content)
        
        self.validation_stats['sanitization_applied'] += 1
        return html_content.strip()
    
    def categorize_content(self, content_item: ContentItem) -> str:
        """
        Categorize content based on its metadata and content
        
        Args:
            content_item: Content item to categorize
            
        Returns:
            Category string (ContentCategory value)
        """
        title_lower = content_item.title.lower()
        summary_lower = content_item.summary.lower()
        content_text = f"{title_lower} {summary_lower}"
        
        # Security & Reliability keywords
        security_keywords = [
            'security', 'iam', 'vpc', 'encryption', 'compliance', 'audit',
            'vulnerability', 'threat', 'firewall', 'access control', 'authentication',
            'authorization', 'ssl', 'tls', 'certificate', 'key management',
            'reliability', 'disaster recovery', 'backup', 'failover', 'redundancy'
        ]
        
        # AI/ML & GenAI keywords
        ai_ml_keywords = [
            'machine learning', 'artificial intelligence', 'ai', 'ml', 'genai',
            'generative ai', 'llm', 'large language model', 'neural network',
            'deep learning', 'model training', 'inference', 'sagemaker', 'bedrock',
            'comprehend', 'textract', 'rekognition', 'polly', 'transcribe'
        ]
        
        # Best Practices keywords
        best_practices_keywords = [
            'best practice', 'architecture', 'well-architected', 'design pattern',
            'optimization', 'performance', 'cost optimization', 'operational excellence',
            'sustainability', 'scalability', 'microservices', 'serverless'
        ]
        
        # Count keyword matches for each category
        security_score = sum(1 for keyword in security_keywords if keyword in content_text)
        ai_ml_score = sum(1 for keyword in ai_ml_keywords if keyword in content_text)
        best_practices_score = sum(1 for keyword in best_practices_keywords if keyword in content_text)
        
        # Determine category based on highest score
        if security_score > ai_ml_score and security_score > best_practices_score:
            return ContentCategory.SECURITY_RELIABILITY.value
        elif ai_ml_score > best_practices_score:
            return ContentCategory.AI_ML_GENAI.value
        else:
            return ContentCategory.BEST_PRACTICES.value
    
    def extract_service_tags(self, content_item: ContentItem) -> List[str]:
        """
        Extract AWS service tags from content
        
        Args:
            content_item: Content item to analyze
            
        Returns:
            List of AWS service tags
        """
        content_text = f"{content_item.title} {content_item.summary}".lower()
        extracted_tags = []
        
        # Extract AI/ML service tags
        for service in AI_ML_SERVICE_TAGS:
            if service in content_text:
                extracted_tags.append(service)
        
        # Extract general AWS service tags
        aws_services = [
            'ec2', 's3', 'rds', 'lambda', 'dynamodb', 'cloudformation',
            'cloudwatch', 'iam', 'vpc', 'elb', 'autoscaling', 'route53',
            'cloudfront', 'api gateway', 'sns', 'sqs', 'kinesis', 'redshift',
            'elasticsearch', 'elasticache', 'efs', 'fsx', 'workspaces',
            'connect', 'chime', 'workmail', 'organizations', 'control tower'
        ]
        
        for service in aws_services:
            if service in content_text or service.replace(' ', '') in content_text:
                extracted_tags.append(service)
        
        return extracted_tags
    
    def extract_difficulty_level(self, content_item: ContentItem) -> str:
        """
        Extract difficulty level for best practices content
        
        Args:
            content_item: Content item to analyze
            
        Returns:
            Difficulty level string
        """
        content_text = f"{content_item.title} {content_item.summary}".lower()
        
        # Easy indicators
        easy_indicators = [
            'beginner', 'getting started', 'introduction', 'basic', 'simple',
            'quick start', 'tutorial', 'walkthrough', '101', 'fundamentals'
        ]
        
        # Hard indicators
        hard_indicators = [
            'advanced', 'expert', 'complex', 'enterprise', 'production',
            'deep dive', 'comprehensive', 'sophisticated', 'optimization',
            'troubleshooting', 'debugging', 'performance tuning'
        ]
        
        # Count indicators
        easy_score = sum(1 for indicator in easy_indicators if indicator in content_text)
        hard_score = sum(1 for indicator in hard_indicators if indicator in content_text)
        
        if easy_score > hard_score:
            return 'Easy'
        elif hard_score > easy_score:
            return 'Hard'
        else:
            return 'Medium'
    
    def process_external_link(self, url: str, title: str, target: str = '_blank') -> Dict[str, str]:
        """
        Process external link with security attributes
        
        Args:
            url: The link URL
            title: The link title
            target: The link target (default: _blank)
            
        Returns:
            Dict with processed link attributes
        """
        processed_link = {
            'href': url,
            'title': title,
            'target': target
        }
        
        # Add security attributes for external links
        if target == '_blank':
            processed_link['rel'] = 'noopener noreferrer nofollow'
        
        return processed_link
    
    def _is_valid_url(self, url: str) -> bool:
        """
        Validate URL format and security
        
        Args:
            url: URL to validate
            
        Returns:
            True if URL is valid and secure
        """
        if not url or not isinstance(url, str):
            return False
            
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            
            # Must have scheme and netloc
            if not parsed.scheme or not parsed.netloc:
                return False
                
            # Only allow HTTP/HTTPS
            if parsed.scheme not in ['http', 'https']:
                return False
                
            return True
            
        except Exception:
            return False
    
    def validate_link_security(self, url: str) -> Dict[str, Any]:
        """
        Validate link security based on domain whitelist
        
        Args:
            url: The URL to validate
            
        Returns:
            Dict with validation result and reason
        """
        from urllib.parse import urlparse
        
        try:
            parsed_url = urlparse(url)
            
            # Only HTTPS allowed
            if parsed_url.scheme != 'https':
                return {
                    'allowed': False,
                    'reason': 'non_https_protocol'
                }
            
            # Check trusted domains
            trusted_domains = ['aws.amazon.com', 'amazon.com', 'docs.aws.amazon.com']
            domain = parsed_url.netloc.lower()
            
            is_trusted = any(
                domain == trusted or domain.endswith(f'.{trusted}')
                for trusted in trusted_domains
            )
            
            if is_trusted:
                return {
                    'allowed': True,
                    'reason': 'trusted_domain'
                }
            else:
                return {
                    'allowed': False,
                    'reason': 'untrusted_domain'
                }
                
        except Exception as e:
            return {
                'allowed': False,
                'reason': f'validation_error: {str(e)}'
            }
        """
        Validate URL format
        
        Args:
            url: URL to validate
            
        Returns:
            True if URL is valid, False otherwise
        """
        try:
            from urllib.parse import urlparse
            result = urlparse(url)
            return all([result.scheme, result.netloc]) and result.scheme in ['http', 'https']
        except Exception:
            return False
    
    def get_processing_stats(self) -> Dict[str, int]:
        """
        Get content processing statistics
        
        Returns:
            Dictionary with processing statistics
        """
        return self.validation_stats.copy()
    
    def prioritize_content(self, content_items: List[ContentItem]) -> List[ContentItem]:
        """
        Prioritize content items, putting newer content first and archived content last
        
        Args:
            content_items: List of content items to prioritize
            
        Returns:
            Sorted list with newer content prioritized
        """
        def content_priority_key(item: ContentItem) -> tuple:
            # Priority order: (is_archived, -is_new, -publish_date_timestamp)
            # This ensures: new content first, then regular content, then archived content
            # Within each group, newer content comes first
            return (
                item.is_archived,  # False (0) comes before True (1)
                not item.is_new,   # True (new) becomes False (0), comes first
                -item.publish_date.timestamp()  # Newer dates (higher timestamps) come first
            )
        
        return sorted(content_items, key=content_priority_key)
    
    def reset_stats(self):
        """Reset processing statistics"""
        self.validation_stats = {
            'total_processed': 0,
            'validation_failures': 0,
            'sanitization_applied': 0
        }