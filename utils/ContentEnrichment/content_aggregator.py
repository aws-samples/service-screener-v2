"""
Content Aggregator

Fetches RSS feeds from AWS sources with security validation, timeout handling,
and retry logic. Implements HTTPS-only fetching with domain whitelisting.
"""

import requests
import feedparser
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse
from datetime import datetime, timedelta

from utils.Tools import _pr, _warn
from .base_interfaces import ContentFetcher, ContentFetchError
from .models import ContentItem, ContentCategory, AWS_CONTENT_SOURCES
from .error_handler import ContentEnrichmentErrorHandler, ContentEnrichmentCircuitBreaker


class ContentAggregator(ContentFetcher):
    """
    Aggregates content from AWS RSS feeds with security and performance considerations
    """
    
    # Trusted AWS domains for content sources
    TRUSTED_DOMAINS = {
        'aws.amazon.com',
        'amazon.com',
        'docs.aws.amazon.com'
    }
    
    def __init__(self, timeout: int = 30, max_retries: int = 3):
        """
        Initialize the content aggregator
        
        Args:
            timeout: Request timeout in seconds
            max_retries: Maximum number of retry attempts
        """
        self.timeout = timeout
        self.max_retries = max_retries
        self.session = requests.Session()
        
        # Initialize error handling
        self.error_handler = ContentEnrichmentErrorHandler(enable_fallback=True)
        self.circuit_breaker = ContentEnrichmentCircuitBreaker(failure_threshold=3, recovery_timeout=300)
        
        # Configure session for security
        self.session.headers.update({
            'User-Agent': 'AWS-Service-Screener-ContentEnrichment/1.0',
            'Accept': 'application/rss+xml, application/xml, text/xml'
        })
    
    def fetch_aws_content(self) -> Dict[str, List[ContentItem]]:
        """
        Fetch content from all configured AWS RSS sources
        
        Returns:
            Dictionary mapping categories to lists of content items
            
        Raises:
            ContentFetchError: If all content fetching fails
        """
        _pr("Starting AWS content aggregation...")
        
        content_by_category = {}
        fetch_tasks = []
        
        # Prepare fetch tasks for parallel execution
        with ThreadPoolExecutor(max_workers=5) as executor:
            for category, sources in AWS_CONTENT_SOURCES.items():
                for source_url in sources:
                    if self.validate_source(source_url):
                        future = executor.submit(self._fetch_single_source, source_url, category)
                        fetch_tasks.append((future, category, source_url))
                    else:
                        _warn(f"Skipping untrusted source: {source_url}")
            
            # Collect results as they complete
            for future, category, source_url in fetch_tasks:
                try:
                    content_items = future.result(timeout=self.timeout + 10)
                    if content_items:
                        if category not in content_by_category:
                            content_by_category[category] = []
                        content_by_category[category].extend(content_items)
                        _pr(f"Fetched {len(content_items)} items from {source_url}")
                except Exception as e:
                    _warn(f"Failed to fetch content from {source_url}: {str(e)}")
                    # Use error handler for graceful degradation
                    fallback_items = self.error_handler.handle_fetch_error(e, source_url)
                    if fallback_items:
                        if category not in content_by_category:
                            content_by_category[category] = []
                        content_by_category[category].extend(fallback_items)
        
        # Log summary
        total_items = sum(len(items) for items in content_by_category.values())
        _pr(f"Content aggregation complete. Total items: {total_items}")
        
        return content_by_category
    
    def _fetch_single_source(self, source_url: str, category: str) -> List[ContentItem]:
        """
        Fetch content from a single RSS source with retry logic
        
        Args:
            source_url: URL of the RSS feed
            category: Content category for the source
            
        Returns:
            List of content items from the source
        """
        for attempt in range(self.max_retries):
            try:
                return self.fetch_content(source_url, self.timeout)
            except Exception as e:
                if attempt < self.max_retries - 1:
                    wait_time = 2 ** attempt  # Exponential backoff
                    _warn(f"Fetch attempt {attempt + 1} failed for {source_url}, retrying in {wait_time}s: {str(e)}")
                    time.sleep(wait_time)
                else:
                    _warn(f"All fetch attempts failed for {source_url}: {str(e)}")
                    raise ContentFetchError(f"Failed to fetch content from {source_url} after {self.max_retries} attempts")
        
        return []
    
    def fetch_content(self, source_url: str, timeout: int = 30) -> List[ContentItem]:
        """
        Fetch content from a single RSS source
        
        Args:
            source_url: URL to fetch content from
            timeout: Timeout in seconds for the request
            
        Returns:
            List of content items
            
        Raises:
            ContentFetchError: If fetching fails
        """
        # Validate source URL for security compliance
        if not self.validate_source(source_url):
            raise ContentFetchError(f"Source URL failed security validation: {source_url}")
        
        try:
            # Fetch RSS feed with timeout
            response = self.session.get(source_url, timeout=timeout)
            response.raise_for_status()
            
            # Parse RSS feed
            feed = feedparser.parse(response.content)
            
            if feed.bozo and feed.bozo_exception:
                raise ContentFetchError(f"Invalid RSS feed: {feed.bozo_exception}")
            
            # Convert feed entries to ContentItem objects
            content_items = []
            for entry in feed.entries[:20]:  # Limit to 20 most recent items
                try:
                    content_item = self._parse_feed_entry(entry, source_url)
                    if content_item:
                        content_items.append(content_item)
                except Exception as e:
                    _warn(f"Failed to parse feed entry: {str(e)}")
                    continue
            
            return content_items
            
        except requests.exceptions.Timeout:
            raise ContentFetchError(f"Timeout fetching content from {source_url}")
        except requests.exceptions.ConnectionError:
            raise ContentFetchError(f"Connection error fetching content from {source_url}")
        except requests.exceptions.HTTPError as e:
            raise ContentFetchError(f"HTTP error fetching content from {source_url}: {e.response.status_code}")
        except Exception as e:
            raise ContentFetchError(f"Unexpected error fetching content from {source_url}: {str(e)}")
    
    def _parse_feed_entry(self, entry: Any, source_url: str) -> Optional[ContentItem]:
        """
        Parse a single RSS feed entry into a ContentItem
        
        Args:
            entry: RSS feed entry from feedparser
            source_url: Source URL for categorization
            
        Returns:
            ContentItem or None if parsing fails
        """
        try:
            # Extract basic fields
            title = getattr(entry, 'title', '').strip()
            summary = getattr(entry, 'summary', '').strip()
            link = getattr(entry, 'link', '').strip()
            
            # Skip entries missing required fields
            if not title or not link:
                return None
            
            # Parse publication date
            pub_date = datetime.now()
            if hasattr(entry, 'published_parsed') and entry.published_parsed:
                try:
                    pub_date = datetime(*entry.published_parsed[:6])
                except (TypeError, ValueError):
                    pass
            
            # Determine category based on source URL
            category = self._categorize_by_source(source_url)
            
            # Generate unique ID
            content_id = f"{category}_{hash(link)}_{int(pub_date.timestamp())}"
            
            # Extract tags from content
            tags = self._extract_tags(entry, category)
            
            # Determine if content is new (published within last 7 days)
            is_new = (datetime.now() - pub_date) <= timedelta(days=7)
            
            # Determine if content is archived (older than 30 days)
            is_archived = (datetime.now() - pub_date) > timedelta(days=30)
            
            return ContentItem(
                id=content_id,
                title=title,
                summary=summary[:500],  # Limit summary length
                url=link,
                publish_date=pub_date,
                category=category,
                source=self._extract_source_name(source_url),
                tags=tags,
                relevance_score=0.0,  # Will be calculated later
                is_new=is_new,
                is_archived=is_archived,  # Task 5.4: Add archival marking
                difficulty=self._extract_difficulty(entry, category)
            )
            
        except Exception as e:
            _warn(f"Error parsing feed entry: {str(e)}")
            return None
    
    def _categorize_by_source(self, source_url: str) -> str:
        """
        Determine content category based on source URL
        
        Args:
            source_url: RSS feed source URL
            
        Returns:
            Category string
        """
        # Check each category's sources
        for category, sources in AWS_CONTENT_SOURCES.items():
            if source_url in sources:
                return category
        
        # Default categorization based on URL patterns
        if 'security' in source_url.lower():
            return ContentCategory.SECURITY_RELIABILITY.value
        elif 'machine-learning' in source_url.lower() or 'ai' in source_url.lower():
            return ContentCategory.AI_ML_GENAI.value
        elif 'architecture' in source_url.lower() or 'whats-new' in source_url.lower():
            return ContentCategory.BEST_PRACTICES.value
        
        return ContentCategory.BEST_PRACTICES.value  # Default
    
    def _extract_source_name(self, source_url: str) -> str:
        """
        Extract a friendly source name from URL
        
        Args:
            source_url: RSS feed source URL
            
        Returns:
            Friendly source name
        """
        if 'security' in source_url:
            return 'AWS Security Blog'
        elif 'machine-learning' in source_url:
            return 'AWS Machine Learning Blog'
        elif 'ai' in source_url:
            return 'AWS AI Blog'
        elif 'architecture' in source_url:
            return 'AWS Architecture Blog'
        elif 'whats-new' in source_url:
            return "What's New with AWS"
        else:
            return 'AWS Blog'
    
    def _extract_tags(self, entry: Any, category: str) -> List[str]:
        """
        Extract relevant tags from RSS entry
        
        Args:
            entry: RSS feed entry
            category: Content category
            
        Returns:
            List of tags
        """
        tags = []
        
        # Extract tags from RSS entry if available
        if hasattr(entry, 'tags'):
            for tag in entry.tags:
                if hasattr(tag, 'term'):
                    tags.append(tag.term.lower())
        
        # Add category-specific tags based on content
        title_lower = getattr(entry, 'title', '').lower()
        summary_lower = getattr(entry, 'summary', '').lower()
        content_text = f"{title_lower} {summary_lower}"
        
        if category == ContentCategory.AI_ML_GENAI.value:
            # Add AI/ML service tags
            from .models import AI_ML_SERVICE_TAGS
            for service in AI_ML_SERVICE_TAGS:
                if service in content_text:
                    tags.append(service)
            
            # Add specific AI/ML concepts that might appear with different formatting
            ai_ml_concepts = [
                'machine-learning', 'artificial-intelligence', 'deep-learning', 
                'neural-network', 'model-training', 'inference', 'embeddings'
            ]
            for concept in ai_ml_concepts:
                if concept in content_text or concept.replace('-', ' ') in content_text:
                    tags.append(concept)
        
        elif category == ContentCategory.SECURITY_RELIABILITY.value:
            # Add security-related tags
            security_keywords = ['iam', 'vpc', 'security-group', 'encryption', 'compliance', 'audit']
            for keyword in security_keywords:
                if keyword in content_text:
                    tags.append(keyword)
        
        elif category == ContentCategory.BEST_PRACTICES.value:
            # Add Well-Architected pillar tags
            from .models import WELL_ARCHITECTED_PILLARS
            for pillar in WELL_ARCHITECTED_PILLARS:
                if pillar.replace('-', ' ') in content_text:
                    tags.append(pillar)
        
        return list(set(tags))  # Remove duplicates
    
    def get_error_summary(self) -> Dict[str, Any]:
        """
        Get error handling summary for monitoring and debugging
        
        Returns:
            Dictionary with error statistics and circuit breaker state
        """
        return {
            'error_handler': self.error_handler.get_error_summary(),
            'circuit_breaker': self.circuit_breaker.get_state(),
            'scan_should_continue': self.error_handler.should_continue_scan()
        }
    
    def create_empty_enrichment_data_on_failure(self, detected_services: List[str] = None) -> str:
        """
        Create empty enrichment data when all content fetching fails
        
        Args:
            detected_services: List of detected AWS services
            
        Returns:
            JSON string with empty content data for HTML embedding
        """
        return self.error_handler.create_empty_enrichment_data(detected_services)
    
    def _extract_difficulty(self, entry: Any, category: str) -> Optional[str]:
        """
        Extract difficulty level for best practices content
        
        Args:
            entry: RSS feed entry
            category: Content category
            
        Returns:
            Difficulty level string or None
        """
        if category != ContentCategory.BEST_PRACTICES.value:
            return None
        
        content_text = f"{getattr(entry, 'title', '')} {getattr(entry, 'summary', '')}".lower()
        
        # Simple heuristics for difficulty assessment
        if any(word in content_text for word in ['beginner', 'getting started', 'introduction', 'basic']):
            return 'Easy'
        elif any(word in content_text for word in ['advanced', 'expert', 'complex', 'enterprise']):
            return 'Hard'
        else:
            return 'Medium'
    
    def validate_source(self, source_url: str) -> bool:
        """
        Validate that a source URL is from a trusted domain and uses HTTPS
        
        Args:
            source_url: URL to validate
            
        Returns:
            True if source is trusted and secure, False otherwise
        """
        try:
            parsed_url = urlparse(source_url)
            
            # Check HTTPS requirement
            if parsed_url.scheme != 'https':
                _warn(f"Source URL must use HTTPS: {source_url}")
                return False
            
            # Check trusted domain
            domain = parsed_url.netloc.lower()
            
            # Remove 'www.' prefix if present
            if domain.startswith('www.'):
                domain = domain[4:]
            
            # Check if domain is in trusted list or is a subdomain of trusted domain
            for trusted_domain in self.TRUSTED_DOMAINS:
                if domain == trusted_domain or domain.endswith(f'.{trusted_domain}'):
                    return True
            
            _warn(f"Source URL from untrusted domain: {source_url}")
            return False
            
        except Exception as e:
            _warn(f"Error validating source URL {source_url}: {str(e)}")
            return False
    
    def filter_by_services(self, content_items: List[ContentItem], detected_services: List[str]) -> List[ContentItem]:
        """
        Filter content based on detected AWS services
        
        Args:
            content_items: List of content items to filter
            detected_services: List of detected AWS service names
            
        Returns:
            Filtered list of content items relevant to detected services
        """
        if not detected_services:
            return content_items
        
        filtered_items = []
        detected_services_lower = [service.lower() for service in detected_services]
        
        for item in content_items:
            # Check if any detected service appears in content tags or text
            item_text = f"{item.title} {item.summary}".lower()
            item_tags_lower = [tag.lower() for tag in item.tags]
            
            # Check for service matches
            is_relevant = False
            for service in detected_services_lower:
                if (service in item_text or 
                    service in item_tags_lower or
                    any(service in tag for tag in item_tags_lower)):
                    is_relevant = True
                    break
            
            if is_relevant:
                filtered_items.append(item)
        
        return filtered_items
    
    def serialize_for_html(self, content_data: Dict[str, List[ContentItem]], 
                          detected_services: List[str]) -> str:
        """
        Serialize content data for embedding in HTML
        
        Args:
            content_data: Dictionary mapping categories to content items
            detected_services: List of detected AWS services
            
        Returns:
            JSON string ready for HTML embedding
        """
        try:
            # Convert content items to dictionaries
            serialized_data = {}
            for category, items in content_data.items():
                serialized_data[category] = [item.to_dict() for item in items]
            
            # Create embedded data structure
            from .models import EmbeddedContentData, UserPreferences
            
            embedded_data = EmbeddedContentData(
                content_data=serialized_data,
                metadata={
                    'fetchTime': datetime.now().isoformat(),
                    'detectedServices': detected_services,
                    'totalItems': sum(len(items) for items in content_data.values())
                },
                user_preferences=UserPreferences.get_defaults().to_dict()
            )
            
            import json
            return json.dumps(embedded_data.to_dict(), indent=2, default=str)
            
        except Exception as e:
            _warn(f"Error serializing content for HTML: {str(e)}")
            return '{"contentData": {}, "metadata": {}, "userPreferences": {}}'