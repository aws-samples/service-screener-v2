"""
Base Interfaces for Content Enrichment

Defines abstract base classes and interfaces for the content enrichment system
to ensure consistent implementation across all components.
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from .models import ContentItem, UserContext, UserPreferences


class ContentFetcher(ABC):
    """Abstract base class for content fetching implementations"""
    
    @abstractmethod
    def fetch_content(self, source_url: str, timeout: int = 30) -> List[Dict[str, Any]]:
        """
        Fetch content from a source URL
        
        Args:
            source_url: URL to fetch content from
            timeout: Timeout in seconds for the request
            
        Returns:
            List of raw content items
            
        Raises:
            ContentFetchError: If fetching fails
        """
        pass
    
    @abstractmethod
    def validate_source(self, source_url: str) -> bool:
        """
        Validate that a source URL is from a trusted domain
        
        Args:
            source_url: URL to validate
            
        Returns:
            True if source is trusted, False otherwise
        """
        pass


class ContentValidator(ABC):
    """Abstract base class for content validation implementations"""
    
    @abstractmethod
    def validate_content(self, raw_content: Dict[str, Any]) -> bool:
        """
        Validate raw content structure and required fields
        
        Args:
            raw_content: Raw content dictionary from RSS feed
            
        Returns:
            True if content is valid, False otherwise
        """
        pass
    
    @abstractmethod
    def sanitize_html(self, html_content: str) -> str:
        """
        Sanitize HTML content to remove potentially dangerous elements
        
        Args:
            html_content: Raw HTML content
            
        Returns:
            Sanitized HTML content
        """
        pass


class ContentCategorizer(ABC):
    """Abstract base class for content categorization implementations"""
    
    @abstractmethod
    def categorize_content(self, content_item: ContentItem) -> str:
        """
        Categorize content based on its metadata and content
        
        Args:
            content_item: Content item to categorize
            
        Returns:
            Category string (ContentCategory value)
        """
        pass
    
    @abstractmethod
    def extract_service_tags(self, content_item: ContentItem) -> List[str]:
        """
        Extract AWS service tags from content
        
        Args:
            content_item: Content item to analyze
            
        Returns:
            List of AWS service tags
        """
        pass


class RelevanceScorer(ABC):
    """Abstract base class for content relevance scoring implementations"""
    
    @abstractmethod
    def calculate_relevance(self, content_item: ContentItem, user_context: UserContext) -> float:
        """
        Calculate relevance score for content based on user context
        
        Args:
            content_item: Content item to score
            user_context: User's AWS environment context
            
        Returns:
            Relevance score between 0.0 and 1.0
        """
        pass
    
    @abstractmethod
    def prioritize_content(self, content_items: List[ContentItem], user_context: UserContext) -> List[ContentItem]:
        """
        Sort content items by relevance for the user
        
        Args:
            content_items: List of content items to prioritize
            user_context: User's AWS environment context
            
        Returns:
            Sorted list of content items (highest relevance first)
        """
        pass


class ContentSerializer(ABC):
    """Abstract base class for content serialization implementations"""
    
    @abstractmethod
    def serialize_for_html(self, content_data: Dict[str, List[ContentItem]], 
                          metadata: Dict[str, Any], 
                          preferences: UserPreferences) -> str:
        """
        Serialize content data for embedding in HTML
        
        Args:
            content_data: Dictionary mapping categories to content items
            metadata: Metadata about the content fetch
            preferences: User preferences
            
        Returns:
            JSON string ready for HTML embedding
        """
        pass
    
    @abstractmethod
    def escape_for_html(self, json_data: str) -> str:
        """
        Escape JSON data for safe embedding in HTML
        
        Args:
            json_data: JSON string to escape
            
        Returns:
            HTML-safe JSON string
        """
        pass


# Custom Exceptions
class ContentEnrichmentError(Exception):
    """Base exception for content enrichment errors"""
    pass


class ContentFetchError(ContentEnrichmentError):
    """Exception raised when content fetching fails"""
    pass


class ContentValidationError(ContentEnrichmentError):
    """Exception raised when content validation fails"""
    pass


class ContentProcessingError(ContentEnrichmentError):
    """Exception raised when content processing fails"""
    pass


class ContentSerializationError(ContentEnrichmentError):
    """Exception raised when content serialization fails"""
    pass