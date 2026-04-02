"""
Error Handler for Content Enrichment

Provides comprehensive error handling and graceful degradation for the content
enrichment system to ensure the Service Screener continues to function even
when content fetching fails.
"""

import logging
from typing import Dict, List, Any, Optional
from datetime import datetime
from utils.Tools import _pr, _warn

from .models import ContentItem, EmbeddedContentData, UserPreferences
from .base_interfaces import ContentEnrichmentError


class ContentEnrichmentErrorHandler:
    """
    Handles errors and provides graceful degradation for content enrichment
    """
    
    def __init__(self, enable_fallback: bool = True):
        """
        Initialize the error handler
        
        Args:
            enable_fallback: Whether to provide fallback content on failures
        """
        self.enable_fallback = enable_fallback
        self.error_stats = {
            'fetch_failures': 0,
            'processing_failures': 0,
            'validation_failures': 0,
            'total_errors': 0,
            'last_error_time': None
        }
    
    def handle_fetch_error(self, error: Exception, source_url: str) -> List[ContentItem]:
        """
        Handle content fetching errors with graceful degradation
        
        Args:
            error: The exception that occurred
            source_url: URL that failed to fetch
            
        Returns:
            Empty list or fallback content items
        """
        self._log_error('fetch', error, {'source_url': source_url})
        
        if self.enable_fallback:
            return self._create_fallback_content(source_url)
        
        return []
    
    def handle_processing_error(self, error: Exception, content_item: ContentItem) -> Optional[ContentItem]:
        """
        Handle content processing errors
        
        Args:
            error: The exception that occurred
            content_item: Content item that failed to process
            
        Returns:
            None or a minimal processed item
        """
        self._log_error('processing', error, {'content_id': content_item.id})
        
        if self.enable_fallback:
            return self._create_minimal_content_item(content_item)
        
        return None
    
    def handle_validation_error(self, error: Exception, content_data: Any) -> bool:
        """
        Handle content validation errors
        
        Args:
            error: The exception that occurred
            content_data: Data that failed validation
            
        Returns:
            False (validation failed)
        """
        self._log_error('validation', error, {'data_type': type(content_data).__name__})
        return False
    
    def create_empty_enrichment_data(self, detected_services: List[str] = None) -> str:
        """
        Create empty enrichment data for HTML embedding when all content fetching fails
        
        Args:
            detected_services: List of detected AWS services
            
        Returns:
            JSON string with empty content data
        """
        try:
            empty_data = EmbeddedContentData(
                content_data={
                    'security-reliability': [],
                    'ai-ml-genai': [],
                    'best-practices': []
                },
                metadata={
                    'fetchTime': datetime.now().isoformat(),
                    'detectedServices': detected_services or [],
                    'totalItems': 0,
                    'enrichmentStatus': 'failed',
                    'errorMessage': 'Content enrichment temporarily unavailable'
                },
                user_preferences=UserPreferences.get_defaults().to_dict()
            )
            
            import json
            return json.dumps(empty_data.to_dict(), indent=2, default=str)
            
        except Exception as e:
            _warn(f"Failed to create empty enrichment data: {str(e)}")
            return '{"contentData": {}, "metadata": {"enrichmentStatus": "failed"}, "userPreferences": {}}'
    
    def should_continue_scan(self) -> bool:
        """
        Determine if the Service Screener scan should continue despite content enrichment failures
        
        Returns:
            True (scan should always continue)
        """
        # Content enrichment failures should never block the main scan
        return True
    
    def get_error_summary(self) -> Dict[str, Any]:
        """
        Get a summary of all errors encountered
        
        Returns:
            Dictionary with error statistics
        """
        return {
            'error_stats': self.error_stats.copy(),
            'total_errors': self.error_stats['total_errors'],
            'last_error': self.error_stats['last_error_time'],
            'scan_impact': 'none'  # Content enrichment errors don't impact scan
        }
    
    def reset_error_stats(self):
        """Reset error statistics"""
        self.error_stats = {
            'fetch_failures': 0,
            'processing_failures': 0,
            'validation_failures': 0,
            'total_errors': 0,
            'last_error_time': None
        }
    
    def _log_error(self, error_type: str, error: Exception, context: Dict[str, Any] = None):
        """
        Log an error with context information
        
        Args:
            error_type: Type of error (fetch, processing, validation)
            error: The exception that occurred
            context: Additional context information
        """
        self.error_stats[f'{error_type}_failures'] += 1
        self.error_stats['total_errors'] += 1
        self.error_stats['last_error_time'] = datetime.now().isoformat()
        
        context_str = f" Context: {context}" if context else ""
        _warn(f"Content enrichment {error_type} error: {str(error)}{context_str}")
        
        # Log to Python logging system for debugging
        logging.warning(f"ContentEnrichment {error_type} error", exc_info=error, extra=context or {})
    
    def _create_fallback_content(self, source_url: str) -> List[ContentItem]:
        """
        Create fallback content when fetching fails
        
        Args:
            source_url: URL that failed to fetch
            
        Returns:
            List with a single fallback content item
        """
        try:
            # Determine category from URL
            category = 'best-practices'  # Default
            if 'security' in source_url.lower():
                category = 'security-reliability'
            elif 'machine-learning' in source_url.lower() or 'ai' in source_url.lower():
                category = 'ai-ml-genai'
            
            fallback_item = ContentItem(
                id=f"fallback_{hash(source_url)}_{int(datetime.now().timestamp())}",
                title="AWS Content Temporarily Unavailable",
                summary="We're experiencing temporary issues fetching the latest AWS content. Please check back later for updates.",
                url="https://aws.amazon.com/",
                publish_date=datetime.now(),
                category=category,
                source="Content Enrichment System",
                tags=["system", "fallback"],
                relevance_score=0.1,  # Low relevance for fallback content
                is_new=False,
                difficulty=None
            )
            
            return [fallback_item]
            
        except Exception as e:
            _warn(f"Failed to create fallback content: {str(e)}")
            return []
    
    def _create_minimal_content_item(self, original_item: ContentItem) -> ContentItem:
        """
        Create a minimal content item when processing fails
        
        Args:
            original_item: Original content item that failed processing
            
        Returns:
            Minimal processed content item
        """
        try:
            # Create minimal item with basic sanitization
            import html
            
            return ContentItem(
                id=original_item.id if original_item.id else f"minimal_{int(datetime.now().timestamp())}",
                title=html.escape(original_item.title[:200]) if original_item.title else "Untitled",
                summary=html.escape(original_item.summary[:300]) if original_item.summary else "",
                url=original_item.url if original_item.url else "https://aws.amazon.com/",
                publish_date=original_item.publish_date if original_item.publish_date else datetime.now(),
                category=original_item.category if original_item.category else 'best-practices',
                source=original_item.source if original_item.source else "AWS",
                tags=original_item.tags[:5] if original_item.tags else [],  # Limit tags
                relevance_score=0.2,  # Low relevance for minimally processed content
                is_new=False,
                difficulty=original_item.difficulty
            )
            
        except Exception as e:
            _warn(f"Failed to create minimal content item: {str(e)}")
            return None


class ContentEnrichmentCircuitBreaker:
    """
    Circuit breaker pattern for content enrichment to prevent cascading failures
    """
    
    def __init__(self, failure_threshold: int = 5, recovery_timeout: int = 300):
        """
        Initialize circuit breaker
        
        Args:
            failure_threshold: Number of failures before opening circuit
            recovery_timeout: Seconds to wait before attempting recovery
        """
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.failure_count = 0
        self.last_failure_time = None
        self.state = 'closed'  # closed, open, half-open
    
    def call(self, func, *args, **kwargs):
        """
        Execute function with circuit breaker protection
        
        Args:
            func: Function to execute
            *args: Function arguments
            **kwargs: Function keyword arguments
            
        Returns:
            Function result or raises CircuitBreakerOpen exception
        """
        if self.state == 'open':
            if self._should_attempt_reset():
                self.state = 'half-open'
            else:
                raise ContentEnrichmentError("Circuit breaker is open - content enrichment disabled")
        
        try:
            result = func(*args, **kwargs)
            self._on_success()
            return result
        except Exception as e:
            self._on_failure()
            raise e
    
    def _should_attempt_reset(self) -> bool:
        """Check if enough time has passed to attempt reset"""
        if self.last_failure_time is None:
            return True
        
        time_since_failure = (datetime.now() - self.last_failure_time).total_seconds()
        return time_since_failure >= self.recovery_timeout
    
    def _on_success(self):
        """Handle successful execution"""
        self.failure_count = 0
        self.state = 'closed'
    
    def _on_failure(self):
        """Handle failed execution"""
        self.failure_count += 1
        self.last_failure_time = datetime.now()
        
        if self.failure_count >= self.failure_threshold:
            self.state = 'open'
            _warn(f"Content enrichment circuit breaker opened after {self.failure_count} failures")
    
    def get_state(self) -> Dict[str, Any]:
        """Get current circuit breaker state"""
        return {
            'state': self.state,
            'failure_count': self.failure_count,
            'last_failure_time': self.last_failure_time.isoformat() if self.last_failure_time else None,
            'failure_threshold': self.failure_threshold,
            'recovery_timeout': self.recovery_timeout
        }