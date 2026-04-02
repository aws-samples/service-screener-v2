"""
Content Enrichment Module

This module provides content aggregation and processing functionality for the
AWS Service Screener dashboard enrichment feature. It fetches curated AWS
content during scan execution and embeds it in generated HTML files for
complete offline compatibility.

Main Components:
- ContentAggregator: Fetches RSS feeds from AWS sources
- ContentProcessor: Validates and processes content
- RelevanceEngine: Scores content based on detected services

Usage:
    from utils.ContentEnrichment import ContentAggregator, ContentProcessor
    
    aggregator = ContentAggregator()
    content = aggregator.fetch_aws_content()
    
    processor = ContentProcessor()
    processed_content = processor.process_content(content)
"""

from .content_aggregator import ContentAggregator
from .content_processor import ContentProcessor
from .relevance_engine import RelevanceEngine
from .error_handler import ContentEnrichmentErrorHandler, ContentEnrichmentCircuitBreaker
from .models import ContentItem, ContentCategory, UserPreferences
from .base_interfaces import (
    ContentFetcher, ContentValidator, ContentCategorizer, 
    RelevanceScorer, ContentSerializer, ContentEnrichmentError
)

__version__ = "1.0.0"
__author__ = "AWS Service Screener Team"

__all__ = [
    'ContentAggregator',
    'ContentProcessor', 
    'RelevanceEngine',
    'ContentEnrichmentErrorHandler',
    'ContentEnrichmentCircuitBreaker',
    'ContentItem',
    'ContentCategory',
    'UserPreferences',
    'ContentFetcher',
    'ContentValidator',
    'ContentCategorizer',
    'RelevanceScorer',
    'ContentSerializer',
    'ContentEnrichmentError'
]