"""
Data Models for Content Enrichment

Defines the core data structures used throughout the content enrichment system.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional, Dict, Any
from enum import Enum


class ContentCategory(Enum):
    """Content categories for AWS enrichment content"""
    SECURITY_RELIABILITY = 'security-reliability'
    AI_ML_GENAI = 'ai-ml-genai'
    BEST_PRACTICES = 'best-practices'


class DifficultyLevel(Enum):
    """Implementation difficulty levels for best practices"""
    EASY = 'Easy'
    MEDIUM = 'Medium'
    HARD = 'Hard'


@dataclass
class ContentItem:
    """
    Represents a single piece of enrichment content from AWS sources
    
    This model is used both in Python processing and JavaScript rendering
    after JSON serialization.
    """
    id: str
    title: str
    summary: str
    url: str
    publish_date: datetime
    category: str  # ContentCategory value as string
    source: str
    tags: List[str]
    relevance_score: float
    is_new: bool
    is_archived: bool = False  # Task 5.4: Content older than 30 days
    difficulty: Optional[str] = None  # DifficultyLevel value as string
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            'id': self.id,
            'title': self.title,
            'summary': self.summary,
            'url': self.url,
            'publish_date': self.publish_date.isoformat(),
            'category': self.category,
            'source': self.source,
            'tags': self.tags,
            'relevance_score': self.relevance_score,
            'is_new': self.is_new,
            'is_archived': self.is_archived,  # Task 5.4: Include archival status
            'difficulty': self.difficulty
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ContentItem':
        """Create ContentItem from dictionary"""
        return cls(
            id=data['id'],
            title=data['title'],
            summary=data['summary'],
            url=data['url'],
            publish_date=datetime.fromisoformat(data['publish_date']),
            category=data['category'],
            source=data['source'],
            tags=data['tags'],
            relevance_score=data['relevance_score'],
            is_new=data['is_new'],
            is_archived=data.get('is_archived', False),  # Task 5.4: Handle archival status
            difficulty=data.get('difficulty')
        )


@dataclass
class UserPreferences:
    """User preferences for content display and filtering"""
    enabled_categories: List[str]  # ContentCategory values as strings
    category_priority: List[str]   # ContentCategory values as strings
    max_items_per_category: int
    auto_refresh: bool
    show_new_badges: bool
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            'enabledCategories': self.enabled_categories,
            'categoryPriority': self.category_priority,
            'maxItemsPerCategory': self.max_items_per_category,
            'autoRefresh': self.auto_refresh,
            'showNewBadges': self.show_new_badges
        }
    
    @classmethod
    def get_defaults(cls) -> 'UserPreferences':
        """Get default user preferences"""
        return cls(
            enabled_categories=[
                ContentCategory.SECURITY_RELIABILITY.value,
                ContentCategory.AI_ML_GENAI.value,
                ContentCategory.BEST_PRACTICES.value
            ],
            category_priority=[
                ContentCategory.SECURITY_RELIABILITY.value,
                ContentCategory.BEST_PRACTICES.value,
                ContentCategory.AI_ML_GENAI.value
            ],
            max_items_per_category=5,
            auto_refresh=True,
            show_new_badges=True
        )


@dataclass
class UserContext:
    """Context information about the user's AWS environment"""
    detected_services: List[str]
    scan_findings: List[Dict[str, Any]]
    user_role: Optional[str] = None
    previous_interactions: List[Dict[str, Any]] = None
    
    def __post_init__(self):
        if self.previous_interactions is None:
            self.previous_interactions = []


@dataclass
class EmbeddedContentData:
    """Structure for content data embedded in HTML files"""
    content_data: Dict[str, List[Dict[str, Any]]]  # category -> content items
    metadata: Dict[str, Any]
    user_preferences: Dict[str, Any]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON embedding"""
        return {
            'contentData': self.content_data,
            'metadata': self.metadata,
            'userPreferences': self.user_preferences
        }


# RSS Feed Configuration
AWS_CONTENT_SOURCES = {
    ContentCategory.SECURITY_RELIABILITY.value: [
        'https://aws.amazon.com/blogs/security/feed/',
        'https://aws.amazon.com/blogs/architecture/feed/'
    ],
    ContentCategory.AI_ML_GENAI.value: [
        'https://aws.amazon.com/blogs/machine-learning/feed/',
        'https://aws.amazon.com/blogs/ai/feed/'
    ],
    ContentCategory.BEST_PRACTICES.value: [
        'https://aws.amazon.com/blogs/architecture/feed/',
        'https://aws.amazon.com/about-aws/whats-new/recent/feed/'
    ]
}

# AWS Well-Architected Pillars for best practices categorization
WELL_ARCHITECTED_PILLARS = [
    'operational-excellence',
    'security',
    'reliability', 
    'performance-efficiency',
    'cost-optimization',
    'sustainability'
]

# Service tags for AI/ML content
AI_ML_SERVICE_TAGS = [
    'sagemaker',
    'bedrock',
    'comprehend',
    'textract',
    'rekognition',
    'polly',
    'transcribe',
    'translate',
    'lex',
    'kendra',
    'personalize',
    'forecast',
    'lookout',
    'monitron',
    'healthlake',
    'panorama',
    # New AI/ML services and concepts
    'agentic-ai',
    'agent',
    'agents',
    'quicksuite',
    'quick-suite',
    'generative-ai',
    'genai',
    'llm',
    'large-language-model',
    'foundation-model',
    'claude',
    'titan',
    'anthropic',
    'ai-assistant',
    'chatbot',
    'conversational-ai'
]


@dataclass
class ContentEnrichmentConfig:
    """Configuration for content enrichment system"""
    # AI/ML topics of interest
    ai_ml_topics: List[str]
    # Security topics of interest  
    security_topics: List[str]
    # Best practices topics of interest
    best_practices_topics: List[str]
    # Content sources to fetch from
    enabled_sources: List[str]
    # Maximum items per category
    max_items_per_category: int
    # Content freshness threshold in days
    freshness_threshold_days: int
    
    @classmethod
    def get_defaults(cls) -> 'ContentEnrichmentConfig':
        """Get default configuration"""
        return cls(
            ai_ml_topics=[
                'bedrock', 'sagemaker', 'comprehend', 'textract', 'rekognition',
                'agentic-ai', 'agents', 'quicksuite', 'generative-ai', 'genai',
                'llm', 'foundation-model', 'claude', 'titan', 'anthropic',
                'ai-assistant', 'chatbot', 'conversational-ai'
            ],
            security_topics=[
                'iam', 'vpc', 'security-group', 'encryption', 'compliance',
                'audit', 'guardduty', 'securityhub', 'inspector', 'macie',
                'kms', 'secrets-manager', 'certificate-manager'
            ],
            best_practices_topics=[
                'well-architected', 'cost-optimization', 'performance',
                'reliability', 'security', 'operational-excellence',
                'sustainability', 'architecture', 'design-patterns'
            ],
            enabled_sources=[
                'aws-security-blog',
                'aws-machine-learning-blog', 
                'aws-architecture-blog',
                'aws-whats-new'
            ],
            max_items_per_category=10,
            freshness_threshold_days=90
        )