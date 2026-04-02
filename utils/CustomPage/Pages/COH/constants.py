"""
Constants for Cost Optimization Hub

This module contains configuration constants and mappings used throughout
the Cost Optimization Hub implementation.
"""

# API Configuration
COH_SUPPORTED_REGIONS = [
    'us-east-1', 'us-west-2', 'eu-west-1', 'eu-central-1', 
    'ap-southeast-1', 'ap-northeast-1'
]

# Cost Explorer is global (us-east-1 only)
COST_EXPLORER_REGION = 'us-east-1'

# Savings Plans is global (us-east-1 only)  
SAVINGS_PLANS_REGION = 'us-east-1'

# Data Collection Configuration
DEFAULT_MAX_RECOMMENDATIONS = 1000
DEFAULT_LOOKBACK_DAYS = 30
DEFAULT_CACHE_TTL_SECONDS = 3600  # 1 hour

# Priority Calculation Constants
PRIORITY_THRESHOLDS = {
    'high': 7.0,
    'medium': 3.0,
    'low': 0.0
}

EFFORT_PENALTIES = {
    'low': 0,
    'medium': 2,
    'high': 5
}

# Service Category Mappings
SERVICE_CATEGORIES = {
    'ec2': 'compute',
    'ecs': 'compute',
    'eks': 'compute',
    'lambda': 'compute',
    'fargate': 'compute',
    
    's3': 'storage',
    'ebs': 'storage',
    'efs': 'storage',
    'fsx': 'storage',
    
    'rds': 'database',
    'dynamodb': 'database',
    'redshift': 'database',
    'elasticache': 'database',
    'documentdb': 'database',
    
    'savings_plans': 'commitment',
    'reserved_instances': 'commitment',
    
    'cloudfront': 'networking',
    'elb': 'networking',
    'nat_gateway': 'networking',
    'vpc_endpoint': 'networking'
}

# Implementation Effort Mappings
IMPLEMENTATION_EFFORTS = {
    'VERY_LOW': 'low',
    'LOW': 'low', 
    'MEDIUM': 'medium',
    'HIGH': 'high',
    'VERY_HIGH': 'high'
}

# Confidence Level Mappings
CONFIDENCE_LEVELS = {
    'VERY_LOW': 'low',
    'LOW': 'low',
    'MEDIUM': 'medium', 
    'HIGH': 'high',
    'VERY_HIGH': 'high'
}

# Badge Classes for UI
PRIORITY_BADGE_CLASSES = {
    'high': 'danger',
    'medium': 'warning',
    'low': 'info'
}

EFFORT_BADGE_CLASSES = {
    'low': 'success',
    'medium': 'warning', 
    'high': 'danger'
}

CONFIDENCE_BADGE_CLASSES = {
    'high': 'success',
    'medium': 'warning',
    'low': 'danger'
}

# Category Icons
CATEGORY_ICONS = {
    'compute': 'fas fa-server',
    'storage': 'fas fa-hdd',
    'database': 'fas fa-database',
    'commitment': 'fas fa-handshake',
    'networking': 'fas fa-network-wired',
    'general': 'fas fa-cogs'
}

# Required IAM Permissions by Service
REQUIRED_PERMISSIONS = {
    'cost_optimization_hub': [
        'cost-optimization-hub:ListRecommendations',
        'cost-optimization-hub:GetRecommendation'
    ],
    'cost_explorer': [
        'ce:GetRightsizingRecommendation',
        'ce:GetReservationCoverage',
        'ce:GetSavingsPlanssPurchaseRecommendation',
        'ce:GetSavingsPlansCoverage'
    ],
    'savings_plans': [
        'savingsplans:DescribeSavingsPlans',
        'savingsplans:DescribeSavingsPlansOfferings'
    ]
}

# Error Messages
ERROR_MESSAGES = {
    'opt_in_required': 'Cost Optimization Hub is not enabled in this region. Please enable it in the AWS Console.',
    'access_denied': 'Insufficient permissions to access cost optimization services. Please check IAM permissions.',
    'service_unavailable': 'Cost optimization service is temporarily unavailable. Please try again later.',
    'no_data': 'No cost optimization recommendations found. This may indicate optimal resource usage or insufficient data.',
    'invalid_region': 'Cost Optimization Hub is not available in the specified region.',
    'rate_limited': 'API rate limit exceeded. Please wait before making additional requests.'
}

# Chart Colors for Visualizations
CHART_COLORS = [
    '#FF6384', '#36A2EB', '#FFCE56', '#4BC0C0', '#9966FF',
    '#FF9F40', '#FF6384', '#C9CBCF', '#4BC0C0', '#FF6384'
]

# Export Formats
EXPORT_FORMATS = {
    'csv': 'text/csv',
    'json': 'application/json', 
    'xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
}

# Recommendation Status Options
RECOMMENDATION_STATUSES = [
    'new',
    'reviewed', 
    'approved',
    'implemented',
    'dismissed',
    'deferred'
]