"""
Cost Optimization Hub (COH) Package

This package provides cost optimization functionality for AWS Service Screener,
integrating with multiple AWS cost optimization APIs to provide unified
recommendations and executive reporting.

Main Components:
- COH: Main data collection and processing class
- COHPageBuilder: HTML page generation for cost optimization dashboard
- CostRecommendation: Unified data model for recommendations
- ExecutiveSummary: Executive-level summary and metrics

Usage:
    from utils.CustomPage.Pages.COH import COH, COHPageBuilder
    
    # Create and build cost optimization data
    coh = COH()
    coh.build()
    
    # Generate HTML page
    page_builder = COHPageBuilder()
    page_builder.loadData(coh)
"""

from .COH import COH, CostRecommendation, ExecutiveSummary
from .COHPageBuilder import COHPageBuilder
from . import constants

__version__ = "1.0.0"
__author__ = "AWS Service Screener Team"

__all__ = [
    'COH',
    'COHPageBuilder', 
    'CostRecommendation',
    'ExecutiveSummary',
    'constants'
]