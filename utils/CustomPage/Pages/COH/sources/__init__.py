"""
Cost Optimization Hub Data Sources

This module contains specialized clients for different AWS cost optimization data sources.
Each source is implemented as a separate module for better maintainability.
"""

from .base_client import BaseOptimizationClient
from .cost_optimization_hub_client import CostOptimizationHubClient
from .cost_explorer_client import CostExplorerClient
from .savings_plans_client import SavingsPlansClient
from .coh_data_processor import COHDataProcessor

__all__ = [
    'CostOptimizationHubClient',
    'CostExplorerClient', 
    'SavingsPlansClient',
    'BaseOptimizationClient',
    'COHDataProcessor'
]