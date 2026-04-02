"""
Cost Optimization Hub (COH) - Refactored Main Class

This is the new, simplified main class that orchestrates data collection
from multiple sources using the modular client architecture.
"""

import json
import time
import threading
import hashlib
from datetime import datetime, timedelta
from collections import defaultdict
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional, Any
from concurrent.futures import ThreadPoolExecutor, as_completed

from services.Service import Service
from utils.Tools import _pr, _warn
from utils.Config import Config
from utils.CustomPage.CustomObject import CustomObject
from .sources import (
    CostOptimizationHubClient,
    CostExplorerClient, 
    SavingsPlansClient
)
from .sources.coh_data_processor import COHDataProcessor


@dataclass
class CostRecommendation:
    """Unified data model for cost optimization recommendations from all sources"""
    id: str
    source: str  # 'coh', 'cost_explorer', 'savings_plans'
    category: str  # 'compute', 'storage', 'database', etc.
    service: str  # 'ec2', 's3', 'rds', etc.
    title: str
    description: str
    
    # Financial Impact
    monthly_savings: float
    annual_savings: float
    confidence_level: str  # 'high', 'medium', 'low'
    
    # Implementation Details
    implementation_effort: str  # 'low', 'medium', 'high'
    implementation_steps: List[str]
    required_permissions: List[str]
    potential_risks: List[str]
    
    # Resource Information
    affected_resources: List[Dict]
    resource_count: int
    
    # Prioritization
    priority_score: float
    priority_level: str  # 'high', 'medium', 'low'
    
    # Metadata
    created_date: str  # ISO format datetime string
    last_updated: str  # ISO format datetime string
    status: str  # 'new', 'reviewed', 'implemented', 'dismissed'


@dataclass
class ExecutiveSummary:
    """Executive-level summary of cost optimization opportunities"""
    total_recommendations: int
    total_monthly_savings: float
    total_annual_savings: float
    high_priority_count: int
    medium_priority_count: int
    low_priority_count: int
    top_categories: List[Dict]
    implementation_roadmap: List[Dict]
    data_freshness: str  # ISO format datetime string


class COH(CustomObject):
    """
    Cost Optimization Hub main class - Refactored
    
    Orchestrates data collection from multiple AWS cost optimization sources
    using a modular client architecture for better maintainability.
    """
    
    def __init__(self):
        super().__init__()
        
        # Initialize specialized clients
        self.coh_client = CostOptimizationHubClient()
        self.cost_explorer_client = CostExplorerClient()
        self.savings_plans_client = SavingsPlansClient()
        
        # Initialize data processor
        self.data_processor = COHDataProcessor()
        
        # Data storage
        self.recommendations = []
        self.executive_summary = None
        self.error_messages = []
        self.data_collection_time = None
        self.data_already_collected = False  # Flag to prevent duplicate collection
        
        # Performance optimization settings
        self.max_recommendations_per_source = 100
        self.supported_regions = ['us-east-1']  # COH is global, only need us-east-1
        self.parallel_execution = True
        self.max_workers = 3  # One for each source
        
        # Caching settings
        self.cache_enabled = True
        self.cache_ttl_minutes = 30
        self.cache_data = {}
        self.cache_timestamps = {}
        self.cache_lock = threading.Lock()
        
        # Circuit breaker settings
        self.circuit_breaker_enabled = True
        self.failure_threshold = 3
        self.recovery_timeout_minutes = 5
        self.circuit_states = {
            'coh': {'failures': 0, 'last_failure': None, 'state': 'closed'},
            'cost_explorer': {'failures': 0, 'last_failure': None, 'state': 'closed'},
            'savings_plans': {'failures': 0, 'last_failure': None, 'state': 'closed'}
        }
        
        # Retry settings
        self.retry_enabled = True
        self.max_retries = 3
        self.base_delay = 1.0  # Base delay for exponential backoff
        self.max_delay = 60.0  # Maximum delay between retries
    
    def setData(self, pre_collected_data):
        """
        Mark that data has already been collected to avoid duplicate API calls.
        Only sets the flag if there's actually meaningful data.
        
        Args:
            pre_collected_data: Previously collected COH data
        """
        # Check if the pre_collected_data actually contains meaningful data
        has_meaningful_data = False
        
        if pre_collected_data:
            for service_data in pre_collected_data.values():
                if (isinstance(service_data, dict) and 
                    service_data.get('recommendations') and 
                    len(service_data.get('recommendations', [])) > 0):
                    has_meaningful_data = True
                    break
        
        if has_meaningful_data:
            self.data_already_collected = True
            _pr("COH: Data already collected, will skip duplicate API calls in build()")
        else:
            self.data_already_collected = False
            _pr("COH: No meaningful pre-collected data found, will perform fresh data collection")
    
    def build(self):
        """
        Main entry point for cost optimization analysis (CustomObject interface)
        
        Collects data from all sources and generates unified recommendations
        with comprehensive error handling and graceful degradation.
        
        Fail-Fast Protection: Sets data_already_collected=True immediately to prevent
        duplicate API calls even if collection fails. This ensures error messages
        are only shown once per scan execution.
        """
        try:
            # Check if data was already collected to avoid duplicate collection
            if self.data_already_collected:
                _pr("COH: Skipping data collection - already completed in previous call")
                return
            
            # Mark as attempted immediately to prevent duplicate calls (fail-fast)
            # This prevents retries even if collection fails
            self.data_already_collected = True
            
            _pr("Starting Cost Optimization Hub analysis...")
            self.data_collection_time = datetime.now().isoformat()
            
            # Clear previous data
            self.recommendations = []
            self.error_messages = []
            
            # Track successful data sources for graceful degradation
            successful_sources = []
            failed_sources = []
            
            # Collect data from all sources with comprehensive error handling
            if self.parallel_execution:
                successful_sources, failed_sources = self._collect_data_parallel_with_graceful_degradation()
            else:
                # Fallback to sequential collection with graceful degradation
                sources = [
                    ('COH', self._collect_coh_recommendations_with_retry),
                    ('Cost Explorer', self._collect_cost_explorer_recommendations_with_retry),
                    ('Savings Plans', self._collect_savings_plans_recommendations_with_retry)
                ]
                
                for source_name, collect_func in sources:
                    try:
                        result = collect_func()
                        if result:
                            successful_sources.append(source_name)
                        else:
                            failed_sources.append(f"{source_name} (no data)")
                    except Exception as e:
                        error_msg = f"{source_name} data collection failed: {str(e)}"
                        _warn(error_msg)
                        self.error_messages.append(error_msg)
                        failed_sources.append(f"{source_name} (error)")
            
            # Graceful degradation based on available data
            self._handle_graceful_degradation(successful_sources, failed_sources)
            
            # Process and prioritize recommendations with error handling
            if self.recommendations:
                try:
                    self._process_unified_recommendations()
                    self._generate_executive_summary()
                    _pr(f"COH analysis completed with {len(self.recommendations)} recommendations from {len(successful_sources)} sources")
                except Exception as e:
                    error_msg = f"Error processing recommendations: {str(e)}"
                    _warn(error_msg)
                    self.error_messages.append(error_msg)
                    # Create minimal executive summary even if processing fails
                    self._create_fallback_executive_summary()
            else:
                _warn("No cost optimization recommendations found from any source")
                self.error_messages.append("No recommendations available from any source")
                # Create empty but valid executive summary
                self._create_empty_executive_summary()
            
            # Note: data_already_collected is already set to True at the start of build()
            # This ensures no retries even if collection fails
            
        except Exception as e:
            error_msg = f"Critical error in COH analysis: {str(e)}"
            _warn(error_msg)
            self.error_messages.append(error_msg)
            # Ensure we always have valid data structures for UI
            self._create_emergency_fallback_data()
            # Keep data_already_collected = True to prevent retries
    
    def _collect_coh_recommendations(self):
        """Collect recommendations from Cost Optimization Hub (us-east-1 only)"""
        try:
            _pr("Collecting Cost Optimization Hub recommendations from us-east-1...")
            
            # COH is a global service, us-east-1 endpoint provides all recommendations
            region = 'us-east-1'
            try:
                recommendations = self.coh_client.list_recommendations(
                    region=region,
                    max_results=self.max_recommendations_per_source
                )
                
                if recommendations:
                    _pr(f"Found {len(recommendations)} COH recommendations")
                    
                    # Transform COH recommendations to unified format
                    for rec in recommendations:
                        try:
                            unified_rec = self._transform_coh_recommendation(rec)
                            if unified_rec:
                                self.recommendations.append(unified_rec)
                        except Exception as e:
                            _warn(f"Error transforming COH recommendation: {str(e)}")
                else:
                    _pr("No COH recommendations found")
                        
            except Exception as e:
                error_msg = f"Error collecting COH recommendations: {str(e)}"
                _warn(error_msg)
                self.error_messages.append(error_msg)
            
        except Exception as e:
            error_msg = f"Error in COH data collection: {str(e)}"
            _warn(error_msg)
            self.error_messages.append(error_msg)
    
    def _collect_cost_explorer_recommendations(self):
        """Collect recommendations from Cost Explorer"""
        try:
            _pr("Collecting Cost Explorer recommendations...")
            
            # Get rightsizing recommendations
            rightsizing_recs = self.cost_explorer_client.get_rightsizing_recommendations()
            
            if rightsizing_recs:
                _pr(f"Found {len(rightsizing_recs)} rightsizing recommendations")
                
                # Transform to unified format
                for rec in rightsizing_recs:
                    try:
                        unified_rec = self._transform_cost_explorer_recommendation(rec)
                        if unified_rec:
                            self.recommendations.append(unified_rec)
                    except Exception as e:
                        _warn(f"Error transforming Cost Explorer recommendation: {str(e)}")
            
        except Exception as e:
            error_msg = f"Error in Cost Explorer data collection: {str(e)}"
            _warn(error_msg)
            self.error_messages.append(error_msg)
    
    def _collect_savings_plans_recommendations(self):
        """Collect recommendations from Savings Plans"""
        try:
            _pr("Collecting Savings Plans recommendations...")
            
            # Analyze savings opportunities
            analysis = self.savings_plans_client.analyze_savings_opportunities()
            
            if analysis.get('total_recommendations', 0) > 0:
                _pr(f"Found {analysis['total_recommendations']} Savings Plans opportunities")
                
                # Transform best recommendations to unified format
                for term in ['1_year', '3_year']:
                    for rec in analysis['recommendations_by_term'].get(term, [])[:5]:  # Top 5 per term
                        try:
                            unified_rec = self._transform_savings_plans_recommendation(rec)
                            if unified_rec:
                                self.recommendations.append(unified_rec)
                        except Exception as e:
                            _warn(f"Error transforming Savings Plans recommendation: {str(e)}")
            
        except Exception as e:
            error_msg = f"Error in Savings Plans data collection: {str(e)}"
            _warn(error_msg)
            self.error_messages.append(error_msg)
    
    def _transform_coh_recommendation(self, rec):
        """Transform COH API recommendation to unified format using data processor"""
        try:
            # Use the data processor to normalize the recommendation
            normalized_rec = self.data_processor.normalize_coh_recommendation(rec)
            
            # Convert to CostRecommendation dataclass format
            return CostRecommendation(
                id=normalized_rec['id'],
                source=normalized_rec['source'],
                category=normalized_rec['category'],
                service=normalized_rec['service'],
                title=normalized_rec['title'],
                description=normalized_rec['description'],
                monthly_savings=normalized_rec['estimatedMonthlySavings'],
                annual_savings=normalized_rec['annualSavings'],
                confidence_level='high',
                implementation_effort=normalized_rec['implementationEffort'].lower(),
                implementation_steps=[],
                required_permissions=[],
                potential_risks=[],
                affected_resources=normalized_rec['affectedResources'],
                resource_count=normalized_rec['resourceCount'],
                priority_score=0.0,
                priority_level='medium',
                created_date=datetime.now().isoformat(),
                last_updated=datetime.now().isoformat(),
                status=normalized_rec['status']
            )
        except Exception as e:
            _warn(f"Error transforming COH recommendation: {str(e)}")
            return None
    
    def _transform_cost_explorer_recommendation(self, rec):
        """Transform Cost Explorer recommendation to unified format"""
        try:
            current_instance = rec.get('CurrentInstance', {})
            
            return CostRecommendation(
                id=f"ce_{current_instance.get('ResourceId', int(datetime.now().timestamp()))}",
                source='cost_explorer',
                category='compute',
                service='ec2',
                title=f"Rightsize {current_instance.get('InstanceName', 'EC2 Instance')}",
                description=f"Optimize instance type from {current_instance.get('InstanceType', 'current')} for better cost efficiency",
                monthly_savings=float(rec.get('EstimatedMonthlySavings', 0)),
                annual_savings=float(rec.get('EstimatedMonthlySavings', 0)) * 12,
                confidence_level='high',
                implementation_effort='medium',
                implementation_steps=[],
                required_permissions=[],
                potential_risks=[],
                affected_resources=[{
                    'id': current_instance.get('ResourceId', ''),
                    'type': 'EC2Instance',
                    'region': rec.get('_region', 'us-east-1')
                }],
                resource_count=1,
                priority_score=0.0,
                priority_level='medium',
                created_date=datetime.now().isoformat(),
                last_updated=datetime.now().isoformat(),
                status='new'
            )
        except Exception as e:
            _warn(f"Error transforming Cost Explorer recommendation: {str(e)}")
            return None
    
    def _transform_savings_plans_recommendation(self, rec):
        """Transform Savings Plans recommendation to unified format"""
        try:
            return CostRecommendation(
                id=f"sp_{rec.get('_term_years', 1)}y_{int(datetime.now().timestamp())}",
                source='savings_plans',
                category='commitment',
                service='savings_plans',
                title=f"{rec.get('_term_years', 1)}-Year Savings Plan",
                description=f"Purchase {rec.get('_term_years', 1)}-year Savings Plan for compute workloads",
                monthly_savings=float(rec.get('EstimatedMonthlySavings', 0)),
                annual_savings=float(rec.get('EstimatedMonthlySavings', 0)) * 12,
                confidence_level='high',
                implementation_effort='low',
                implementation_steps=[],
                required_permissions=[],
                potential_risks=[],
                affected_resources=[],
                resource_count=0,
                priority_score=0.0,
                priority_level='high',
                created_date=datetime.now().isoformat(),
                last_updated=datetime.now().isoformat(),
                status='new'
            )
        except Exception as e:
            _warn(f"Error transforming Savings Plans recommendation: {str(e)}")
            return None
    
    def _process_recommendations(self):
        """Process and prioritize all recommendations"""
        try:
            # Calculate priority scores
            for rec in self.recommendations:
                rec.priority_score = self._calculate_priority_score(rec)
                rec.priority_level = self._determine_priority_level(rec.priority_score)
            
            # Sort by priority score (highest first)
            self.recommendations.sort(key=lambda x: x.priority_score, reverse=True)
            
        except Exception as e:
            _warn(f"Error processing recommendations: {str(e)}")
    
    def _generate_executive_summary(self):
        """Generate executive summary from all recommendations with data quality monitoring."""
        try:
            # Add data quality monitoring
            self._add_data_quality_monitoring()
            
            total_monthly_savings = sum(rec.monthly_savings for rec in self.recommendations)
            total_annual_savings = total_monthly_savings * 12
            
            # Count by priority
            priority_counts = {'high': 0, 'medium': 0, 'low': 0}
            for rec in self.recommendations:
                priority_counts[rec.priority_level] += 1
            
            # Top categories
            category_savings = defaultdict(float)
            for rec in self.recommendations:
                category_savings[rec.category] += rec.monthly_savings
            
            top_categories = [
                {'category': cat, 'savings': savings}
                for cat, savings in sorted(category_savings.items(), key=lambda x: x[1], reverse=True)[:5]
            ]
            
            # Implementation roadmap based on priority and effort
            roadmap = self._generate_implementation_roadmap()
            
            self.executive_summary = ExecutiveSummary(
                total_recommendations=len(self.recommendations),
                total_monthly_savings=total_monthly_savings,
                total_annual_savings=total_annual_savings,
                high_priority_count=priority_counts['high'],
                medium_priority_count=priority_counts['medium'],
                low_priority_count=priority_counts['low'],
                top_categories=top_categories,
                implementation_roadmap=roadmap,
                data_freshness=self.data_collection_time
            )
            
        except Exception as e:
            _warn(f"Error generating executive summary: {str(e)}")
    
    def _generate_implementation_roadmap(self):
        """Generate implementation roadmap based on priority and effort."""
        try:
            roadmap = []
            
            # Phase 1: High priority, low effort (quick wins)
            quick_wins = [rec for rec in self.recommendations 
                         if rec.priority_level == 'high' and rec.implementation_effort == 'low']
            if quick_wins:
                roadmap.append({
                    'phase': 'Phase 1: Quick Wins',
                    'timeframe': '0-30 days',
                    'count': len(quick_wins),
                    'total_savings': sum(rec.monthly_savings for rec in quick_wins),
                    'description': 'High-impact, low-effort optimizations'
                })
            
            # Phase 2: High priority, medium effort
            high_impact = [rec for rec in self.recommendations 
                          if rec.priority_level == 'high' and rec.implementation_effort == 'medium']
            if high_impact:
                roadmap.append({
                    'phase': 'Phase 2: High Impact',
                    'timeframe': '1-3 months',
                    'count': len(high_impact),
                    'total_savings': sum(rec.monthly_savings for rec in high_impact),
                    'description': 'High-impact optimizations requiring moderate effort'
                })
            
            # Phase 3: Medium priority or high effort
            strategic = [rec for rec in self.recommendations 
                        if (rec.priority_level == 'medium') or 
                           (rec.priority_level == 'high' and rec.implementation_effort == 'high')]
            if strategic:
                roadmap.append({
                    'phase': 'Phase 3: Strategic',
                    'timeframe': '3-6 months',
                    'count': len(strategic),
                    'total_savings': sum(rec.monthly_savings for rec in strategic),
                    'description': 'Strategic optimizations for long-term savings'
                })
            
            return roadmap
            
        except Exception as e:
            _warn(f"Error generating implementation roadmap: {str(e)}")
            return []
    
    def _map_category(self, category):
        """Map service category to standardized category"""
        mapping = {
            'compute': 'compute',
            'storage': 'storage',
            'database': 'database',
            'networking': 'networking',
            'cost_optimization': 'general'
        }
        return mapping.get(category.lower(), 'general')
    
    def _map_effort(self, effort):
        """Map implementation effort to standardized levels"""
        mapping = {
            'VERY_LOW': 'low',
            'LOW': 'low',
            'MEDIUM': 'medium',
            'HIGH': 'high',
            'VERY_HIGH': 'high'
        }
        return mapping.get(effort.upper(), 'medium')
    
    def _calculate_priority_score(self, rec):
        """Calculate priority score for recommendation"""
        score = 0.0
        
        # Savings impact (0-50 points)
        if rec.monthly_savings >= 1000:
            score += 50
        elif rec.monthly_savings >= 500:
            score += 40
        elif rec.monthly_savings >= 100:
            score += 30
        elif rec.monthly_savings >= 50:
            score += 20
        else:
            score += 10
        
        # Implementation effort (0-30 points, inverse)
        effort_scores = {'low': 30, 'medium': 20, 'high': 10}
        score += effort_scores.get(rec.implementation_effort, 20)
        
        # Confidence level (0-20 points)
        confidence_scores = {'high': 20, 'medium': 15, 'low': 10}
        score += confidence_scores.get(rec.confidence_level, 15)
        
        return score
    
    def _determine_priority_level(self, score):
        """Determine priority level from score"""
        if score >= 80:
            return 'high'
        elif score >= 50:
            return 'medium'
        else:
            return 'low'
    
    def get_data_for_ui(self):
        """Get data formatted for UI consumption with enhanced error handling and graceful degradation"""
        try:
            # Convert recommendations to dictionaries with enhanced fields
            recommendations_data = []
            
            for rec in self.recommendations:
                try:
                    rec_dict = asdict(rec)
                    
                    # Add enhanced fields if this is a COH recommendation
                    if rec.source == 'coh':
                        try:
                            # Get the original raw recommendation to extract enhanced fields
                            # For now, we'll add placeholder enhanced fields
                            rec_dict.update({
                                'topRecommendedAction': self._extract_top_action_from_description(rec.description),
                                'recommendedResourceSummary': self._extract_resource_summary_from_description(rec.description),
                                'currentResourceSummary': self._extract_current_summary_from_resources(rec.affected_resources),
                                'estimatedSavingsPercentage': self._calculate_savings_percentage(rec.monthly_savings),
                                'resourceType': self._extract_resource_type_from_resources(rec.affected_resources)
                            })
                        except Exception as e:
                            _warn(f"Error adding enhanced fields to COH recommendation {rec.id}: {str(e)}")
                            # Continue with basic recommendation data
                    
                    recommendations_data.append(rec_dict)
                    
                except Exception as e:
                    _warn(f"Error processing recommendation {getattr(rec, 'id', 'unknown')}: {str(e)}")
                    # Skip this recommendation but continue with others
                    continue
            
            # Ensure executive summary is available
            executive_summary_data = {}
            if self.executive_summary:
                try:
                    executive_summary_data = asdict(self.executive_summary)
                except Exception as e:
                    _warn(f"Error formatting executive summary: {str(e)}")
                    # Create minimal executive summary
                    executive_summary_data = {
                        'total_recommendations': len(recommendations_data),
                        'total_monthly_savings': sum(rec.get('monthly_savings', 0) for rec in recommendations_data),
                        'total_annual_savings': sum(rec.get('annual_savings', 0) for rec in recommendations_data),
                        'high_priority_count': len([r for r in recommendations_data if r.get('priority_level') == 'high']),
                        'medium_priority_count': len([r for r in recommendations_data if r.get('priority_level') == 'medium']),
                        'low_priority_count': len([r for r in recommendations_data if r.get('priority_level') == 'low']),
                        'top_categories': [],
                        'implementation_roadmap': [],
                        'data_freshness': self.data_collection_time or datetime.now().isoformat()
                    }
            
            # Add data quality indicators
            data_quality = self._assess_data_quality(recommendations_data)
            
            return {
                'executive_summary': executive_summary_data,
                'recommendations': recommendations_data,
                'error_messages': self.error_messages or [],
                'data_collection_time': self.data_collection_time or datetime.now().isoformat(),
                'data_quality': data_quality,
                'data_quality_summary': getattr(self, 'data_quality_summary', {}),
                'graceful_degradation_info': self._get_degradation_info()
            }
            
        except Exception as e:
            error_msg = f"Critical error formatting data for UI: {str(e)}"
            _warn(error_msg)
            
            # Return minimal valid data structure
            return {
                'executive_summary': {
                    'total_recommendations': 0,
                    'total_monthly_savings': 0.0,
                    'total_annual_savings': 0.0,
                    'high_priority_count': 0,
                    'medium_priority_count': 0,
                    'low_priority_count': 0,
                    'top_categories': [],
                    'implementation_roadmap': [],
                    'data_freshness': datetime.now().isoformat()
                },
                'recommendations': [],
                'error_messages': [error_msg] + (self.error_messages or []),
                'data_collection_time': datetime.now().isoformat(),
                'data_quality': {'status': 'error', 'completeness': 0.0, 'reliability': 0.0},
                'data_quality_summary': {
                    'total_processed': 0,
                    'valid_recommendations': 0,
                    'removed_recommendations': 0,
                    'validation_errors': [error_msg],
                    'quality_score': 0.0
                },
                'graceful_degradation_info': {'status': 'failed', 'available_sources': [], 'failed_sources': ['all']}
            }
    
    def _assess_data_quality(self, recommendations_data):
        """Assess the quality of collected data for UI display."""
        try:
            total_expected_sources = 3  # COH, Cost Explorer, Savings Plans
            available_sources = set()
            
            for rec in recommendations_data:
                source = rec.get('source', 'unknown')
                available_sources.add(source)
            
            completeness = len(available_sources) / total_expected_sources
            
            # Assess reliability based on error count and data consistency
            error_count = len(self.error_messages)
            reliability = max(0.0, 1.0 - (error_count * 0.1))  # Reduce by 10% per error
            
            # Overall status
            if completeness >= 0.8 and reliability >= 0.8:
                status = 'excellent'
            elif completeness >= 0.6 and reliability >= 0.6:
                status = 'good'
            elif completeness >= 0.3 and reliability >= 0.4:
                status = 'fair'
            else:
                status = 'poor'
            
            return {
                'status': status,
                'completeness': round(completeness, 2),
                'reliability': round(reliability, 2),
                'available_sources': list(available_sources),
                'total_recommendations': len(recommendations_data),
                'error_count': error_count
            }
            
        except Exception as e:
            _warn(f"Error assessing data quality: {str(e)}")
            return {
                'status': 'unknown',
                'completeness': 0.0,
                'reliability': 0.0,
                'available_sources': [],
                'total_recommendations': 0,
                'error_count': len(self.error_messages) if self.error_messages else 0
            }
    
    def _get_degradation_info(self):
        """Get information about graceful degradation status."""
        try:
            # Analyze error messages to determine degradation status
            source_errors = {
                'coh': any('coh' in msg.lower() for msg in self.error_messages),
                'cost_explorer': any('cost explorer' in msg.lower() for msg in self.error_messages),
                'savings_plans': any('savings plans' in msg.lower() for msg in self.error_messages)
            }
            
            failed_sources = [source for source, has_error in source_errors.items() if has_error]
            available_sources = [source for source, has_error in source_errors.items() if not has_error]
            
            if not failed_sources:
                status = 'full_service'
            elif len(failed_sources) == 1:
                status = 'partial_degradation'
            elif len(failed_sources) == 2:
                status = 'significant_degradation'
            else:
                status = 'minimal_service'
            
            return {
                'status': status,
                'available_sources': available_sources,
                'failed_sources': failed_sources,
                'recommendation_count': len(self.recommendations),
                'has_executive_summary': self.executive_summary is not None
            }
            
        except Exception as e:
            _warn(f"Error getting degradation info: {str(e)}")
            return {
                'status': 'unknown',
                'available_sources': [],
                'failed_sources': [],
                'recommendation_count': 0,
                'has_executive_summary': False
            }
    
    def _extract_top_action_from_description(self, description):
        """Extract top recommended action from description"""
        if 'delete' in description.lower() or 'terminate' in description.lower():
            return 'Delete idle or unused resources'
        elif 'graviton' in description.lower() or 'migrate' in description.lower():
            return 'Migrate to Graviton'
        elif 'rightsize' in description.lower():
            return 'Rightsize instance'
        else:
            return 'Optimize resource configuration'
    
    def _extract_resource_summary_from_description(self, description):
        """Extract recommended resource summary from description"""
        if 'volume' in description.lower() and 'delete' in description.lower():
            return "Detach volume from instance, create a snapshot and delete."
        elif 'graviton' in description.lower():
            return "t4g.micro"
        else:
            return description[:100] + "..." if len(description) > 100 else description
    
    def _extract_current_summary_from_resources(self, resources):
        """Extract current resource summary from affected resources"""
        if not resources:
            return "Current configuration"
        
        resource_ids = []
        for resource in resources[:3]:  # Limit to first 3
            if isinstance(resource, dict):
                resource_id = resource.get('id', resource.get('arn', ''))
                if resource_id:
                    # Extract just the resource ID part
                    if resource_id.startswith('arn:'):
                        parts = resource_id.split(':')
                        if len(parts) >= 6:
                            resource_ids.append(parts[-1])
                    else:
                        resource_ids.append(resource_id)
        
        return ', '.join(resource_ids) if resource_ids else "Current configuration"
    
    def _calculate_savings_percentage(self, monthly_savings):
        """Calculate estimated savings percentage"""
        # This is a simplified calculation - in reality, you'd need the current cost
        # For now, assume 100% savings for delete actions, 20% for others
        if monthly_savings > 0:
            return 100  # Placeholder - should be calculated based on current cost
        return 0
    
    def _extract_resource_type_from_resources(self, resources):
        """Extract resource type from affected resources"""
        if not resources:
            return "Unknown"
    
    def recordItem(self, driver, name, results, inventoryInfo):
        """
        Record item method required by CustomPage framework
        This method is called for each service evaluation result
        """
        try:
            # For COH, we don't need to record individual service items
            # as we collect data directly from AWS Cost Optimization Hub
            pass
        except Exception as e:
            _warn(f"Error recording item in COH: {str(e)}")
            pass
    
    def printInfo(self, service):
        """
        Print info method required by CustomPage framework
        Returns JSON data for the COH service
        
        NOTE: COH data is account-wide, not service-specific, so we don't build here.
        Build happens later in buildPage() after all services are scanned.
        """
        try:
            # Return None to skip per-service file generation
            # COH data will be generated once during buildPage()
            if not self.recommendations and not self.data_already_collected:
                return None
            
            # Return the data formatted for UI consumption
            return json.dumps(self.get_data_for_ui(), indent=2, default=str)
        except Exception as e:
            _warn(f"Error generating COH output: {str(e)}")
            return json.dumps({
                'executive_summary': {},
                'recommendations': [],
                'error_messages': [f"Error generating COH data: {str(e)}"],
                'data_collection_time': None
            }, indent=2)
    
    def cross_reference_with_service_screener(self):
        """
        Create cross-references between cost optimization recommendations and Service Screener findings.
        
        Returns:
            dict: Cross-reference analysis with integrated recommendations and conflicts
        """
        try:
            # Get Service Screener findings from Config (if available)
            service_screener_data = Config.get('service_screener_findings', {})
            
            integrated_recommendations = []
            cost_security_conflicts = []
            complementary_actions = []
            resource_overlap_analysis = {}
            unified_action_plans = []
            
            # Analyze each cost recommendation for security implications
            for cost_rec in self.recommendations:
                # Find overlapping resources in security findings
                overlapping_security_findings = self._find_overlapping_security_findings(
                    cost_rec, service_screener_data
                )
                
                if overlapping_security_findings:
                    # Create integrated recommendation
                    integrated_rec = self._create_integrated_recommendation(
                        cost_rec, overlapping_security_findings
                    )
                    integrated_recommendations.append(integrated_rec)
                    
                    # Check for conflicts
                    conflicts = self._identify_cost_security_conflicts(
                        cost_rec, overlapping_security_findings
                    )
                    if conflicts:
                        cost_security_conflicts.extend(conflicts)
                    
                    # Identify complementary actions
                    complementary = self._identify_complementary_actions(
                        cost_rec, overlapping_security_findings
                    )
                    if complementary:
                        complementary_actions.extend(complementary)
                
                # Track resource overlap
                for resource in cost_rec.affected_resources:
                    resource_id = resource.get('id', '')
                    if resource_id:
                        if resource_id not in resource_overlap_analysis:
                            resource_overlap_analysis[resource_id] = {
                                'cost_recommendations': [],
                                'security_findings': [],
                                'risk_level': 'low'
                            }
                        resource_overlap_analysis[resource_id]['cost_recommendations'].append({
                            'id': cost_rec.id,
                            'title': cost_rec.title,
                            'monthly_savings': cost_rec.monthly_savings,
                            'implementation_effort': cost_rec.implementation_effort
                        })
            
            # Create unified action plans for high-impact resources
            for resource_id, overlap_data in resource_overlap_analysis.items():
                if (len(overlap_data['cost_recommendations']) > 0 and 
                    len(overlap_data['security_findings']) > 0):
                    
                    unified_plan = self._create_unified_action_plan(resource_id, overlap_data)
                    unified_action_plans.append(unified_plan)
            
            # Generate summary
            summary = {
                'total_cost_recommendations': len(self.recommendations),
                'total_security_findings': len(service_screener_data),
                'total_overlapping_resources': len([r for r in resource_overlap_analysis.values() 
                                                  if len(r['cost_recommendations']) > 0 and len(r['security_findings']) > 0]),
                'integrated_recommendations_count': len(integrated_recommendations),
                'conflicts_identified': len(cost_security_conflicts),
                'complementary_actions_count': len(complementary_actions)
            }
            
            return {
                'integrated_recommendations': integrated_recommendations,
                'cost_security_conflicts': cost_security_conflicts,
                'complementary_actions': complementary_actions,
                'resource_overlap_analysis': resource_overlap_analysis,
                'unified_action_plans': unified_action_plans,
                'summary': summary
            }
            
        except Exception as e:
            _warn(f"Error in Service Screener cross-reference: {str(e)}")
            return {
                'integrated_recommendations': [],
                'cost_security_conflicts': [],
                'complementary_actions': [],
                'resource_overlap_analysis': {},
                'unified_action_plans': [],
                'summary': {
                    'total_cost_recommendations': len(self.recommendations),
                    'total_security_findings': 0,
                    'total_overlapping_resources': 0,
                    'integrated_recommendations_count': 0,
                    'conflicts_identified': 0,
                    'complementary_actions_count': 0
                }
            }
    
    def _find_overlapping_security_findings(self, cost_rec, service_screener_data):
        """Find security findings that affect the same resources as the cost recommendation."""
        overlapping_findings = []
        
        # Extract resource IDs from cost recommendation
        cost_resource_ids = set()
        for resource in cost_rec.affected_resources:
            resource_id = resource.get('id', '')
            if resource_id:
                cost_resource_ids.add(resource_id)
        
        # Search through service screener data for overlapping resources
        # This is a simplified implementation - in practice, you'd need to match
        # the actual structure of Service Screener findings
        for service, findings in service_screener_data.items():
            if isinstance(findings, dict) and 'findings' in findings:
                for finding in findings['findings']:
                    finding_resources = set()
                    
                    # Extract resource IDs from finding (structure may vary)
                    if 'resource_id' in finding:
                        finding_resources.add(finding['resource_id'])
                    if 'resources' in finding:
                        for res in finding['resources']:
                            if isinstance(res, str):
                                finding_resources.add(res)
                            elif isinstance(res, dict) and 'id' in res:
                                finding_resources.add(res['id'])
                    
                    # Check for overlap
                    if cost_resource_ids.intersection(finding_resources):
                        overlapping_findings.append({
                            'service': service,
                            'finding': finding,
                            'overlapping_resources': list(cost_resource_ids.intersection(finding_resources))
                        })
        
        return overlapping_findings
    
    def _create_integrated_recommendation(self, cost_rec, security_findings):
        """Create an integrated recommendation combining cost and security aspects."""
        return {
            'recommendation_id': f"integrated_{cost_rec.id}",
            'title': f"Integrated Optimization: {cost_rec.title}",
            'cost_component': {
                'monthly_savings': cost_rec.monthly_savings,
                'annual_savings': cost_rec.annual_savings,
                'implementation_effort': cost_rec.implementation_effort,
                'priority_level': cost_rec.priority_level
            },
            'security_component': {
                'affected_findings': len(security_findings),
                'severity': self._determine_max_severity(security_findings),
                'security_services': list(set(f['service'] for f in security_findings))
            },
            'integrated_steps': self._create_integrated_implementation_steps(cost_rec, security_findings),
            'priority': self._calculate_integrated_priority(cost_rec, security_findings),
            'affected_resources': cost_rec.affected_resources
        }
    
    def _identify_cost_security_conflicts(self, cost_rec, security_findings):
        """Identify potential conflicts between cost optimization and security requirements."""
        conflicts = []
        
        # Common conflict patterns
        conflict_patterns = {
            'encryption': {
                'cost_keywords': ['unencrypted', 'standard', 'basic'],
                'security_keywords': ['encryption', 'kms', 'ssl', 'tls'],
                'description': 'Cost optimization may reduce encryption capabilities'
            },
            'monitoring': {
                'cost_keywords': ['disable', 'reduce', 'minimal'],
                'security_keywords': ['logging', 'monitoring', 'cloudtrail', 'cloudwatch'],
                'description': 'Cost reduction may impact security monitoring'
            },
            'access_control': {
                'cost_keywords': ['public', 'open', 'unrestricted'],
                'security_keywords': ['iam', 'policy', 'access', 'permission'],
                'description': 'Cost optimization may affect access controls'
            }
        }
        
        cost_description = (cost_rec.description or '').lower()
        cost_steps = ' '.join(cost_rec.implementation_steps or []).lower()
        
        for finding_data in security_findings:
            finding = finding_data['finding']
            finding_description = (finding.get('description', '') or finding.get('title', '')).lower()
            
            for conflict_type, pattern in conflict_patterns.items():
                cost_has_keywords = any(keyword in cost_description or keyword in cost_steps 
                                      for keyword in pattern['cost_keywords'])
                security_has_keywords = any(keyword in finding_description 
                                          for keyword in pattern['security_keywords'])
                
                if cost_has_keywords and security_has_keywords:
                    conflicts.append({
                        'type': conflict_type,
                        'cost_recommendation_id': cost_rec.id,
                        'security_finding': finding,
                        'description': pattern['description'],
                        'severity': 'medium',
                        'mitigation_required': True
                    })
        
        return conflicts
    
    def _identify_complementary_actions(self, cost_rec, security_findings):
        """Identify actions that can address both cost and security concerns."""
        complementary = []
        
        # Common complementary patterns
        complementary_patterns = {
            'rightsizing': {
                'cost_benefits': ['reduce instance costs', 'optimize resource utilization'],
                'security_benefits': ['reduce attack surface', 'minimize exposed resources'],
                'actions': ['Right-size instances', 'Remove unused resources', 'Optimize configurations']
            },
            'automation': {
                'cost_benefits': ['reduce operational overhead', 'eliminate manual processes'],
                'security_benefits': ['consistent security policies', 'reduce human error'],
                'actions': ['Implement Infrastructure as Code', 'Automate security policies', 'Use managed services']
            },
            'consolidation': {
                'cost_benefits': ['reduce licensing costs', 'improve resource efficiency'],
                'security_benefits': ['centralized security management', 'consistent policies'],
                'actions': ['Consolidate accounts', 'Centralize logging', 'Standardize configurations']
            }
        }
        
        for pattern_name, pattern in complementary_patterns.items():
            # Check if this pattern applies to the current recommendation and findings
            if self._pattern_applies(cost_rec, security_findings, pattern):
                complementary.append({
                    'type': pattern_name,
                    'cost_recommendation_id': cost_rec.id,
                    'security_findings': [f['finding'].get('id', 'unknown') for f in security_findings],
                    'cost_benefits': pattern['cost_benefits'],
                    'security_benefits': pattern['security_benefits'],
                    'recommended_actions': pattern['actions'],
                    'priority': 'high' if cost_rec.priority_level == 'high' else 'medium'
                })
        
        return complementary
    
    def _create_unified_action_plan(self, resource_id, overlap_data):
        """Create a unified action plan for a resource with both cost and security concerns."""
        cost_recs = overlap_data['cost_recommendations']
        security_findings = overlap_data['security_findings']
        
        # Calculate combined priority
        max_cost_savings = max((rec.get('monthly_savings', 0) for rec in cost_recs), default=0)
        has_high_priority_cost = any(rec.get('priority_level') == 'high' for rec in cost_recs)
        has_critical_security = any(finding.get('severity') == 'critical' for finding in security_findings)
        
        if has_critical_security or (has_high_priority_cost and max_cost_savings > 500):
            priority = 'critical'
        elif has_high_priority_cost or max_cost_savings > 200:
            priority = 'high'
        else:
            priority = 'medium'
        
        return {
            'resource_id': resource_id,
            'priority': priority,
            'total_monthly_savings': sum(rec.get('monthly_savings', 0) for rec in cost_recs),
            'cost_recommendations_count': len(cost_recs),
            'security_findings_count': len(security_findings),
            'recommended_approach': self._determine_unified_approach(cost_recs, security_findings),
            'implementation_order': self._determine_implementation_order(cost_recs, security_findings),
            'risk_mitigation': self._generate_risk_mitigation_plan(cost_recs, security_findings)
        }
    
    def _determine_max_severity(self, security_findings):
        """Determine the maximum severity level from security findings."""
        severity_order = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
        max_severity = 'low'
        
        for finding_data in security_findings:
            finding = finding_data['finding']
            severity = finding.get('severity', 'low').lower()
            if severity_order.get(severity, 1) > severity_order.get(max_severity, 1):
                max_severity = severity
        
        return max_severity
    
    def _create_integrated_implementation_steps(self, cost_rec, security_findings):
        """Create implementation steps that address both cost and security concerns."""
        steps = []
        
        # Start with security validation
        steps.append("1. Review security implications and validate compliance requirements")
        
        # Add cost optimization steps with security considerations
        for i, step in enumerate(cost_rec.implementation_steps or [], 2):
            steps.append(f"{i}. {step} (ensure security policies are maintained)")
        
        # Add security-specific steps
        if security_findings:
            steps.append(f"{len(steps) + 1}. Address related security findings before implementation")
            steps.append(f"{len(steps) + 1}. Validate security controls after cost optimization")
        
        return steps
    
    def _calculate_integrated_priority(self, cost_rec, security_findings):
        """Calculate priority for integrated recommendation considering both cost and security."""
        cost_priority_score = {'low': 1, 'medium': 2, 'high': 3}.get(cost_rec.priority_level, 2)
        
        max_security_severity = self._determine_max_severity(security_findings)
        security_priority_score = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}.get(max_security_severity, 1)
        
        # Combined score with security having slightly higher weight
        combined_score = (cost_priority_score * 0.4) + (security_priority_score * 0.6)
        
        if combined_score >= 3:
            return 'high'
        elif combined_score >= 2:
            return 'medium'
        else:
            return 'low'
    
    def _pattern_applies(self, cost_rec, security_findings, pattern):
        """Check if a complementary pattern applies to the given recommendation and findings."""
        # Simplified pattern matching - in practice, this would be more sophisticated
        cost_text = f"{cost_rec.title} {cost_rec.description}".lower()
        
        # Check for pattern keywords in cost recommendation
        pattern_keywords = {
            'rightsizing': ['instance', 'size', 'utilization', 'capacity'],
            'automation': ['manual', 'automate', 'script', 'process'],
            'consolidation': ['multiple', 'separate', 'consolidate', 'centralize']
        }
        
        for pattern_name, keywords in pattern_keywords.items():
            if any(keyword in cost_text for keyword in keywords):
                return True
        
        return False
    
    def _determine_unified_approach(self, cost_recs, security_findings):
        """Determine the best unified approach for addressing both cost and security."""
        if len(security_findings) > len(cost_recs):
            return "Security-first approach: Address security findings before cost optimization"
        elif any(rec.get('monthly_savings', 0) > 1000 for rec in cost_recs):
            return "Balanced approach: Implement cost optimization with security validation"
        else:
            return "Cost-first approach: Optimize costs while maintaining security baseline"
    
    def _determine_implementation_order(self, cost_recs, security_findings):
        """Determine the optimal implementation order."""
        return [
            "1. Assess current security posture",
            "2. Implement high-priority security fixes",
            "3. Execute cost optimization with security validation",
            "4. Monitor and validate both cost and security outcomes"
        ]
    
    def _generate_risk_mitigation_plan(self, cost_recs, security_findings):
        """Generate a risk mitigation plan for the unified approach."""
        return {
            'pre_implementation': [
                "Backup current configurations",
                "Document security baseline",
                "Identify rollback procedures"
            ],
            'during_implementation': [
                "Monitor security metrics continuously",
                "Validate each change before proceeding",
                "Maintain audit trail of all changes"
            ],
            'post_implementation': [
                "Verify security controls are intact",
                "Validate cost savings are realized",
                "Update documentation and procedures"
            ]
        }
    
    def getBuiltData(self):
        """Get built data for JSON export"""
        return self.get_data_for_ui()
    # Performance Optimization Methods
    
    def _collect_data_parallel(self):
        """
        Collect data from all sources in parallel for improved performance.
        """
        _pr("Collecting cost optimization data in parallel...")
        
        # Define collection tasks
        tasks = [
            ('coh', self._collect_coh_recommendations_with_retry),
            ('cost_explorer', self._collect_cost_explorer_recommendations_with_retry),
            ('savings_plans', self._collect_savings_plans_recommendations_with_retry)
        ]
        
        # Execute tasks in parallel
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all tasks
            future_to_source = {
                executor.submit(task_func): source_name 
                for source_name, task_func in tasks
            }
            
            # Collect results as they complete
            for future in as_completed(future_to_source):
                source_name = future_to_source[future]
                try:
                    result = future.result(timeout=120)  # 2 minute timeout per source
                    if result:
                        _pr(f"Successfully collected data from {source_name}")
                    else:
                        _warn(f"No data collected from {source_name}")
                except Exception as e:
                    error_msg = f"Error collecting data from {source_name}: {str(e)}"
                    _warn(error_msg)
                    self.error_messages.append(error_msg)
                    self._record_circuit_breaker_failure(source_name)
    
    def _collect_data_parallel_with_graceful_degradation(self):
        """
        Collect data from all sources in parallel with graceful degradation tracking.
        
        Returns:
            tuple: (successful_sources, failed_sources)
        """
        _pr("Collecting cost optimization data in parallel with graceful degradation...")
        
        successful_sources = []
        failed_sources = []
        
        # Define collection tasks
        tasks = [
            ('COH', self._collect_coh_recommendations_with_retry),
            ('Cost Explorer', self._collect_cost_explorer_recommendations_with_retry),
            ('Savings Plans', self._collect_savings_plans_recommendations_with_retry)
        ]
        
        # Execute tasks in parallel
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all tasks
            future_to_source = {
                executor.submit(task_func): source_name 
                for source_name, task_func in tasks
            }
            
            # Collect results as they complete
            for future in as_completed(future_to_source):
                source_name = future_to_source[future]
                try:
                    result = future.result(timeout=120)  # 2 minute timeout per source
                    if result:
                        _pr(f"✓ Successfully collected data from {source_name}")
                        successful_sources.append(source_name)
                    else:
                        _pr(f"○ {source_name}: No recommendations available (this is normal - see details above)")
                        failed_sources.append(f"{source_name} (no recommendations)")
                except Exception as e:
                    error_msg = f"Error collecting data from {source_name}: {str(e)}"
                    _warn(error_msg)
                    self.error_messages.append(error_msg)
                    self._record_circuit_breaker_failure(source_name)
                    failed_sources.append(f"{source_name} (error)")
        
        return successful_sources, failed_sources
    
    def _handle_graceful_degradation(self, successful_sources, failed_sources):
        """
        Handle graceful degradation based on which sources succeeded or failed.
        
        Args:
            successful_sources (list): List of successful source names
            failed_sources (list): List of failed source names with reasons
        """
        total_sources = len(successful_sources) + len(failed_sources)
        success_rate = len(successful_sources) / total_sources if total_sources > 0 else 0
        
        if success_rate == 1.0:
            _pr("✓ All cost optimization sources collected successfully")
        elif success_rate >= 0.67:
            _pr(f"⚠ Partial success: {len(successful_sources)}/{total_sources} sources available")
            _pr(f"   Failed sources: {', '.join(failed_sources)}")
            self.error_messages.append(f"Some data sources unavailable: {', '.join(failed_sources)}")
        elif success_rate >= 0.33:
            _warn(f"⚠ Limited data: Only {len(successful_sources)}/{total_sources} sources available")
            _warn(f"   Failed sources: {', '.join(failed_sources)}")
            self.error_messages.append(f"Limited cost optimization data due to source failures: {', '.join(failed_sources)}")
        else:
            _warn(f"⚠ Minimal data: Only {len(successful_sources)}/{total_sources} sources available")
            _warn(f"   Failed sources: {', '.join(failed_sources)}")
            self.error_messages.append(f"Severely limited cost optimization data. Most sources failed: {', '.join(failed_sources)}")
        
        # Add specific guidance based on available sources
        if successful_sources:
            available_msg = f"✓ Available data sources: {', '.join(successful_sources)}"
            _pr(available_msg)
        else:
            _warn("✗ No cost optimization data sources available")
            self.error_messages.append("No cost optimization data sources available")
    
    def _create_fallback_executive_summary(self):
        """Create a fallback executive summary when processing fails."""
        try:
            total_monthly_savings = sum(rec.monthly_savings for rec in self.recommendations if hasattr(rec, 'monthly_savings'))
            
            self.executive_summary = ExecutiveSummary(
                total_recommendations=len(self.recommendations),
                total_monthly_savings=total_monthly_savings,
                total_annual_savings=total_monthly_savings * 12,
                high_priority_count=0,
                medium_priority_count=0,
                low_priority_count=len(self.recommendations),
                top_categories=[],
                implementation_roadmap=[],
                data_freshness=self.data_collection_time
            )
            _pr("Created fallback executive summary")
        except Exception as e:
            _warn(f"Error creating fallback executive summary: {str(e)}")
            self._create_empty_executive_summary()
    
    def _create_empty_executive_summary(self):
        """Create an empty but valid executive summary."""
        try:
            self.executive_summary = ExecutiveSummary(
                total_recommendations=0,
                total_monthly_savings=0.0,
                total_annual_savings=0.0,
                high_priority_count=0,
                medium_priority_count=0,
                low_priority_count=0,
                top_categories=[],
                implementation_roadmap=[],
                data_freshness=self.data_collection_time or datetime.now().isoformat()
            )
            _pr("Created empty executive summary")
        except Exception as e:
            _warn(f"Error creating empty executive summary: {str(e)}")
            self.executive_summary = None
    
    def _create_emergency_fallback_data(self):
        """Create emergency fallback data when everything fails."""
        try:
            self.recommendations = []
            self.executive_summary = ExecutiveSummary(
                total_recommendations=0,
                total_monthly_savings=0.0,
                total_annual_savings=0.0,
                high_priority_count=0,
                medium_priority_count=0,
                low_priority_count=0,
                top_categories=[],
                implementation_roadmap=[],
                data_freshness=datetime.now().isoformat()
            )
            if not self.error_messages:
                self.error_messages = ["Cost Optimization Hub analysis failed due to system error"]
            _pr("Created emergency fallback data")
        except Exception as e:
            _warn(f"Critical error in emergency fallback: {str(e)}")
            # Absolute minimum fallback
            self.recommendations = []
            self.executive_summary = None
            self.error_messages = ["Critical system error in Cost Optimization Hub"]
    
    def _collect_coh_recommendations_with_retry(self):
        """Collect COH recommendations with retry logic and circuit breaker."""
        return self._execute_with_retry_and_circuit_breaker(
            'coh', 
            self._collect_coh_recommendations_cached
        )
    
    def _collect_cost_explorer_recommendations_with_retry(self):
        """Collect Cost Explorer recommendations with retry logic and circuit breaker."""
        return self._execute_with_retry_and_circuit_breaker(
            'cost_explorer', 
            self._collect_cost_explorer_recommendations_cached
        )
    
    def _collect_savings_plans_recommendations_with_retry(self):
        """Collect Savings Plans recommendations with retry logic and circuit breaker."""
        return self._execute_with_retry_and_circuit_breaker(
            'savings_plans', 
            self._collect_savings_plans_recommendations_cached
        )
    
    def _execute_with_retry_and_circuit_breaker(self, source_name, func):
        """
        Execute a function with retry logic and circuit breaker pattern.
        
        Args:
            source_name (str): Name of the data source
            func (callable): Function to execute
            
        Returns:
            Any: Result of the function execution
        """
        # Check circuit breaker state
        if not self._is_circuit_breaker_closed(source_name):
            _warn(f"Circuit breaker open for {source_name}, skipping data collection")
            return None
        
        if not self.retry_enabled:
            return func()
        
        last_exception = None
        delay = self.base_delay
        
        for attempt in range(self.max_retries + 1):
            try:
                result = func()
                # Reset circuit breaker on success
                self._reset_circuit_breaker(source_name)
                return result
                
            except Exception as e:
                last_exception = e
                self._record_circuit_breaker_failure(source_name)
                
                if attempt < self.max_retries:
                    _warn(f"Attempt {attempt + 1} failed for {source_name}: {str(e)}. Retrying in {delay}s...")
                    time.sleep(delay)
                    delay = min(delay * 2, self.max_delay)  # Exponential backoff
                else:
                    _warn(f"All {self.max_retries + 1} attempts failed for {source_name}")
        
        # All retries failed
        raise last_exception
    
    def _collect_coh_recommendations_cached(self):
        """Collect COH recommendations with caching."""
        cache_key = 'coh_recommendations'
        
        # Check cache first
        if self.cache_enabled:
            cached_data = self._get_from_cache(cache_key)
            if cached_data is not None:
                _pr("Using cached COH recommendations")
                self._process_cached_coh_data(cached_data)
                return True
        
        # Collect fresh data
        try:
            _pr("Collecting fresh COH recommendations from us-east-1...")
            region = 'us-east-1'
            
            recommendations = self.coh_client.list_recommendations(
                region=region,
                max_results=self.max_recommendations_per_source
            )
            
            if recommendations:
                _pr(f"Found {len(recommendations)} COH recommendations")
                
                # Cache the raw data
                if self.cache_enabled:
                    self._store_in_cache(cache_key, recommendations)
                
                # Transform COH recommendations to unified format
                for rec in recommendations:
                    try:
                        unified_rec = self._transform_coh_recommendation(rec)
                        if unified_rec:
                            self.recommendations.append(unified_rec)
                    except Exception as e:
                        _warn(f"Error transforming COH recommendation: {str(e)}")
                
                return True
            else:
                _pr("No COH recommendations found")
                return False
                
        except Exception as e:
            error_msg = f"Error collecting COH recommendations: {str(e)}"
            _warn(error_msg)
            self.error_messages.append(error_msg)
            raise
    
    def _collect_cost_explorer_recommendations_cached(self):
        """Collect Cost Explorer recommendations with caching."""
        cache_key = 'cost_explorer_recommendations'
        
        # Check cache first
        if self.cache_enabled:
            cached_data = self._get_from_cache(cache_key)
            if cached_data is not None:
                _pr("Using cached Cost Explorer recommendations")
                self._process_cached_cost_explorer_data(cached_data)
                return True
        
        # Collect fresh data
        try:
            _pr("Collecting Cost Explorer recommendations...")
            
            # Collect rightsizing recommendations
            rightsizing_recs = self.cost_explorer_client.get_rightsizing_recommendations()
            
            if rightsizing_recs:
                _pr(f"✓ Found {len(rightsizing_recs)} Cost Explorer recommendations")
                
                # Cache the raw data
                if self.cache_enabled:
                    self._store_in_cache(cache_key, rightsizing_recs)
                
                # Transform to unified format
                for rec in rightsizing_recs:
                    try:
                        unified_rec = self._transform_cost_explorer_recommendation(rec)
                        if unified_rec:
                            self.recommendations.append(unified_rec)
                    except Exception as e:
                        _warn(f"Error transforming Cost Explorer recommendation: {str(e)}")
            else:
                _pr("✓ Cost Explorer API call successful - No rightsizing recommendations available")
                _pr("   This is normal if: 1) Instances are already optimally sized, 2) Feature not enabled, 3) Insufficient usage data")
            
            # Return True for successful API call regardless of recommendation count
            return True
                
        except Exception as e:
            # Provide user-friendly error messages for common issues
            error_str = str(e)
            if 'AccessDeniedException' in error_str and 'cost explorer' in error_str.lower():
                error_msg = "Cost Explorer access not enabled for this account. To enable: AWS Console → Cost Management → Cost Explorer → Enable Cost Explorer. Note: Rightsizing recommendations require additional opt-in."
            elif 'AccessDeniedException' in error_str:
                error_msg = f"Access denied to Cost Explorer API. Please check IAM permissions. Error: {error_str}"
            else:
                error_msg = f"Error collecting Cost Explorer recommendations: {error_str}"
            
            _warn(error_msg)
            self.error_messages.append(error_msg)
            raise
    
    def _collect_savings_plans_recommendations_cached(self):
        """Collect Savings Plans recommendations with caching."""
        cache_key = 'savings_plans_recommendations'
        
        # Check cache first
        if self.cache_enabled:
            cached_data = self._get_from_cache(cache_key)
            if cached_data is not None:
                _pr("Using cached Savings Plans recommendations")
                self._process_cached_savings_plans_data(cached_data)
                return True
        
        # Collect fresh data
        try:
            _pr("Collecting Savings Plans recommendations...")
            
            # Collect purchase recommendations
            sp_recs = self.savings_plans_client.get_savings_plans_purchase_recommendations()
            
            if sp_recs:
                _pr(f"✓ Found {len(sp_recs)} Savings Plans recommendations")
                
                # Cache the raw data
                if self.cache_enabled:
                    self._store_in_cache(cache_key, sp_recs)
                
                # Transform to unified format
                for rec in sp_recs:
                    try:
                        unified_rec = self._transform_savings_plans_recommendation(rec)
                        if unified_rec:
                            self.recommendations.append(unified_rec)
                    except Exception as e:
                        _warn(f"Error transforming Savings Plans recommendation: {str(e)}")
            else:
                _pr("✓ Savings Plans API call successful - No purchase recommendations available")
                _pr("   This is normal if: 1) Already have optimal coverage, 2) No consistent usage patterns, 3) Account is new")
            
            # Return True for successful API call regardless of recommendation count
            return True
                
        except Exception as e:
            error_msg = f"Error collecting Savings Plans recommendations: {str(e)}"
            _warn(error_msg)
            self.error_messages.append(error_msg)
            raise
    
    # Caching Methods
    
    def _get_from_cache(self, cache_key):
        """Get data from cache if not expired."""
        with self.cache_lock:
            if cache_key in self.cache_data and cache_key in self.cache_timestamps:
                cache_time = self.cache_timestamps[cache_key]
                if datetime.now() - cache_time < timedelta(minutes=self.cache_ttl_minutes):
                    return self.cache_data[cache_key]
                else:
                    # Cache expired, remove it
                    del self.cache_data[cache_key]
                    del self.cache_timestamps[cache_key]
            return None
    
    def _store_in_cache(self, cache_key, data):
        """Store data in cache with timestamp."""
        with self.cache_lock:
            self.cache_data[cache_key] = data
            self.cache_timestamps[cache_key] = datetime.now()
    
    def _process_cached_coh_data(self, cached_data):
        """Process cached COH data."""
        for rec in cached_data:
            try:
                unified_rec = self._transform_coh_recommendation(rec)
                if unified_rec:
                    self.recommendations.append(unified_rec)
            except Exception as e:
                _warn(f"Error processing cached COH recommendation: {str(e)}")
    
    def _process_cached_cost_explorer_data(self, cached_data):
        """Process cached Cost Explorer data."""
        for rec in cached_data:
            try:
                unified_rec = self._transform_cost_explorer_recommendation(rec)
                if unified_rec:
                    self.recommendations.append(unified_rec)
            except Exception as e:
                _warn(f"Error processing cached Cost Explorer recommendation: {str(e)}")
    
    def _process_cached_savings_plans_data(self, cached_data):
        """Process cached Savings Plans data."""
        for rec in cached_data:
            try:
                unified_rec = self._transform_savings_plans_recommendation(rec)
                if unified_rec:
                    self.recommendations.append(unified_rec)
            except Exception as e:
                _warn(f"Error processing cached Savings Plans recommendation: {str(e)}")
    
    # Circuit Breaker Methods
    
    def _is_circuit_breaker_closed(self, source_name):
        """Check if circuit breaker is closed (allowing requests)."""
        if not self.circuit_breaker_enabled:
            return True
        
        circuit = self.circuit_states.get(source_name, {})
        state = circuit.get('state', 'closed')
        
        if state == 'closed':
            return True
        elif state == 'open':
            # Check if recovery timeout has passed
            last_failure = circuit.get('last_failure')
            if last_failure and datetime.now() - last_failure > timedelta(minutes=self.recovery_timeout_minutes):
                # Move to half-open state
                circuit['state'] = 'half-open'
                return True
            return False
        elif state == 'half-open':
            return True
        
        return False
    
    def _record_circuit_breaker_failure(self, source_name):
        """Record a failure for circuit breaker tracking."""
        if not self.circuit_breaker_enabled:
            return
        
        circuit = self.circuit_states.get(source_name, {
            'failures': 0, 'last_failure': None, 'state': 'closed'
        })
        
        circuit['failures'] += 1
        circuit['last_failure'] = datetime.now()
        
        if circuit['failures'] >= self.failure_threshold:
            circuit['state'] = 'open'
            _warn(f"Circuit breaker opened for {source_name} after {circuit['failures']} failures")
        
        self.circuit_states[source_name] = circuit
    
    def _reset_circuit_breaker(self, source_name):
        """Reset circuit breaker after successful operation."""
        if not self.circuit_breaker_enabled:
            return
        
        circuit = self.circuit_states.get(source_name, {})
        circuit['failures'] = 0
        circuit['last_failure'] = None
        circuit['state'] = 'closed'
        self.circuit_states[source_name] = circuit
    
    # Optimized Processing Methods
    
    def _process_unified_recommendations(self):
        """Process and optimize recommendations with performance improvements and data quality checks."""
        if not self.recommendations:
            return
        
        _pr("Processing unified recommendations with optimizations and quality assurance...")
        
        # Step 1: Data quality validation
        self._validate_recommendation_data_quality()
        
        # Step 2: Deduplicate recommendations efficiently
        self.recommendations = self._deduplicate_recommendations_optimized(self.recommendations)
        
        # Step 3: Calculate priorities in batch
        self.recommendations = self._calculate_priorities_batch(self.recommendations)
        
        # Step 4: Verify cost calculations
        self._verify_cost_calculations()
        
        # Step 5: Detect anomalies
        anomalies = self._detect_cost_anomalies()
        if anomalies:
            _warn(f"Detected {len(anomalies)} cost anomalies")
            for anomaly in anomalies[:3]:  # Log first 3
                _warn(f"Anomaly: {anomaly}")
        
        # Step 6: Sort by priority score (highest first)
        self.recommendations.sort(key=lambda x: x.priority_score, reverse=True)
        
        _pr(f"Processed {len(self.recommendations)} unique recommendations with quality assurance")
    
    def _validate_recommendation_data_quality(self):
        """Validate data quality of all recommendations and flag issues."""
        _pr("Validating recommendation data quality...")
        
        valid_recommendations = []
        validation_errors = []
        
        for i, rec in enumerate(self.recommendations):
            validation_result = self._validate_single_recommendation(rec, i)
            
            if validation_result['is_valid']:
                valid_recommendations.append(rec)
            else:
                validation_errors.extend(validation_result['errors'])
                _warn(f"Invalid recommendation {rec.id}: {', '.join(validation_result['errors'])}")
        
        # Update recommendations list with only valid ones
        removed_count = len(self.recommendations) - len(valid_recommendations)
        if removed_count > 0:
            _warn(f"Removed {removed_count} invalid recommendations")
            self.error_messages.append(f"Removed {removed_count} recommendations due to data quality issues")
        
        self.recommendations = valid_recommendations
        
        # Store validation summary
        self.data_quality_summary = {
            'total_processed': len(self.recommendations) + removed_count,
            'valid_recommendations': len(valid_recommendations),
            'removed_recommendations': removed_count,
            'validation_errors': validation_errors,
            'quality_score': len(valid_recommendations) / max(1, len(self.recommendations) + removed_count)
        }
    
    def _validate_single_recommendation(self, rec, index):
        """Validate a single recommendation for data quality."""
        errors = []
        
        # Required field validation
        required_fields = ['id', 'source', 'category', 'service', 'title']
        for field in required_fields:
            if not hasattr(rec, field) or not getattr(rec, field):
                errors.append(f"Missing or empty required field: {field}")
        
        # Financial data validation
        if hasattr(rec, 'monthly_savings'):
            if not isinstance(rec.monthly_savings, (int, float)) or rec.monthly_savings < 0:
                errors.append(f"Invalid monthly_savings: {rec.monthly_savings}")
        else:
            errors.append("Missing monthly_savings field")
        
        if hasattr(rec, 'annual_savings'):
            if not isinstance(rec.annual_savings, (int, float)) or rec.annual_savings < 0:
                errors.append(f"Invalid annual_savings: {rec.annual_savings}")
            elif hasattr(rec, 'monthly_savings') and abs(rec.annual_savings - rec.monthly_savings * 12) > 0.01:
                errors.append(f"Annual savings inconsistent with monthly: {rec.annual_savings} != {rec.monthly_savings * 12}")
        else:
            errors.append("Missing annual_savings field")
        
        # Categorical data validation
        valid_sources = {'coh', 'cost_explorer', 'savings_plans'}
        if hasattr(rec, 'source') and rec.source not in valid_sources:
            errors.append(f"Invalid source: {rec.source}")
        
        valid_categories = {'compute', 'storage', 'database', 'networking', 'commitment', 'general'}
        if hasattr(rec, 'category') and rec.category not in valid_categories:
            errors.append(f"Invalid category: {rec.category}")
        
        valid_priorities = {'high', 'medium', 'low'}
        if hasattr(rec, 'priority_level') and rec.priority_level not in valid_priorities:
            errors.append(f"Invalid priority_level: {rec.priority_level}")
        
        valid_efforts = {'low', 'medium', 'high'}
        if hasattr(rec, 'implementation_effort') and rec.implementation_effort not in valid_efforts:
            errors.append(f"Invalid implementation_effort: {rec.implementation_effort}")
        
        valid_confidence = {'high', 'medium', 'low'}
        if hasattr(rec, 'confidence_level') and rec.confidence_level not in valid_confidence:
            errors.append(f"Invalid confidence_level: {rec.confidence_level}")
        
        # Resource count validation
        if hasattr(rec, 'resource_count'):
            if not isinstance(rec.resource_count, int) or rec.resource_count < 0:
                errors.append(f"Invalid resource_count: {rec.resource_count}")
        
        # List field validation
        list_fields = ['implementation_steps', 'required_permissions', 'potential_risks', 'affected_resources']
        for field in list_fields:
            if hasattr(rec, field):
                field_value = getattr(rec, field)
                if not isinstance(field_value, list):
                    errors.append(f"Field {field} should be a list, got {type(field_value)}")
        
        return {
            'is_valid': len(errors) == 0,
            'errors': errors
        }
    
    def _verify_cost_calculations(self):
        """Verify cost calculations are mathematically consistent."""
        _pr("Verifying cost calculations...")
        
        calculation_errors = []
        
        for rec in self.recommendations:
            # Verify annual = monthly * 12
            if abs(rec.annual_savings - rec.monthly_savings * 12) > 0.01:
                error = f"Rec {rec.id}: Annual savings {rec.annual_savings} != monthly * 12 ({rec.monthly_savings * 12})"
                calculation_errors.append(error)
                # Fix the calculation
                rec.annual_savings = rec.monthly_savings * 12
        
        if calculation_errors:
            _warn(f"Fixed {len(calculation_errors)} cost calculation errors")
            self.error_messages.append(f"Fixed {len(calculation_errors)} cost calculation inconsistencies")
    
    def _detect_cost_anomalies(self):
        """Detect anomalies in cost recommendations using statistical analysis."""
        if len(self.recommendations) < 3:
            return []  # Need at least 3 recommendations for anomaly detection
        
        anomalies = []
        
        # Extract monthly savings for analysis
        monthly_savings = [rec.monthly_savings for rec in self.recommendations]
        
        # Calculate statistical measures
        import statistics
        mean_savings = statistics.mean(monthly_savings)
        median_savings = statistics.median(monthly_savings)
        
        if len(monthly_savings) > 1:
            stdev_savings = statistics.stdev(monthly_savings)
        else:
            stdev_savings = 0
        
        # Detect outliers (values more than 3 standard deviations from mean)
        outlier_threshold = 3 * stdev_savings if stdev_savings > 0 else float('inf')
        
        for rec in self.recommendations:
            # Check for extreme values
            if abs(rec.monthly_savings - mean_savings) > outlier_threshold:
                anomalies.append({
                    'type': 'extreme_savings',
                    'recommendation_id': rec.id,
                    'value': rec.monthly_savings,
                    'mean': mean_savings,
                    'deviation': abs(rec.monthly_savings - mean_savings)
                })
            
            # Check for suspiciously round numbers (might indicate estimates)
            if rec.monthly_savings > 0 and rec.monthly_savings % 100 == 0 and rec.monthly_savings >= 1000:
                anomalies.append({
                    'type': 'round_number_estimate',
                    'recommendation_id': rec.id,
                    'value': rec.monthly_savings,
                    'note': 'Suspiciously round number, may be estimate'
                })
            
            # Check for zero or very low savings
            if rec.monthly_savings < 1.0:
                anomalies.append({
                    'type': 'very_low_savings',
                    'recommendation_id': rec.id,
                    'value': rec.monthly_savings,
                    'note': 'Very low savings amount'
                })
            
            # Check for inconsistent priority vs savings
            if rec.priority_level == 'high' and rec.monthly_savings < mean_savings * 0.5:
                anomalies.append({
                    'type': 'priority_savings_mismatch',
                    'recommendation_id': rec.id,
                    'priority': rec.priority_level,
                    'savings': rec.monthly_savings,
                    'mean_savings': mean_savings
                })
        
        return anomalies
    
    def _add_data_quality_monitoring(self):
        """Add data quality metrics for monitoring."""
        if not hasattr(self, 'data_quality_summary'):
            self.data_quality_summary = {
                'total_processed': 0,
                'valid_recommendations': 0,
                'removed_recommendations': 0,
                'validation_errors': [],
                'quality_score': 0.0
            }
        
        # Add monitoring metrics
        self.data_quality_summary.update({
            'monitoring_timestamp': datetime.now().isoformat(),
            'source_distribution': self._calculate_source_distribution(),
            'category_distribution': self._calculate_category_distribution(),
            'savings_statistics': self._calculate_savings_statistics(),
            'data_freshness_score': self._calculate_data_freshness_score()
        })
    
    def _calculate_source_distribution(self):
        """Calculate distribution of recommendations by source."""
        distribution = {}
        for rec in self.recommendations:
            source = rec.source
            distribution[source] = distribution.get(source, 0) + 1
        return distribution
    
    def _calculate_category_distribution(self):
        """Calculate distribution of recommendations by category."""
        distribution = {}
        for rec in self.recommendations:
            category = rec.category
            distribution[category] = distribution.get(category, 0) + 1
        return distribution
    
    def _calculate_savings_statistics(self):
        """Calculate savings statistics for monitoring."""
        if not self.recommendations:
            return {'total': 0, 'mean': 0, 'median': 0, 'max': 0, 'min': 0}
        
        monthly_savings = [rec.monthly_savings for rec in self.recommendations]
        
        import statistics
        return {
            'total_monthly': sum(monthly_savings),
            'total_annual': sum(monthly_savings) * 12,
            'mean_monthly': statistics.mean(monthly_savings),
            'median_monthly': statistics.median(monthly_savings),
            'max_monthly': max(monthly_savings),
            'min_monthly': min(monthly_savings),
            'count': len(monthly_savings)
        }
    
    def _calculate_data_freshness_score(self):
        """Calculate data freshness score based on collection time."""
        if not self.data_collection_time:
            return 0.0
        
        try:
            collection_time = datetime.fromisoformat(self.data_collection_time.replace('Z', '+00:00'))
            current_time = datetime.now()
            age_minutes = (current_time - collection_time).total_seconds() / 60
            
            # Score decreases as data gets older
            # 100% fresh for < 5 minutes, 50% at 30 minutes, 0% at 2 hours
            if age_minutes < 5:
                return 1.0
            elif age_minutes < 30:
                return 1.0 - (age_minutes - 5) / 25 * 0.5
            elif age_minutes < 120:
                return 0.5 - (age_minutes - 30) / 90 * 0.5
            else:
                return 0.0
        except Exception:
            return 0.0
    
    def _deduplicate_recommendations_optimized(self, recommendations):
        """Optimized deduplication using hash-based approach."""
        seen_hashes = set()
        unique_recommendations = []
        
        for rec in recommendations:
            # Create hash based on key attributes
            hash_key = self._create_recommendation_hash(rec)
            
            if hash_key not in seen_hashes:
                seen_hashes.add(hash_key)
                unique_recommendations.append(rec)
            else:
                # Merge with existing recommendation if beneficial
                existing_rec = next((r for r in unique_recommendations 
                                   if self._create_recommendation_hash(r) == hash_key), None)
                if existing_rec and rec.monthly_savings > existing_rec.monthly_savings:
                    # Replace with higher savings recommendation
                    unique_recommendations.remove(existing_rec)
                    unique_recommendations.append(rec)
        
        return unique_recommendations
    
    def _create_recommendation_hash(self, rec):
        """Create a hash for recommendation deduplication."""
        # Use service, category, and affected resources for deduplication
        resource_ids = sorted([r.get('id', '') for r in rec.affected_resources])
        hash_input = f"{rec.service}_{rec.category}_{','.join(resource_ids)}"
        return hashlib.md5(hash_input.encode(), usedforsecurity=False).hexdigest()
    
    def _calculate_priorities_batch(self, recommendations):
        """Calculate priorities for all recommendations in batch for efficiency."""
        _pr("Calculating priorities in batch...")
        
        # Pre-calculate common values
        total_savings = sum(rec.monthly_savings for rec in recommendations)
        avg_savings = total_savings / len(recommendations) if recommendations else 0
        
        # Calculate priorities
        for rec in recommendations:
            rec.priority_score = self._calculate_priority_score_optimized(rec, avg_savings)
            rec.priority_level = self._determine_priority_level(rec.priority_score)
        
        return recommendations
    
    def _calculate_priority_score_optimized(self, rec, avg_savings):
        """Optimized priority score calculation."""
        # Financial impact (40% weight)
        financial_score = min(100, (rec.monthly_savings / max(avg_savings, 1)) * 40)
        
        # Implementation feasibility (30% weight)
        effort_scores = {'low': 30, 'medium': 20, 'high': 10}
        feasibility_score = effort_scores.get(rec.implementation_effort, 20)
        
        # Confidence level (20% weight)
        confidence_scores = {'high': 20, 'medium': 15, 'low': 10}
        confidence_score = confidence_scores.get(rec.confidence_level, 15)
        
        # Resource impact (10% weight)
        resource_score = min(10, rec.resource_count * 2)
        
        return financial_score + feasibility_score + confidence_score + resource_score
    
    def _determine_priority_level(self, priority_score):
        """Determine priority level based on score."""
        if priority_score >= 75:
            return 'high'
        elif priority_score >= 50:
            return 'medium'
        else:
            return 'low'