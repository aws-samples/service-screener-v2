"""
Base client for AWS cost optimization data sources

Provides common functionality and retry logic for all optimization clients.
"""

import time
import boto3
from datetime import datetime
from botocore.exceptions import ClientError, NoCredentialsError
from utils.Config import Config
from utils.Tools import _pr, _warn


class BaseOptimizationClient:
    """
    Base class for AWS cost optimization clients
    
    Provides common functionality like retry logic, client management,
    and error handling for all cost optimization data sources.
    """
    
    def __init__(self, service_name, session=None, retry_config=None):
        """
        Initialize base client
        
        Args:
            service_name: AWS service name (e.g., 'cost-optimization-hub')
            session: Optional boto3 session
            retry_config: Optional retry configuration
        """
        self.service_name = service_name
        self.session = session or boto3.Session()
        self.clients = {}  # Cache clients by region
        self.retry_config = retry_config or {
            'max_attempts': 3,
            'backoff_factor': 2,
            'initial_delay': 1
        }
        
    def _get_client(self, region='us-east-1'):
        """Get or create AWS client for specified region with caching"""
        if region not in self.clients:
            try:
                # Try to use ssBoto from Config first
                ssboto = Config.get('ssBoto')
                if ssboto:
                    client = ssboto.client(self.service_name, region_name=region)
                else:
                    # Fallback to session client
                    client = self.session.client(self.service_name, region_name=region)
                
                self.clients[region] = client
                return client
                
            except NoCredentialsError:
                _warn(f"No AWS credentials found for {self.service_name}")
                return None
            except Exception as e:
                _warn(f"Error creating {self.service_name} client for {region}: {str(e)}")
                return None
        
        return self.clients[region]
    
    def _retry_with_backoff(self, operation):
        """
        Execute operation with exponential backoff retry logic
        
        Args:
            operation: Function to execute with retry logic
            
        Returns:
            Result of the operation
        """
        for attempt in range(self.retry_config['max_attempts']):
            try:
                return operation()
                
            except ClientError as e:
                error_code = e.response['Error']['Code']
                
                # Don't retry certain errors
                if error_code in ['AccessDeniedException', 'UnauthorizedOperation', 
                                'OptInRequiredException', 'ValidationException']:
                    raise e
                
                # Retry throttling and temporary errors
                if error_code in ['Throttling', 'ThrottlingException', 'RequestLimitExceeded',
                                'ServiceUnavailable', 'InternalError'] and attempt < self.retry_config['max_attempts'] - 1:
                    delay = self.retry_config['initial_delay'] * (self.retry_config['backoff_factor'] ** attempt)
                    _warn(f"Retrying {self.service_name} after {delay}s due to {error_code} (attempt {attempt + 1})")
                    time.sleep(delay)
                    continue
                
                raise e
            except Exception as e:
                # Check for specific savings plans errors and provide helpful guidance
                if 'get_savings_plans_purchase_recommendation' in str(e):
                    if attempt == 0:  # Only show this message once
                        _warn(f"Savings Plans recommendations unavailable. To enable:")
                        _warn("1. Go to AWS Cost Management Console")
                        _warn("2. Navigate to Savings Plans > Recommendations")
                        _warn("3. Enable Savings Plans recommendations for your account")
                    # Don't retry for this specific error - it won't help
                    raise e
                
                # Reduce retries for savings plans to avoid spam
                max_retries = 1 if 'savingsplans' in self.service_name.lower() else self.retry_config['max_attempts']
                
                if attempt < max_retries - 1:
                    delay = min(self.retry_config['initial_delay'] * (self.retry_config['backoff_factor'] ** attempt), 5)  # Cap delay at 5s
                    _warn(f"Retrying {self.service_name} after {delay}s due to unexpected error (attempt {attempt + 1})")
                    time.sleep(delay)
                    continue
                    
                # Final attempt failed - provide helpful error message
                if 'savingsplans' in self.service_name.lower():
                    _warn(f"Savings Plans recommendations are not available for this account.")
                    _warn("This may be because Savings Plans recommendations are not enabled in the AWS Console.")
                else:
                    _warn(f"Unexpected error in {self.service_name} recommendations: {str(e)}")
                    
                raise e
        
        raise Exception(f"Max retry attempts ({max_retries}) exceeded")
    
    def _add_metadata(self, data, region, additional_metadata=None):
        """
        Add common metadata to recommendation data
        
        Args:
            data: Recommendation data to enhance
            region: AWS region
            additional_metadata: Optional additional metadata
            
        Returns:
            Enhanced data with metadata
        """
        if isinstance(data, dict):
            data['_region'] = region
            data['_retrieved_at'] = datetime.now().isoformat()
            data['_source_service'] = self.service_name
            
            if additional_metadata:
                data.update(additional_metadata)
        
        return data