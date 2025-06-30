import os
import json
from utils.Tools import _warn, _info

class SuppressionsManager:
    """
    Manages suppressions for Service Screener findings.
    Loads suppressions from a JSON file and provides methods to check if a finding should be suppressed.
    """
    
    def __init__(self):
        self.suppressions = {}
        self.is_loaded = False
        self.suppression_count = 0
    
    def __getstate__(self):
        """Support for pickling (multiprocessing compatibility)."""
        return self.__dict__
    
    def __setstate__(self, state):
        """Support for unpickling (multiprocessing compatibility)."""
        self.__dict__.update(state)
        
    def load_suppressions(self, file_path):
        """
        Load suppressions from a JSON file.
        
        Args:
            file_path (str): Path to the JSON suppressions file
            
        Returns:
            bool: True if suppressions were loaded successfully, False otherwise
        """
        if not file_path or not os.path.exists(file_path):
            _warn(f"Suppression file not found: {file_path}")
            return False
            
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
                
            # Process suppressions into a more efficient lookup structure
            processed = {
                'service_rules': {},  # service -> rule -> True
                'resource_specific': {}  # service -> rule -> [resource_ids]
            }
            
            for item in data.get('suppressions', []):
                service = item.get('service')
                rule = item.get('rule')
                resource_ids = item.get('resource_id', [])
                
                if not service or not rule:
                    continue
                
                # If resource_ids is specified, add to resource-specific suppressions
                if resource_ids:
                    if service not in processed['resource_specific']:
                        processed['resource_specific'][service] = {}
                    
                    if rule not in processed['resource_specific'][service]:
                        processed['resource_specific'][service][rule] = []
                    
                    # Ensure resource_ids is a list
                    if isinstance(resource_ids, str):
                        resource_ids = [resource_ids]
                    
                    processed['resource_specific'][service][rule].extend(resource_ids)
                    print(f"[SUPPRESSION] Resource-specific: {service}:{rule} for resources {resource_ids}")
                    self.suppression_count += len(resource_ids)
                else:
                    # Otherwise, add to service-level suppressions
                    if service not in processed['service_rules']:
                        processed['service_rules'][service] = set()
                    
                    processed['service_rules'][service].add(rule)
                    print(f"[SUPPRESSION] Service-level: {service}:{rule}")
                    self.suppression_count += 1
            
            self.suppressions = processed
            self.is_loaded = True
            
            # Print summary of loaded suppressions
            service_rule_count = sum(len(rules) for rules in processed['service_rules'].values())
            resource_specific_count = sum(
                len(resources) for service_rules in processed['resource_specific'].values() 
                for resources in service_rules.values()
            )
            
            print("-"*80)
            print(f"SUPPRESSION SUMMARY: {service_rule_count} service-level and {resource_specific_count} resource-specific suppressions loaded")
            print("="*80 + "\n")
            
            return True
            
        except Exception as e:
            _warn(f"Error loading suppressions file: {e}")
            return False
    
    def is_suppressed(self, service, rule_id, resource_id=None):
        """
        Check if a finding should be suppressed.
        
        Args:
            service (str): The AWS service (e.g., 's3', 'rds')
            rule_id (str): The rule identifier (e.g., 'BucketReplication')
            resource_id (str, optional): The resource identifier
            
        Returns:
            bool: True if the finding should be suppressed, False otherwise
        """
        if not self.is_loaded:
            return False
        
        # Check service-level suppressions
        if service in self.suppressions['service_rules'] and rule_id in self.suppressions['service_rules'][service]:
            return True
        
        # Check resource-specific suppressions
        if resource_id and service in self.suppressions['resource_specific']:
            if rule_id in self.suppressions['resource_specific'][service]:
                if resource_id in self.suppressions['resource_specific'][service][rule_id]:
                    return True
        
        return False
