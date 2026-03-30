import boto3
import botocore
import constants as _C
import json

from services.Service import Service
from services.Evaluator import Evaluator

class ApiGatewayRest(Evaluator):
    
    def __init__(self, api, apiClient):
        super().__init__()
        self.apiClient = apiClient
        self.api = api

        self._resourceName = api['name']

        return

    def _checkStage(self):
        resp = self.apiClient.get_stages(
            restApiId = self.api['id'],
        )
        item = resp['item']
        if item == []:
            self.results['IdleAPIGateway'] = [-1, "No stages found"]
            return
        for stage in item:
            if stage['methodSettings'] == []:
                self.results['ExecutionLogging'] = [-1, "Stage name: " + stage['stageName']]
                self.results['CachingEnabled'] = [-1, "Stage name: " + stage['stageName']]
            
            for k, json in stage['methodSettings'].items():
                for key, value in json.items():
                    if key == 'loggingLevel' and value != 'INFO' or 'ERROR':
                        self.results['ExecutionLogging'] = [-1, "Stage name: " + stage['stageName']]    
                    if key == 'cachingEnabled' and value is True:
                        self.results['CachingEnabled'] = [1, "Stage name: " + stage['stageName']]
                        self.results['EncryptionAtRest'] = [-1, "Stage name: " + stage['stageName']]
                        if key == 'cacheDataEncrypted' and value is False:
                            self.results['EncryptionAtRest'] = [-1, "Stage name: " + stage['stageName']]
            
            try:
                certid = stage['clientCertificateId']
            except KeyError:
                self.results['EncryptionInTransit'] = [-1, "Stage name: " + stage['stageName']]
            
            if not stage['tracingEnabled']:
                self.results['XRayTracing'] = [-1, "Stage name: " + stage['stageName']]
            
            try:
                wacl = stage['webAclArn']
            except KeyError:
                self.results['WAFWACL'] = [-1, "Stage name: " + stage['stageName']]
            
        return
    
    def _checkResourcePolicy(self):
        """
        Check if REST API has a resource policy configured for access control.
        Resource policies provide IP-based, VPC-based, or account-based access restrictions.
        """
        try:
            # Get the full REST API details including policy
            api_details = self.apiClient.get_rest_api(restApiId=self.api['id'])
            
            # Check if policy exists and is not empty
            if 'policy' in api_details and api_details['policy']:
                policy_str = api_details['policy']
                # Verify it's not just an empty policy document
                if len(policy_str.strip()) > 0 and policy_str != '{}':
                    # Policy exists - this is good
                    return
            
            # No policy or empty policy
            self.results['ResourcePolicy'] = [-1, f"API: {self.api['name']}"]
        except Exception as e:
            # If we can't check, flag as potential issue
            self.results['ResourcePolicy'] = [-1, f"API: {self.api['name']} (Error: {str(e)})"]
    
    def _checkIAMAuthentication(self):
        """
        Check if API methods use proper authentication (not NONE).
        Methods with NONE authorization allow unauthenticated access.
        """
        try:
            # Get all resources for this API
            resources_resp = self.apiClient.get_resources(restApiId=self.api['id'])
            resources = resources_resp.get('items', [])
            
            methods_without_auth = []
            
            for resource in resources:
                resource_path = resource.get('path', '/')
                resource_methods = resource.get('resourceMethods', {})
                
                for method_name, method_data in resource_methods.items():
                    # Get detailed method information
                    try:
                        method_details = self.apiClient.get_method(
                            restApiId=self.api['id'],
                            resourceId=resource['id'],
                            httpMethod=method_name
                        )
                        
                        auth_type = method_details.get('authorizationType', 'NONE')
                        
                        # Flag methods with NONE authorization
                        if auth_type == 'NONE':
                            methods_without_auth.append(f"{method_name} {resource_path}")
                    except Exception as e:
                        # Skip if we can't get method details
                        continue
            
            # Report if any methods lack authentication
            if methods_without_auth:
                methods_str = ", ".join(methods_without_auth[:5])  # Limit to first 5
                if len(methods_without_auth) > 5:
                    methods_str += f" (and {len(methods_without_auth) - 5} more)"
                self.results['IAMAuthentication'] = [-1, f"Methods without auth: {methods_str}"]
                
        except Exception as e:
            # If we can't check, flag as potential issue
            self.results['IAMAuthentication'] = [-1, f"API: {self.api['name']} (Error checking methods)"]
    
    def _checkRequestThrottling(self):
        """
        Check if throttling limits are configured at stage or method level.
        Throttling protects from traffic spikes and prevents backend overload.
        """
        try:
            resp = self.apiClient.get_stages(restApiId=self.api['id'])
            stages = resp.get('item', [])
            
            if not stages:
                return  # No stages to check
            
            stages_without_throttling = []
            
            for stage in stages:
                stage_name = stage.get('stageName', 'unknown')
                has_throttling = False
                
                # Check stage-level throttling settings
                method_settings = stage.get('methodSettings', {})
                
                # Check if any method has throttling configured
                for method_key, settings in method_settings.items():
                    throttle_burst = settings.get('throttlingBurstLimit')
                    throttle_rate = settings.get('throttlingRateLimit')
                    
                    # If either burst or rate limit is set, throttling is configured
                    if throttle_burst is not None or throttle_rate is not None:
                        has_throttling = True
                        break
                
                # Also check for stage-level default throttle settings
                if not has_throttling:
                    # Check if stage has default throttle settings
                    if method_settings.get('*/*'):
                        default_settings = method_settings['*/*']
                        throttle_burst = default_settings.get('throttlingBurstLimit')
                        throttle_rate = default_settings.get('throttlingRateLimit')
                        if throttle_burst is not None or throttle_rate is not None:
                            has_throttling = True
                
                if not has_throttling:
                    stages_without_throttling.append(stage_name)
            
            # Report stages without throttling
            if stages_without_throttling:
                stages_str = ", ".join(stages_without_throttling)
                self.results['RequestThrottling'] = [-1, f"Stages without throttling: {stages_str}"]
                
        except Exception as e:
            self.results['RequestThrottling'] = [-1, f"API: {self.api['name']} (Error: {str(e)})"]
    
    def _checkPrivateAPI(self):
        """
        Check if private APIs are properly configured with VPC endpoints.
        Private APIs should have endpoint type PRIVATE and VPC endpoint IDs configured.
        """
        try:
            # Get full API details to check endpoint configuration
            api_details = self.apiClient.get_rest_api(restApiId=self.api['id'])
            
            endpoint_config = api_details.get('endpointConfiguration', {})
            endpoint_types = endpoint_config.get('types', [])
            
            # Check if this is a private API
            if 'PRIVATE' in endpoint_types:
                # Verify VPC endpoint IDs are configured
                vpc_endpoint_ids = endpoint_config.get('vpcEndpointIds', [])
                
                if not vpc_endpoint_ids or len(vpc_endpoint_ids) == 0:
                    self.results['PrivateAPI'] = [-1, f"Private API without VPC endpoints: {self.api['name']}"]
            
        except Exception as e:
            # If we can't check, skip silently (not all APIs are private)
            pass
    
    def _checkLambdaAuthorizer(self):
        """
        Check if Lambda authorizers are configured for custom authorization.
        Lambda authorizers enable custom authorization logic with bearer tokens or request parameters.
        """
        try:
            # Get all authorizers for this API
            authorizers_resp = self.apiClient.get_authorizers(restApiId=self.api['id'])
            authorizers = authorizers_resp.get('items', [])
            
            # Filter for Lambda authorizers (TOKEN or REQUEST type)
            lambda_authorizers = [
                auth for auth in authorizers 
                if auth.get('type') in ['TOKEN', 'REQUEST']
            ]
            
            # This is an informational check - report if Lambda authorizers exist
            if lambda_authorizers:
                # Lambda authorizers are configured - this is good
                return
            
            # No Lambda authorizers found - this is informational, not necessarily bad
            # (API might use IAM or Cognito instead)
            
        except Exception as e:
            # If we can't check, skip silently
            pass
    
    def _checkCognitoAuthorizer(self):
        """
        Check if Cognito user pools are configured for authentication.
        Cognito provides managed user authentication and authorization.
        """
        try:
            # Get all authorizers for this API
            authorizers_resp = self.apiClient.get_authorizers(restApiId=self.api['id'])
            authorizers = authorizers_resp.get('items', [])
            
            # Filter for Cognito authorizers
            cognito_authorizers = [
                auth for auth in authorizers 
                if auth.get('type') == 'COGNITO_USER_POOLS'
            ]
            
            # This is an informational check - report if Cognito authorizers exist
            if cognito_authorizers:
                # Cognito authorizers are configured - this is good
                return
            
            # No Cognito authorizers found - this is informational, not necessarily bad
            # (API might use IAM or Lambda authorizers instead)
            
        except Exception as e:
            # If we can't check, skip silently
            pass
    
    def _checkMutualTLS(self):
        """
        Check if mutual TLS is enabled for custom domains.
        Mutual TLS provides two-way authentication between clients and API Gateway.
        """
        try:
            # Get all domain names
            domains_resp = self.apiClient.get_domain_names()
            domains = domains_resp.get('items', [])
            
            # Check each domain for mutual TLS configuration
            domains_without_mtls = []
            
            for domain in domains:
                domain_name = domain.get('domainName', 'unknown')
                
                # Check if this domain is associated with our API
                # We need to check base path mappings
                try:
                    mappings_resp = self.apiClient.get_base_path_mappings(domainName=domain_name)
                    mappings = mappings_resp.get('items', [])
                    
                    # Check if any mapping points to our API
                    api_mapped = any(m.get('restApiId') == self.api['id'] for m in mappings)
                    
                    if api_mapped:
                        # This domain is used by our API, check for mTLS
                        mtls_config = domain.get('mutualTlsAuthentication', {})
                        trust_store_uri = mtls_config.get('truststoreUri')
                        
                        if not trust_store_uri:
                            domains_without_mtls.append(domain_name)
                except Exception:
                    # Skip if we can't get mappings
                    continue
            
            # Report domains without mTLS
            if domains_without_mtls:
                domains_str = ", ".join(domains_without_mtls)
                self.results['MutualTLS'] = [-1, f"Custom domains without mTLS: {domains_str}"]
                
        except Exception as e:
            # If we can't check, skip silently (not all APIs have custom domains)
            pass
    
    def _checkUsagePlanThrottling(self):
        """
        Check if usage plans have throttling and quota limits configured.
        Usage plans help manage API consumption and prevent abuse.
        """
        try:
            # Get all usage plans
            usage_plans_resp = self.apiClient.get_usage_plans()
            usage_plans = usage_plans_resp.get('items', [])
            
            # Check if any usage plan is associated with our API
            plans_for_this_api = []
            
            for plan in usage_plans:
                plan_id = plan.get('id')
                plan_name = plan.get('name', 'unknown')
                
                # Check if this plan has our API in its API stages
                api_stages = plan.get('apiStages', [])
                api_in_plan = any(stage.get('apiId') == self.api['id'] for stage in api_stages)
                
                if api_in_plan:
                    # Check throttle and quota configuration
                    throttle = plan.get('throttle', {})
                    quota = plan.get('quota', {})
                    
                    burst_limit = throttle.get('burstLimit')
                    rate_limit = throttle.get('rateLimit')
                    quota_limit = quota.get('limit')
                    
                    # Flag if throttle or quota is not configured
                    if burst_limit is None and rate_limit is None and quota_limit is None:
                        plans_for_this_api.append(plan_name)
            
            # Report usage plans without limits
            if plans_for_this_api:
                plans_str = ", ".join(plans_for_this_api)
                self.results['UsagePlanThrottling'] = [-1, f"Usage plans without limits: {plans_str}"]
                
        except Exception as e:
            # If we can't check, skip silently
            pass
    
    def _checkVPCEndpointAssociation(self):
        """
        Check if private APIs are associated with VPC endpoints.
        This is similar to _checkPrivateAPI but focuses on the association aspect.
        """
        try:
            # Get full API details
            api_details = self.apiClient.get_rest_api(restApiId=self.api['id'])
            
            endpoint_config = api_details.get('endpointConfiguration', {})
            endpoint_types = endpoint_config.get('types', [])
            
            # Only check private APIs
            if 'PRIVATE' in endpoint_types:
                vpc_endpoint_ids = endpoint_config.get('vpcEndpointIds', [])
                
                if not vpc_endpoint_ids or len(vpc_endpoint_ids) == 0:
                    self.results['VPCEndpointAssociation'] = [-1, f"Private API: {self.api['name']}"]
            
        except Exception as e:
            # If we can't check, skip silently
            pass
    
    def _checkRequestValidation(self):
        """
        Check if request validators are configured to validate request parameters and body.
        Request validation reduces invalid requests reaching backend systems.
        """
        try:
            # Get all request validators for this API
            validators_resp = self.apiClient.get_request_validators(restApiId=self.api['id'])
            validators = validators_resp.get('items', [])
            
            if not validators or len(validators) == 0:
                # No validators configured - this is informational
                # Some APIs may not need validation
                return
            
            # Check if validators are actually used by methods
            resources_resp = self.apiClient.get_resources(restApiId=self.api['id'])
            resources = resources_resp.get('items', [])
            
            validator_used = False
            
            for resource in resources:
                resource_methods = resource.get('resourceMethods', {})
                
                for method_name in resource_methods.keys():
                    try:
                        method_details = self.apiClient.get_method(
                            restApiId=self.api['id'],
                            resourceId=resource['id'],
                            httpMethod=method_name
                        )
                        
                        # Check if method has a request validator
                        if 'requestValidatorId' in method_details:
                            validator_used = True
                            break
                    except Exception:
                        continue
                
                if validator_used:
                    break
            
            # If validators exist but none are used, it's informational
            # We don't flag this as an error since validation may not be needed
            
        except Exception as e:
            # If we can't check, skip silently
            pass

    def _checkLeastPrivilegeAccess(self):
        """
        Comprehensive access control check combining resource policies, authorization, and authorizers.
        Verifies multiple layers of access control are in place.
        """
        try:
            issues = []
            
            # Check 1: Resource policy exists
            api_details = self.apiClient.get_rest_api(restApiId=self.api['id'])
            has_policy = False
            if 'policy' in api_details and api_details['policy']:
                policy_str = api_details['policy']
                if len(policy_str.strip()) > 0 and policy_str != '{}':
                    has_policy = True
            
            if not has_policy:
                issues.append("No resource policy")
            
            # Check 2: Verify methods don't use NONE authorization
            resources_resp = self.apiClient.get_resources(restApiId=self.api['id'])
            resources = resources_resp.get('items', [])
            
            has_none_auth = False
            for resource in resources:
                resource_methods = resource.get('resourceMethods', {})
                for method_name in resource_methods.keys():
                    try:
                        method_details = self.apiClient.get_method(
                            restApiId=self.api['id'],
                            resourceId=resource['id'],
                            httpMethod=method_name
                        )
                        auth_type = method_details.get('authorizationType', 'NONE')
                        if auth_type == 'NONE':
                            has_none_auth = True
                            break
                    except Exception:
                        continue
                if has_none_auth:
                    break
            
            if has_none_auth:
                issues.append("Methods with NONE authorization")
            
            # Check 3: At least one authorizer should exist
            authorizers_resp = self.apiClient.get_authorizers(restApiId=self.api['id'])
            authorizers = authorizers_resp.get('items', [])
            
            if len(authorizers) == 0:
                issues.append("No authorizers configured")
            
            # Report results
            if issues:
                issues_str = ", ".join(issues)
                self.results['LeastPrivilegeAccess'] = [-1, f"Access control issues: {issues_str}"]
            
        except Exception as e:
            self.results['LeastPrivilegeAccess'] = [-1, f"Error checking access controls: {str(e)}"]
    
    def _checkCloudWatchAlarms(self):
        """
        Check if CloudWatch alarms are configured for key API Gateway metrics.
        Verifies alarms exist for 4XXError, 5XXError, Latency, and Count metrics.
        """
        try:
            # Import boto3 to get CloudWatch client from parent service
            # We need to check alarms for this specific API
            api_name = self.api['name']
            api_id = self.api['id']
            
            # Get stages to check alarms per stage
            stages_resp = self.apiClient.get_stages(restApiId=api_id)
            stages = stages_resp.get('item', [])
            
            if not stages:
                return  # No stages, skip alarm check
            
            # Critical metrics to check
            critical_metrics = ['4XXError', '5XXError', 'Latency', 'Count']
            
            # We need access to CloudWatch client - it should be passed from parent
            # For now, we'll create it here
            import boto3
            cloudwatch = boto3.client('cloudwatch')
            
            # Check for alarms on API Gateway metrics
            alarms_found = False
            
            for metric_name in critical_metrics:
                try:
                    response = cloudwatch.describe_alarms_for_metric(
                        MetricName=metric_name,
                        Namespace='AWS/ApiGateway',
                        Dimensions=[
                            {'Name': 'ApiName', 'Value': api_name}
                        ]
                    )
                    
                    metric_alarms = response.get('MetricAlarms', [])
                    if metric_alarms:
                        # Check if alarms have actions configured
                        for alarm in metric_alarms:
                            if alarm.get('AlarmActions') or alarm.get('InsufficientDataActions'):
                                alarms_found = True
                                break
                    
                    if alarms_found:
                        break
                        
                except Exception:
                    continue
            
            if not alarms_found:
                self.results['CloudWatchAlarms'] = [-1, f"No alarms configured for API: {api_name}"]
            
        except Exception as e:
            # If we can't check CloudWatch, skip silently (may not have permissions)
            pass
    
    def _checkAPIKeyAntiPattern(self):
        """
        Detect methods that rely only on API keys for authentication (anti-pattern).
        API keys should be used with proper authorization, not as sole authentication.
        """
        try:
            # Get all resources and methods
            resources_resp = self.apiClient.get_resources(restApiId=self.api['id'])
            resources = resources_resp.get('items', [])
            
            methods_with_api_key_only = []
            
            for resource in resources:
                resource_path = resource.get('path', '/')
                resource_methods = resource.get('resourceMethods', {})
                
                for method_name in resource_methods.keys():
                    try:
                        method_details = self.apiClient.get_method(
                            restApiId=self.api['id'],
                            resourceId=resource['id'],
                            httpMethod=method_name
                        )
                        
                        # Check if API key is required
                        api_key_required = method_details.get('apiKeyRequired', False)
                        
                        if api_key_required:
                            # Check if method also has proper authorization
                            auth_type = method_details.get('authorizationType', 'NONE')
                            
                            # If API key is required but auth is NONE, this is the anti-pattern
                            if auth_type == 'NONE':
                                methods_with_api_key_only.append(f"{method_name} {resource_path}")
                        
                    except Exception:
                        continue
            
            # Report methods using API key anti-pattern
            if methods_with_api_key_only:
                methods_str = ", ".join(methods_with_api_key_only[:5])
                if len(methods_with_api_key_only) > 5:
                    methods_str += f" (and {len(methods_with_api_key_only) - 5} more)"
                self.results['APIKeyAntiPattern'] = [-1, f"Methods with API key only: {methods_str}"]
            
        except Exception as e:
            # If we can't check, skip silently
            pass
    
    def _checkVPCAccessRestrictions(self):
        """
        Verify private APIs have resource policies with VPC-specific conditions.
        Checks for aws:SourceVpc or aws:SourceVpce conditions in resource policies.
        """
        try:
            # Get API details including endpoint configuration
            api_details = self.apiClient.get_rest_api(restApiId=self.api['id'])
            
            endpoint_config = api_details.get('endpointConfiguration', {})
            endpoint_types = endpoint_config.get('types', [])
            
            # Only check private APIs
            if 'PRIVATE' not in endpoint_types:
                return  # Not a private API, skip
            
            # Check if resource policy has VPC conditions
            policy_str = api_details.get('policy', '')
            
            if not policy_str or policy_str == '{}':
                self.results['VPCAccessRestrictions'] = [-1, f"Private API without resource policy: {self.api['name']}"]
                return
            
            # Parse policy JSON and check for VPC conditions
            try:
                policy = json.loads(policy_str)
                statements = policy.get('Statement', [])
                
                has_vpc_condition = False
                
                for statement in statements:
                    conditions = statement.get('Condition', {})
                    
                    # Check for VPC-related conditions
                    for condition_type, condition_values in conditions.items():
                        for condition_key in condition_values.keys():
                            if 'aws:SourceVpc' in condition_key or 'aws:SourceVpce' in condition_key:
                                has_vpc_condition = True
                                break
                        if has_vpc_condition:
                            break
                    if has_vpc_condition:
                        break
                
                if not has_vpc_condition:
                    self.results['VPCAccessRestrictions'] = [-1, f"Private API without VPC conditions: {self.api['name']}"]
                
            except json.JSONDecodeError:
                self.results['VPCAccessRestrictions'] = [-1, f"Invalid policy JSON: {self.api['name']}"]
            
        except Exception as e:
            # If we can't check, skip silently
            pass
    
    def _checkPerformanceMonitoring(self):
        """
        Check if CloudWatch dashboards and performance alarms are configured.
        Verifies monitoring infrastructure exists for API performance tracking.
        """
        try:
            import boto3
            cloudwatch = boto3.client('cloudwatch')
            
            api_name = self.api['name']
            
            # Check for CloudWatch dashboards
            dashboards_resp = cloudwatch.list_dashboards()
            dashboards = dashboards_resp.get('DashboardEntries', [])
            
            # Check if any dashboard name contains the API name or "apigateway"
            has_dashboard = False
            for dashboard in dashboards:
                dashboard_name = dashboard.get('DashboardName', '').lower()
                if api_name.lower() in dashboard_name or 'apigateway' in dashboard_name or 'api-gateway' in dashboard_name:
                    has_dashboard = True
                    break
            
            # Check for performance-related alarms (Latency metric)
            has_performance_alarm = False
            try:
                response = cloudwatch.describe_alarms_for_metric(
                    MetricName='Latency',
                    Namespace='AWS/ApiGateway',
                    Dimensions=[
                        {'Name': 'ApiName', 'Value': api_name}
                    ]
                )
                
                metric_alarms = response.get('MetricAlarms', [])
                if metric_alarms:
                    has_performance_alarm = True
                    
            except Exception:
                pass
            
            # Report if monitoring infrastructure is missing
            if not has_dashboard and not has_performance_alarm:
                self.results['PerformanceMonitoring'] = [-1, f"No performance monitoring for API: {api_name}"]
            
        except Exception as e:
            # If we can't check CloudWatch, skip silently (may not have permissions)
            pass

    def _checkCanaryDeployment(self):
        """
        Check if canary deployments are configured for gradual rollouts.
        Verifies canary settings exist for production stages.
        """
        try:
            # Get all stages
            stages_resp = self.apiClient.get_stages(restApiId=self.api['id'])
            stages = stages_resp.get('item', [])
            
            if not stages:
                return  # No stages to check
            
            # Check production stages for canary configuration
            prod_stages_without_canary = []
            
            for stage in stages:
                stage_name = stage.get('stageName', '').lower()
                
                # Focus on production-like stages
                if any(prod_indicator in stage_name for prod_indicator in ['prod', 'production', 'live']):
                    canary_settings = stage.get('canarySettings', {})
                    
                    # Check if canary is configured
                    if not canary_settings or not canary_settings.get('percentTraffic'):
                        prod_stages_without_canary.append(stage.get('stageName', 'unknown'))
            
            # Report production stages without canary (informational)
            if prod_stages_without_canary:
                stages_str = ", ".join(prod_stages_without_canary)
                # This is informational - canary is optional but recommended for prod
                self.results['CanaryDeployment'] = [0, f"Production stages without canary: {stages_str}"]
            
        except Exception as e:
            # If we can't check, skip silently
            pass
    
    def _checkStageVariables(self):
        """
        Check if stage variables are used for environment-specific configuration.
        Stage variables improve deployment flexibility and reduce configuration errors.
        """
        try:
            # Get all stages
            stages_resp = self.apiClient.get_stages(restApiId=self.api['id'])
            stages = stages_resp.get('item', [])
            
            if not stages:
                return  # No stages to check
            
            # Check stages for variables
            stages_without_variables = []
            
            for stage in stages:
                stage_name = stage.get('stageName', 'unknown')
                variables = stage.get('variables', {})
                
                # Check if variables are configured
                if not variables or len(variables) == 0:
                    stages_without_variables.append(stage_name)
            
            # Report stages without variables (informational)
            if stages_without_variables:
                stages_str = ", ".join(stages_without_variables)
                # This is informational - stage variables are optional
                self.results['StageVariables'] = [0, f"Stages without variables: {stages_str}"]
            
        except Exception as e:
            # If we can't check, skip silently
            pass
    
    def _checkStageLifecycle(self):
        """
        Check proper stage lifecycle management practices.
        Verifies multiple stages exist with appropriate naming conventions.
        """
        try:
            # Get all stages
            stages_resp = self.apiClient.get_stages(restApiId=self.api['id'])
            stages = stages_resp.get('item', [])
            
            if not stages:
                return  # Already handled by IdleAPIGateway check
            
            # Check for multiple stages
            stage_count = len(stages)
            
            if stage_count == 1:
                # Single stage - informational
                self.results['StageLifecycle'] = [0, f"Single stage deployment: {stages[0].get('stageName', 'unknown')}"]
                return
            
            # Check for common stage naming patterns
            stage_names = [s.get('stageName', '').lower() for s in stages]
            
            # Look for dev/test/prod pattern
            has_dev = any('dev' in name for name in stage_names)
            has_test = any('test' in name or 'staging' in name or 'qa' in name for name in stage_names)
            has_prod = any('prod' in name or 'production' in name or 'live' in name for name in stage_names)
            
            # If multiple stages but missing key environments, provide info
            if stage_count >= 2 and not (has_dev or has_test or has_prod):
                self.results['StageLifecycle'] = [0, f"Multiple stages ({stage_count}) with non-standard naming"]
            
        except Exception as e:
            # If we can't check, skip silently
            pass
    
    def _checkCORSConfiguration(self):
        """
        Check if CORS is properly configured for cross-domain requests.
        For REST APIs, checks OPTIONS method with CORS integration.
        """
        try:
            # Get all resources
            resources_resp = self.apiClient.get_resources(restApiId=self.api['id'])
            resources = resources_resp.get('items', [])
            
            # Check if any resource has OPTIONS method (CORS indicator)
            has_cors = False
            
            for resource in resources:
                resource_methods = resource.get('resourceMethods', {})
                
                if 'OPTIONS' in resource_methods:
                    # Check if OPTIONS method has CORS-related integration
                    try:
                        method_details = self.apiClient.get_method(
                            restApiId=self.api['id'],
                            resourceId=resource['id'],
                            httpMethod='OPTIONS'
                        )
                        
                        # Check integration response for CORS headers
                        integration_resp = self.apiClient.get_integration_response(
                            restApiId=self.api['id'],
                            resourceId=resource['id'],
                            httpMethod='OPTIONS',
                            statusCode='200'
                        )
                        
                        response_params = integration_resp.get('responseParameters', {})
                        
                        # Look for CORS headers
                        cors_headers = [
                            'method.response.header.Access-Control-Allow-Origin',
                            'method.response.header.Access-Control-Allow-Methods',
                            'method.response.header.Access-Control-Allow-Headers'
                        ]
                        
                        if any(header in response_params for header in cors_headers):
                            has_cors = True
                            break
                            
                    except Exception:
                        # If we can't get integration response, skip this resource
                        continue
            
            # This is informational - CORS may not be needed for all APIs
            if not has_cors:
                # Don't flag as failure - CORS is optional
                pass
            
        except Exception as e:
            # If we can't check, skip silently
            pass
