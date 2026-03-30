import boto3
import botocore
import requests

from utils.Config import Config
from services.Service import Service

###### TO DO #####
## Import required service module below
## Example
from services.cloudwatch.drivers.CloudwatchCommon import CloudwatchCommon
from services.cloudwatch.drivers.CloudwatchTrails import CloudwatchTrails
from services.cloudwatch.drivers.CloudwatchAlarms import CloudwatchAlarms
from services.cloudwatch.drivers.CloudwatchDashboards import CloudwatchDashboards

from utils.Tools import _pi

###### TO DO #####
## Replace ServiceName with
## getResources and advise method is default method that must have
## Feel free to develop method to support your checks
class Cloudwatch(Service):
    def __init__(self, region):
        super().__init__(region)
        ssBoto = self.ssBoto

        self.cwClient = ssBoto.client('cloudwatch', config=self.bConfig)
        self.cwLogClient = ssBoto.client('logs', config=self.bConfig)
        self.ctClient = ssBoto.client('cloudtrail', config=self.bConfig)
        self.xrayClient = ssBoto.client('xray', config=self.bConfig)

        self.ctLogs = []
        self.logGroups = []
        self.alarms = []
        self.compositeAlarms = []
        self.dashboards = []

        return
    
    ## method to get resources for the services
    ## return the array of the resources
    def loopTrail(self, NextToken=None):
        """
        Collect all CloudTrail trails using pagination
        
        AWS API Pagination:
        - list_trails returns paginated results
        - NextToken is used to retrieve subsequent pages
        
        Trail Processing:
        - Only processes trails where HomeRegion matches current region
        - Retrieves detailed trail info including CloudWatch Logs integration
        - Stores trail ARN, log group ARN, and log group name
        
        Args:
            NextToken: Pagination token from previous API call (None for first call)
        
        Note:
            Results are accumulated in self.ctLogs list across all pagination calls
        """
        args = {}
        if NextToken:
            args['NextToken'] = NextToken
        
        resp = self.ctClient.list_trails(**args)
        trails = resp.get('Trails')
        for trail in trails:
            # Only process trails in their home region to avoid duplicate checks
            if trail['HomeRegion'] == self.region:
                info = self.ctClient.describe_trails(trailNameList=[trail['TrailARN']])
                tl = info.get('trailList')[0]
                # Extract CloudWatch Logs log group name from ARN if configured
                # ARN format: arn:aws:logs:region:account-id:log-group:log-group-name:*
                if 'CloudWatchLogsLogGroupArn' in tl:
                    logGroupName = tl['CloudWatchLogsLogGroupArn'].split(':')[6]
                    self.ctLogs.append([trail['TrailARN'], tl['CloudWatchLogsLogGroupArn'], logGroupName])
                else:
                    # Trail exists but CloudWatch Logs integration not configured
                    self.ctLogs.append([trail['TrailARN'], None, None])
           
        # Recursively fetch next page if more results exist
        if resp.get('NextToken'):
            self.loopTrail(resp.get('NextToken'))
    
    def getAllLogs(self, nextToken=None):
        """
        Collect all CloudWatch log groups using pagination
        
        AWS API Pagination:
        - describe_log_groups returns paginated results
        - nextToken is used to retrieve subsequent pages
        - Must recursively call until nextToken is None
        
        Args:
            nextToken: Pagination token from previous API call (None for first call)
        
        Note:
            Results are accumulated in self.logGroups list across all pagination calls
        """
        args = {}
        if nextToken:
            args['nextToken'] = nextToken
        
        resp = self.cwLogClient.describe_log_groups(**args)
        logGroups = resp.get('logGroups')
        for lg in logGroups:
            self.logGroups.append({
                'logGroupName': lg['logGroupName'],
                'storedBytes': lg['storedBytes'],
                'retentionInDays': lg['retentionInDays'] if 'retentionInDays' in lg else -1,
                'dataProtectionStatus': lg['dataProtectionStatus'] if 'dataProtectionStatus' in lg else ''
            })
        
        # Recursively fetch next page if more results exist
        if resp.get('nextToken'):
            self.getAllLogs(resp.get('nextToken'))
    
    def getAllAlarms(self, nextToken=None):
        """
        Collect all CloudWatch alarms using pagination
        
        AWS API Pagination:
        - describe_alarms returns max 100 alarms per call
        - NextToken is used to retrieve subsequent pages
        - Must recursively call until NextToken is None
        
        Args:
            nextToken: Pagination token from previous API call (None for first call)
        
        Note:
            Results are accumulated in self.alarms list across all pagination calls
        """
        args = {}
        if nextToken:
            args['NextToken'] = nextToken
        
        resp = self.cwClient.describe_alarms(**args)
        # MetricAlarms contains standard metric-based alarms (not composite alarms)
        alarms = resp.get('MetricAlarms', [])
        for alarm in alarms:
            self.alarms.append(alarm)
        
        # Recursively fetch next page if more results exist
        # This ensures we collect ALL alarms across multiple API calls
        if resp.get('NextToken'):
            self.getAllAlarms(resp.get('NextToken'))

    def getAllDashboards(self, nextToken=None):
        """
        Collect all CloudWatch dashboards using pagination

        AWS API Pagination:
        - list_dashboards returns paginated results
        - NextToken is used to retrieve subsequent pages
        - Must recursively call until NextToken is None

        Args:
            nextToken: Pagination token from previous API call (None for first call)

        Note:
            Results are accumulated in self.dashboards list across all pagination calls

        Validates: Requirements 4.1, 20.1, 20.2, 20.3
        """
        args = {}
        if nextToken:
            args['NextToken'] = nextToken

        resp = self.cwClient.list_dashboards(**args)
        dashboards = resp.get('DashboardEntries', [])
        for dashboard in dashboards:
            self.dashboards.append(dashboard)

        # Recursively fetch next page if more results exist
        if resp.get('NextToken'):
            self.getAllDashboards(resp.get('NextToken'))

    def getAllCompositeAlarms(self, nextToken=None):
        """
        Collect all composite alarms using pagination

        AWS API Pagination:
        - describe_alarms with AlarmTypes=['CompositeAlarm'] returns paginated results
        - NextToken is used to retrieve subsequent pages
        - Must recursively call until NextToken is None

        Composite Alarms:
        - Combine multiple alarms using boolean logic (AND, OR, NOT)
        - Reduce alarm noise by creating higher-level alarm conditions
        - Useful for complex monitoring scenarios

        Args:
            nextToken: Pagination token from previous API call (None for first call)

        Note:
            Results are accumulated in self.compositeAlarms list across all pagination calls

        Validates: Requirements 11.1, 20.1
        """
        args = {'AlarmTypes': ['CompositeAlarm']}
        if nextToken:
            args['NextToken'] = nextToken

        resp = self.cwClient.describe_alarms(**args)
        # CompositeAlarms contains composite alarm definitions
        composite_alarms = resp.get('CompositeAlarms', [])
        for alarm in composite_alarms:
            self.compositeAlarms.append(alarm)

        # Recursively fetch next page if more results exist
        if resp.get('NextToken'):
            self.getAllCompositeAlarms(resp.get('NextToken'))


    

    def checkBillingAlarms(self):
        """
        Check if billing alarms are configured (account-level check)
        
        AWS Billing Metrics Restriction:
        - Billing metrics are ONLY available in us-east-1 region
        - This is an AWS platform limitation, not a configuration issue
        - Metric namespace: AWS/Billing, MetricName: EstimatedCharges
        
        Implementation:
        - This is an account-level check (not per-alarm)
        - Only runs in us-east-1 to avoid false positives in other regions
        - Returns None for non-us-east-1 regions (check not applicable)
        - Returns failure result if no billing alarms found in us-east-1
        
        Returns:
            dict: Failure result if no billing alarms configured in us-east-1
            None: If region is not us-east-1 or billing alarms exist
        """
        # Skip check in non-us-east-1 regions since billing metrics don't exist there
        # This prevents false positives when scanning multiple regions
        if self.region != 'us-east-1':
            return None
        
        # Search for billing alarms in the collected alarms
        # Billing alarms monitor AWS/Billing namespace with EstimatedCharges metric
        hasBillingAlarm = False
        for alarm in self.alarms:
            namespace = alarm.get('Namespace', '')
            metricName = alarm.get('MetricName', '')
            # Match both namespace and metric name to identify billing alarms
            if namespace == 'AWS/Billing' and metricName == 'EstimatedCharges':
                hasBillingAlarm = True
                break
        
        # Return failure result only if we're in us-east-1 and no billing alarms exist
        if not hasBillingAlarm:
            return {'missingBillingAlarms': [-1, 'No billing alarms configured']}
        
        # Return None if billing alarms are properly configured
        return None

    def checkApplicationSignals(self):
        """
        Check if Application Signals SLOs are configured (account-level check)

        Application Signals provides:
        - Application topology discovery
        - Service level objective (SLO) monitoring
        - Dependency mapping for microservices

        Regional Availability:
        - Application Signals is not available in all regions
        - Check will skip gracefully if region doesn't support the feature

        Returns:
            dict: Failure result with check ID "missingApplicationSignals" if no SLOs found
            None: If SLOs exist or region doesn't support feature

        Validates: Requirements 6.1, 6.2, 6.3, 6.4, 22.2
        """
        try:
            # Application Signals uses a separate client
            appSignalsClient = self.ssBoto.client('application-signals', config=self.bConfig)
            response = appSignalsClient.list_service_level_objectives()

            # Check if at least one SLO is configured
            slos = response.get('SloSummaries', [])

            if not slos:
                return {'missingApplicationSignals': [-1, 'No Application Signals SLOs configured. Consider enabling Application Signals for application topology and dependency discovery.']}

            # SLOs exist, check passes
            return None

        except botocore.exceptions.ClientError as e:
            error_code = e.response['Error']['Code']
            # InvalidAction or similar errors indicate feature not available in region
            if error_code in ['InvalidAction', 'UnsupportedOperation', 'UnknownOperationException']:
                # Region doesn't support Application Signals, skip check
                return None
            elif error_code == 'AccessDeniedException':
                # Insufficient permissions, log and skip
                print(f"Access denied checking Application Signals: {str(e)}")
                return None
            else:
                # Other errors, log and skip
                print(f"Error checking Application Signals: {str(e)}")
                return None
        except Exception as e:
            # Catch all other exceptions to prevent check from failing
            print(f"Unexpected error checking Application Signals: {str(e)}")
            return None

    def checkXRayIntegration(self):
        """
        Check if X-Ray sampling rules are configured (account-level check)

        X-Ray provides:
        - Distributed tracing for microservices
        - Performance bottleneck identification
        - Service dependency mapping
        - Request flow visualization

        Sampling Rules:
        - Control which requests are traced
        - Manage tracing costs
        - Required for X-Ray to collect trace data

        Returns:
            dict: Failure result with check ID "missingXRayIntegration" if no rules found
            None: If X-Ray is configured

        Validates: Requirements 7.1, 7.2, 7.3, 7.4
        """
        try:
            # Query X-Ray sampling rules
            response = self.xrayClient.get_sampling_rules()

            # Check if sampling rules are configured
            sampling_rules = response.get('SamplingRuleRecords', [])

            if not sampling_rules:
                return {'missingXRayIntegration': [-1, 'No X-Ray sampling rules configured. Consider enabling X-Ray for distributed tracing and performance analysis.']}

            # X-Ray is configured, check passes
            return None

        except botocore.exceptions.ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'AccessDeniedException':
                # Insufficient permissions, log and skip
                print(f"Access denied checking X-Ray integration: {str(e)}")
                return None
            else:
                # Other errors, log and skip
                print(f"Error checking X-Ray integration: {str(e)}")
                return None
        except Exception as e:
            # Catch all other exceptions to prevent check from failing
            print(f"Unexpected error checking X-Ray integration: {str(e)}")
            return None

    def checkCustomMetrics(self):
        """
        Check if custom metrics are being published (account-level check)

        Custom Metrics:
        - Application-specific metrics published by your code
        - Namespace does NOT start with "AWS/" (AWS-managed namespaces)
        - Enable monitoring of business and application KPIs
        - Examples: order processing rate, user signups, custom error rates

        Returns:
            dict: Failure result with check ID "missingCustomMetrics" if no custom metrics found
            None: If custom metrics exist

        Validates: Requirements 9.1, 9.2, 9.3, 9.4
        """
        try:
            # Query all metric namespaces
            response = self.cwClient.list_metrics()

            # Filter for custom namespaces (not starting with "AWS/")
            custom_namespaces = set()
            metrics = response.get('Metrics', [])

            for metric in metrics:
                namespace = metric.get('Namespace', '')
                # Custom metrics have namespaces that don't start with "AWS/"
                if namespace and not namespace.startswith('AWS/'):
                    custom_namespaces.add(namespace)

            if not custom_namespaces:
                return {'missingCustomMetrics': [-1, 'No custom metrics found. Consider publishing application-specific metrics for better monitoring visibility.']}

            # Custom metrics exist, check passes
            return None

        except botocore.exceptions.ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'AccessDeniedException':
                # Insufficient permissions, log and skip
                print(f"Access denied checking custom metrics: {str(e)}")
                return None
            else:
                # Other errors, log and skip
                print(f"Error checking custom metrics: {str(e)}")
                return None
        except Exception as e:
            # Catch all other exceptions to prevent check from failing
            print(f"Unexpected error checking custom metrics: {str(e)}")
            return None

    def checkCompositeAlarms(self):
        """
        Check if composite alarms are configured (account-level check)

        Composite Alarms:
        - Combine multiple alarms using boolean logic (AND, OR, NOT)
        - Reduce alarm noise by creating higher-level conditions
        - Enable complex monitoring scenarios
        - Example: Alert only if CPU high AND memory high AND disk full

        Returns:
            dict: Failure result with check ID "missingCompositeAlarms" if no composite alarms found
            None: If composite alarms exist

        Validates: Requirements 11.1, 11.2, 11.3, 11.4
        """
        try:
            # Check if composite alarms were collected
            if not self.compositeAlarms:
                return {'missingCompositeAlarms': [-1, f'No composite alarms configured. Found 0 composite alarms. Consider using composite alarms to reduce alarm noise.']}

            # Composite alarms exist, check passes
            return None

        except Exception as e:
            # Catch all exceptions to prevent check from failing
            print(f"Unexpected error checking composite alarms: {str(e)}")
            return None

    def checkDashboardExistence(self):
        """
        Check if CloudWatch dashboards are configured (account-level check)

        CloudWatch Dashboards:
        - Provide customizable visualization of metrics and logs
        - Enable operational awareness and monitoring
        - Support cross-account and cross-region metrics
        - Essential for operations teams

        Returns:
            dict: Failure result with check ID "missingCloudWatchDashboards" if no dashboards found
            None: If dashboards exist

        Validates: Requirements 8.1, 8.2, 8.3, 8.4
        """
        try:
            # Check if dashboards were collected
            if not self.dashboards:
                return {'missingCloudWatchDashboards': [-1, f'No CloudWatch dashboards configured. Found 0 dashboards. Consider creating dashboards for operational visibility.']}

            # Dashboards exist, check passes
            return None

        except Exception as e:
            # Catch all exceptions to prevent check from failing
            print(f"Unexpected error checking dashboard existence: {str(e)}")
            return None

    def checkAlarmTagging(self):
        """
        Check if alarms have required tags (account-level aggregation check)

        Required Tags:
        - Environment: Identifies deployment environment (prod, dev, staging)
        - Project: Associates alarm with project or application
        - CostCenter: Enables cost allocation and chargeback

        This is an aggregated check that examines all alarms and reports
        if any are missing required tags.

        Returns:
            dict: Failure result with check ID "cloudwatchResourcesWithoutTags" for untagged alarms
            None: If all alarms are properly tagged

        Validates: Requirements 2.1, 2.2, 2.4, 2.5
        """
        try:
            # Define required tags
            required_tags = ['Environment', 'Project', 'CostCenter']

            # Track alarms without required tags
            untagged_alarms = []

            # Check tags for each alarm
            for alarm in self.alarms:
                alarm_arn = alarm.get('AlarmArn', '')
                alarm_name = alarm.get('AlarmName', 'unknown')

                if not alarm_arn:
                    continue

                try:
                    # Retrieve tags for the alarm
                    response = self.cwClient.list_tags_for_resource(
                        ResourceARN=alarm_arn
                    )

                    # Get tags list from response
                    tags = response.get('Tags', [])
                    tag_keys = [tag['Key'] for tag in tags]

                    # Check which required tags are missing
                    missing_tags = [tag for tag in required_tags if tag not in tag_keys]

                    if missing_tags:
                        untagged_alarms.append(alarm_name)

                except botocore.exceptions.ClientError as e:
                    error_code = e.response['Error']['Code']
                    if error_code == 'AccessDeniedException':
                        # Skip this alarm if access denied
                        continue
                    else:
                        print(f"Error checking tags for alarm {alarm_name}: {str(e)}")
                        continue

            # Return failure if any alarms are untagged
            if untagged_alarms:
                # Limit to first 5 alarms in message to avoid overly long messages
                alarm_list = ', '.join(untagged_alarms[:5])
                if len(untagged_alarms) > 5:
                    alarm_list += f' and {len(untagged_alarms) - 5} more'

                return {'cloudwatchResourcesWithoutTags': [-1, f'{len(untagged_alarms)} alarms missing required tags: {alarm_list}']}

            # All alarms properly tagged, check passes
            return None

        except Exception as e:
            # Catch all exceptions to prevent check from failing
            print(f"Unexpected error checking alarm tagging: {str(e)}")
            return None






    
    def advise(self):
        objs = {}
        
        self.loopTrail()
        for log in self.ctLogs:
            _pi("CloudTrail's CloudWatch Logs", log[0])
            obj = CloudwatchTrails(log, log[2], self.cwLogClient)
            obj.run(self.__class__)
            
            objs[f"ctLog::{log[0]}"] = obj.getInfo()
            del obj
        
        self.getAllLogs()
        for log in self.logGroups:
            _pi('Cloudwatch Logs', log['logGroupName'])
            obj = CloudwatchCommon(log, self.cwLogClient)
            obj.run(self.__class__)
            
            objs[f"Log::{log['logGroupName']}"] = obj.getInfo()
            del obj
        
        # Check CloudWatch Alarms
        self.getAllAlarms()
        for alarm in self.alarms:
            _pi('CloudWatch Alarm', alarm['AlarmName'])
            obj = CloudwatchAlarms(alarm, self.cwClient)
            obj.run(self.__class__)
            objs[f"Alarm::{alarm['AlarmName']}"] = obj.getInfo()
            del obj
        
        # Collect composite alarms for service-level check
        self.getAllCompositeAlarms()
        
        # Check CloudWatch Dashboards
        self.getAllDashboards()
        for dashboard in self.dashboards:
            _pi('CloudWatch Dashboard', dashboard['DashboardName'])
            obj = CloudwatchDashboards(dashboard, self.cwClient)
            obj.run(self.__class__)
            objs[f"Dashboard::{dashboard['DashboardName']}"] = obj.getInfo()
            del obj
        
        # Service-level checks (account-level)
        
        # Check billing alarms (account-level check, only in us-east-1)
        billingCheck = self.checkBillingAlarms()
        if billingCheck:
            objs['Account::BillingAlarms'] = {'results': billingCheck, 'info': {}}
        
        # Check Application Signals
        appSignalsCheck = self.checkApplicationSignals()
        if appSignalsCheck:
            objs['Account::ApplicationSignals'] = {'results': appSignalsCheck, 'info': {}}
        
        # Check X-Ray Integration
        xrayCheck = self.checkXRayIntegration()
        if xrayCheck:
            objs['Account::XRayIntegration'] = {'results': xrayCheck, 'info': {}}
        
        # Check Custom Metrics
        customMetricsCheck = self.checkCustomMetrics()
        if customMetricsCheck:
            objs['Account::CustomMetrics'] = {'results': customMetricsCheck, 'info': {}}
        
        # Check Composite Alarms
        compositeAlarmsCheck = self.checkCompositeAlarms()
        if compositeAlarmsCheck:
            objs['Account::CompositeAlarms'] = {'results': compositeAlarmsCheck, 'info': {}}
        
        # Check Dashboard Existence
        dashboardCheck = self.checkDashboardExistence()
        if dashboardCheck:
            objs['Account::DashboardExistence'] = {'results': dashboardCheck, 'info': {}}
        
        # Check Alarm Tagging
        alarmTaggingCheck = self.checkAlarmTagging()
        if alarmTaggingCheck:
            objs['Account::AlarmTagging'] = {'results': alarmTaggingCheck, 'info': {}}
            
        return objs