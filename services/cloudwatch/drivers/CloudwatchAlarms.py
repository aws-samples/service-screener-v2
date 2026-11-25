import boto3
import botocore
import constants as _C

from services.Evaluator import Evaluator

class CloudwatchAlarms(Evaluator):
    """
    Driver for CloudWatch Alarms checks
    Handles alarm configuration validation including SNS notifications and billing alarms
    """

    ## AWS namespaces that publish datapoints continuously while the resource
    ## exists, so two weeks without data means the resource is gone (or
    ## stopped). Other AWS/* namespaces (Lambda, SNS, SQS, API Gateway, ALB,
    ## Step Functions, ...) publish only when there is activity, so an idle
    ## resource looks the same as a deleted one.
    CONTINUOUS_AWS_NAMESPACES = frozenset(('AWS/EC2', 'AWS/RDS', 'AWS/ElastiCache'))
    
    def __init__(self, alarm, cwClient, metricFilterMetrics=None):
        super().__init__()
        self.init()
        
        self.alarm = alarm
        self.cwClient = cwClient
        ## set of (namespace, metricName) produced by CloudWatch Logs metric
        ## filters in this region, or None when it could not be read.
        self.metricFilterMetrics = metricFilterMetrics
        
        try:
            self._resourceName = alarm.get('AlarmName', 'unknown')
        except Exception as e:
            self._resourceName = 'unknown'
            print(f"Error getting alarm name: {str(e)}")
        
        return
    
    def _checkSNSNotifications(self):
        """
        Check if CloudWatch alarm has SNS topic actions configured
        Alarms without SNS notifications provide no value for operational awareness
        """
        try:
            # AlarmActions contains ARNs of actions to execute when alarm state changes
            # Can include SNS topics, Auto Scaling policies, EC2 actions, or Systems Manager actions
            alarmActions = self.alarm.get('AlarmActions', [])
            
            # Check if any SNS topic ARNs are configured
            # SNS ARNs follow format: arn:aws:sns:region:account-id:topic-name
            hasSNS = False
            for action in alarmActions:
                # Validate action is not None/empty and is an SNS ARN
                if action and action.startswith('arn:aws:sns:'):
                    hasSNS = True
                    break
            
            # Flag alarm as non-compliant if no SNS notifications configured
            # This is critical for operational awareness and incident response
            if not hasSNS:
                self.results['alarmsWithoutSNS'] = [-1, 'No SNS notifications configured']
        except Exception as e:
            # Log error but don't fail the check - allows other checks to continue
            # This handles edge cases like malformed alarm data
            print(f"Error checking SNS notifications for alarm {self._resourceName}: {str(e)}")
    
    def _checkBillingAlarms(self):
        """
        Check if billing alarms are configured (account-level check)
        
        AWS Billing Metrics Behavior:
        - Billing metrics are ONLY available in us-east-1 region
        - This is an AWS limitation, not a configuration issue
        - Metric namespace: AWS/Billing, MetricName: EstimatedCharges
        
        Implementation Note:
        - This check is handled at the service level (Cloudwatch.py), not per-alarm
        - Individual alarms don't need to implement this check
        - This method exists as a placeholder for documentation purposes
        """
        # This check is handled at the service level, not per-alarm
        # Individual alarms don't need to implement this check
        pass
    def _checkServiceQuotaAlarms(self):
        """
        Check if alarm monitors AWS/Usage namespace for service quotas

        Service quotas are critical limits that can cause service disruptions if exceeded.
        This check verifies that alarms monitor AWS/Usage metrics for critical services:
        - VPC (Virtual Private Cloud resources)
        - EC2 (Elastic Compute Cloud instances)
        - Lambda (Function executions and concurrency)
        - RDS (Relational Database Service instances)
        - ECS (Elastic Container Service tasks)

        Validates: Requirements 1.1, 1.2, 1.3, 1.4
        """
        try:
            # Get the namespace of the alarm
            namespace = self.alarm.get('Namespace', '')

            # Only check alarms that monitor AWS/Usage namespace
            # If not AWS/Usage, this check doesn't apply
            if namespace != 'AWS/Usage':
                return

            # Define critical services that should have quota monitoring
            critical_services = ['VPC', 'EC2', 'Lambda', 'RDS', 'ECS']

            # Get the metric name to identify which service quota is being monitored
            metric_name = self.alarm.get('MetricName', '')

            # Check if the alarm monitors a critical service quota
            # AWS/Usage metrics typically have format like "ResourceCount" with dimensions
            # specifying the service and resource type
            monitors_critical_quota = False
            service_name = ''

            # Check dimensions to identify the service
            dimensions = self.alarm.get('Dimensions', [])
            for dimension in dimensions:
                if dimension.get('Name') == 'Service':
                    service_value = dimension.get('Value', '')
                    # Extract service name from dimension value
                    for critical_service in critical_services:
                        if critical_service in service_value:
                            monitors_critical_quota = True
                            service_name = critical_service
                            break
                if dimension.get('Name') == 'Resource':
                    # Resource dimension contains the quota name
                    pass

            # If this AWS/Usage alarm doesn't monitor a critical service quota, flag it
            if not monitors_critical_quota:
                failure_message = f"Alarm monitors AWS/Usage but not for critical service quotas. Service: {service_name if service_name else 'Unknown'}, Metric: {metric_name}"
                self.results['missingServiceQuotaAlarms'] = [-1, failure_message]
        except Exception as e:
            # Log error but don't fail the check - allows other checks to continue
            print(f"Error checking service quota alarms for alarm {self._resourceName}: {str(e)}")

    def _checkAutoScalingActions(self):
        """
        Check if alarm has Auto Scaling actions for scaling-related metrics

        Auto Scaling alarms should trigger Auto Scaling policies to automatically
        adjust capacity based on metrics. This check identifies alarms monitoring
        Auto Scaling-related namespaces that lack Auto Scaling policy actions.

        Auto Scaling-related namespaces:
        - AWS/EC2: EC2 instance metrics (CPU, network, disk)
        - AWS/ECS: ECS service and task metrics
        - AWS/ApplicationAutoScaling: Application Auto Scaling metrics

        Validates: Requirements 5.1, 5.2, 5.3
        """
        try:
            # Get the namespace of the alarm
            namespace = self.alarm.get('Namespace', '')

            # Define Auto Scaling-related namespaces
            autoscaling_namespaces = ['AWS/EC2', 'AWS/ECS', 'AWS/ApplicationAutoScaling']

            # Only check alarms in Auto Scaling-related namespaces
            # If not an Auto Scaling namespace, this check doesn't apply
            if namespace not in autoscaling_namespaces:
                return

            # Get alarm actions
            alarm_actions = self.alarm.get('AlarmActions', [])

            # Check if any actions are Auto Scaling policy ARNs
            # Auto Scaling policy ARNs follow format: arn:aws:autoscaling:region:account-id:scalingPolicy:...
            has_autoscaling_action = False
            for action in alarm_actions:
                # Validate action is not None/empty and is an Auto Scaling ARN
                if action and action.startswith('arn:aws:autoscaling:'):
                    has_autoscaling_action = True
                    break

            # Flag alarm as non-compliant if no Auto Scaling actions configured
            # This indicates a missed opportunity for automatic scaling
            if not has_autoscaling_action:
                self.results['alarmsWithoutAutoScalingActions'] = [-1, f'Alarm monitors {namespace} but has no Auto Scaling actions configured']
        except Exception as e:
            # Log error but don't fail the check - allows other checks to continue
            print(f"Error checking Auto Scaling actions for alarm {self._resourceName}: {str(e)}")

    def _checkMetricMath(self):
        """
        Check if alarm uses metric math expressions

        Metric math allows combining multiple metrics using mathematical expressions,
        enabling more sophisticated monitoring scenarios. This is an informational check
        that identifies opportunities to use metric math for advanced monitoring.

        Metric math alarms have a 'Metrics' array instead of single metric fields,
        and at least one entry in the array has an 'Expression' field.

        Standard alarms use: MetricName, Namespace, Dimensions
        Metric math alarms use: Metrics array with Id, Expression, MetricStat

        Validates: Requirements 10.1, 10.2, 10.3, 10.4
        """
        try:
            # Check if alarm has a Metrics array (metric math alarms use this)
            # Standard alarms don't have this field
            metrics = self.alarm.get('Metrics', [])

            # If no Metrics array, this is a standard alarm without metric math
            if not metrics:
                self.results['alarmsWithoutMetricMath'] = [-1, 'Alarm does not use metric math expressions']
                return

            # Check if any metric in the array has an Expression field
            # Expression field indicates metric math is being used
            has_metric_math = False
            for metric in metrics:
                if 'Expression' in metric:
                    has_metric_math = True
                    break

            # Flag alarm if it has Metrics array but no expressions
            # This could indicate incomplete metric math configuration
            if not has_metric_math:
                self.results['alarmsWithoutMetricMath'] = [-1, 'Alarm has Metrics array but no metric math expressions']
        except Exception as e:
            # Log error but don't fail the check - allows other checks to continue
            print(f"Error checking metric math for alarm {self._resourceName}: {str(e)}")




    def _checkAlarmActionsDisabled(self):
        """
        Flag alarms that cannot notify anyone: actions are configured but
        ActionsEnabled is false, or the alarm has been stuck in
        INSUFFICIENT_DATA for more than 7 days AND the metric it watches has
        published no data for two weeks (list_metrics only returns metrics with
        data in the last 14 days), i.e. the metric was renamed or its resource
        deleted.

        Alarms on sparse metrics are not flagged: CloudTrail / log metric
        filter alarms (CIS-style) and other event-driven metrics publish no
        datapoints until a matching event happens, so with the default
        TreatMissingData='missing' they legitimately sit in INSUFFICIENT_DATA
        yet still go to ALARM and notify when the event arrives.
        """
        import datetime
        key = 'cwAlarmActionsDisabled'
        actions = (self.alarm.get('AlarmActions') or []) + (self.alarm.get('OKActions') or []) \
            + (self.alarm.get('InsufficientDataActions') or [])
        if self.alarm.get('ActionsEnabled') is False and actions:
            self.results[key] = [-1, f'Actions disabled ({len(actions)} configured action(s) will not run)']
            return

        okMsg = [1, 'Alarm actions enabled and alarm is evaluating']
        if self.alarm.get('StateValue') != 'INSUFFICIENT_DATA':
            self.results[key] = okMsg
            return
        since = self.alarm.get('StateTransitionedTimestamp') or self.alarm.get('StateUpdatedTimestamp')
        if not isinstance(since, datetime.datetime):
            self.results[key] = okMsg
            return
        if since.tzinfo is None:
            since = since.replace(tzinfo=datetime.timezone.utc)
        days = (datetime.datetime.now(datetime.timezone.utc) - since).days
        if days <= 7:
            self.results[key] = okMsg
            return

        metrics = []
        if self.alarm.get('MetricName'):
            metrics.append((self.alarm.get('Namespace'), self.alarm.get('MetricName'),
                            self.alarm.get('Dimensions') or []))
        for m in self.alarm.get('Metrics', []) or []:
            if m.get('AccountId'):
                ## Cross-account metric: cannot be listed from this account.
                self.results[key] = [0, f'In INSUFFICIENT_DATA for {days} days; cross-account metric not evaluable']
                return
            metric = (m.get('MetricStat') or {}).get('Metric') or {}
            if metric.get('MetricName'):
                metrics.append((metric.get('Namespace'), metric.get('MetricName'), metric.get('Dimensions') or []))
        if not metrics:
            self.results[key] = [1, f'In INSUFFICIENT_DATA for {days} days; expression-only alarm not evaluated']
            return

        if self.metricFilterMetrics is None:
            self.results[key] = [0, 'Unable to evaluate (log metric filters unreadable)']
            return
        if any((ns, mn) in self.metricFilterMetrics for ns, mn, _ in metrics):
            self.results[key] = [1, f'In INSUFFICIENT_DATA for {days} days, but the metric comes from a log metric '
                                    'filter (sparse; the alarm still fires when a matching event arrives)']
            return

        try:
            for ns, mn, dims in metrics:
                args = {'MetricName': mn,
                        'Dimensions': [{'Name': d.get('Name'), 'Value': d.get('Value')} for d in dims]}
                if ns:
                    args['Namespace'] = ns
                if self.cwClient.list_metrics(**args).get('Metrics'):
                    self.results[key] = [1, f'In INSUFFICIENT_DATA for {days} days, but its metric has recent '
                                            'data (sparse metric)']
                    return
        except botocore.exceptions.ClientError as e:
            self.results[key] = [0, f"Unable to evaluate ({e.response.get('Error', {}).get('Code', 'ClientError')})"]
            return

        names = ', '.join(sorted({f'{ns}/{mn}' for ns, mn, _ in metrics}))
        eventDriven = sorted({ns for ns, _, _ in metrics
                              if (ns or '').startswith('AWS/') and ns not in self.CONTINUOUS_AWS_NAMESPACES})
        if eventDriven:
            self.results[key] = [0, f'In INSUFFICIENT_DATA for {days} days and its metric ({names}) has published '
                                    f'no data in the last 14 days; {", ".join(eventDriven)} publishes only on '
                                    'activity, so the resource may be idle or deleted - verify it still exists']
            return
        self.results[key] = [-1, f'In INSUFFICIENT_DATA for {days} days and its metric ({names}) has published '
                                 'no data in the last 14 days']
