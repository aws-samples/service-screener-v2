import boto3
import botocore
import constants as _C

from services.Evaluator import Evaluator

class CloudwatchAlarms(Evaluator):
    """
    Driver for CloudWatch Alarms checks
    Handles alarm configuration validation including SNS notifications and billing alarms
    """
    
    def __init__(self, alarm, cwClient):
        super().__init__()
        self.init()
        
        self.alarm = alarm
        self.cwClient = cwClient
        
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



