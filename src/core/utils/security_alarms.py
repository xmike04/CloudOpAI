"""CloudWatch security alarms and monitoring for CloudOpAI"""
import boto3
import json
from typing import Dict, Any, List, Optional
from enum import Enum
from datetime import datetime, timezone

class AlarmSeverity(Enum):
    """Alarm severity levels"""
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"

class SecurityAlarmType(Enum):
    """Types of security alarms"""
    AUTHENTICATION_FAILURES = "authentication_failures"
    AUTHORIZATION_FAILURES = "authorization_failures"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    INPUT_VALIDATION_FAILURES = "input_validation_failures"
    CONFIGURATION_CHANGES = "configuration_changes"
    DATA_ACCESS_ANOMALIES = "data_access_anomalies"
    ERROR_RATE_HIGH = "error_rate_high"
    SCAN_FAILURES = "scan_failures"
    COMPLIANCE_VIOLATIONS = "compliance_violations"

class SecurityAlarmManager:
    """Manage CloudWatch alarms for security monitoring"""
    
    def __init__(self, sns_topic_arn: Optional[str] = None):
        self.cloudwatch = boto3.client('cloudwatch')
        self.logs = boto3.client('logs')
        self.sns = boto3.client('sns')
        self.sns_topic_arn = sns_topic_arn
        
        # Create SNS topic if not provided
        if not self.sns_topic_arn:
            self.sns_topic_arn = self._create_security_topic()
    
    def _create_security_topic(self) -> str:
        """Create SNS topic for security alerts"""
        try:
            response = self.sns.create_topic(
                Name='CloudOpAI-Security-Alerts',
                Tags=[
                    {'Key': 'Application', 'Value': 'CloudOpAI'},
                    {'Key': 'Purpose', 'Value': 'SecurityAlerting'}
                ]
            )
            
            topic_arn = response['TopicArn']
            
            # Set topic policy to allow CloudWatch to publish
            policy = {
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {"Service": "cloudwatch.amazonaws.com"},
                    "Action": "SNS:Publish",
                    "Resource": topic_arn
                }]
            }
            
            self.sns.set_topic_attributes(
                TopicArn=topic_arn,
                AttributeName='Policy',
                AttributeValue=json.dumps(policy)
            )
            
            return topic_arn
            
        except Exception as e:
            print(f"Failed to create SNS topic: {e}")
            return None
    
    def create_security_alarms(self):
        """Create all security monitoring alarms"""
        alarms_created = []
        
        # Authentication failure alarm
        alarms_created.append(self._create_metric_filter_alarm(
            alarm_name="CloudOpAI-Authentication-Failures",
            alarm_description="High number of authentication failures detected",
            log_group_name="/aws/lambda/cloudopai-security",
            filter_pattern='{ $.event_type = "authentication_failure" }',
            metric_name="AuthenticationFailures",
            threshold=5,
            period=300,  # 5 minutes
            evaluation_periods=1,
            severity=AlarmSeverity.CRITICAL
        ))
        
        # Suspicious activity alarm
        alarms_created.append(self._create_metric_filter_alarm(
            alarm_name="CloudOpAI-Suspicious-Activity",
            alarm_description="Suspicious activity detected",
            log_group_name="/aws/lambda/cloudopai-security",
            filter_pattern='{ $.event_type = "suspicious_activity" || $.event_type = "xss_attempt" || $.event_type = "path_traversal_attempt" }',
            metric_name="SuspiciousActivity",
            threshold=1,
            period=300,
            evaluation_periods=1,
            severity=AlarmSeverity.CRITICAL
        ))
        
        # Rate limiting alarm
        alarms_created.append(self._create_metric_filter_alarm(
            alarm_name="CloudOpAI-Rate-Limit-Exceeded",
            alarm_description="Rate limiting thresholds exceeded",
            log_group_name="/aws/lambda/cloudopai-security",
            filter_pattern='{ $.event_type = "rate_limit_exceeded" }',
            metric_name="RateLimitExceeded",
            threshold=10,
            period=300,
            evaluation_periods=2,
            severity=AlarmSeverity.WARNING
        ))
        
        # Input validation failures
        alarms_created.append(self._create_metric_filter_alarm(
            alarm_name="CloudOpAI-Input-Validation-Failures",
            alarm_description="High number of input validation failures",
            log_group_name="/aws/lambda/cloudopai-security",
            filter_pattern='{ $.event_type = "input_validation_failure" }',
            metric_name="InputValidationFailures",
            threshold=20,
            period=600,  # 10 minutes
            evaluation_periods=1,
            severity=AlarmSeverity.WARNING
        ))
        
        # Lambda error rate alarm
        alarms_created.append(self._create_lambda_error_alarm(
            alarm_name="CloudOpAI-Lambda-Error-Rate",
            alarm_description="High error rate in CloudOpAI Lambda function",
            function_name="CloudOpAI-Scanner",
            threshold=5.0,  # 5% error rate
            period=300,
            evaluation_periods=2,
            severity=AlarmSeverity.CRITICAL
        ))
        
        # Scan failure alarm
        alarms_created.append(self._create_metric_filter_alarm(
            alarm_name="CloudOpAI-Scan-Failures",
            alarm_description="High number of scan failures",
            log_group_name="/aws/lambda/cloudopai-security",
            filter_pattern='{ $.event_type = "scan_failed" }',
            metric_name="ScanFailures",
            threshold=3,
            period=600,
            evaluation_periods=1,
            severity=AlarmSeverity.WARNING
        ))
        
        # Configuration change monitoring
        alarms_created.append(self._create_metric_filter_alarm(
            alarm_name="CloudOpAI-Configuration-Changes",
            alarm_description="Unauthorized configuration changes detected",
            log_group_name="/aws/lambda/cloudopai-audit",
            filter_pattern='{ $.eventName = "configuration_change" }',
            metric_name="ConfigurationChanges",
            threshold=1,
            period=300,
            evaluation_periods=1,
            severity=AlarmSeverity.INFO
        ))
        
        # Data access anomalies
        alarms_created.append(self._create_custom_metric_alarm(
            alarm_name="CloudOpAI-Data-Access-Anomalies",
            alarm_description="Unusual data access patterns detected",
            namespace="CloudOpAI/Security",
            metric_name="DataAccessAnomalies",
            threshold=1,
            period=300,
            evaluation_periods=1,
            severity=AlarmSeverity.WARNING
        ))
        
        return alarms_created
    
    def _create_metric_filter_alarm(
        self,
        alarm_name: str,
        alarm_description: str,
        log_group_name: str,
        filter_pattern: str,
        metric_name: str,
        threshold: float,
        period: int,
        evaluation_periods: int,
        severity: AlarmSeverity
    ) -> bool:
        """Create a metric filter and associated alarm"""
        try:
            # Create metric filter
            self.logs.put_metric_filter(
                logGroupName=log_group_name,
                filterName=f"{alarm_name}-Filter",
                filterPattern=filter_pattern,
                metricTransformations=[{
                    'metricName': metric_name,
                    'metricNamespace': 'CloudOpAI/Security',
                    'metricValue': '1',
                    'defaultValue': 0
                }]
            )
            
            # Create alarm
            return self._create_custom_metric_alarm(
                alarm_name=alarm_name,
                alarm_description=alarm_description,
                namespace="CloudOpAI/Security",
                metric_name=metric_name,
                threshold=threshold,
                period=period,
                evaluation_periods=evaluation_periods,
                severity=severity
            )
            
        except Exception as e:
            print(f"Failed to create metric filter alarm {alarm_name}: {e}")
            return False
    
    def _create_custom_metric_alarm(
        self,
        alarm_name: str,
        alarm_description: str,
        namespace: str,
        metric_name: str,
        threshold: float,
        period: int,
        evaluation_periods: int,
        severity: AlarmSeverity,
        statistic: str = "Sum",
        comparison_operator: str = "GreaterThanOrEqualToThreshold"
    ) -> bool:
        """Create a CloudWatch alarm"""
        try:
            alarm_actions = []
            if self.sns_topic_arn:
                alarm_actions.append(self.sns_topic_arn)
            
            self.cloudwatch.put_metric_alarm(
                AlarmName=alarm_name,
                AlarmDescription=alarm_description,
                ActionsEnabled=True,
                AlarmActions=alarm_actions,
                MetricName=metric_name,
                Namespace=namespace,
                Statistic=statistic,
                Period=period,
                EvaluationPeriods=evaluation_periods,
                Threshold=threshold,
                ComparisonOperator=comparison_operator,
                Tags=[
                    {'Key': 'Application', 'Value': 'CloudOpAI'},
                    {'Key': 'Severity', 'Value': severity.value},
                    {'Key': 'Purpose', 'Value': 'SecurityMonitoring'}
                ]
            )
            
            print(f"Created alarm: {alarm_name}")
            return True
            
        except Exception as e:
            print(f"Failed to create alarm {alarm_name}: {e}")
            return False
    
    def _create_lambda_error_alarm(
        self,
        alarm_name: str,
        alarm_description: str,
        function_name: str,
        threshold: float,
        period: int,
        evaluation_periods: int,
        severity: AlarmSeverity
    ) -> bool:
        """Create Lambda function error rate alarm"""
        try:
            alarm_actions = []
            if self.sns_topic_arn:
                alarm_actions.append(self.sns_topic_arn)
            
            # Create error rate alarm using math expression
            self.cloudwatch.put_metric_alarm(
                AlarmName=alarm_name,
                AlarmDescription=alarm_description,
                ActionsEnabled=True,
                AlarmActions=alarm_actions,
                Metrics=[
                    {
                        'Id': 'm1',
                        'MetricStat': {
                            'Metric': {
                                'Namespace': 'AWS/Lambda',
                                'MetricName': 'Errors',
                                'Dimensions': [
                                    {'Name': 'FunctionName', 'Value': function_name}
                                ]
                            },
                            'Period': period,
                            'Stat': 'Sum'
                        },
                        'ReturnData': False
                    },
                    {
                        'Id': 'm2',
                        'MetricStat': {
                            'Metric': {
                                'Namespace': 'AWS/Lambda',
                                'MetricName': 'Invocations',
                                'Dimensions': [
                                    {'Name': 'FunctionName', 'Value': function_name}
                                ]
                            },
                            'Period': period,
                            'Stat': 'Sum'
                        },
                        'ReturnData': False
                    },
                    {
                        'Id': 'e1',
                        'Expression': '(m1/m2)*100',
                        'Label': 'Error Rate (%)',
                        'ReturnData': True
                    }
                ],
                EvaluationPeriods=evaluation_periods,
                Threshold=threshold,
                ComparisonOperator='GreaterThanThreshold',
                TreatMissingData='notBreaching',
                Tags=[
                    {'Key': 'Application', 'Value': 'CloudOpAI'},
                    {'Key': 'Severity', 'Value': severity.value},
                    {'Key': 'Purpose', 'Value': 'LambdaMonitoring'}
                ]
            )
            
            print(f"Created Lambda error alarm: {alarm_name}")
            return True
            
        except Exception as e:
            print(f"Failed to create Lambda error alarm {alarm_name}: {e}")
            return False
    
    def create_dashboard(self) -> str:
        """Create CloudWatch dashboard for security monitoring"""
        try:
            dashboard_body = {
                "widgets": [
                    {
                        "type": "metric",
                        "x": 0, "y": 0, "width": 12, "height": 6,
                        "properties": {
                            "metrics": [
                                ["CloudOpAI/Security", "AuthenticationFailures"],
                                [".", "SuspiciousActivity"],
                                [".", "RateLimitExceeded"],
                                [".", "InputValidationFailures"]
                            ],
                            "period": 300,
                            "stat": "Sum",
                            "region": "us-east-1",
                            "title": "Security Events"
                        }
                    },
                    {
                        "type": "metric",
                        "x": 12, "y": 0, "width": 12, "height": 6,
                        "properties": {
                            "metrics": [
                                ["AWS/Lambda", "Errors", "FunctionName", "CloudOpAI-Scanner"],
                                [".", "Duration", ".", "."],
                                [".", "Invocations", ".", "."]
                            ],
                            "period": 300,
                            "stat": "Average",
                            "region": "us-east-1",
                            "title": "Lambda Performance"
                        }
                    },
                    {
                        "type": "log",
                        "x": 0, "y": 6, "width": 24, "height": 6,
                        "properties": {
                            "query": "SOURCE '/aws/lambda/cloudopai-security'\n| fields @timestamp, event_type, severity, action, result\n| filter severity = \"high\" or severity = \"critical\"\n| sort @timestamp desc\n| limit 100",
                            "region": "us-east-1",
                            "title": "Recent High-Severity Security Events"
                        }
                    }
                ]
            }
            
            dashboard_name = "CloudOpAI-Security-Dashboard"
            self.cloudwatch.put_dashboard(
                DashboardName=dashboard_name,
                DashboardBody=json.dumps(dashboard_body)
            )
            
            print(f"Created security dashboard: {dashboard_name}")
            return dashboard_name
            
        except Exception as e:
            print(f"Failed to create dashboard: {e}")
            return None
    
    def add_email_subscriber(self, email: str) -> bool:
        """Add email subscriber to security alerts"""
        try:
            if not self.sns_topic_arn:
                return False
                
            self.sns.subscribe(
                TopicArn=self.sns_topic_arn,
                Protocol='email',
                Endpoint=email
            )
            
            print(f"Added email subscriber: {email}")
            return True
            
        except Exception as e:
            print(f"Failed to add email subscriber: {e}")
            return False
    
    def trigger_test_alarm(self, alarm_name: str) -> bool:
        """Trigger a test alarm for verification"""
        try:
            self.cloudwatch.set_alarm_state(
                AlarmName=alarm_name,
                StateValue='ALARM',
                StateReason='Test alarm triggered for verification'
            )
            
            print(f"Test alarm triggered: {alarm_name}")
            return True
            
        except Exception as e:
            print(f"Failed to trigger test alarm: {e}")
            return False
    
    def get_alarm_status(self) -> Dict[str, Any]:
        """Get status of all CloudOpAI security alarms"""
        try:
            response = self.cloudwatch.describe_alarms(
                AlarmNamePrefix="CloudOpAI-"
            )
            
            alarm_status = {}
            for alarm in response['MetricAlarms']:
                alarm_status[alarm['AlarmName']] = {
                    'state': alarm['StateValue'],
                    'reason': alarm['StateReason'],
                    'updated': alarm['StateUpdatedTimestamp']
                }
            
            return alarm_status
            
        except Exception as e:
            print(f"Failed to get alarm status: {e}")
            return {}

# Global alarm manager instance
security_alarm_manager = SecurityAlarmManager()

# Convenience functions
def create_security_alarms():
    """Create all security monitoring alarms"""
    return security_alarm_manager.create_security_alarms()

def create_security_dashboard():
    """Create security monitoring dashboard"""
    return security_alarm_manager.create_dashboard()

def add_security_email_alert(email: str):
    """Add email to security alerts"""
    return security_alarm_manager.add_email_subscriber(email)