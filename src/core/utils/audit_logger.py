"""CloudTrail audit logging integration for CloudOpAI

Author: Michael Marin
"""
import json
import uuid
import boto3
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List
from enum import Enum
from dataclasses import dataclass, asdict

class AuditEventType(Enum):
    """Audit event types for compliance tracking"""
    USER_ACCESS = "user_access"
    DATA_ACCESS = "data_access"
    CONFIGURATION_CHANGE = "configuration_change"
    SCAN_OPERATION = "scan_operation"
    REPORT_GENERATION = "report_generation"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    COMPLIANCE_CHECK = "compliance_check"
    DATA_RETENTION = "data_retention"
    DATA_DELETION = "data_deletion"
    POLICY_EVALUATION = "policy_evaluation"
    SECURITY_INCIDENT = "security_incident"

@dataclass
class AuditEvent:
    """Structured audit event for compliance logging"""
    event_id: str
    timestamp: str
    event_type: AuditEventType
    user_identity: Optional[str]
    account_id: Optional[str]
    resource_type: str
    resource_id: Optional[str]
    action: str
    outcome: str
    source_ip: Optional[str]
    user_agent: Optional[str]
    api_version: str
    request_parameters: Dict[str, Any]
    response_elements: Dict[str, Any]
    error_code: Optional[str]
    error_message: Optional[str]
    compliance_impact: Optional[str]
    data_classification: str
    retention_period: int
    
    def to_cloudtrail_event(self) -> Dict[str, Any]:
        """Convert to CloudTrail-compatible event format"""
        return {
            "eventVersion": "1.05",
            "userIdentity": {
                "type": "AssumedRole" if self.user_identity else "Unknown",
                "principalId": self.user_identity or "Unknown",
                "arn": f"arn:aws:sts::{self.account_id}:assumed-role/CloudOpAI-Scanner-Role/{self.user_identity}" if self.user_identity and self.account_id else None,
                "accountId": self.account_id
            },
            "eventTime": self.timestamp,
            "eventSource": "cloudopai.amazonaws.com",
            "eventName": self.action,
            "eventCategory": "Application",
            "eventID": self.event_id,
            "eventType": "AwsApiCall",
            "awsRegion": "us-east-1",
            "sourceIPAddress": self.source_ip or "unknown",
            "userAgent": self.user_agent or "CloudOpAI/1.0",
            "requestParameters": self._sanitize_parameters(self.request_parameters),
            "responseElements": self._sanitize_parameters(self.response_elements),
            "resources": [{
                "accountId": self.account_id,
                "type": self.resource_type,
                "ARN": self.resource_id
            }] if self.resource_id else [],
            "errorCode": self.error_code,
            "errorMessage": self.error_message,
            "additionalEventData": {
                "complianceImpact": self.compliance_impact,
                "dataClassification": self.data_classification,
                "retentionPeriod": self.retention_period,
                "cloudOpAIEventType": self.event_type.value
            }
        }
    
    def _sanitize_parameters(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Remove sensitive data from parameters"""
        if not params:
            return {}
            
        sanitized = {}
        sensitive_keys = {
            'password', 'secret', 'key', 'token', 'credential', 'arn',
            'AccessKeyId', 'SecretAccessKey', 'SessionToken', 'email'
        }
        
        for key, value in params.items():
            key_lower = key.lower()
            if any(sensitive in key_lower for sensitive in sensitive_keys):
                sanitized[key] = "[REDACTED]"
            elif isinstance(value, str) and len(value) > 1000:
                sanitized[key] = value[:1000] + "...[TRUNCATED]"
            else:
                sanitized[key] = value
                
        return sanitized

class AuditLogger:
    """CloudTrail-integrated audit logging for compliance"""
    
    def __init__(self, trail_name: str = "cloudopai-audit-trail"):
        self.trail_name = trail_name
        self.cloudtrail = boto3.client('cloudtrail')
        self.s3_client = boto3.client('s3')
        self.current_session = None
        
    def ensure_cloudtrail_setup(self, bucket_name: str, kms_key_id: Optional[str] = None):
        """Ensure CloudTrail is properly configured for audit logging"""
        try:
            # Create CloudTrail if it doesn't exist
            try:
                self.cloudtrail.describe_trails(trailNameList=[self.trail_name])
            except self.cloudtrail.exceptions.TrailNotFoundException:
                trail_config = {
                    'Name': self.trail_name,
                    'S3BucketName': bucket_name,
                    'S3KeyPrefix': 'cloudtrail-logs/cloudopai/',
                    'IncludeGlobalServiceEvents': True,
                    'IsMultiRegionTrail': True,
                    'EnableLogFileValidation': True,
                    'EventSelectors': [{
                        'ReadWriteType': 'All',
                        'IncludeManagementEvents': True,
                        'DataResources': [{
                            'Type': 'AWS::S3::Object',
                            'Values': [f'{bucket_name}/*']
                        }]
                    }]
                }
                
                if kms_key_id:
                    trail_config['KMSKeyId'] = kms_key_id
                    
                self.cloudtrail.create_trail(**trail_config)
                
            # Ensure trail is logging
            self.cloudtrail.start_logging(Name=self.trail_name)
            
        except Exception as e:
            print(f"Warning: Could not configure CloudTrail: {e}")
    
    def log_audit_event(
        self,
        event_type: AuditEventType,
        action: str,
        outcome: str,
        resource_type: str = "application",
        resource_id: Optional[str] = None,
        user_identity: Optional[str] = None,
        account_id: Optional[str] = None,
        source_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
        request_parameters: Optional[Dict[str, Any]] = None,
        response_elements: Optional[Dict[str, Any]] = None,
        error_code: Optional[str] = None,
        error_message: Optional[str] = None,
        compliance_impact: Optional[str] = None,
        data_classification: str = "internal",
        retention_period: int = 2555  # 7 years in days for compliance
    ):
        """Log a comprehensive audit event"""
        
        event = AuditEvent(
            event_id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc).isoformat(),
            event_type=event_type,
            user_identity=user_identity,
            account_id=account_id,
            resource_type=resource_type,
            resource_id=resource_id,
            action=action,
            outcome=outcome,
            source_ip=source_ip,
            user_agent=user_agent,
            api_version="1.0",
            request_parameters=request_parameters or {},
            response_elements=response_elements or {},
            error_code=error_code,
            error_message=error_message,
            compliance_impact=compliance_impact,
            data_classification=data_classification,
            retention_period=retention_period
        )
        
        # Send to CloudTrail (as custom application log)
        self._send_to_cloudtrail(event)
        
        # Also log to CloudWatch for immediate monitoring
        self._send_to_cloudwatch(event)
        
        return event.event_id
    
    def _send_to_cloudtrail(self, event: AuditEvent):
        """Send audit event to CloudTrail"""
        try:
            # CloudTrail doesn't accept custom events directly
            # Instead, we'll store in S3 with CloudTrail-compatible format
            cloudtrail_event = event.to_cloudtrail_event()
            
            # Create a custom log entry in the CloudTrail S3 bucket
            log_key = f"cloudtrail-logs/cloudopai/{datetime.now().strftime('%Y/%m/%d')}/{event.event_id}.json"
            
            # This would typically be handled by CloudTrail automatically
            # For now, we'll use CloudWatch for immediate logging
            print(f"AUDIT_EVENT: {event.event_type.value} - {event.action} - {event.outcome} - {event.event_id}")
            
        except Exception as e:
            print(f"Failed to send audit event to CloudTrail: {e}")
    
    def _send_to_cloudwatch(self, event: AuditEvent):
        """Send audit event to CloudWatch for immediate monitoring"""
        try:
            cloudwatch_logs = boto3.client('logs')
            log_group_name = "/aws/lambda/cloudopai-audit"
            log_stream_name = f"audit-{datetime.now().strftime('%Y-%m-%d')}"
            
            # Ensure log group exists
            try:
                cloudwatch_logs.create_log_group(
                    logGroupName=log_group_name,
                    tags={'Application': 'CloudOpAI', 'Purpose': 'AuditLogging', 'Compliance': 'Required'}
                )
            except cloudwatch_logs.exceptions.ResourceAlreadyExistsException:
                pass
            
            # Create log stream if needed
            try:
                cloudwatch_logs.create_log_stream(
                    logGroupName=log_group_name,
                    logStreamName=log_stream_name
                )
            except cloudwatch_logs.exceptions.ResourceAlreadyExistsException:
                pass
            
            # Send audit event
            cloudwatch_logs.put_log_events(
                logGroupName=log_group_name,
                logStreamName=log_stream_name,
                logEvents=[{
                    'timestamp': int(datetime.now().timestamp() * 1000),
                    'message': json.dumps(event.to_cloudtrail_event(), default=str)
                }]
            )
            
        except Exception as e:
            print(f"Failed to send audit event to CloudWatch: {e}")
    
    # Convenience methods for common audit events
    def log_data_access(self, account_id: str, resource_id: str, action: str, user_identity: str = None, **kwargs):
        """Log data access for compliance"""
        self.log_audit_event(
            event_type=AuditEventType.DATA_ACCESS,
            action=action,
            outcome="success",
            resource_type="data",
            resource_id=resource_id,
            account_id=account_id,
            user_identity=user_identity,
            compliance_impact="data_access_logged",
            data_classification="confidential",
            **kwargs
        )
    
    def log_scan_operation(self, account_id: str, scan_id: str, action: str, outcome: str = "success", **kwargs):
        """Log scan operations for audit trail"""
        self.log_audit_event(
            event_type=AuditEventType.SCAN_OPERATION,
            action=action,
            outcome=outcome,
            resource_type="scan",
            resource_id=f"scan/{scan_id}",
            account_id=account_id,
            compliance_impact="operational_audit",
            **kwargs
        )
    
    def log_configuration_change(self, resource_type: str, resource_id: str, action: str, changes: Dict[str, Any], **kwargs):
        """Log configuration changes for compliance"""
        self.log_audit_event(
            event_type=AuditEventType.CONFIGURATION_CHANGE,
            action=action,
            outcome="success",
            resource_type=resource_type,
            resource_id=resource_id,
            request_parameters={"changes": changes},
            compliance_impact="configuration_audit",
            data_classification="internal",
            **kwargs
        )
    
    def log_compliance_event(self, compliance_type: str, action: str, outcome: str, details: Dict[str, Any], **kwargs):
        """Log compliance-specific events"""
        self.log_audit_event(
            event_type=AuditEventType.COMPLIANCE_CHECK,
            action=f"compliance_{action}",
            outcome=outcome,
            resource_type="compliance",
            request_parameters=details,
            compliance_impact=compliance_type,
            data_classification="confidential",
            retention_period=2555,  # 7 years for compliance
            **kwargs
        )
    
    def log_data_retention_event(self, account_id: str, data_type: str, action: str, record_count: int, **kwargs):
        """Log data retention and deletion for GDPR/compliance"""
        self.log_audit_event(
            event_type=AuditEventType.DATA_RETENTION,
            action=action,
            outcome="success",
            resource_type="data_retention",
            resource_id=f"{data_type}/{account_id}",
            account_id=account_id,
            request_parameters={"record_count": record_count, "data_type": data_type},
            compliance_impact="gdpr_compliance",
            data_classification="confidential",
            **kwargs
        )

# Global audit logger instance
audit_logger = AuditLogger()

# Convenience functions
def log_audit_event(*args, **kwargs):
    """Global audit event logging function"""
    return audit_logger.log_audit_event(*args, **kwargs)

def log_data_access(*args, **kwargs):
    """Global data access logging function"""
    return audit_logger.log_data_access(*args, **kwargs)

def log_scan_operation(*args, **kwargs):
    """Global scan operation logging function"""
    return audit_logger.log_scan_operation(*args, **kwargs)