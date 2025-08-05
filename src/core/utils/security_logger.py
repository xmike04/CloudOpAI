"""Comprehensive security logging and monitoring system

Author: Michael Marin
"""
import json
import uuid
import time
import hashlib
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List
from enum import Enum
from dataclasses import dataclass, asdict
import boto3
from contextlib import contextmanager

class SecurityEventType(Enum):
    """Security event types for structured logging"""
    AUTHENTICATION_SUCCESS = "authentication_success"
    AUTHENTICATION_FAILURE = "authentication_failure"
    AUTHORIZATION_SUCCESS = "authorization_success"
    AUTHORIZATION_FAILURE = "authorization_failure"
    INPUT_VALIDATION_FAILURE = "input_validation_failure"
    SCAN_INITIATED = "scan_initiated"
    SCAN_COMPLETED = "scan_completed"
    SCAN_FAILED = "scan_failed"
    DATA_ACCESS = "data_access"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    XSS_ATTEMPT = "xss_attempt"
    PATH_TRAVERSAL_ATTEMPT = "path_traversal_attempt"
    PRIVILEGE_ESCALATION_ATTEMPT = "privilege_escalation_attempt"
    CONFIGURATION_CHANGE = "configuration_change"
    ERROR_THRESHOLD_EXCEEDED = "error_threshold_exceeded"

class SecurityLevel(Enum):
    """Security event severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class SecurityEvent:
    """Structured security event for logging"""
    timestamp: str
    correlation_id: str
    event_type: SecurityEventType
    severity: SecurityLevel
    account_id_hash: Optional[str]
    source_ip: Optional[str]
    user_agent: Optional[str]
    resource: Optional[str]
    action: str
    result: str
    details: Dict[str, Any]
    request_id: Optional[str]
    session_id: Optional[str]
    
    def to_cloudwatch_log(self) -> str:
        """Convert to CloudWatch structured log format"""
        log_data = {
            "timestamp": self.timestamp,
            "correlation_id": self.correlation_id,
            "event_type": self.event_type.value,
            "severity": self.severity.value,
            "account_id_hash": self.account_id_hash,
            "source_ip": self.source_ip,
            "user_agent": self.user_agent,
            "resource": self.resource,
            "action": self.action,
            "result": self.result,
            "details": self.details,
            "request_id": self.request_id,
            "session_id": self.session_id
        }
        return json.dumps(log_data, default=str)

class SecurityLogger:
    """Comprehensive security logging system"""
    
    def __init__(self, log_group_name: str = "/aws/lambda/cloudopai-security"):
        self.log_group_name = log_group_name
        self.cloudwatch_logs = boto3.client('logs')
        self.current_correlation_id = None
        self.current_session_id = None
        self.current_account_hash = None
        
        # Initialize CloudWatch log group
        self._ensure_log_group_exists()
    
    def _ensure_log_group_exists(self):
        """Ensure CloudWatch log group exists"""
        try:
            self.cloudwatch_logs.create_log_group(
                logGroupName=self.log_group_name,
                tags={'Application': 'CloudOpAI', 'Purpose': 'SecurityLogging'}
            )
        except self.cloudwatch_logs.exceptions.ResourceAlreadyExistsException:
            pass  # Log group already exists
        except Exception as e:
            print(f"Warning: Could not create log group {self.log_group_name}: {e}")
    
    def _hash_account_id(self, account_id: str) -> str:
        """Create consistent hash for account ID"""
        return hashlib.sha256(f"cloudopai-{account_id}".encode()).hexdigest()[:16]
    
    def _sanitize_details(self, details: Dict[str, Any]) -> Dict[str, Any]:
        """Remove sensitive information from log details"""
        sanitized = {}
        sensitive_keys = {
            'password', 'secret', 'key', 'token', 'credential', 'arn',
            'AccessKeyId', 'SecretAccessKey', 'SessionToken', 'email'
        }
        
        for key, value in details.items():
            key_lower = key.lower()
            if any(sensitive in key_lower for sensitive in sensitive_keys):
                if 'arn' in key_lower:
                    # Show only account ID from ARN
                    try:
                        arn_parts = str(value).split(':')
                        if len(arn_parts) >= 5:
                            sanitized[key] = f"arn:aws:iam::{arn_parts[4]}:role/[REDACTED]"
                        else:
                            sanitized[key] = "[ARN-REDACTED]"
                    except:
                        sanitized[key] = "[ARN-REDACTED]"
                elif 'email' in key_lower:
                    # Show only domain
                    try:
                        domain = str(value).split('@')[1]
                        sanitized[key] = f"[USER]@{domain}"
                    except:
                        sanitized[key] = "[EMAIL-REDACTED]"
                else:
                    sanitized[key] = "[REDACTED]"
            else:
                sanitized[key] = str(value)[:1000]  # Truncate long values
        
        return sanitized
    
    @contextmanager
    def security_context(self, account_id: Optional[str] = None, correlation_id: Optional[str] = None):
        """Context manager for security logging session"""
        old_correlation_id = self.current_correlation_id
        old_account_hash = self.current_account_hash
        old_session_id = self.current_session_id
        
        try:
            self.current_correlation_id = correlation_id or str(uuid.uuid4())
            self.current_session_id = str(uuid.uuid4())[:8]
            if account_id:
                self.current_account_hash = self._hash_account_id(account_id)
            
            yield self.current_correlation_id
            
        finally:
            self.current_correlation_id = old_correlation_id
            self.current_account_hash = old_account_hash
            self.current_session_id = old_session_id
    
    def log_security_event(
        self,
        event_type: SecurityEventType,
        severity: SecurityLevel,
        action: str,
        result: str,
        details: Optional[Dict[str, Any]] = None,
        account_id: Optional[str] = None,
        source_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
        resource: Optional[str] = None,
        request_id: Optional[str] = None
    ):
        """Log a structured security event"""
        
        # Create security event
        event = SecurityEvent(
            timestamp=datetime.now(timezone.utc).isoformat(),
            correlation_id=self.current_correlation_id or str(uuid.uuid4()),
            event_type=event_type,
            severity=severity,
            account_id_hash=self.current_account_hash or (self._hash_account_id(account_id) if account_id else None),
            source_ip=source_ip,
            user_agent=user_agent,
            resource=resource,
            action=action,
            result=result,
            details=self._sanitize_details(details or {}),
            request_id=request_id,
            session_id=self.current_session_id
        )
        
        # Log to CloudWatch
        self._send_to_cloudwatch(event)
        
        # Log to console for debugging
        print(f"SECURITY_EVENT: {event.event_type.value} - {event.result} - {event.correlation_id}")
        
        # Trigger alarms for critical events
        if severity in [SecurityLevel.HIGH, SecurityLevel.CRITICAL]:
            self._trigger_security_alarm(event)
    
    def _send_to_cloudwatch(self, event: SecurityEvent):
        """Send security event to CloudWatch Logs"""
        try:
            log_stream_name = f"security-{datetime.now().strftime('%Y-%m-%d')}"
            
            # Create log stream if it doesn't exist
            try:
                self.cloudwatch_logs.create_log_stream(
                    logGroupName=self.log_group_name,
                    logStreamName=log_stream_name
                )
            except self.cloudwatch_logs.exceptions.ResourceAlreadyExistsException:
                pass
            
            # Send log event
            self.cloudwatch_logs.put_log_events(
                logGroupName=self.log_group_name,
                logStreamName=log_stream_name,
                logEvents=[
                    {
                        'timestamp': int(time.time() * 1000),
                        'message': event.to_cloudwatch_log()
                    }
                ]
            )
            
        except Exception as e:
            print(f"Failed to send security event to CloudWatch: {e}")
    
    def _trigger_security_alarm(self, event: SecurityEvent):
        """Trigger CloudWatch alarm for critical security events"""
        try:
            cloudwatch = boto3.client('cloudwatch')
            
            # Send custom metric
            cloudwatch.put_metric_data(
                Namespace='CloudOpAI/Security',
                MetricData=[
                    {
                        'MetricName': 'SecurityEvents',
                        'Dimensions': [
                            {
                                'Name': 'EventType',
                                'Value': event.event_type.value
                            },
                            {
                                'Name': 'Severity',
                                'Value': event.severity.value
                            }
                        ],
                        'Value': 1,
                        'Unit': 'Count',
                        'Timestamp': datetime.now(timezone.utc)
                    }
                ]
            )
            
        except Exception as e:
            print(f"Failed to trigger security alarm: {e}")
    
    # Convenience methods for common security events
    def log_authentication_success(self, account_id: str, source_ip: str = None, **kwargs):
        """Log successful authentication"""
        self.log_security_event(
            event_type=SecurityEventType.AUTHENTICATION_SUCCESS,
            severity=SecurityLevel.LOW,
            action="assume_role",
            result="success",
            account_id=account_id,
            source_ip=source_ip,
            details=kwargs
        )
    
    def log_authentication_failure(self, account_id: str, error: str, source_ip: str = None, **kwargs):
        """Log failed authentication"""
        self.log_security_event(
            event_type=SecurityEventType.AUTHENTICATION_FAILURE,
            severity=SecurityLevel.HIGH,
            action="assume_role",
            result="failure",
            account_id=account_id,
            source_ip=source_ip,
            details={"error": error, **kwargs}
        )
    
    def log_scan_initiated(self, account_id: str, scan_id: str, **kwargs):
        """Log scan initiation"""
        self.log_security_event(
            event_type=SecurityEventType.SCAN_INITIATED,
            severity=SecurityLevel.LOW,
            action="scan_gpu_resources",
            result="initiated",
            account_id=account_id,
            resource=f"scan/{scan_id}",
            details=kwargs
        )
    
    def log_scan_completed(self, account_id: str, scan_id: str, instances_scanned: int, **kwargs):
        """Log scan completion"""
        self.log_security_event(
            event_type=SecurityEventType.SCAN_COMPLETED,
            severity=SecurityLevel.LOW,
            action="scan_gpu_resources",
            result="completed",
            account_id=account_id,
            resource=f"scan/{scan_id}",
            details={"instances_scanned": instances_scanned, **kwargs}
        )
    
    def log_suspicious_activity(self, activity_type: str, details: Dict[str, Any], severity: SecurityLevel = SecurityLevel.HIGH):
        """Log suspicious activity"""
        self.log_security_event(
            event_type=SecurityEventType.SUSPICIOUS_ACTIVITY,
            severity=severity,
            action=activity_type,
            result="detected",
            details=details
        )
    
    def log_input_validation_failure(self, validation_error: str, input_data: Dict[str, Any], **kwargs):
        """Log input validation failure"""
        self.log_security_event(
            event_type=SecurityEventType.INPUT_VALIDATION_FAILURE,
            severity=SecurityLevel.MEDIUM,
            action="validate_input",
            result="failure",
            details={"validation_error": validation_error, "input_summary": str(input_data)[:500], **kwargs}
        )
    
    def log_rate_limit_exceeded(self, account_id: str, limit_type: str, source_ip: str = None, **kwargs):
        """Log rate limit exceeded"""
        self.log_security_event(
            event_type=SecurityEventType.RATE_LIMIT_EXCEEDED,
            severity=SecurityLevel.MEDIUM,
            action="rate_limit_check",
            result="exceeded",
            account_id=account_id,
            source_ip=source_ip,
            details={"limit_type": limit_type, **kwargs}
        )

# Global security logger instance
security_logger = SecurityLogger()

# Convenience functions for easy access
def log_security_event(*args, **kwargs):
    """Global security event logging function"""
    return security_logger.log_security_event(*args, **kwargs)

def security_context(*args, **kwargs):
    """Global security context manager"""
    return security_logger.security_context(*args, **kwargs)