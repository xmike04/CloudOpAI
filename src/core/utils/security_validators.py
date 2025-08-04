"""Comprehensive security validation utilities"""
import re
import html
import os
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import quote, unquote
from src.core.utils.logger import get_logger

logger = get_logger(__name__)

class SecurityValidator:
    """Advanced security validation for all user inputs"""
    
    # Enhanced validation patterns
    AWS_ACCOUNT_ID_PATTERN = re.compile(r'^[0-9]{12}$')
    AWS_ROLE_ARN_PATTERN = re.compile(r'^arn:aws:iam::[0-9]{12}:role/[a-zA-Z0-9+=,.@_/-]+$')
    EMAIL_PATTERN = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
    INSTANCE_ID_PATTERN = re.compile(r'^i-[0-9a-f]{8,17}$')
    SCAN_ID_PATTERN = re.compile(r'^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$')
    
    # Path traversal patterns
    PATH_TRAVERSAL_PATTERNS = [
        r'\.\.',
        r'\/\.\.',
        r'\.\.\/',
        r'%2e%2e',
        r'%2f%2e%2e',
        r'%2e%2e%2f',
        r'\.%2e',
        r'%2e\.',
    ]
    
    # XSS/Injection patterns
    XSS_PATTERNS = [
        r'<script.*?>.*?</script>',
        r'javascript:',
        r'vbscript:',
        r'onload\s*=',
        r'onerror\s*=',
        r'onclick\s*=',
        r'<iframe.*?>',
        r'<object.*?>',
        r'<embed.*?>',
        r'<svg.*?>.*?</svg>',
        r'expression\s*\(',
        r'url\s*\(',
        r'@import',
    ]
    
    # Command injection patterns
    COMMAND_INJECTION_PATTERNS = [
        r'[;&|`$]',
        r'\$\(',
        r'`.*?`',
        r'\|\|',
        r'&&',
        r'>\s*[/\w]',
        r'<\s*[/\w]',
    ]
    
    @staticmethod
    def validate_account_id(account_id: Any) -> str:
        """Validate AWS account ID with enhanced security"""
        if not isinstance(account_id, str):
            raise ValueError("Account ID must be a string")
        
        account_id = account_id.strip()
        
        if not account_id:
            raise ValueError("Account ID cannot be empty")
        
        if len(account_id) != 12:
            raise ValueError("Account ID must be exactly 12 digits")
        
        if not SecurityValidator.AWS_ACCOUNT_ID_PATTERN.match(account_id):
            raise ValueError("Account ID must contain only digits")
        
        # Additional checks for common test/invalid values
        invalid_accounts = ['000000000000', '123456789012', '111111111111']
        if account_id in invalid_accounts:
            raise ValueError("Invalid test account ID")
        
        return account_id
    
    @staticmethod
    def validate_role_arn(role_arn: Any) -> str:
        """Validate AWS IAM role ARN with security checks"""
        if not isinstance(role_arn, str):
            raise ValueError("Role ARN must be a string")
        
        role_arn = role_arn.strip()
        
        if not role_arn:
            raise ValueError("Role ARN cannot be empty")
        
        if len(role_arn) > 2048:  # AWS ARN limit
            raise ValueError("Role ARN too long")
        
        if not SecurityValidator.AWS_ROLE_ARN_PATTERN.match(role_arn):
            raise ValueError("Invalid role ARN format")
        
        # Extract and validate role name
        try:
            role_name = role_arn.split('/')[-1].lower()
        except IndexError:
            raise ValueError("Invalid role ARN structure")
        
        # Security: block privileged role names
        prohibited_roles = [
            'root', 'admin', 'administrator', 'superuser', 'sudo',
            'system', 'service', 'aws', 'iam', 'security'
        ]
        if any(prohibited in role_name for prohibited in prohibited_roles):
            raise ValueError("Cannot assume privileged roles")
        
        # Check for suspicious patterns
        if re.search(r'[<>"\']', role_arn):
            raise ValueError("Role ARN contains invalid characters")
        
        return role_arn
    
    @staticmethod
    def validate_email(email: Any) -> Optional[str]:
        """Validate email with comprehensive security checks"""
        if email is None:
            return None
        
        if not isinstance(email, str):
            raise ValueError("Email must be a string")
        
        email = email.strip().lower()
        
        if not email:
            return None
        
        if len(email) > 254:  # RFC 5321 limit
            raise ValueError("Email address too long")
        
        if not SecurityValidator.EMAIL_PATTERN.match(email):
            raise ValueError("Invalid email format")
        
        # Security checks
        dangerous_chars = ['<', '>', '"', "'", '\\', '/', '&', '|', ';']
        if any(char in email for char in dangerous_chars):
            raise ValueError("Email contains dangerous characters")
        
        # Check for suspicious domains
        suspicious_domains = ['example.com', 'test.com', 'localhost']
        domain = email.split('@')[1]
        if domain in suspicious_domains:
            raise ValueError("Test email addresses not allowed")
        
        return email
    
    @staticmethod
    def validate_s3_key(key: Any) -> str:
        """Validate S3 key to prevent path traversal"""
        if not isinstance(key, str):
            raise ValueError("S3 key must be a string")
        
        key = key.strip()
        
        if not key:
            raise ValueError("S3 key cannot be empty")
        
        if len(key) > 1024:  # S3 key limit
            raise ValueError("S3 key too long")
        
        # Check for path traversal
        for pattern in SecurityValidator.PATH_TRAVERSAL_PATTERNS:
            if re.search(pattern, key, re.IGNORECASE):
                raise ValueError("S3 key contains path traversal attempt")
        
        # Check for dangerous characters
        if re.search(r'[<>"\']', key):
            raise ValueError("S3 key contains dangerous characters")
        
        # Ensure key doesn't start with /
        if key.startswith('/'):
            raise ValueError("S3 key cannot start with /")
        
        # URL decode and check again (double encoding attacks)
        try:
            decoded_key = unquote(key)
            if decoded_key != key:
                # If decoding changed the key, validate the decoded version
                return SecurityValidator.validate_s3_key(decoded_key)
        except Exception:
            pass  # If decoding fails, continue with original key
        
        return key
    
    @staticmethod
    def validate_scan_id(scan_id: Any) -> str:
        """Validate scan ID (UUID format)"""
        if not isinstance(scan_id, str):
            raise ValueError("Scan ID must be a string")
        
        scan_id = scan_id.strip()
        
        if not scan_id:
            raise ValueError("Scan ID cannot be empty")
        
        if not SecurityValidator.SCAN_ID_PATTERN.match(scan_id):
            raise ValueError("Invalid scan ID format (must be UUID)")
        
        return scan_id
    
    @staticmethod
    def sanitize_html_content(content: str) -> str:
        """Sanitize content for safe HTML output"""
        if not isinstance(content, str):
            return str(content)
        
        # HTML escape
        sanitized = html.escape(content, quote=True)
        
        # Additional XSS protection
        for pattern in SecurityValidator.XSS_PATTERNS:
            sanitized = re.sub(pattern, '[FILTERED]', sanitized, flags=re.IGNORECASE | re.DOTALL)
        
        return sanitized
    
    @staticmethod
    def validate_lambda_event(event: Dict[str, Any]) -> Dict[str, Any]:
        """Validate complete Lambda event with enhanced security"""
        if not isinstance(event, dict):
            raise ValueError("Event must be a dictionary")
        
        # Size check
        if len(str(event)) > 10240:  # 10KB limit
            raise ValueError("Event payload too large")
        
        # Validate required fields
        account_id = SecurityValidator.validate_account_id(event.get('account_id'))
        role_arn = SecurityValidator.validate_role_arn(event.get('role_arn'))
        email = SecurityValidator.validate_email(event.get('email'))
        
        # Check for unexpected fields (security)
        allowed_fields = {'account_id', 'role_arn', 'email'}
        extra_fields = set(event.keys()) - allowed_fields
        if extra_fields:
            logger.warning(f"Unexpected fields in event: {extra_fields}")
        
        return {
            'account_id': account_id,
            'role_arn': role_arn,
            'email': email
        }
    
    @staticmethod
    def create_secure_s3_key(account_id: str, scan_id: str, file_type: str = 'html') -> str:
        """Create secure S3 key with sanitization"""
        # Validate inputs first
        account_id = SecurityValidator.validate_account_id(account_id)
        scan_id = SecurityValidator.validate_scan_id(scan_id)
        
        # Sanitize file type
        file_type = re.sub(r'[^a-zA-Z0-9]', '', file_type.lower())
        if not file_type:
            file_type = 'html'
        
        # Create safe key
        safe_key = f"reports/{account_id}/{scan_id}.{file_type}"
        
        # Final validation
        return SecurityValidator.validate_s3_key(safe_key)
    
    @staticmethod
    def is_valid_aws_account_id(account_id: Any) -> bool:
        """Check if AWS account ID is valid"""
        try:
            SecurityValidator.validate_account_id(account_id)
            return True
        except (ValueError, TypeError):
            return False
    
    @staticmethod
    def is_valid_email(email: Any) -> bool:
        """Check if email is valid"""
        try:
            result = SecurityValidator.validate_email(email)
            return result is not None
        except (ValueError, TypeError):
            return False
    
    @staticmethod
    def is_valid_iam_role_arn(role_arn: Any) -> bool:
        """Check if IAM role ARN is valid"""
        try:
            SecurityValidator.validate_role_arn(role_arn)
            return True
        except (ValueError, TypeError):
            return False
    
    @staticmethod
    def contains_xss(input_string: str) -> bool:
        """Check if input contains XSS patterns"""
        if not isinstance(input_string, str):
            return False
        
        for pattern in SecurityValidator.XSS_PATTERNS:
            if re.search(pattern, input_string, re.IGNORECASE | re.DOTALL):
                return True
        return False
    
    @staticmethod
    def contains_sql_injection(input_string: str) -> bool:
        """Check if input contains SQL injection patterns"""
        if not isinstance(input_string, str):
            return False
        
        sql_patterns = [
            r"'.*?--",
            r"';.*?--",
            r"'\s*or\s*'1'\s*=\s*'1",
            r"'\s*union\s*select",
            r"drop\s+table",
            r"delete\s+from",
            r"insert\s+into",
            r"update\s+.+\s+set",
            r"exec\s*\(",
            r"execute\s*\("
        ]
        
        for pattern in sql_patterns:
            if re.search(pattern, input_string, re.IGNORECASE):
                return True
        return False
    
    @staticmethod
    def contains_path_traversal(input_string: str) -> bool:
        """Check if input contains path traversal patterns"""
        if not isinstance(input_string, str):
            return False
        
        for pattern in SecurityValidator.PATH_TRAVERSAL_PATTERNS:
            if re.search(pattern, input_string, re.IGNORECASE):
                return True
        return False
    
    @staticmethod
    def is_safe_string(input_string: str, max_length: int = 5000) -> bool:
        """Check if string is safe (no malicious patterns, reasonable length)"""
        if not isinstance(input_string, str):
            return False
        
        # Check length
        if len(input_string) > max_length:
            return False
        
        # Check for null bytes and control characters
        if '\x00' in input_string or any(ord(c) < 32 and c not in '\t\n\r' for c in input_string):
            return False
        
        # Check for Unicode attacks
        unicode_attacks = ['\ufeff', '\u202e', '\u200e', '\u200f']
        if any(attack in input_string for attack in unicode_attacks):
            return False
        
        # Check for malicious patterns
        if (SecurityValidator.contains_xss(input_string) or 
            SecurityValidator.contains_sql_injection(input_string) or 
            SecurityValidator.contains_path_traversal(input_string)):
            return False
        
        return True
    
    @staticmethod
    def sanitize_error_message(error_message: str) -> str:
        """Sanitize error messages to prevent information disclosure"""
        if not isinstance(error_message, str):
            return "An error occurred"
        
        # Remove sensitive patterns
        sensitive_patterns = [
            r'arn:aws:iam::\d{12}:.*',  # ARNs
            r'AKIA[0-9A-Z]{16}',        # Access Key IDs
            r'[A-Za-z0-9/+=]{40}',      # Secret Access Keys
            r'\d{12}',                  # Account IDs
            r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',  # Emails
        ]
        
        sanitized = error_message.lower()
        
        for pattern in sensitive_patterns:
            sanitized = re.sub(pattern, '[REDACTED]', sanitized, flags=re.IGNORECASE)
        
        # Generic error messages for common errors
        if 'access denied' in sanitized or 'unauthorized' in sanitized:
            return "Access denied - insufficient permissions"
        elif 'not found' in sanitized:
            return "Resource not found"
        elif 'invalid' in sanitized:
            return "Invalid request parameters"
        elif 'forbidden' in sanitized:
            return "Operation not permitted"
        else:
            return "An error occurred while processing your request"
    
    @staticmethod
    def validate_api_gateway_request(event: Dict[str, Any]) -> Dict[str, Any]:
        """Validate API Gateway request event"""
        if not isinstance(event, dict):
            raise ValueError("Event must be a dictionary")
        
        # Extract and validate body
        body = event.get('body', '{}')
        if isinstance(body, str):
            try:
                import json
                body_data = json.loads(body)
            except json.JSONDecodeError:
                raise ValueError("Invalid JSON in request body")
        else:
            body_data = body
        
        # Validate body data
        if 'account_id' in body_data:
            account_id = body_data['account_id']
            if SecurityValidator.contains_xss(str(account_id)):
                raise ValueError("Request body contains XSS patterns")
            if not SecurityValidator.is_valid_aws_account_id(account_id):
                raise ValueError("Invalid account_id in request body")
        
        return event
    
    @staticmethod
    def validate_json_input(json_string: str) -> Dict[str, Any]:
        """Validate and parse JSON input safely"""
        if not isinstance(json_string, str):
            raise ValueError("Input must be a string")
        
        if len(json_string) > 10240:  # 10KB limit
            raise ValueError("JSON input too large")
        
        try:
            import json
            data = json.loads(json_string)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON: {str(e)}")
        
        # Check for malicious content in JSON values
        def check_json_values(obj):
            if isinstance(obj, dict):
                for key, value in obj.items():
                    if isinstance(value, str):
                        if (SecurityValidator.contains_xss(value) or 
                            SecurityValidator.contains_sql_injection(value)):
                            raise ValueError(f"Malicious content detected in field: {key}")
                    elif isinstance(value, (dict, list)):
                        check_json_values(value)
            elif isinstance(obj, list):
                for item in obj:
                    if isinstance(item, str):
                        if (SecurityValidator.contains_xss(item) or 
                            SecurityValidator.contains_sql_injection(item)):
                            raise ValueError("Malicious content detected in array")
                    elif isinstance(item, (dict, list)):
                        check_json_values(item)
        
        check_json_values(data)
        return data