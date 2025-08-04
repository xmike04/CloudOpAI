"""Input validation utilities for security"""
import re
from typing import Optional, Dict, Any

class ValidationError(Exception):
    """Raised when input validation fails"""
    pass

class InputValidator:
    """Validates and sanitizes user inputs"""
    
    # AWS Account ID: 12 digits
    AWS_ACCOUNT_PATTERN = re.compile(r'^\d{12}$')
    
    # AWS IAM Role ARN pattern
    AWS_ROLE_ARN_PATTERN = re.compile(
        r'^arn:aws:iam::\d{12}:role/[a-zA-Z0-9+=,.@_-]+$'
    )
    
    # Email validation (RFC 5322 compliant)
    EMAIL_PATTERN = re.compile(
        r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    )
    
    # Instance ID pattern
    INSTANCE_ID_PATTERN = re.compile(r'^i-[0-9a-f]{8,17}$')
    
    @staticmethod
    def validate_aws_account_id(account_id: Any) -> str:
        """Validate AWS account ID format"""
        if not isinstance(account_id, str):
            raise ValidationError("Account ID must be a string")
        
        if not account_id or len(account_id.strip()) == 0:
            raise ValidationError("Account ID cannot be empty")
        
        account_id = account_id.strip()
        
        if not InputValidator.AWS_ACCOUNT_PATTERN.match(account_id):
            raise ValidationError("Invalid AWS account ID format")
        
        return account_id
    
    @staticmethod
    def validate_role_arn(role_arn: Any) -> str:
        """Validate AWS IAM role ARN format"""
        if not isinstance(role_arn, str):
            raise ValidationError("Role ARN must be a string")
        
        if not role_arn or len(role_arn.strip()) == 0:
            raise ValidationError("Role ARN cannot be empty")
        
        role_arn = role_arn.strip()
        
        if not InputValidator.AWS_ROLE_ARN_PATTERN.match(role_arn):
            raise ValidationError("Invalid AWS IAM role ARN format")
        
        # Additional security: ensure it's not trying to access privileged roles
        prohibited_roles = ['root', 'administrator', 'admin']
        role_name = role_arn.split('/')[-1].lower()
        if any(prohibited in role_name for prohibited in prohibited_roles):
            raise ValidationError("Cannot assume privileged roles")
        
        return role_arn
    
    @staticmethod
    def validate_email(email: Any) -> Optional[str]:
        """Validate email format"""
        if email is None:
            return None
        
        if not isinstance(email, str):
            raise ValidationError("Email must be a string")
        
        email = email.strip().lower()
        
        if len(email) == 0:
            return None
        
        if len(email) > 254:  # RFC 5321 limit
            raise ValidationError("Email address too long")
        
        if not InputValidator.EMAIL_PATTERN.match(email):
            raise ValidationError("Invalid email format")
        
        # Basic security: prevent common malicious patterns
        if any(char in email for char in ['<', '>', '"', "'"]):
            raise ValidationError("Email contains invalid characters")
        
        return email
    
    @staticmethod
    def validate_lambda_event(event: Dict[str, Any]) -> Dict[str, Any]:
        """Validate and sanitize Lambda event input"""
        if not isinstance(event, dict):
            raise ValidationError("Event must be a dictionary")
        
        # Validate required fields
        account_id = InputValidator.validate_aws_account_id(
            event.get('account_id')
        )
        role_arn = InputValidator.validate_role_arn(
            event.get('role_arn')
        )
        email = InputValidator.validate_email(
            event.get('email')
        )
        
        # Sanitize and return validated event
        return {
            'account_id': account_id,
            'role_arn': role_arn,
            'email': email
        }
    
    @staticmethod
    def sanitize_instance_id(instance_id: Any) -> str:
        """Sanitize EC2 instance ID"""
        if not isinstance(instance_id, str):
            raise ValidationError("Instance ID must be a string")
        
        instance_id = instance_id.strip()
        
        if not InputValidator.INSTANCE_ID_PATTERN.match(instance_id):
            raise ValidationError("Invalid EC2 instance ID format")
        
        return instance_id