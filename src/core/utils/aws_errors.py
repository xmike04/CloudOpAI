"""AWS-specific error handling utilities"""
import boto3
from botocore.exceptions import ClientError, BotoCoreError
from typing import Optional, Dict, Any
from src.core.utils.logger import get_logger

logger = get_logger(__name__)

class AWSErrorHandler:
    """Handles AWS service errors with proper security practices"""
    
    @staticmethod
    def handle_sts_error(error: Exception, operation: str = "STS operation") -> str:
        """Handle STS-specific errors without exposing sensitive information"""
        if isinstance(error, ClientError):
            error_code = error.response['Error']['Code']
            
            if error_code == 'AccessDenied':
                logger.error(f"STS {operation}: Access denied")
                return "Access denied: Check role permissions and external ID"
            elif error_code == 'InvalidParameterValue':
                logger.error(f"STS {operation}: Invalid parameter")
                return "Invalid role configuration"
            elif error_code == 'MalformedPolicyDocument':
                logger.error(f"STS {operation}: Malformed policy")
                return "Role policy configuration error"
            elif error_code == 'TokenRefreshRequired':
                logger.error(f"STS {operation}: Token refresh required")
                return "Authentication token expired"
            else:
                logger.error(f"STS {operation}: Unexpected error - {error_code}")
                return "STS operation failed"
        else:
            logger.error(f"STS {operation}: Non-client error")
            return "Service temporarily unavailable"
    
    @staticmethod
    def handle_ec2_error(error: Exception, operation: str = "EC2 operation") -> Optional[Dict[str, Any]]:
        """Handle EC2-specific errors"""
        if isinstance(error, ClientError):
            error_code = error.response['Error']['Code']
            
            if error_code == 'UnauthorizedOperation':
                logger.error(f"EC2 {operation}: Unauthorized operation")
                return None
            elif error_code == 'InvalidInstanceID.NotFound':
                logger.error(f"EC2 {operation}: Instance not found")
                return None
            elif error_code == 'Throttling':
                logger.warning(f"EC2 {operation}: API throttling")
                # Could implement exponential backoff here
                return None
            else:
                logger.error(f"EC2 {operation}: Unexpected error - {error_code}")
                return None
        else:
            logger.error(f"EC2 {operation}: Non-client error")
            return None
    
    @staticmethod
    def handle_cloudwatch_error(error: Exception, operation: str = "CloudWatch operation") -> Dict[str, Any]:
        """Handle CloudWatch-specific errors"""
        default_metrics = {
            'avg_gpu_util': 25,  # Conservative estimate
            'max_gpu_util': 50,
            'measurement_period_hours': 24
        }
        
        if isinstance(error, ClientError):
            error_code = error.response['Error']['Code']
            
            if error_code == 'AccessDenied':
                logger.error(f"CloudWatch {operation}: Access denied")
            elif error_code == 'InvalidParameterValue':
                logger.error(f"CloudWatch {operation}: Invalid parameter")
            elif error_code == 'ResourceNotFound':
                logger.warning(f"CloudWatch {operation}: Metrics not available")
            else:
                logger.error(f"CloudWatch {operation}: Unexpected error - {error_code}")
        else:
            logger.error(f"CloudWatch {operation}: Non-client error")
        
        return default_metrics
    
    @staticmethod
    def handle_dynamodb_error(error: Exception, operation: str = "DynamoDB operation") -> bool:
        """Handle DynamoDB-specific errors"""
        if isinstance(error, ClientError):
            error_code = error.response['Error']['Code']
            
            if error_code == 'AccessDenied':
                logger.error(f"DynamoDB {operation}: Access denied")
            elif error_code == 'ResourceNotFound':
                logger.error(f"DynamoDB {operation}: Table not found")
            elif error_code == 'ProvisionedThroughputExceeded':
                logger.warning(f"DynamoDB {operation}: Throughput exceeded")
            elif error_code == 'ValidationException':
                logger.error(f"DynamoDB {operation}: Validation error")
            elif error_code == 'ItemCollectionSizeLimitExceeded':
                logger.warning(f"DynamoDB {operation}: Item size limit exceeded")
            else:
                logger.error(f"DynamoDB {operation}: Unexpected error - {error_code}")
        else:
            logger.error(f"DynamoDB {operation}: Non-client error")
        
        return False
    
    @staticmethod
    def handle_s3_error(error: Exception, operation: str = "S3 operation") -> Optional[str]:
        """Handle S3-specific errors"""
        if isinstance(error, ClientError):
            error_code = error.response['Error']['Code']
            
            if error_code == 'AccessDenied':
                logger.error(f"S3 {operation}: Access denied")
            elif error_code == 'NoSuchBucket':
                logger.error(f"S3 {operation}: Bucket not found")
            elif error_code == 'NoSuchKey':
                logger.error(f"S3 {operation}: Object not found")
            elif error_code == 'BucketAlreadyExists':
                logger.warning(f"S3 {operation}: Bucket already exists")
            else:
                logger.error(f"S3 {operation}: Unexpected error - {error_code}")
        else:
            logger.error(f"S3 {operation}: Non-client error")
        
        return None
    
    @staticmethod
    def handle_ses_error(error: Exception, operation: str = "SES operation") -> bool:
        """Handle SES-specific errors"""
        if isinstance(error, ClientError):
            error_code = error.response['Error']['Code']
            
            if error_code == 'AccessDenied':
                logger.error(f"SES {operation}: Access denied")
            elif error_code == 'MessageRejected':
                logger.error(f"SES {operation}: Message rejected")
            elif error_code == 'SendingPausedException':
                logger.error(f"SES {operation}: Sending paused")
            elif error_code == 'MailFromDomainNotVerifiedException':
                logger.error(f"SES {operation}: Domain not verified")
            else:
                logger.error(f"SES {operation}: Unexpected error - {error_code}")
        else:
            logger.error(f"SES {operation}: Non-client error")
        
        return False
    
    @staticmethod
    def handle_secrets_manager_error(error: Exception, operation: str = "Secrets Manager operation") -> str:
        """Handle Secrets Manager-specific errors"""
        if isinstance(error, ClientError):
            error_code = error.response['Error']['Code']
            
            if error_code == 'ResourceNotFoundException':
                logger.error(f"Secrets Manager {operation}: Secret not found")
                return "Secret not found"
            elif error_code == 'InvalidParameterException':
                logger.error(f"Secrets Manager {operation}: Invalid parameter")
                return "Invalid secret parameter"
            elif error_code == 'InvalidRequestException':
                logger.error(f"Secrets Manager {operation}: Invalid request")
                return "Invalid secret request"
            elif error_code == 'DecryptionFailureException':
                logger.error(f"Secrets Manager {operation}: Decryption failed")
                return "Secret decryption failed"
            elif error_code == 'InternalServiceErrorException':
                logger.error(f"Secrets Manager {operation}: Internal service error")
                return "Secrets Manager service error"
            else:
                logger.error(f"Secrets Manager {operation}: Unexpected error - {error_code}")
                return "Secrets Manager operation failed"
        else:
            logger.error(f"Secrets Manager {operation}: Non-client error")
            return "Secrets Manager service unavailable"