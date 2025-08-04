"""AWS STS service for assuming customer roles"""
import boto3
from typing import Dict, Any
from botocore.exceptions import ClientError
from src.core.utils.aws_errors import AWSErrorHandler
from src.core.utils.logger import get_logger

logger = get_logger(__name__)


class STSService:
    """Handle STS operations for cross-account access"""
    
    def __init__(self):
        self.sts_client = boto3.client('sts')
    
    def assume_customer_role(self, role_arn: str, external_id: str, session_name: str = 'CloudOpAI-Scanner') -> Dict[str, Any]:
        """
        Assume customer's IAM role for scanning with ExternalId
        
        Args:
            role_arn: Customer's IAM role ARN
            external_id: External ID for additional security
            session_name: Session name for the assumed role
            
        Returns:
            Temporary credentials dictionary
            
        Raises:
            Exception: When role assumption fails
        """
        try:
            logger.info(f"Attempting to assume role with session: {session_name}")
            
            response = self.sts_client.assume_role(
                RoleArn=role_arn,
                RoleSessionName=session_name,
                ExternalId=external_id,
                DurationSeconds=1800,  # 30 minutes - reduced from 1 hour
                Policy=None  # Use role's permissions, don't restrict further
            )
            
            credentials = response['Credentials']
            
            logger.info("Successfully assumed customer role")
            
            return {
                'aws_access_key_id': credentials['AccessKeyId'],
                'aws_secret_access_key': credentials['SecretAccessKey'],
                'aws_session_token': credentials['SessionToken'],
                'expiration': credentials['Expiration'].isoformat()
            }
            
        except Exception as e:
            error_message = AWSErrorHandler.handle_sts_error(e, "AssumeRole")
            raise Exception(error_message)