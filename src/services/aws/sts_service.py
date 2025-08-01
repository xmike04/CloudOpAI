"""AWS STS service for assuming customer roles"""
import boto3
from typing import Dict, Any


class STSService:
    """Handle STS operations for cross-account access"""
    
    def __init__(self):
        self.sts_client = boto3.client('sts')
    
    def assume_customer_role(self, role_arn: str, session_name: str = 'CloudOpAI-Scanner') -> Dict[str, Any]:
        """
        Assume customer's IAM role for scanning
        
        Args:
            role_arn: Customer's IAM role ARN
            session_name: Session name for the assumed role
            
        Returns:
            Temporary credentials dictionary
        """
        try:
            response = self.sts_client.assume_role(
                RoleArn=role_arn,
                RoleSessionName=session_name,
                DurationSeconds=3600  # 1 hour
            )
            
            credentials = response['Credentials']
            return {
                'aws_access_key_id': credentials['AccessKeyId'],
                'aws_secret_access_key': credentials['SecretAccessKey'],
                'aws_session_token': credentials['SessionToken']
            }
            
        except Exception as e:
            raise Exception(f"Failed to assume role {role_arn}: {str(e)}")