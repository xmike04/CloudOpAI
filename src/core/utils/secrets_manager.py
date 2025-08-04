"""AWS Secrets Manager integration for secure configuration"""
import boto3
import json
from typing import Dict, Any, Optional
from functools import lru_cache
from src.core.utils.logger import get_logger
from src.core.utils.aws_errors import AWSErrorHandler

logger = get_logger(__name__)

class SecretsManager:
    """Manages secure configuration via AWS Secrets Manager"""
    
    def __init__(self, region: str = 'us-east-1'):
        self.region = region
        self.secrets_client = boto3.client('secretsmanager', region_name=region)
        
    @lru_cache(maxsize=10)  # Cache secrets for performance
    def get_secret(self, secret_name: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve secret from AWS Secrets Manager with caching
        
        Args:
            secret_name: Name of the secret in Secrets Manager
            
        Returns:
            Dictionary containing secret values or None if not found
        """
        try:
            response = self.secrets_client.get_secret_value(SecretId=secret_name)
            
            if 'SecretString' in response:
                secret_data = json.loads(response['SecretString'])
                logger.info(f"Successfully retrieved secret: {secret_name}")
                return secret_data
            else:
                logger.error(f"Secret {secret_name} does not contain string data")
                return None
                
        except Exception as e:
            error_msg = AWSErrorHandler.handle_secrets_manager_error(e, f"Get secret {secret_name}")
            logger.error(f"Failed to retrieve secret {secret_name}: {error_msg}")
            return None
    
    def get_cloudopai_config(self) -> Dict[str, str]:
        """
        Get CloudOpAI configuration from Secrets Manager
        
        Returns:
            Configuration dictionary with fallback to environment variables
        """
        import os
        
        # Try to get from Secrets Manager first
        secret_config = self.get_secret('cloudopai/config')
        
        if secret_config:
            config = {
                'email_source': secret_config.get('email_source', os.environ.get('EMAIL_SOURCE', 'alerts@cloudopai.com')),
                'calendly_link': secret_config.get('calendly_link', os.environ.get('CALENDLY_LINK', 'https://calendly.com/cloudopai/demo')),
                'support_email': secret_config.get('support_email', 'support@cloudopai.com'),
                'company_domain': secret_config.get('company_domain', 'cloudopai.com'),
                'aws_region': secret_config.get('aws_region', os.environ.get('AWS_REGION', 'us-east-1')),
                'reports_bucket': secret_config.get('reports_bucket', os.environ.get('REPORTS_BUCKET', 'cloudopai-reports')),
                'scan_results_table': secret_config.get('scan_results_table', os.environ.get('SCAN_RESULTS_TABLE', 'CloudOpAI-ScanResults'))
            }
        else:
            # Fallback to environment variables
            logger.warning("Using environment variables as fallback for configuration")
            config = {
                'email_source': os.environ.get('EMAIL_SOURCE', 'alerts@cloudopai.com'),
                'calendly_link': os.environ.get('CALENDLY_LINK', 'https://calendly.com/cloudopai/demo'),
                'support_email': 'support@cloudopai.com',
                'company_domain': 'cloudopai.com',
                'aws_region': os.environ.get('AWS_REGION', 'us-east-1'),
                'reports_bucket': os.environ.get('REPORTS_BUCKET', 'cloudopai-reports'),
                'scan_results_table': os.environ.get('SCAN_RESULTS_TABLE', 'CloudOpAI-ScanResults')
            }
        
        return config
    
    def get_external_service_config(self) -> Dict[str, str]:
        """
        Get external service configuration (APIs, webhooks, etc.)
        
        Returns:
            External service configuration
        """
        secret_config = self.get_secret('cloudopai/external-services')
        
        if secret_config:
            return {
                'webhook_url': secret_config.get('webhook_url', ''),
                'slack_webhook': secret_config.get('slack_webhook', ''),
                'datadog_api_key': secret_config.get('datadog_api_key', ''),
                'sentry_dsn': secret_config.get('sentry_dsn', ''),
            }
        else:
            return {
                'webhook_url': '',
                'slack_webhook': '',
                'datadog_api_key': '',
                'sentry_dsn': '',
            }
    
    def create_secrets(self) -> bool:
        """
        Create default secrets in Secrets Manager for initial setup
        
        Returns:
            True if successful, False otherwise
        """
        try:
            # Create main configuration secret
            main_config = {
                'email_source': 'alerts@cloudopai.com',
                'calendly_link': 'https://calendly.com/cloudopai/demo',
                'support_email': 'support@cloudopai.com',
                'company_domain': 'cloudopai.com',
                'aws_region': 'us-east-1',
                'reports_bucket': 'cloudopai-reports',
                'scan_results_table': 'CloudOpAI-ScanResults'
            }
            
            self.secrets_client.create_secret(
                Name='cloudopai/config',
                Description='CloudOpAI main configuration',
                SecretString=json.dumps(main_config),
                ReplicaRegions=[
                    {'Region': 'us-west-2'},
                    {'Region': 'eu-west-1'}
                ]
            )
            
            # Create external services secret
            external_config = {
                'webhook_url': '',
                'slack_webhook': '',
                'datadog_api_key': '',
                'sentry_dsn': '',
            }
            
            self.secrets_client.create_secret(
                Name='cloudopai/external-services',
                Description='CloudOpAI external service configuration',
                SecretString=json.dumps(external_config)
            )
            
            logger.info("Successfully created CloudOpAI secrets")
            return True
            
        except Exception as e:
            logger.error(f"Failed to create secrets: {str(e)}")
            return False

# Global instance for easy access
secrets_manager = SecretsManager()

def get_secure_config() -> Dict[str, str]:
    """
    Get secure configuration with Secrets Manager integration
    
    Returns:
        Configuration dictionary
    """
    return secrets_manager.get_cloudopai_config()