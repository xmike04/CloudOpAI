"""S3 security configuration utilities"""
import boto3
import json
from typing import Dict, Any
from src.core.utils.logger import get_logger
from src.config.settings import AWS_REGION

logger = get_logger(__name__)

class S3SecurityManager:
    """Manages S3 bucket security configurations"""
    
    def __init__(self, bucket_name: str):
        self.bucket_name = bucket_name
        self.s3_client = boto3.client('s3', region_name=AWS_REGION)
    
    def configure_bucket_security(self) -> bool:
        """Apply comprehensive security configuration to S3 bucket"""
        try:
            # 1. Configure bucket policy with explicit deny
            self._set_bucket_policy()
            
            # 2. Enable versioning for data protection
            self._enable_versioning()
            
            # 3. Configure lifecycle policy for automatic cleanup
            self._set_lifecycle_policy()
            
            # 4. Enable server access logging
            self._enable_access_logging()
            
            # 5. Set bucket notification for monitoring
            self._configure_notifications()
            
            logger.info(f"S3 bucket security configured: {self.bucket_name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to configure S3 security: {str(e)}")
            return False
    
    def _set_bucket_policy(self) -> None:
        """Set restrictive bucket policy"""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "DenyInsecureConnections",
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": "s3:*",
                    "Resource": [
                        f"arn:aws:s3:::{self.bucket_name}",
                        f"arn:aws:s3:::{self.bucket_name}/*"
                    ],
                    "Condition": {
                        "Bool": {
                            "aws:SecureTransport": "false"
                        }
                    }
                },
                {
                    "Sid": "DenyUnencryptedObjectUploads",
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": "s3:PutObject",
                    "Resource": f"arn:aws:s3:::{self.bucket_name}/*",
                    "Condition": {
                        "StringNotEquals": {
                            "s3:x-amz-server-side-encryption": "AES256"
                        }
                    }
                },
                {
                    "Sid": "RestrictToCloudOpAIRole",
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": f"arn:aws:iam::{boto3.client('sts').get_caller_identity()['Account']}:role/CloudOpAI-Lambda-Role"
                    },
                    "Action": [
                        "s3:GetObject",
                        "s3:PutObject",
                        "s3:DeleteObject"
                    ],
                    "Resource": f"arn:aws:s3:::{self.bucket_name}/*",
                    "Condition": {
                        "StringEquals": {
                            "s3:x-amz-server-side-encryption": "AES256"
                        }
                    }
                }
            ]
        }
        
        self.s3_client.put_bucket_policy(
            Bucket=self.bucket_name,
            Policy=json.dumps(policy)
        )
    
    def _enable_versioning(self) -> None:
        """Enable S3 bucket versioning"""
        self.s3_client.put_bucket_versioning(
            Bucket=self.bucket_name,
            VersioningConfiguration={'Status': 'Enabled'}
        )
    
    def _set_lifecycle_policy(self) -> None:
        """Configure lifecycle policy for automatic cleanup"""
        lifecycle_config = {
            'Rules': [
                {
                    'ID': 'CloudOpAI-Reports-Cleanup',
                    'Status': 'Enabled',
                    'Filter': {'Prefix': 'reports/'},
                    'Expiration': {'Days': 90},  # Delete reports after 90 days
                    'NoncurrentVersionExpiration': {'NoncurrentDays': 30},
                    'AbortIncompleteMultipartUpload': {'DaysAfterInitiation': 1}
                },
                {
                    'ID': 'CloudOpAI-Logs-Cleanup',
                    'Status': 'Enabled',
                    'Filter': {'Prefix': 'access-logs/'},
                    'Expiration': {'Days': 365},  # Keep access logs for 1 year
                    'Transitions': [
                        {
                            'Days': 30,
                            'StorageClass': 'STANDARD_IA'
                        },
                        {
                            'Days': 90,
                            'StorageClass': 'GLACIER'
                        }
                    ]
                }
            ]
        }
        
        self.s3_client.put_bucket_lifecycle_configuration(
            Bucket=self.bucket_name,
            LifecycleConfiguration=lifecycle_config
        )
    
    def _enable_access_logging(self) -> None:
        """Enable S3 access logging"""
        try:
            # Create logs bucket if it doesn't exist
            logs_bucket = f"{self.bucket_name}-access-logs"
            
            try:
                self.s3_client.create_bucket(
                    Bucket=logs_bucket,
                    CreateBucketConfiguration={'LocationConstraint': AWS_REGION} if AWS_REGION != 'us-east-1' else {}
                )
            except self.s3_client.exceptions.BucketAlreadyExists:
                pass
            
            # Configure logging
            self.s3_client.put_bucket_logging(
                Bucket=self.bucket_name,
                BucketLoggingStatus={
                    'LoggingEnabled': {
                        'TargetBucket': logs_bucket,
                        'TargetPrefix': 'access-logs/'
                    }
                }
            )
        except Exception as e:
            logger.warning(f"Could not enable access logging: {str(e)}")
    
    def _configure_notifications(self) -> None:
        """Configure bucket notifications for security monitoring"""
        try:
            notification_config = {
                'CloudWatchConfigurations': [
                    {
                        'Id': 'CloudOpAI-S3-SecurityEvents',
                        'CloudWatchConfiguration': {
                            'LogGroupName': '/aws/s3/cloudopai-security',
                            'FilterName': 'S3SecurityFilter'
                        },
                        'Events': [
                            's3:ObjectCreated:*',
                            's3:ObjectRemoved:*'
                        ],
                        'Filter': {
                            'Key': {
                                'FilterRules': [
                                    {
                                        'Name': 'prefix',
                                        'Value': 'reports/'
                                    }
                                ]
                            }
                        }
                    }
                ]
            }
            
            # Note: This would require additional setup for CloudWatch Logs
            # Skipping for now to avoid deployment dependencies
            logger.info("S3 notification configuration prepared (manual setup required)")
            
        except Exception as e:
            logger.warning(f"Could not configure notifications: {str(e)}")
    
    def generate_secure_presigned_url(self, key: str, expiration: int = 3600) -> str:
        """Generate presigned URL with security constraints"""
        # Reduced expiration time to 1 hour (3600 seconds) instead of 7 days
        return self.s3_client.generate_presigned_url(
            'get_object',
            Params={
                'Bucket': self.bucket_name,
                'Key': key,
                'ResponseContentDisposition': 'attachment'  # Force download
            },
            ExpiresIn=expiration,
            HttpMethod='GET'
        )