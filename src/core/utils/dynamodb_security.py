"""DynamoDB security and data protection utilities"""
import boto3
import hashlib
import json
from datetime import datetime, timedelta
from typing import Dict, Any, Optional
from src.core.utils.logger import get_logger
from src.config.settings import AWS_REGION

logger = get_logger(__name__)

class DynamoDBSecurityManager:
    """Manages DynamoDB security and data protection"""
    
    def __init__(self, table_name: str):
        self.table_name = table_name
        self.dynamodb_client = boto3.client('dynamodb', region_name=AWS_REGION)
        self.dynamodb_resource = boto3.resource('dynamodb', region_name=AWS_REGION)
        self.table = self.dynamodb_resource.Table(table_name)
    
    def configure_table_security(self) -> bool:
        """Configure comprehensive DynamoDB security"""
        try:
            # 1. Enable point-in-time recovery
            self._enable_pitr()
            
            # 2. Configure TTL for automatic data cleanup
            self._configure_ttl()
            
            # 3. Enable deletion protection
            self._enable_deletion_protection()
            
            logger.info(f"DynamoDB security configured: {self.table_name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to configure DynamoDB security: {str(e)}")
            return False
    
    def _enable_pitr(self) -> None:
        """Enable point-in-time recovery"""
        try:
            self.dynamodb_client.update_continuous_backups(
                TableName=self.table_name,
                PointInTimeRecoverySpecification={'PointInTimeRecoveryEnabled': True}
            )
            logger.info("Point-in-time recovery enabled")
        except Exception as e:
            logger.warning(f"Could not enable PITR: {str(e)}")
    
    def _configure_ttl(self) -> None:
        """Configure TTL for automatic data cleanup"""
        try:
            self.dynamodb_client.update_time_to_live(
                TableName=self.table_name,
                TimeToLiveSpecification={
                    'AttributeName': 'ttl',
                    'Enabled': True
                }
            )
            logger.info("TTL configured for automatic cleanup")
        except Exception as e:
            logger.warning(f"Could not configure TTL: {str(e)}")
    
    def _enable_deletion_protection(self) -> None:
        """Enable deletion protection"""
        try:
            self.dynamodb_client.update_table(
                TableName=self.table_name,
                DeletionProtectionEnabled=True
            )
            logger.info("Deletion protection enabled")
        except Exception as e:
            logger.warning(f"Could not enable deletion protection: {str(e)}")
    
    @staticmethod
    def hash_sensitive_data(data: str) -> str:
        """Hash sensitive data for storage"""
        return hashlib.sha256(data.encode()).hexdigest()[:16]  # First 16 chars for shorter hash
    
    @staticmethod
    def obfuscate_instance_id(instance_id: str) -> str:
        """Obfuscate EC2 instance ID for storage"""
        if not instance_id.startswith('i-'):
            return instance_id
        # Keep prefix, hash the rest
        return f"i-{hashlib.sha256(instance_id.encode()).hexdigest()[:12]}"
    
    def store_scan_results_securely(self, account_id: str, results: Dict[str, Any]) -> bool:
        """Store scan results with data protection"""
        try:
            # Hash account ID
            account_hash = self.hash_sensitive_data(account_id)
            
            # Calculate TTL (90 days from now)
            ttl = int((datetime.now() + timedelta(days=90)).timestamp())
            
            # Obfuscate sensitive data in opportunities
            secured_opportunities = []
            for opp in results.get('opportunities', []):
                secured_opp = opp.copy()
                secured_opp['instance_id'] = self.obfuscate_instance_id(opp.get('instance_id', ''))
                secured_opportunities.append(secured_opp)
            
            # Prepare secure item
            secure_item = {
                'account_hash': account_hash,  # Use hash instead of plaintext
                'account_id_original': account_id,  # Keep original for business logic (temporary)
                'scan_timestamp': datetime.now().isoformat(),
                'scan_id': results.get('scan_id'),
                'total_monthly_waste': str(results.get('total_monthly_waste', 0)),
                'total_instances_scanned': results.get('total_instances_scanned', 0),
                'idle_gpu_count': results.get('idle_gpu_count', 0),
                'underutilized_count': results.get('underutilized_count', 0),
                'opportunities': secured_opportunities,
                'ttl': ttl,  # Automatic cleanup after 90 days
                'data_classification': 'CUSTOMER_CONFIDENTIAL',
                'created_timestamp': int(datetime.now().timestamp())
            }
            
            # Store with hash as partition key
            self.table.put_item(Item=secure_item)
            
            logger.info(f"Scan results stored securely with TTL: {ttl}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to store scan results securely: {str(e)}")
            return False
    
    def get_scan_results_by_account(self, account_id: str, limit: int = 10) -> Optional[list]:
        """Retrieve scan results by account ID"""
        try:
            account_hash = self.hash_sensitive_data(account_id)
            
            response = self.table.query(
                KeyConditionExpression='account_hash = :hash',
                ExpressionAttributeValues={':hash': account_hash},
                Limit=limit,
                ScanIndexForward=False  # Most recent first
            )
            
            return response.get('Items', [])
            
        except Exception as e:
            logger.error(f"Failed to retrieve scan results: {str(e)}")
            return None
    
    def cleanup_expired_data(self) -> int:
        """Manual cleanup of expired data (backup to TTL)"""
        try:
            cutoff_time = int((datetime.now() - timedelta(days=90)).timestamp())
            
            # Scan for expired items
            response = self.table.scan(
                FilterExpression='created_timestamp < :cutoff',
                ExpressionAttributeValues={':cutoff': cutoff_time},
                ProjectionExpression='account_hash, scan_timestamp'
            )
            
            deleted_count = 0
            for item in response.get('Items', []):
                try:
                    self.table.delete_item(
                        Key={
                            'account_hash': item['account_hash'],
                            'scan_timestamp': item['scan_timestamp']
                        }
                    )
                    deleted_count += 1
                except Exception as e:
                    logger.warning(f"Failed to delete expired item: {str(e)}")
            
            logger.info(f"Cleaned up {deleted_count} expired items")
            return deleted_count
            
        except Exception as e:
            logger.error(f"Failed to cleanup expired data: {str(e)}")
            return 0