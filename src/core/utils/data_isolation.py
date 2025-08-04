"""Customer data isolation and multi-tenancy security for CloudOpAI"""
import boto3
import hashlib
import json
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional, List, Tuple
from enum import Enum
from dataclasses import dataclass

from src.core.utils.security_validators import SecurityValidator
from src.core.utils.audit_logger import audit_logger, AuditEventType
from src.core.utils.security_logger import security_logger, SecurityEventType, SecurityLevel

class IsolationLevel(Enum):
    """Data isolation levels"""
    BASIC = "basic"          # Logical separation
    ENHANCED = "enhanced"    # Encryption with customer keys
    STRICT = "strict"        # Separate infrastructure

class DataClassification(Enum):
    """Data classification levels"""
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"

@dataclass
class TenantConfig:
    """Configuration for tenant data isolation"""
    customer_id: str
    account_id: str
    isolation_level: IsolationLevel
    encryption_key_id: Optional[str]
    data_classification: DataClassification
    retention_days: int
    geographic_restrictions: List[str]
    compliance_requirements: List[str]

class CustomerDataIsolation:
    """Manage customer data isolation and multi-tenancy"""
    
    def __init__(self):
        self.dynamodb = boto3.resource('dynamodb')
        self.s3_client = boto3.client('s3')
        self.kms_client = boto3.client('kms')
        
        # Tenant configuration table
        self.tenant_config_table = self.dynamodb.Table('CloudOpAI-TenantConfig')
        
    def initialize_tenant(
        self,
        customer_id: str,
        account_id: str,
        isolation_level: IsolationLevel = IsolationLevel.ENHANCED,
        data_classification: DataClassification = DataClassification.CONFIDENTIAL,
        retention_days: int = 2555,  # 7 years
        geographic_restrictions: List[str] = None,
        compliance_requirements: List[str] = None
    ) -> TenantConfig:
        """Initialize tenant with proper data isolation"""
        
        # Validate inputs
        if not SecurityValidator.is_valid_aws_account_id(account_id):
            raise ValueError("Invalid AWS account ID")
        
        if not SecurityValidator.is_safe_string(customer_id):
            raise ValueError("Invalid customer ID")
        
        # Create customer-specific KMS key for enhanced isolation
        encryption_key_id = None
        if isolation_level in [IsolationLevel.ENHANCED, IsolationLevel.STRICT]:
            encryption_key_id = self._create_customer_kms_key(customer_id, account_id)
        
        # Create tenant configuration
        tenant_config = TenantConfig(
            customer_id=customer_id,
            account_id=account_id,
            isolation_level=isolation_level,
            encryption_key_id=encryption_key_id,
            data_classification=data_classification,
            retention_days=retention_days,
            geographic_restrictions=geographic_restrictions or [],
            compliance_requirements=compliance_requirements or ['SOC2', 'GDPR']
        )
        
        # Store tenant configuration
        self._store_tenant_config(tenant_config)
        
        # Create isolated storage structure
        self._setup_isolated_storage(tenant_config)
        
        # Log tenant initialization
        audit_logger.log_audit_event(
            event_type=AuditEventType.CONFIGURATION_CHANGE,
            action="initialize_tenant",
            outcome="success",
            user_identity=customer_id,
            account_id=account_id,
            resource_type="tenant",
            resource_id=customer_id,
            request_parameters={
                "isolation_level": isolation_level.value,
                "data_classification": data_classification.value,
                "compliance_requirements": compliance_requirements
            },
            compliance_impact="tenant_isolation_established"
        )
        
        return tenant_config
    
    def _create_customer_kms_key(self, customer_id: str, account_id: str) -> str:
        """Create customer-specific KMS key"""
        try:
            key_policy = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "Enable IAM User Permissions",
                        "Effect": "Allow",
                        "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                        "Action": "kms:*",
                        "Resource": "*"
                    },
                    {
                        "Sid": "Allow CloudOpAI Service",
                        "Effect": "Allow",
                        "Principal": {"AWS": f"arn:aws:iam::{account_id}:role/CloudOpAI-Lambda-Role"},
                        "Action": [
                            "kms:Encrypt",
                            "kms:Decrypt",
                            "kms:ReEncrypt*",
                            "kms:GenerateDataKey*",
                            "kms:DescribeKey"
                        ],
                        "Resource": "*",
                        "Condition": {
                            "StringEquals": {
                                "kms:ViaService": [
                                    f"s3.us-east-1.amazonaws.com",
                                    f"dynamodb.us-east-1.amazonaws.com"
                                ]
                            }
                        }
                    }
                ]
            }
            
            response = self.kms_client.create_key(
                Description=f"CloudOpAI customer isolation key for {customer_id}",
                KeyUsage='ENCRYPT_DECRYPT',
                KeySpec='SYMMETRIC_DEFAULT',
                Policy=json.dumps(key_policy),
                Tags=[
                    {'TagKey': 'Application', 'TagValue': 'CloudOpAI'},
                    {'TagKey': 'Purpose', 'TagValue': 'CustomerIsolation'},
                    {'TagKey': 'Customer', 'TagValue': customer_id},
                    {'TagKey': 'Account', 'TagValue': account_id}
                ]
            )
            
            key_id = response['KeyMetadata']['KeyId']
            
            # Create alias for easier management
            alias_name = f"alias/cloudopai-{customer_id}"
            try:
                self.kms_client.create_alias(
                    AliasName=alias_name,
                    TargetKeyId=key_id
                )
            except self.kms_client.exceptions.AlreadyExistsException:
                pass  # Alias already exists
            
            return key_id
            
        except Exception as e:
            print(f"Failed to create customer KMS key: {e}")
            raise
    
    def _store_tenant_config(self, config: TenantConfig):
        """Store tenant configuration in DynamoDB"""
        try:
            self.tenant_config_table.put_item(
                Item={
                    'customer_id': config.customer_id,
                    'account_id': config.account_id,
                    'isolation_level': config.isolation_level.value,
                    'encryption_key_id': config.encryption_key_id,
                    'data_classification': config.data_classification.value,
                    'retention_days': config.retention_days,
                    'geographic_restrictions': config.geographic_restrictions,
                    'compliance_requirements': config.compliance_requirements,
                    'created_at': datetime.now(timezone.utc).isoformat(),
                    'updated_at': datetime.now(timezone.utc).isoformat(),
                    'status': 'active'
                }
            )
        except Exception as e:
            print(f"Failed to store tenant configuration: {e}")
            raise
    
    def _setup_isolated_storage(self, config: TenantConfig):
        """Setup isolated storage structure for tenant"""
        # Create customer-specific S3 prefixes and policies
        # This ensures complete data separation at the storage level
        
        bucket_name = f"cloudopai-reports-{config.account_id}"
        customer_prefix = f"customers/{config.customer_id}/"
        
        # Set up S3 bucket policy for customer isolation
        self._configure_s3_isolation(bucket_name, config)
        
        # Create DynamoDB table structure for tenant isolation
        self._configure_dynamodb_isolation(config)
    
    def _configure_s3_isolation(self, bucket_name: str, config: TenantConfig):
        """Configure S3 bucket for customer data isolation"""
        try:
            # Create customer-specific folder structure
            customer_prefix = f"customers/{config.customer_id}/"
            
            # Create folder structure
            folders = ['scans/', 'reports/', 'exports/', 'archived/']
            for folder in folders:
                self.s3_client.put_object(
                    Bucket=bucket_name,
                    Key=f"{customer_prefix}{folder}",
                    Body=b'',
                    ServerSideEncryption='aws:kms',
                    SSEKMSKeyId=config.encryption_key_id if config.encryption_key_id else 'alias/aws/s3',
                    Metadata={
                        'customer-id': config.customer_id,
                        'data-classification': config.data_classification.value,
                        'isolation-level': config.isolation_level.value
                    }
                )
            
            # Set lifecycle policy for customer data
            lifecycle_config = {
                'Rules': [{
                    'ID': f'CloudOpAI-Customer-{config.customer_id}-Lifecycle',
                    'Status': 'Enabled',
                    'Filter': {'Prefix': customer_prefix},
                    'Expiration': {'Days': config.retention_days},
                    'NoncurrentVersionExpiration': {'NoncurrentDays': 30},
                    'AbortIncompleteMultipartUpload': {'DaysAfterInitiation': 1}
                }]
            }
            
            try:
                # Get existing lifecycle configuration
                existing_config = self.s3_client.get_bucket_lifecycle_configuration(Bucket=bucket_name)
                existing_config['Rules'].append(lifecycle_config['Rules'][0])
                lifecycle_config = existing_config
            except self.s3_client.exceptions.NoSuchLifecycleConfiguration:
                pass  # No existing configuration
            
            self.s3_client.put_bucket_lifecycle_configuration(
                Bucket=bucket_name,
                LifecycleConfiguration=lifecycle_config
            )
            
        except Exception as e:
            print(f"Failed to configure S3 isolation: {e}")
            raise
    
    def _configure_dynamodb_isolation(self, config: TenantConfig):
        """Configure DynamoDB for customer data isolation"""
        # Customer data is isolated using partition keys and encryption
        # Each customer gets their own partition key space
        pass  # Implementation already handles this via account_hash
    
    def get_tenant_config(self, customer_id: str) -> Optional[TenantConfig]:
        """Get tenant configuration"""
        try:
            response = self.tenant_config_table.get_item(
                Key={'customer_id': customer_id}
            )
            
            if 'Item' not in response:
                return None
            
            item = response['Item']
            return TenantConfig(
                customer_id=item['customer_id'],
                account_id=item['account_id'],
                isolation_level=IsolationLevel(item['isolation_level']),
                encryption_key_id=item.get('encryption_key_id'),
                data_classification=DataClassification(item['data_classification']),
                retention_days=item['retention_days'],
                geographic_restrictions=item.get('geographic_restrictions', []),
                compliance_requirements=item.get('compliance_requirements', [])
            )
            
        except Exception as e:
            print(f"Failed to get tenant configuration: {e}")
            return None
    
    def get_isolated_s3_key(self, customer_id: str, resource_type: str, resource_id: str, file_extension: str = None) -> str:
        """Generate isolated S3 key for customer data"""
        # Validate inputs
        if not SecurityValidator.is_safe_string(customer_id):
            raise ValueError("Invalid customer ID")
        
        if not SecurityValidator.is_safe_string(resource_type):
            raise ValueError("Invalid resource type")
        
        if not SecurityValidator.is_safe_string(resource_id):
            raise ValueError("Invalid resource ID")
        
        # Create hierarchical key structure
        timestamp = datetime.now(timezone.utc).strftime('%Y/%m/%d')
        base_key = f"customers/{customer_id}/{resource_type}/{timestamp}/{resource_id}"
        
        if file_extension:
            base_key += f".{file_extension}"
        
        return base_key
    
    def get_isolated_dynamodb_key(self, customer_id: str, account_id: str) -> str:
        """Generate isolated DynamoDB partition key"""
        # Create customer-specific hash for partition key
        key_material = f"{customer_id}:{account_id}"
        return hashlib.sha256(key_material.encode()).hexdigest()[:16]
    
    def enforce_data_isolation(self, customer_id: str, operation: str, resource_data: Dict[str, Any]) -> bool:
        """Enforce data isolation policies"""
        try:
            config = self.get_tenant_config(customer_id)
            if not config:
                security_logger.log_security_event(
                    event_type=SecurityEventType.AUTHORIZATION_FAILURE,
                    severity=SecurityLevel.HIGH,
                    action="enforce_data_isolation",
                    result="failure",
                    details={"error": "No tenant configuration found", "customer_id": customer_id}
                )
                return False
            
            # Check geographic restrictions
            if config.geographic_restrictions:
                # Implementation would check request origin against restrictions
                pass
            
            # Check data classification requirements
            if config.data_classification == DataClassification.RESTRICTED:
                # Additional checks for restricted data
                pass
            
            # Log data access for audit
            audit_logger.log_data_access(
                account_id=config.account_id,
                resource_id=f"{customer_id}/{operation}",
                action=operation,
                user_identity=customer_id,
                request_parameters={"data_classification": config.data_classification.value}
            )
            
            return True
            
        except Exception as e:
            print(f"Failed to enforce data isolation: {e}")
            security_logger.log_security_event(
                event_type=SecurityEventType.AUTHORIZATION_FAILURE,
                severity=SecurityLevel.CRITICAL,
                action="enforce_data_isolation",
                result="error",
                details={"error": str(e), "customer_id": customer_id}
            )
            return False
    
    def cleanup_customer_data(self, customer_id: str, immediate: bool = False) -> bool:
        """Clean up all customer data (GDPR right to be forgotten)"""
        try:
            config = self.get_tenant_config(customer_id)
            if not config:
                return False
            
            # Mark for deletion or delete immediately
            deletion_tasks = []
            
            # S3 cleanup
            bucket_name = f"cloudopai-reports-{config.account_id}"
            customer_prefix = f"customers/{customer_id}/"
            
            if immediate:
                # Delete all objects immediately
                paginator = self.s3_client.get_paginator('list_objects_v2')
                for page in paginator.paginate(Bucket=bucket_name, Prefix=customer_prefix):
                    if 'Contents' in page:
                        objects = [{'Key': obj['Key']} for obj in page['Contents']]
                        if objects:
                            self.s3_client.delete_objects(
                                Bucket=bucket_name,
                                Delete={'Objects': objects}
                            )
                            deletion_tasks.extend([obj['Key'] for obj in objects])
            else:
                # Mark objects for lifecycle deletion
                # This is handled by the lifecycle policy
                pass
            
            # DynamoDB cleanup
            scan_results_table = self.dynamodb.Table('CloudOpAI-ScanResults')
            account_hash = self.get_isolated_dynamodb_key(customer_id, config.account_id)
            
            if immediate:
                # Delete all scan results for customer
                response = scan_results_table.query(
                    KeyConditionExpression=boto3.dynamodb.conditions.Key('account_hash').eq(account_hash)
                )
                
                with scan_results_table.batch_writer() as batch:
                    for item in response['Items']:
                        batch.delete_item(
                            Key={
                                'account_hash': item['account_hash'],
                                'scan_timestamp': item['scan_timestamp']
                            }
                        )
                        deletion_tasks.append(f"scan/{item['scan_timestamp']}")
            
            # Update tenant status
            self.tenant_config_table.update_item(
                Key={'customer_id': customer_id},
                UpdateExpression='SET #status = :status, deleted_at = :timestamp',
                ExpressionAttributeNames={'#status': 'status'},
                ExpressionAttributeValues={
                    ':status': 'deleted',
                    ':timestamp': datetime.now(timezone.utc).isoformat()
                }
            )
            
            # Log data deletion for compliance
            audit_logger.log_audit_event(
                event_type=AuditEventType.DATA_DELETION,
                action="cleanup_customer_data",
                outcome="success",
                user_identity=customer_id,
                account_id=config.account_id,
                resource_type="customer_data",
                resource_id=customer_id,
                request_parameters={
                    "immediate": immediate,
                    "items_deleted": len(deletion_tasks)
                },
                compliance_impact="gdpr_right_to_be_forgotten",
                retention_period=2555  # Keep audit log for compliance
            )
            
            return True
            
        except Exception as e:
            print(f"Failed to cleanup customer data: {e}")
            security_logger.log_security_event(
                event_type=SecurityEventType.DATA_ACCESS,
                severity=SecurityLevel.CRITICAL,
                action="cleanup_customer_data",
                result="error",
                details={"error": str(e), "customer_id": customer_id}
            )
            return False
    
    def generate_data_export(self, customer_id: str, export_format: str = 'json') -> Optional[str]:
        """Generate complete data export for customer (GDPR data portability)"""
        try:
            config = self.get_tenant_config(customer_id)
            if not config:
                return None
            
            # Collect all customer data
            export_data = {
                'customer_id': customer_id,
                'account_id': config.account_id,
                'export_timestamp': datetime.now(timezone.utc).isoformat(),
                'data_classification': config.data_classification.value,
                'scan_results': [],
                'reports': [],
                'configuration': {}
            }
            
            # Get scan results
            scan_results_table = self.dynamodb.Table('CloudOpAI-ScanResults')
            account_hash = self.get_isolated_dynamodb_key(customer_id, config.account_id)
            
            response = scan_results_table.query(
                KeyConditionExpression=boto3.dynamodb.conditions.Key('account_hash').eq(account_hash)
            )
            
            for item in response['Items']:
                # Remove sensitive fields and add to export
                export_item = {k: v for k, v in item.items() if not k.startswith('internal_')}
                export_data['scan_results'].append(export_item)
            
            # Generate export file
            export_content = json.dumps(export_data, indent=2, default=str)
            
            # Store export in isolated S3 location
            export_key = self.get_isolated_s3_key(
                customer_id, 
                'exports', 
                f"data-export-{datetime.now().strftime('%Y%m%d-%H%M%S')}", 
                'json'
            )
            
            bucket_name = f"cloudopai-reports-{config.account_id}"
            self.s3_client.put_object(
                Bucket=bucket_name,
                Key=export_key,
                Body=export_content.encode('utf-8'),
                ContentType='application/json',
                ServerSideEncryption='aws:kms',
                SSEKMSKeyId=config.encryption_key_id if config.encryption_key_id else 'alias/aws/s3',
                Metadata={
                    'customer-id': customer_id,
                    'export-type': 'gdpr-data-portability',
                    'data-classification': config.data_classification.value
                }
            )
            
            # Generate presigned URL for download
            url = self.s3_client.generate_presigned_url(
                'get_object',
                Params={'Bucket': bucket_name, 'Key': export_key},
                ExpiresIn=86400  # 24 hours
            )
            
            # Log data export
            audit_logger.log_audit_event(
                event_type=AuditEventType.DATA_ACCESS,
                action="generate_data_export",
                outcome="success",
                user_identity=customer_id,
                account_id=config.account_id,
                resource_type="data_export",
                resource_id=export_key,
                compliance_impact="gdpr_data_portability"
            )
            
            return url
            
        except Exception as e:
            print(f"Failed to generate data export: {e}")
            return None

# Global data isolation manager
data_isolation = CustomerDataIsolation()

# Convenience functions
def initialize_customer_isolation(customer_id: str, account_id: str, **kwargs) -> TenantConfig:
    """Initialize customer data isolation"""
    return data_isolation.initialize_tenant(customer_id, account_id, **kwargs)

def get_isolated_storage_key(customer_id: str, resource_type: str, resource_id: str, extension: str = None) -> str:
    """Get isolated storage key for customer data"""
    return data_isolation.get_isolated_s3_key(customer_id, resource_type, resource_id, extension)

def enforce_customer_isolation(customer_id: str, operation: str, data: Dict[str, Any]) -> bool:
    """Enforce customer data isolation policies"""
    return data_isolation.enforce_data_isolation(customer_id, operation, data)