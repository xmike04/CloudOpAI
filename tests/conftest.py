"""Pytest configuration and fixtures for CloudOpAI security tests"""
import pytest
import boto3
import json
import uuid
from datetime import datetime, timezone
from moto import mock_dynamodb, mock_s3, mock_kms, mock_secretsmanager, mock_lambda, mock_cloudwatch
from unittest.mock import Mock, patch

# Test configuration
TEST_ACCOUNT_ID = "123456789012"
TEST_CUSTOMER_ID = "test-customer-123"
TEST_EMAIL = "test@example.com"
TEST_REGION = "us-east-1"

@pytest.fixture(scope="session")
def aws_credentials():
    """Mocked AWS Credentials for moto."""
    import os
    os.environ["AWS_ACCESS_KEY_ID"] = "testing"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
    os.environ["AWS_SECURITY_TOKEN"] = "testing"
    os.environ["AWS_SESSION_TOKEN"] = "testing"
    os.environ["AWS_DEFAULT_REGION"] = TEST_REGION

@pytest.fixture
def mock_aws_services(aws_credentials):
    """Mock all AWS services used by CloudOpAI"""
    with mock_dynamodb(), mock_s3(), mock_kms(), mock_secretsmanager(), \
         mock_lambda(), mock_cloudwatch():
        yield

@pytest.fixture
def dynamodb_table(mock_aws_services):
    """Create test DynamoDB table"""
    dynamodb = boto3.resource('dynamodb', region_name=TEST_REGION)
    
    # Create scan results table
    table = dynamodb.create_table(
        TableName='CloudOpAI-ScanResults',
        KeySchema=[
            {'AttributeName': 'account_hash', 'KeyType': 'HASH'},
            {'AttributeName': 'scan_timestamp', 'KeyType': 'RANGE'}
        ],
        AttributeDefinitions=[
            {'AttributeName': 'account_hash', 'AttributeType': 'S'},
            {'AttributeName': 'scan_timestamp', 'AttributeType': 'S'}
        ],
        BillingMode='PAY_PER_REQUEST'
    )
    
    # Create rate limit table
    rate_limit_table = dynamodb.create_table(
        TableName='CloudOpAI-RateLimits',
        KeySchema=[
            {'AttributeName': 'key', 'KeyType': 'HASH'},
            {'AttributeName': 'window', 'KeyType': 'RANGE'}
        ],
        AttributeDefinitions=[
            {'AttributeName': 'key', 'AttributeType': 'S'},
            {'AttributeName': 'window', 'AttributeType': 'S'}
        ],
        BillingMode='PAY_PER_REQUEST'
    )
    
    # Create API keys table
    api_keys_table = dynamodb.create_table(
        TableName='CloudOpAI-APIKeys',
        KeySchema=[
            {'AttributeName': 'api_key_hash', 'KeyType': 'HASH'}
        ],
        AttributeDefinitions=[
            {'AttributeName': 'api_key_hash', 'AttributeType': 'S'}
        ],
        BillingMode='PAY_PER_REQUEST'
    )
    
    # Create tenant config table
    tenant_table = dynamodb.create_table(
        TableName='CloudOpAI-TenantConfig',
        KeySchema=[
            {'AttributeName': 'customer_id', 'KeyType': 'HASH'}
        ],
        AttributeDefinitions=[
            {'AttributeName': 'customer_id', 'AttributeType': 'S'}
        ],
        BillingMode='PAY_PER_REQUEST'
    )
    
    # Create GDPR requests table
    gdpr_table = dynamodb.create_table(
        TableName='CloudOpAI-GDPR-Requests',
        KeySchema=[
            {'AttributeName': 'request_id', 'KeyType': 'HASH'}
        ],
        AttributeDefinitions=[
            {'AttributeName': 'request_id', 'AttributeType': 'S'}
        ],
        BillingMode='PAY_PER_REQUEST'
    )
    
    # Create SOC2 controls table
    soc2_table = dynamodb.create_table(
        TableName='CloudOpAI-SOC2-Controls',
        KeySchema=[
            {'AttributeName': 'control_id', 'KeyType': 'HASH'}
        ],
        AttributeDefinitions=[
            {'AttributeName': 'control_id', 'AttributeType': 'S'}
        ],
        BillingMode='PAY_PER_REQUEST'
    )
    
    yield {
        'scan_results': table,
        'rate_limits': rate_limit_table,
        'api_keys': api_keys_table,
        'tenant_config': tenant_table,
        'gdpr_requests': gdpr_table,
        'soc2_controls': soc2_table
    }

@pytest.fixture
def s3_bucket(mock_aws_services):
    """Create test S3 bucket"""
    s3_client = boto3.client('s3', region_name=TEST_REGION)
    bucket_name = f'cloudopai-reports-{TEST_ACCOUNT_ID}'
    
    s3_client.create_bucket(Bucket=bucket_name)
    
    # Enable encryption
    s3_client.put_bucket_encryption(
        Bucket=bucket_name,
        ServerSideEncryptionConfiguration={
            'Rules': [{
                'ApplyServerSideEncryptionByDefault': {
                    'SSEAlgorithm': 'AES256'
                }
            }]
        }
    )
    
    yield bucket_name

@pytest.fixture
def kms_key(mock_aws_services):
    """Create test KMS key"""
    kms_client = boto3.client('kms', region_name=TEST_REGION)
    
    key_response = kms_client.create_key(
        Description='Test CloudOpAI encryption key',
        KeyUsage='ENCRYPT_DECRYPT'
    )
    
    yield key_response['KeyMetadata']['KeyId']

@pytest.fixture
def mock_secrets_manager(mock_aws_services):
    """Mock Secrets Manager with test secrets"""
    secrets_client = boto3.client('secretsmanager', region_name=TEST_REGION)
    
    # Create test configuration secret
    config_secret = {
        "email_source": "test@cloudopai.com",
        "calendly_link": "https://calendly.com/test",
        "aws_region": TEST_REGION,
        "reports_bucket": f"cloudopai-reports-{TEST_ACCOUNT_ID}",
        "scan_results_table": "CloudOpAI-ScanResults"
    }
    
    secrets_client.create_secret(
        Name='cloudopai/config',
        SecretString=json.dumps(config_secret)
    )
    
    # Create JWT secret
    jwt_secret = {
        "jwt_secret": "test-jwt-secret-key-for-testing-only"
    }
    
    secrets_client.create_secret(
        Name='cloudopai/jwt-config',
        SecretString=json.dumps(jwt_secret)
    )
    
    yield secrets_client

@pytest.fixture
def sample_lambda_event():
    """Sample Lambda event for testing"""
    return {
        "account_id": TEST_ACCOUNT_ID,
        "role_arn": f"arn:aws:iam::{TEST_ACCOUNT_ID}:role/CloudOpAI-Scanner-Role",
        "email": TEST_EMAIL,
        "regions": ["us-east-1", "us-west-2"],
        "requestContext": {
            "identity": {
                "sourceIp": "192.168.1.100",
                "userAgent": "CloudOpAI-Client/1.0"
            },
            "requestId": "test-request-123"
        },
        "headers": {
            "User-Agent": "CloudOpAI-Client/1.0",
            "X-API-Key": "test-api-key-64-characters-long-for-security-testing-purposes"
        }
    }

@pytest.fixture
def sample_api_gateway_event():
    """Sample API Gateway event for testing"""
    return {
        "httpMethod": "POST",
        "path": "/v1/scan",
        "headers": {
            "Authorization": "Bearer test-jwt-token",
            "X-API-Key": "test-api-key-64-characters-long-for-security-testing-purposes",
            "User-Agent": "CloudOpAI-Client/1.0",
            "Content-Type": "application/json"
        },
        "body": json.dumps({
            "account_id": TEST_ACCOUNT_ID,
            "role_arn": f"arn:aws:iam::{TEST_ACCOUNT_ID}:role/CloudOpAI-Scanner-Role",
            "email": TEST_EMAIL
        }),
        "requestContext": {
            "identity": {
                "sourceIp": "192.168.1.100",
                "userAgent": "CloudOpAI-Client/1.0"
            },
            "requestId": "test-request-123"
        }
    }

@pytest.fixture
def malicious_payloads():
    """Common malicious payloads for security testing"""
    return {
        "xss_payloads": [
            "<script>alert('xss')</script>",
            "javascript:alert('xss')",
            "<img src=x onerror=alert('xss')>",
            "';alert('xss');//",
            "<svg onload=alert('xss')>"
        ],
        "sql_injection_payloads": [
            "'; DROP TABLE users; --",
            "' OR '1'='1",
            "'; SELECT * FROM information_schema.tables; --",
            "' UNION SELECT password FROM users --",
            "'; DELETE FROM scan_results; --"
        ],
        "path_traversal_payloads": [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "....//....//....//etc/passwd",
            "/var/log/auth.log",
            "file:///etc/passwd"
        ],
        "command_injection_payloads": [
            "; cat /etc/passwd",
            "| whoami",
            "&& rm -rf /",
            "`whoami`",
            "$(cat /etc/passwd)"
        ],
        "oversized_payloads": [
            "A" * 10000,  # 10KB string
            "B" * 100000,  # 100KB string
            {"large_field": "C" * 50000}  # Large JSON field
        ]
    }

@pytest.fixture
def mock_context():
    """Mock Lambda context"""
    context = Mock()
    context.aws_request_id = "test-request-123"
    context.function_name = "CloudOpAI-Scanner"
    context.function_version = "1"
    context.memory_limit_in_mb = 512
    context.remaining_time_in_millis = lambda: 30000
    return context

@pytest.fixture
def security_test_data():
    """Security-specific test data"""
    return {
        "valid_account_ids": [
            "123456789012",
            "987654321098",
            "555666777888"
        ],
        "invalid_account_ids": [
            "12345678901",  # Too short
            "1234567890123",  # Too long
            "12345678901a",  # Contains letter
            "",  # Empty
            None,  # None
            "000000000000"  # All zeros
        ],
        "valid_emails": [
            "user@example.com",
            "test.user+tag@domain.co.uk",
            "user123@test-domain.com"
        ],
        "invalid_emails": [
            "invalid-email",
            "@domain.com",
            "user@",
            "user..double.dot@domain.com",
            "user@domain",
            ""
        ],
        "valid_role_arns": [
            f"arn:aws:iam::{TEST_ACCOUNT_ID}:role/CloudOpAI-Scanner-Role",
            f"arn:aws:iam::{TEST_ACCOUNT_ID}:role/TestRole",
            f"arn:aws:iam::{TEST_ACCOUNT_ID}:role/path/to/role"
        ],
        "invalid_role_arns": [
            "not-an-arn",
            "arn:aws:iam::123:role/TooShort",
            "arn:aws:s3:::bucket/key",  # Wrong service
            "",
            None
        ]
    }

# Security test decorators
def security_test(test_func):
    """Decorator to mark security tests"""
    test_func.security_test = True
    return test_func

def integration_test(test_func):
    """Decorator to mark integration tests"""
    test_func.integration_test = True
    return test_func

# Helper functions for security testing
def generate_test_jwt(customer_id=TEST_CUSTOMER_ID, account_id=TEST_ACCOUNT_ID, expired=False):
    """Generate test JWT token"""
    import jwt
    from datetime import timedelta
    
    now = datetime.now(timezone.utc)
    exp_time = now - timedelta(hours=1) if expired else now + timedelta(hours=1)
    
    payload = {
        'customer_id': customer_id,
        'account_id': account_id,
        'permissions': ['scan:read', 'scan:write', 'report:read'],
        'iat': int(now.timestamp()),
        'exp': int(exp_time.timestamp()),
        'iss': 'cloudopai.com',
        'aud': 'api.cloudopai.com'
    }
    
    return jwt.encode(payload, "test-jwt-secret-key-for-testing-only", algorithm="HS256")

def create_test_customer_data(dynamodb_table, customer_id, account_id, num_records=5):
    """Create test data for customer isolation testing"""
    import hashlib
    
    account_hash = hashlib.sha256(f"{customer_id}:{account_id}".encode()).hexdigest()[:16]
    
    for i in range(num_records):
        dynamodb_table['scan_results'].put_item(
            Item={
                'account_hash': account_hash,
                'scan_timestamp': f"2024-01-{i+1:02d}T10:00:00Z",
                'customer_id': customer_id,
                'account_id': account_id,
                'scan_id': f"scan-{customer_id}-{i}",
                'total_monthly_waste': 1000.0 + (i * 100),
                'opportunities_found': i + 1,
                'scan_status': 'completed'
            }
        )
    
    return account_hash

# Test data validation helpers
def assert_no_sensitive_data_in_response(response_data):
    """Assert that response doesn't contain sensitive information"""
    sensitive_patterns = [
        'password', 'secret', 'key', 'token', 'credential',
        'AccessKeyId', 'SecretAccessKey', 'SessionToken'
    ]
    
    response_str = json.dumps(response_data, default=str).lower()
    
    for pattern in sensitive_patterns:
        assert pattern not in response_str, f"Response contains sensitive data: {pattern}"

def assert_security_headers_present(response):
    """Assert that security headers are present in response"""
    required_headers = [
        'X-Content-Type-Options',
        'X-Frame-Options',
        'X-XSS-Protection',
        'Strict-Transport-Security'
    ]
    
    headers = response.get('headers', {})
    
    for header in required_headers:
        assert header in headers, f"Missing security header: {header}"