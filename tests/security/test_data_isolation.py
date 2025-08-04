"""Integration tests for customer data isolation"""
import pytest
import json
import hashlib
from datetime import datetime, timezone
from unittest.mock import patch, Mock

from src.core.utils.data_isolation import CustomerDataIsolation, IsolationLevel, DataClassification
from tests.conftest import integration_test, create_test_customer_data, assert_no_sensitive_data_in_response


class TestCustomerDataIsolation:
    """Test customer data isolation and multi-tenancy security"""
    
    @integration_test
    def test_customers_can_only_access_own_data(self, dynamodb_table, s3_bucket, kms_key):
        """Test that customers can only access their own data"""
        isolation = CustomerDataIsolation()
        
        # Create data for two different customers
        customer1_id = "customer-1"
        customer1_account = "123456789012"
        customer2_id = "customer-2"
        customer2_account = "987654321098"
        
        # Create test data for both customers
        customer1_hash = create_test_customer_data(
            dynamodb_table, customer1_id, customer1_account, 3
        )
        customer2_hash = create_test_customer_data(
            dynamodb_table, customer2_id, customer2_account, 3
        )
        
        # Initialize tenants
        tenant1_config = isolation.initialize_tenant(
            customer1_id, customer1_account, IsolationLevel.ENHANCED
        )
        tenant2_config = isolation.initialize_tenant(
            customer2_id, customer2_account, IsolationLevel.ENHANCED
        )
        
        # Test that customer 1 can only access their own data
        customer1_isolation_key = isolation.get_isolated_dynamodb_key(customer1_id, customer1_account)
        customer2_isolation_key = isolation.get_isolated_dynamodb_key(customer2_id, customer2_account)
        
        assert customer1_isolation_key == customer1_hash
        assert customer2_isolation_key == customer2_hash
        assert customer1_isolation_key != customer2_isolation_key
        
        # Test S3 key isolation
        s3_key1 = isolation.get_isolated_s3_key(customer1_id, "reports", "scan-123", "html")
        s3_key2 = isolation.get_isolated_s3_key(customer2_id, "reports", "scan-123", "html")
        
        assert customer1_id in s3_key1
        assert customer2_id in s3_key2
        assert s3_key1 != s3_key2
        
        # Verify that customer paths don't allow cross-tenant access
        assert customer1_id not in s3_key2
        assert customer2_id not in s3_key1
    
    @integration_test
    def test_data_isolation_enforcement(self, dynamodb_table):
        """Test that data isolation policies are enforced"""
        isolation = CustomerDataIsolation()
        
        customer_id = "test-customer"
        account_id = "123456789012"
        
        # Initialize tenant
        tenant_config = isolation.initialize_tenant(
            customer_id, account_id, IsolationLevel.STRICT
        )
        
        # Test that isolation is enforced
        assert isolation.enforce_data_isolation(customer_id, "scan_access", {"test": "data"}) == True
        
        # Test with non-existent customer
        assert isolation.enforce_data_isolation("non-existent", "scan_access", {"test": "data"}) == False
    
    @integration_test
    def test_cross_tenant_data_leak_prevention(self, dynamodb_table):
        """Test prevention of cross-tenant data leaks"""
        isolation = CustomerDataIsolation()
        
        # Create two customers with similar names (potential confusion attack)
        customer1_id = "customer-abc-123"
        customer1_account = "123456789012"
        customer2_id = "customer-abc-124"  # Very similar ID
        customer2_account = "123456789013"  # Very similar account
        
        # Create isolation keys
        key1 = isolation.get_isolated_dynamodb_key(customer1_id, customer1_account)
        key2 = isolation.get_isolated_dynamodb_key(customer2_id, customer2_account)
        
        # Keys must be different despite similar inputs
        assert key1 != key2
        
        # Keys should be cryptographically separated
        assert len(set([key1, key2])) == 2  # Ensure no collision
        
        # Test S3 paths are isolated
        s3_path1 = isolation.get_isolated_s3_key(customer1_id, "scans", "test", "json")
        s3_path2 = isolation.get_isolated_s3_key(customer2_id, "scans", "test", "json")
        
        assert s3_path1 != s3_path2
        # Ensure no path traversal possible between customers
        assert "../" not in s3_path1
        assert "../" not in s3_path2
    
    @integration_test
    def test_encryption_key_isolation(self, kms_key):
        """Test that each customer gets isolated encryption keys"""
        isolation = CustomerDataIsolation()
        
        customer1_id = "customer-1"
        customer1_account = "123456789012"
        customer2_id = "customer-2"
        customer2_account = "987654321098"
        
        # Initialize tenants with enhanced isolation (requires separate keys)
        with patch.object(isolation, '_create_customer_kms_key') as mock_create_key:
            mock_create_key.side_effect = ["key-1", "key-2"]
            
            tenant1 = isolation.initialize_tenant(
                customer1_id, customer1_account, IsolationLevel.ENHANCED
            )
            tenant2 = isolation.initialize_tenant(
                customer2_id, customer2_account, IsolationLevel.ENHANCED
            )
            
            # Each customer should have different encryption keys
            assert tenant1.encryption_key_id != tenant2.encryption_key_id
            assert mock_create_key.call_count == 2
    
    @integration_test 
    def test_gdpr_data_export_isolation(self, dynamodb_table, s3_bucket):
        """Test that GDPR data exports only include customer's own data"""
        isolation = CustomerDataIsolation()
        
        customer1_id = "customer-1"
        customer1_account = "123456789012"
        customer2_id = "customer-2"
        customer2_account = "987654321098"
        
        # Create test data for both customers
        create_test_customer_data(dynamodb_table, customer1_id, customer1_account, 2)
        create_test_customer_data(dynamodb_table, customer2_id, customer2_account, 2)
        
        # Initialize tenants
        isolation.initialize_tenant(customer1_id, customer1_account)
        isolation.initialize_tenant(customer2_id, customer2_account)
        
        # Mock S3 operations for export
        with patch.object(isolation.s3_client, 'put_object') as mock_put, \
             patch.object(isolation.s3_client, 'generate_presigned_url') as mock_url:
            
            mock_url.return_value = "https://presigned-url.com/export"
            
            # Generate export for customer 1
            export_url = isolation.generate_data_export(customer1_id, 'json')
            
            assert export_url is not None
            assert mock_put.called
            
            # Verify export content only includes customer 1 data
            export_call = mock_put.call_args
            export_body = export_call[1]['Body']
            export_data = json.loads(export_body.decode('utf-8'))
            
            # Should only contain customer 1's data
            assert export_data['customer_id'] == customer1_id
            assert export_data['account_id'] == customer1_account
            
            # Should not contain customer 2's data
            export_str = json.dumps(export_data)
            assert customer2_id not in export_str
            assert customer2_account not in export_str
    
    @integration_test
    def test_customer_data_cleanup_isolation(self, dynamodb_table, s3_bucket):
        """Test that customer data cleanup only affects target customer"""
        isolation = CustomerDataIsolation()
        
        customer1_id = "customer-1"
        customer1_account = "123456789012"
        customer2_id = "customer-2"
        customer2_account = "987654321098"
        
        # Create test data
        customer1_hash = create_test_customer_data(dynamodb_table, customer1_id, customer1_account, 2)
        customer2_hash = create_test_customer_data(dynamodb_table, customer2_id, customer2_account, 2)
        
        # Initialize tenants
        isolation.initialize_tenant(customer1_id, customer1_account)
        isolation.initialize_tenant(customer2_id, customer2_account)
        
        # Cleanup customer 1 data
        success = isolation.cleanup_customer_data(customer1_id, immediate=True)
        assert success == True
        
        # Verify customer 1 data is gone
        response = dynamodb_table['scan_results'].query(
            KeyConditionExpression='account_hash = :hash',
            ExpressionAttributeValues={':hash': customer1_hash}
        )
        assert len(response['Items']) == 0
        
        # Verify customer 2 data is still there
        response = dynamodb_table['scan_results'].query(
            KeyConditionExpression='account_hash = :hash',
            ExpressionAttributeValues={':hash': customer2_hash}
        )
        assert len(response['Items']) == 2  # Original data should remain


class TestPermissionBoundaries:
    """Test permission boundaries and access controls"""
    
    @integration_test
    def test_role_assumption_fails_gracefully(self, sample_lambda_event, mock_context):
        """Test that role assumption failures are handled gracefully"""
        from src.handlers.scanner_handler import lambda_handler
        
        # Test with invalid role ARN
        invalid_event = sample_lambda_event.copy()
        invalid_event["role_arn"] = "arn:aws:iam::000000000000:role/NonExistentRole"
        
        with patch('boto3.client') as mock_boto:
            mock_sts = Mock()
            mock_sts.assume_role.side_effect = Exception("AccessDenied")
            mock_boto.return_value = mock_sts
            
            result = lambda_handler(invalid_event, mock_context)
            
            # Should return error response, not crash
            assert "error" in result
            assert result.get("statusCode", 500) >= 400
            
            # Should not expose internal error details
            assert_no_sensitive_data_in_response(result)
    
    @integration_test
    def test_api_key_permission_boundaries(self, dynamodb_table):
        """Test API key permission boundaries"""
        from src.handlers.auth_handler import APIGatewayAuthenticator
        
        authenticator = APIGatewayAuthenticator()
        
        # Create API key with limited permissions
        api_key = authenticator.create_api_key(
            customer_id="test-customer",
            account_id="123456789012",
            permissions=["scan:read"],  # Read-only permissions
            expires_days=30
        )
        
        # Test authentication
        result = authenticator._authenticate_api_key(
            api_key, "192.168.1.100", "Test-Client/1.0"
        )
        
        assert result.authenticated == True
        assert result.authorized == True
        assert "scan:read" in result.permissions
        assert "scan:write" not in result.permissions
    
    @integration_test
    def test_jwt_token_permission_validation(self):
        """Test JWT token permission validation"""
        from src.handlers.auth_handler import APIGatewayAuthenticator
        from tests.conftest import generate_test_jwt
        
        authenticator = APIGatewayAuthenticator()
        
        # Test with valid token
        valid_token = generate_test_jwt(
            customer_id="test-customer",
            account_id="123456789012"
        )
        
        result = authenticator._authenticate_jwt(
            valid_token, "192.168.1.100", "Test-Client/1.0"
        )
        
        assert result.authenticated == True
        assert result.customer_id == "test-customer"
        assert result.account_id == "123456789012"
        
        # Test with expired token
        expired_token = generate_test_jwt(expired=True)
        
        result = authenticator._authenticate_jwt(
            expired_token, "192.168.1.100", "Test-Client/1.0"
        )
        
        assert result.authenticated == False
        assert "expired" in result.error_message.lower()
    
    @integration_test
    def test_rate_limiting_permission_boundaries(self, dynamodb_table):
        """Test that rate limiting respects permission boundaries"""
        from src.core.utils.rate_limiter import RateLimiter, RateLimitType
        
        limiter = RateLimiter()
        
        # Test normal rate limiting
        for i in range(5):
            result = limiter.check_rate_limit(
                "test-user", RateLimitType.REQUESTS_PER_MINUTE, "123456789012"
            )
            assert result.allowed == True
        
        # Exceed rate limit
        for i in range(60):  # Exceed 60 requests per minute
            result = limiter.check_rate_limit(
                "test-user", RateLimitType.REQUESTS_PER_MINUTE, "123456789012"
            )
        
        # Should now be rate limited
        assert result.allowed == False
        assert result.retry_after is not None


class TestInvalidInputRejection:
    """Test that invalid inputs are properly rejected"""
    
    @integration_test
    def test_scanner_handler_rejects_invalid_inputs(self, mock_context, malicious_payloads):
        """Test that scanner handler rejects invalid inputs"""
        from src.handlers.scanner_handler import lambda_handler
        
        # Test with XSS payload in email
        malicious_event = {
            "account_id": "123456789012",
            "role_arn": "arn:aws:iam::123456789012:role/Test",
            "email": malicious_payloads["xss_payloads"][0]
        }
        
        result = lambda_handler(malicious_event, mock_context)
        
        # Should reject the request
        assert result.get("statusCode", 500) >= 400
        assert "error" in result
    
    @integration_test
    def test_api_gateway_rejects_malicious_requests(self, malicious_payloads, mock_context):
        """Test API Gateway handler rejects malicious requests"""
        from src.handlers.auth_handler import lambda_handler
        
        # Create event with malicious authorization header
        malicious_event = {
            "type": "REQUEST",
            "methodArn": "arn:aws:execute-api:us-east-1:123456789012:abcdef123/test/GET/request",
            "resource": "/request",
            "path": "/request",
            "httpMethod": "GET",
            "headers": {
                "Authorization": malicious_payloads["xss_payloads"][0]
            },
            "requestContext": {
                "identity": {
                    "sourceIp": "192.168.1.100"
                }
            }
        }
        
        result = lambda_handler(malicious_event, mock_context)
        
        # Should deny access
        assert result["policyDocument"]["Statement"][0]["Effect"] == "Deny"
    
    @integration_test
    def test_data_isolation_rejects_invalid_customer_ids(self, malicious_payloads):
        """Test data isolation rejects invalid customer IDs"""
        from src.core.utils.data_isolation import CustomerDataIsolation, IsolationLevel
        
        isolation = CustomerDataIsolation()
        
        # Test with SQL injection payload
        malicious_customer_id = malicious_payloads["sql_injection_payloads"][0]
        
        with pytest.raises(ValueError):
            isolation.initialize_tenant(
                malicious_customer_id, "123456789012", IsolationLevel.BASIC
            )
    
    @integration_test
    def test_gdpr_compliance_rejects_invalid_inputs(self, malicious_payloads):
        """Test GDPR compliance rejects invalid inputs"""
        from src.core.compliance.gdpr_compliance import GDPRComplianceManager, GDPRRights
        
        gdpr = GDPRComplianceManager()
        
        # Test with path traversal in customer ID
        malicious_customer_id = malicious_payloads["path_traversal_payloads"][0]
        
        with pytest.raises(Exception):
            gdpr.submit_gdpr_request(
                malicious_customer_id, 
                GDPRRights.RIGHT_TO_ACCESS,
                "test@example.com"
            )
    
    @integration_test
    def test_oversized_input_rejection(self, malicious_payloads, mock_context):
        """Test rejection of oversized inputs"""
        from src.handlers.scanner_handler import lambda_handler
        
        # Create event with oversized field
        oversized_event = {
            "account_id": "123456789012",
            "role_arn": "arn:aws:iam::123456789012:role/Test",
            "email": "test@example.com",
            "large_field": malicious_payloads["oversized_payloads"][0]
        }
        
        result = lambda_handler(oversized_event, mock_context)
        
        # Should reject oversized input
        assert result.get("statusCode", 500) >= 400
    
    @integration_test
    def test_unicode_attack_rejection(self):
        """Test rejection of Unicode-based attacks"""
        from src.core.utils.security_validators import SecurityValidator
        
        unicode_attacks = [
            "test\u0000null",
            "test\u202e",
            "test%00null",
            "\ufeffBOM test"
        ]
        
        for attack in unicode_attacks:
            # Should be rejected by security validator
            assert SecurityValidator.is_safe_string(attack) == False
            
            # Should be rejected in Lambda event validation
            with pytest.raises(ValueError):
                SecurityValidator.validate_lambda_event({
                    "account_id": "123456789012",
                    "role_arn": "arn:aws:iam::123456789012:role/Test",
                    "email": attack
                })


class TestSecurityHeadersAndResponse:
    """Test security headers and response sanitization"""
    
    @integration_test
    def test_security_headers_in_api_responses(self, sample_lambda_event, mock_context):
        """Test that API responses include security headers"""
        from src.handlers.scanner_handler import lambda_handler
        
        result = lambda_handler(sample_lambda_event, mock_context)
        
        # Should include security headers
        headers = result.get("headers", {})
        
        security_headers = [
            "X-Content-Type-Options",
            "X-Frame-Options", 
            "X-XSS-Protection",
            "Strict-Transport-Security"
        ]
        
        for header in security_headers:
            assert header in headers, f"Missing security header: {header}"
    
    @integration_test
    def test_cors_headers_properly_configured(self, sample_api_gateway_event, mock_context):
        """Test CORS headers are properly configured"""
        from src.handlers.auth_handler import lambda_handler
        
        result = lambda_handler(sample_api_gateway_event, mock_context)
        
        # CORS headers should be restrictive
        context = result.get("context", {})
        if "cors_origin" in context:
            # Should not allow wildcard origin for authenticated requests
            assert context["cors_origin"] != "*"
    
    @integration_test
    def test_response_data_sanitization(self, sample_lambda_event, mock_context):
        """Test that response data is properly sanitized"""
        from src.handlers.scanner_handler import lambda_handler
        
        # Mock scan results with potentially sensitive data
        with patch('src.services.scanner.ec2_scanner.EC2Scanner.scan_account') as mock_scan:
            mock_scan.return_value = {
                "instances": [{
                    "instance_id": "i-1234567890abcdef0",
                    "internal_data": "sensitive-info-that-should-not-be-exposed",
                    "role_arn": "arn:aws:iam::123456789012:role/SensitiveRole"
                }]
            }
            
            result = lambda_handler(sample_lambda_event, mock_context)
            
            # Response should not contain sensitive internal data
            assert_no_sensitive_data_in_response(result)
            
            # ARNs should be sanitized or redacted
            response_str = json.dumps(result, default=str)
            if "arn:aws:iam::" in response_str:
                # Should be redacted (showing only account)
                assert "role/[REDACTED]" in response_str or "****" in response_str