"""Security tests for input validation functions"""
import pytest
import json
from unittest.mock import patch, Mock

from src.core.utils.security_validators import SecurityValidator
from tests.conftest import security_test, malicious_payloads


class TestSecurityValidator:
    """Test security validation functions"""
    
    @security_test
    def test_validate_aws_account_id_valid_inputs(self, security_test_data):
        """Test valid AWS account ID validation"""
        for account_id in security_test_data["valid_account_ids"]:
            assert SecurityValidator.is_valid_aws_account_id(account_id) == True
    
    @security_test
    def test_validate_aws_account_id_invalid_inputs(self, security_test_data):
        """Test invalid AWS account ID validation"""
        for account_id in security_test_data["invalid_account_ids"]:
            assert SecurityValidator.is_valid_aws_account_id(account_id) == False
    
    @security_test
    def test_validate_email_valid_inputs(self, security_test_data):
        """Test valid email validation"""
        for email in security_test_data["valid_emails"]:
            assert SecurityValidator.is_valid_email(email) == True
    
    @security_test
    def test_validate_email_invalid_inputs(self, security_test_data):
        """Test invalid email validation"""
        for email in security_test_data["invalid_emails"]:
            assert SecurityValidator.is_valid_email(email) == False
    
    @security_test
    def test_validate_role_arn_valid_inputs(self, security_test_data):
        """Test valid IAM role ARN validation"""
        for role_arn in security_test_data["valid_role_arns"]:
            assert SecurityValidator.is_valid_iam_role_arn(role_arn) == True
    
    @security_test
    def test_validate_role_arn_invalid_inputs(self, security_test_data):
        """Test invalid IAM role ARN validation"""
        for role_arn in security_test_data["invalid_role_arns"]:
            assert SecurityValidator.is_valid_iam_role_arn(role_arn) == False
    
    @security_test
    def test_xss_detection(self, malicious_payloads):
        """Test XSS payload detection"""
        for payload in malicious_payloads["xss_payloads"]:
            assert SecurityValidator.contains_xss(payload) == True
            
        # Test safe strings
        safe_strings = [
            "normal text",
            "user@example.com",
            "account-123456789012",
            "This is a safe string with numbers 123"
        ]
        
        for safe_string in safe_strings:
            assert SecurityValidator.contains_xss(safe_string) == False
    
    @security_test
    def test_sql_injection_detection(self, malicious_payloads):
        """Test SQL injection payload detection"""
        for payload in malicious_payloads["sql_injection_payloads"]:
            assert SecurityValidator.contains_sql_injection(payload) == True
            
        # Test safe strings
        safe_strings = [
            "normal text",
            "user@example.com", 
            "account-123456789012",
            "SELECT is a normal word"
        ]
        
        for safe_string in safe_strings:
            assert SecurityValidator.contains_sql_injection(safe_string) == False
    
    @security_test
    def test_path_traversal_detection(self, malicious_payloads):
        """Test path traversal payload detection"""
        for payload in malicious_payloads["path_traversal_payloads"]:
            assert SecurityValidator.contains_path_traversal(payload) == True
            
        # Test safe paths
        safe_paths = [
            "reports/customer-123/scan-456.html",
            "data/2024/01/scan-results.json",
            "normal-filename.txt"
        ]
        
        for safe_path in safe_paths:
            assert SecurityValidator.contains_path_traversal(safe_path) == False
    
    @security_test
    def test_safe_string_validation(self):
        """Test safe string validation"""
        # Test safe strings
        safe_strings = [
            "normal-text-123",
            "user@example.com",
            "account_id_123456789012",
            "scan-result-2024-01-01"
        ]
        
        for safe_string in safe_strings:
            assert SecurityValidator.is_safe_string(safe_string) == True
        
        # Test unsafe strings
        unsafe_strings = [
            "<script>alert('xss')</script>",
            "'; DROP TABLE users; --",
            "../../../etc/passwd",
            "null\x00byte",
            "\n\r\t"
        ]
        
        for unsafe_string in unsafe_strings:
            assert SecurityValidator.is_safe_string(unsafe_string) == False
    
    @security_test
    def test_sanitize_html_content(self, malicious_payloads):
        """Test HTML content sanitization"""
        for payload in malicious_payloads["xss_payloads"]:
            sanitized = SecurityValidator.sanitize_html_content(payload)
            # Should not contain script tags or javascript
            assert "<script>" not in sanitized.lower()
            assert "javascript:" not in sanitized.lower()
            assert "onerror=" not in sanitized.lower()
    
    @security_test
    def test_validate_lambda_event_structure(self, sample_lambda_event):
        """Test Lambda event structure validation"""
        # Valid event should pass
        validated_event = SecurityValidator.validate_lambda_event(sample_lambda_event)
        assert validated_event is not None
        assert validated_event["account_id"] == sample_lambda_event["account_id"]
        
        # Missing required fields should fail
        invalid_event = sample_lambda_event.copy()
        del invalid_event["account_id"]
        
        with pytest.raises(ValueError, match="Missing required field"):
            SecurityValidator.validate_lambda_event(invalid_event)
    
    @security_test
    def test_validate_lambda_event_malicious_inputs(self, sample_lambda_event, malicious_payloads):
        """Test Lambda event validation with malicious inputs"""
        # Test XSS in email field
        malicious_event = sample_lambda_event.copy()
        malicious_event["email"] = malicious_payloads["xss_payloads"][0]
        
        with pytest.raises(ValueError, match="contains XSS"):
            SecurityValidator.validate_lambda_event(malicious_event)
        
        # Test SQL injection in account_id
        malicious_event = sample_lambda_event.copy()
        malicious_event["account_id"] = malicious_payloads["sql_injection_payloads"][0]
        
        with pytest.raises(ValueError, match="Invalid account_id"):
            SecurityValidator.validate_lambda_event(malicious_event)
    
    @security_test
    def test_create_secure_s3_key(self):
        """Test secure S3 key generation"""
        account_id = "123456789012"
        scan_id = "scan-123"
        extension = "html"
        
        key = SecurityValidator.create_secure_s3_key(account_id, scan_id, extension)
        
        # Should not contain path traversal
        assert "../" not in key
        assert "..\\" not in key
        
        # Should contain expected components
        assert account_id in key
        assert scan_id in key
        assert extension in key
        
        # Should be deterministic
        key2 = SecurityValidator.create_secure_s3_key(account_id, scan_id, extension)
        assert key == key2
    
    @security_test
    def test_validate_api_gateway_request(self, sample_api_gateway_event):
        """Test API Gateway request validation"""
        # Valid request should pass
        validated_request = SecurityValidator.validate_api_gateway_request(sample_api_gateway_event)
        assert validated_request is not None
        
        # Test with malicious body
        malicious_event = sample_api_gateway_event.copy()
        malicious_body = {
            "account_id": "<script>alert('xss')</script>",
            "role_arn": "'; DROP TABLE users; --",
            "email": "test@example.com"
        }
        malicious_event["body"] = json.dumps(malicious_body)
        
        with pytest.raises(ValueError, match="contains XSS|Invalid account_id"):
            SecurityValidator.validate_api_gateway_request(malicious_event)
    
    @security_test
    def test_input_size_limits(self, malicious_payloads):
        """Test input size validation"""
        # Test oversized inputs
        for payload in malicious_payloads["oversized_payloads"]:
            if isinstance(payload, str):
                assert SecurityValidator.is_safe_string(payload) == False
            elif isinstance(payload, dict):
                # Test that large JSON objects are rejected
                json_str = json.dumps(payload)
                assert len(json_str) > 10000  # Verify it's actually large
                assert SecurityValidator.is_safe_string(json_str) == False
    
    @security_test
    def test_unicode_and_encoding_attacks(self):
        """Test protection against Unicode and encoding attacks"""
        unicode_attacks = [
            "test\u0000null",  # Null byte
            "test\u202e",      # Right-to-left override
            "test%00null",     # URL encoded null
            "test&#x00;null",  # HTML encoded null
            "\ufeffBOM test",  # Byte Order Mark
        ]
        
        for attack in unicode_attacks:
            assert SecurityValidator.is_safe_string(attack) == False
    
    @security_test
    def test_regex_denial_of_service_protection(self):
        """Test protection against ReDoS attacks"""
        # Create a string that could cause ReDoS in poorly written regex
        redos_payload = "a" * 10000 + "X"
        
        # Our validation should complete quickly
        import time
        start_time = time.time()
        result = SecurityValidator.is_safe_string(redos_payload)
        end_time = time.time()
        
        # Should complete in reasonable time (less than 1 second)
        assert (end_time - start_time) < 1.0
        # Should reject the oversized input
        assert result == False


class TestInputValidationIntegration:
    """Integration tests for input validation across modules"""
    
    @security_test
    @patch('src.core.utils.security_validators.SecurityValidator.validate_lambda_event')
    def test_scanner_handler_input_validation(self, mock_validate, sample_lambda_event, mock_context):
        """Test that scanner handler properly validates inputs"""
        from src.handlers.scanner_handler import lambda_handler
        
        # Mock validation to return the event
        mock_validate.return_value = sample_lambda_event
        
        # Should call validation
        try:
            lambda_handler(sample_lambda_event, mock_context)
        except Exception:
            pass  # We expect other errors, but validation should be called
        
        mock_validate.assert_called_once_with(sample_lambda_event)
    
    @security_test
    def test_api_gateway_auth_input_validation(self, sample_api_gateway_event, mock_context):
        """Test API Gateway auth handler input validation"""
        from src.handlers.auth_handler import lambda_handler
        
        # Test with malicious headers
        malicious_event = sample_api_gateway_event.copy()
        malicious_event["headers"]["Authorization"] = "Bearer <script>alert('xss')</script>"
        
        result = lambda_handler(malicious_event, mock_context)
        
        # Should deny access
        assert result["policyDocument"]["Statement"][0]["Effect"] == "Deny"
    
    @security_test
    def test_rate_limiter_input_validation(self):
        """Test rate limiter input validation"""
        from src.core.utils.rate_limiter import RateLimiter, RateLimitType
        
        limiter = RateLimiter()
        
        # Test with malicious identifier
        malicious_identifier = "<script>alert('xss')</script>"
        
        # Should handle malicious input gracefully
        result = limiter.check_rate_limit(
            malicious_identifier, 
            RateLimitType.REQUESTS_PER_MINUTE
        )
        
        # Should not fail, but should sanitize the identifier internally
        assert result.allowed in [True, False]  # Should return a valid result
    
    @security_test
    def test_data_isolation_input_validation(self):
        """Test data isolation input validation"""
        from src.core.utils.data_isolation import CustomerDataIsolation, IsolationLevel, DataClassification
        
        isolation = CustomerDataIsolation()
        
        # Test with malicious customer ID
        malicious_customer_id = "'; DROP TABLE customers; --"
        valid_account_id = "123456789012"
        
        with pytest.raises(ValueError, match="Invalid customer ID"):
            isolation.initialize_tenant(
                malicious_customer_id,
                valid_account_id,
                IsolationLevel.ENHANCED,
                DataClassification.CONFIDENTIAL
            )
    
    @security_test
    def test_gdpr_compliance_input_validation(self):
        """Test GDPR compliance input validation"""
        from src.core.compliance.gdpr_compliance import GDPRComplianceManager, GDPRRights, DataCategory
        
        gdpr = GDPRComplianceManager()
        
        # Test with malicious inputs
        malicious_customer_id = "<script>alert('xss')</script>"
        malicious_email = "'; DROP TABLE gdpr_requests; --@example.com"
        
        with pytest.raises(Exception):  # Should raise validation error
            gdpr.submit_gdpr_request(
                malicious_customer_id,
                GDPRRights.RIGHT_TO_ACCESS,
                malicious_email,
                [DataCategory.CONTACT_INFO]
            )


class TestErrorHandlingWithoutInfoDisclosure:
    """Test that error handling doesn't disclose sensitive information"""
    
    @security_test
    def test_validation_error_messages_safe(self, malicious_payloads):
        """Test that validation error messages don't leak sensitive info"""
        # Test with various malicious inputs
        for payload in malicious_payloads["xss_payloads"]:
            try:
                SecurityValidator.validate_lambda_event({"account_id": payload, "role_arn": "test", "email": "test@example.com"})
            except ValueError as e:
                error_msg = str(e).lower()
                
                # Error message should not contain the malicious payload
                assert payload.lower() not in error_msg
                
                # Should contain generic error description
                assert any(word in error_msg for word in ["invalid", "malformed", "forbidden"])
    
    @security_test
    def test_exception_handling_no_stack_traces(self, sample_lambda_event, mock_context):
        """Test that exceptions don't expose stack traces to users"""
        from src.handlers.scanner_handler import lambda_handler
        
        # Create an event that will cause an internal error
        broken_event = sample_lambda_event.copy()
        broken_event["account_id"] = "000000000000"  # Invalid account
        
        with patch('boto3.client') as mock_boto:
            mock_boto.side_effect = Exception("Internal AWS error with sensitive details")
            
            result = lambda_handler(broken_event, mock_context)
            
            # Response should not contain stack trace or internal error details
            response_str = json.dumps(result, default=str).lower()
            assert "traceback" not in response_str
            assert "internal" not in response_str
            assert "sensitive details" not in response_str
            
            # Should contain generic error message
            assert "error" in response_str
    
    @security_test
    def test_aws_error_sanitization(self):
        """Test that AWS errors are sanitized before returning to user"""
        from src.core.utils.security_validators import SecurityValidator
        
        # Simulate AWS error that might contain sensitive info
        aws_error = "AccessDenied: User arn:aws:iam::123456789012:user/sensitive-user is not authorized"
        
        sanitized_error = SecurityValidator.sanitize_error_message(aws_error)
        
        # Should not contain ARN or account details
        assert "arn:aws:iam::" not in sanitized_error
        assert "123456789012" not in sanitized_error
        assert "sensitive-user" not in sanitized_error
        
        # Should contain generic message
        assert "access denied" in sanitized_error.lower() or "unauthorized" in sanitized_error.lower()
    
    @security_test
    def test_no_sensitive_data_in_logs(self, sample_lambda_event, mock_context):
        """Test that sensitive data is not logged"""
        from src.handlers.scanner_handler import lambda_handler
        
        with patch('builtins.print') as mock_print:
            try:
                lambda_handler(sample_lambda_event, mock_context)
            except Exception:
                pass
            
            # Check all print statements (logs) for sensitive data
            for call_args in mock_print.call_args_list:
                log_message = str(call_args)
                
                # Should not contain sensitive information
                assert sample_lambda_event["role_arn"] not in log_message
                assert "arn:aws:iam::" not in log_message
                
                # Email might be partially logged, but should be redacted
                if sample_lambda_event["email"] in log_message:
                    # Should be redacted like user@[DOMAIN]
                    assert "[DOMAIN]" in log_message or "*" in log_message