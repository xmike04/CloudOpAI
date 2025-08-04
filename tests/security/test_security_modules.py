"""Unit tests for individual security modules"""
import pytest
import json
import jwt
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, Mock, MagicMock

from tests.conftest import security_test


class TestSecurityLogger:
    """Unit tests for security logging module"""
    
    @security_test
    def test_security_logger_initialization(self):
        """Test security logger initializes correctly"""
        from src.core.utils.security_logger import SecurityLogger
        
        logger = SecurityLogger()
        assert logger.log_group_name == "/aws/lambda/cloudopai-security"
        assert logger.current_correlation_id is None
    
    @security_test
    def test_security_event_creation(self):
        """Test security event creation and formatting"""
        from src.core.utils.security_logger import SecurityEvent, SecurityEventType, SecurityLevel
        
        event = SecurityEvent(
            timestamp=datetime.now(timezone.utc).isoformat(),
            correlation_id="test-correlation-123",
            event_type=SecurityEventType.AUTHENTICATION_SUCCESS,
            severity=SecurityLevel.LOW,
            account_id_hash="hash123",
            source_ip="192.168.1.100",
            user_agent="Test-Agent/1.0",
            resource="test-resource",
            action="test-action",
            result="success",
            details={"test": "data"},
            request_id="req-123",
            session_id="sess-123"
        )
        
        log_data = event.to_cloudwatch_log()
        parsed_data = json.loads(log_data)
        
        assert parsed_data["event_type"] == "authentication_success"
        assert parsed_data["severity"] == "low"
        assert parsed_data["source_ip"] == "192.168.1.100"
        assert parsed_data["details"]["test"] == "data"
    
    @security_test
    def test_security_logger_sanitization(self):
        """Test that security logger sanitizes sensitive data"""
        from src.core.utils.security_logger import SecurityLogger
        
        logger = SecurityLogger()
        
        sensitive_details = {
            "password": "secret123",
            "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
            "email": "user@example.com",
            "safe_field": "safe_value"
        }
        
        sanitized = logger._sanitize_details(sensitive_details)
        
        assert sanitized["password"] == "[REDACTED]"
        assert sanitized["AccessKeyId"] == "[REDACTED]"
        assert "[USER]@example.com" in sanitized["email"]
        assert sanitized["safe_field"] == "safe_value"
    
    @security_test
    @patch('boto3.client')
    def test_security_logger_cloudwatch_integration(self, mock_boto):
        """Test CloudWatch integration"""
        from src.core.utils.security_logger import SecurityLogger, SecurityEventType, SecurityLevel
        
        mock_logs_client = Mock()
        mock_boto.return_value = mock_logs_client
        
        logger = SecurityLogger()
        
        logger.log_security_event(
            event_type=SecurityEventType.AUTHENTICATION_SUCCESS,
            severity=SecurityLevel.LOW,
            action="test-action",
            result="success"
        )
        
        # Should attempt to create log group
        mock_logs_client.create_log_group.assert_called()
        
        # Should send log events
        mock_logs_client.put_log_events.assert_called()
    
    @security_test
    def test_security_context_manager(self):
        """Test security context manager"""
        from src.core.utils.security_logger import SecurityLogger
        
        logger = SecurityLogger()
        
        with logger.security_context(account_id="123456789012", correlation_id="test-123") as correlation_id:
            assert logger.current_correlation_id == "test-123"
            assert logger.current_account_hash is not None
            assert correlation_id == "test-123"
        
        # Context should be cleaned up
        assert logger.current_correlation_id is None


class TestAuditLogger:
    """Unit tests for audit logging module"""
    
    @security_test
    def test_audit_event_creation(self):
        """Test audit event creation"""
        from src.core.utils.audit_logger import AuditEvent, AuditEventType
        
        event = AuditEvent(
            event_id="audit-123",
            timestamp=datetime.now(timezone.utc).isoformat(),
            event_type=AuditEventType.DATA_ACCESS,
            user_identity="user-123",
            account_id="123456789012",
            resource_type="scan",
            resource_id="scan-123",
            action="access_data",
            outcome="success",
            source_ip="192.168.1.100",
            user_agent="Test-Agent/1.0",
            api_version="1.0",
            request_parameters={"param": "value"},
            response_elements={"result": "success"},
            error_code=None,
            error_message=None,
            compliance_impact="audit_logged",
            data_classification="confidential",
            retention_period=2555
        )
        
        cloudtrail_event = event.to_cloudtrail_event()
        
        assert cloudtrail_event["eventName"] == "access_data"
        assert cloudtrail_event["eventSource"] == "cloudopai.amazonaws.com"
        assert cloudtrail_event["userIdentity"]["principalId"] == "user-123"
        assert cloudtrail_event["additionalEventData"]["complianceImpact"] == "audit_logged"
    
    @security_test
    def test_audit_logger_parameter_sanitization(self):
        """Test audit logger sanitizes sensitive parameters"""
        from src.core.utils.audit_logger import AuditEvent, AuditEventType
        
        event = AuditEvent(
            event_id="audit-123",
            timestamp=datetime.now(timezone.utc).isoformat(),
            event_type=AuditEventType.DATA_ACCESS,
            user_identity="user-123",
            account_id="123456789012",
            resource_type="scan",
            resource_id="scan-123",
            action="access_data",
            outcome="success",
            source_ip="192.168.1.100",
            user_agent="Test-Agent/1.0",
            api_version="1.0",
            request_parameters={
                "password": "secret123",
                "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
                "safe_param": "safe_value"
            },
            response_elements={},
            error_code=None,
            error_message=None,
            compliance_impact="audit_logged",
            data_classification="confidential",
            retention_period=2555
        )
        
        cloudtrail_event = event.to_cloudtrail_event()
        
        assert cloudtrail_event["requestParameters"]["password"] == "[REDACTED]"
        assert cloudtrail_event["requestParameters"]["AccessKeyId"] == "[REDACTED]"
        assert cloudtrail_event["requestParameters"]["safe_param"] == "safe_value"
    
    @security_test
    @patch('boto3.client')
    def test_audit_logger_cloudwatch_integration(self, mock_boto):
        """Test audit logger CloudWatch integration"""
        from src.core.utils.audit_logger import AuditLogger, AuditEventType
        
        mock_logs_client = Mock()
        mock_boto.return_value = mock_logs_client
        
        logger = AuditLogger()
        
        event_id = logger.log_audit_event(
            event_type=AuditEventType.DATA_ACCESS,
            action="test_access",
            outcome="success",
            user_identity="test-user",
            account_id="123456789012"
        )
        
        assert event_id is not None
        mock_logs_client.put_log_events.assert_called()


class TestRateLimiter:
    """Unit tests for rate limiter module"""
    
    @security_test
    def test_rate_limit_key_generation(self):
        """Test rate limit key generation"""
        from src.core.utils.rate_limiter import RateLimiter, RateLimitType
        
        limiter = RateLimiter()
        
        key1 = limiter._generate_key("user1", RateLimitType.REQUESTS_PER_MINUTE, "account1")
        key2 = limiter._generate_key("user2", RateLimitType.REQUESTS_PER_MINUTE, "account2")
        key3 = limiter._generate_key("user1", RateLimitType.REQUESTS_PER_MINUTE, "account1")
        
        # Different users should have different keys
        assert key1 != key2
        
        # Same user should have same key (deterministic)
        assert key1 == key3
        
        # Keys should be reasonably short for DynamoDB
        assert len(key1) <= 32
    
    @security_test
    def test_window_key_generation(self):
        """Test time window key generation"""
        from src.core.utils.rate_limiter import RateLimiter
        
        limiter = RateLimiter()
        
        # Test that window keys are consistent within the same time window
        window_key1 = limiter._get_window_key(60)  # 1 minute window
        window_key2 = limiter._get_window_key(60)
        
        assert window_key1 == window_key2
    
    @security_test
    def test_rate_limit_configuration(self):
        """Test rate limit configuration"""
        from src.core.utils.rate_limiter import RateLimiter, RateLimitType
        
        limiter = RateLimiter()
        
        # Test default limits exist
        assert RateLimitType.REQUESTS_PER_MINUTE in limiter.default_limits
        assert RateLimitType.SCANS_PER_HOUR in limiter.default_limits
        
        # Test limit properties
        minute_limit = limiter.default_limits[RateLimitType.REQUESTS_PER_MINUTE]
        assert minute_limit.max_requests > 0
        assert minute_limit.window_seconds == 60
    
    @security_test
    @patch('boto3.resource')
    def test_rate_limit_check_logic(self, mock_dynamodb):
        """Test rate limit checking logic"""
        from src.core.utils.rate_limiter import RateLimiter, RateLimitType
        
        # Mock DynamoDB table
        mock_table = Mock()
        mock_dynamodb.return_value.Table.return_value = mock_table
        
        # Mock no existing rate limit record
        mock_table.get_item.return_value = {}
        
        limiter = RateLimiter()
        
        result = limiter.check_rate_limit("test-user", RateLimitType.REQUESTS_PER_MINUTE)
        
        # First request should be allowed
        assert result.allowed == True
        assert result.remaining > 0
        
        # Should update the counter
        mock_table.update_item.assert_called()
    
    @security_test
    def test_rate_limit_decorator(self):
        """Test rate limiting decorator"""
        from src.core.utils.rate_limiter import rate_limit, RateLimitType
        
        @rate_limit(limit_type=RateLimitType.REQUESTS_PER_MINUTE)
        def test_function(event, context):
            return {"statusCode": 200, "body": "success"}
        
        # Mock event with request context
        mock_event = {
            "requestContext": {
                "identity": {
                    "sourceIp": "192.168.1.100"
                }
            }
        }
        
        mock_context = Mock()
        
        with patch.object(RateLimiter, 'check_rate_limit') as mock_check:
            from src.core.utils.rate_limiter import RateLimitResult
            
            # Mock allowing the request
            mock_check.return_value = RateLimitResult(
                allowed=True,
                remaining=59,
                reset_time=datetime.now(timezone.utc) + timedelta(minutes=1)
            )
            
            result = test_function(mock_event, mock_context)
            
            assert result["statusCode"] == 200
            mock_check.assert_called()


class TestAuthenticationHandler:
    """Unit tests for authentication handler"""
    
    @security_test
    def test_jwt_token_validation(self):
        """Test JWT token validation"""
        from src.handlers.auth_handler import APIGatewayAuthenticator
        
        authenticator = APIGatewayAuthenticator()
        
        # Generate test JWT
        test_token = jwt.encode(
            {
                "customer_id": "test-customer",
                "account_id": "123456789012",
                "permissions": ["scan:read"],
                "iat": int(datetime.now(timezone.utc).timestamp()),
                "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()),
                "iss": "cloudopai.com",
                "aud": "api.cloudopai.com"
            },
            "test-jwt-secret-key-for-testing-only",
            algorithm="HS256"
        )
        
        with patch.object(authenticator, '_get_jwt_secret') as mock_secret:
            mock_secret.return_value = "test-jwt-secret-key-for-testing-only"
            
            with patch.object(authenticator, '_get_customer_info') as mock_customer:
                mock_customer.return_value = {"status": "active"}
                
                result = authenticator._authenticate_jwt(
                    test_token, "192.168.1.100", "Test-Agent/1.0"
                )
                
                assert result.authenticated == True
                assert result.customer_id == "test-customer"
                assert result.account_id == "123456789012"
    
    @security_test
    def test_expired_jwt_rejection(self):
        """Test that expired JWT tokens are rejected"""
        from src.handlers.auth_handler import APIGatewayAuthenticator
        
        authenticator = APIGatewayAuthenticator()
        
        # Generate expired JWT
        expired_token = jwt.encode(
            {
                "customer_id": "test-customer",
                "account_id": "123456789012",
                "permissions": ["scan:read"],
                "iat": int((datetime.now(timezone.utc) - timedelta(hours=2)).timestamp()),
                "exp": int((datetime.now(timezone.utc) - timedelta(hours=1)).timestamp()),
                "iss": "cloudopai.com",
                "aud": "api.cloudopai.com"
            },
            "test-jwt-secret-key-for-testing-only",
            algorithm="HS256"
        )
        
        with patch.object(authenticator, '_get_jwt_secret') as mock_secret:
            mock_secret.return_value = "test-jwt-secret-key-for-testing-only"
            
            result = authenticator._authenticate_jwt(
                expired_token, "192.168.1.100", "Test-Agent/1.0"
            )
            
            assert result.authenticated == False
            assert "expired" in result.error_message.lower()
    
    @security_test
    def test_api_key_authentication(self):
        """Test API key authentication"""
        from src.handlers.auth_handler import APIGatewayAuthenticator
        import hashlib
        
        authenticator = APIGatewayAuthenticator()
        
        test_api_key = "test-api-key-64-characters-long-for-security-testing-purposes"
        api_key_hash = hashlib.sha256(test_api_key.encode()).hexdigest()
        
        # Mock DynamoDB table
        mock_table = Mock()
        authenticator.api_keys_table = mock_table
        
        # Mock valid API key record
        mock_table.get_item.return_value = {
            'Item': {
                'api_key_hash': api_key_hash,
                'customer_id': 'test-customer',
                'account_id': '123456789012',
                'permissions': ['scan:read', 'scan:write'],
                'status': 'active'
            }
        }
        
        result = authenticator._authenticate_api_key(
            test_api_key, "192.168.1.100", "Test-Agent/1.0"
        )
        
        assert result.authenticated == True
        assert result.customer_id == 'test-customer'
        assert 'scan:read' in result.permissions
    
    @security_test
    def test_policy_generation(self):
        """Test IAM policy generation"""
        from src.handlers.auth_handler import APIGatewayAuthenticator
        
        authenticator = APIGatewayAuthenticator()
        
        # Test allow policy
        allow_policy = authenticator._generate_allow_policy(
            "test-customer", 
            {"customer_id": "test-customer", "account_id": "123456789012"}
        )
        
        assert allow_policy["principalId"] == "test-customer"
        assert allow_policy["policyDocument"]["Statement"][0]["Effect"] == "Allow"
        
        # Test deny policy
        deny_policy = authenticator._generate_deny_policy("Invalid credentials")
        
        assert deny_policy["principalId"] == "unauthorized"
        assert deny_policy["policyDocument"]["Statement"][0]["Effect"] == "Deny"


class TestDataIsolation:
    """Unit tests for data isolation module"""
    
    @security_test
    def test_tenant_config_creation(self):
        """Test tenant configuration creation"""
        from src.core.utils.data_isolation import TenantConfig, IsolationLevel, DataClassification
        
        config = TenantConfig(
            customer_id="test-customer",
            account_id="123456789012",
            isolation_level=IsolationLevel.ENHANCED,
            encryption_key_id="key-123",
            data_classification=DataClassification.CONFIDENTIAL,
            retention_days=2555,
            geographic_restrictions=["US", "EU"],
            compliance_requirements=["SOC2", "GDPR"]
        )
        
        assert config.customer_id == "test-customer"
        assert config.isolation_level == IsolationLevel.ENHANCED
        assert config.data_classification == DataClassification.CONFIDENTIAL
        assert "GDPR" in config.compliance_requirements
    
    @security_test
    def test_isolation_key_generation(self):
        """Test isolation key generation"""
        from src.core.utils.data_isolation import CustomerDataIsolation
        
        isolation = CustomerDataIsolation()
        
        # Test DynamoDB key generation
        db_key1 = isolation.get_isolated_dynamodb_key("customer1", "123456789012")
        db_key2 = isolation.get_isolated_dynamodb_key("customer2", "987654321098")
        db_key3 = isolation.get_isolated_dynamodb_key("customer1", "123456789012")
        
        # Different customers should have different keys
        assert db_key1 != db_key2
        
        # Same customer should have same key (deterministic)
        assert db_key1 == db_key3
        
        # Keys should be reasonably short
        assert len(db_key1) == 16
    
    @security_test
    def test_s3_key_isolation(self):
        """Test S3 key isolation"""
        from src.core.utils.data_isolation import CustomerDataIsolation
        
        isolation = CustomerDataIsolation()
        
        s3_key1 = isolation.get_isolated_s3_key("customer1", "reports", "scan-123", "html")
        s3_key2 = isolation.get_isolated_s3_key("customer2", "reports", "scan-123", "html")
        
        # Keys should be different for different customers
        assert s3_key1 != s3_key2
        
        # Keys should contain customer identifier
        assert "customer1" in s3_key1
        assert "customer2" in s3_key2
        
        # Keys should not allow path traversal
        assert "../" not in s3_key1
        assert "../" not in s3_key2
    
    @security_test
    @patch('boto3.client')
    def test_kms_key_creation(self, mock_boto):
        """Test customer-specific KMS key creation"""
        from src.core.utils.data_isolation import CustomerDataIsolation
        
        mock_kms = Mock()
        mock_boto.return_value = mock_kms
        
        mock_kms.create_key.return_value = {
            'KeyMetadata': {'KeyId': 'test-key-123'}
        }
        
        isolation = CustomerDataIsolation()
        
        key_id = isolation._create_customer_kms_key("test-customer", "123456789012")
        
        assert key_id == 'test-key-123'
        mock_kms.create_key.assert_called()
        mock_kms.create_alias.assert_called()


class TestGDPRCompliance:
    """Unit tests for GDPR compliance module"""
    
    @security_test
    def test_gdpr_request_creation(self):
        """Test GDPR request creation"""
        from src.core.compliance.gdpr_compliance import GDPRRequest, GDPRRights, DataCategory
        
        request = GDPRRequest(
            request_id="gdpr-123",
            customer_id="test-customer",
            right_type=GDPRRights.RIGHT_TO_ACCESS,
            request_date=datetime.now(timezone.utc),
            status="submitted",
            completion_date=None,
            verification_method="email_verification",
            data_subject_email="user@example.com",
            requested_data_categories=[DataCategory.CONTACT_INFO, DataCategory.SCAN_RESULTS],
            processing_notes="Request submitted"
        )
        
        assert request.customer_id == "test-customer"
        assert request.right_type == GDPRRights.RIGHT_TO_ACCESS
        assert len(request.requested_data_categories) == 2
    
    @security_test
    def test_data_mapping_configuration(self):
        """Test GDPR data mapping configuration"""
        from src.core.compliance.gdpr_compliance import GDPRComplianceManager
        
        manager = GDPRComplianceManager()
        
        # Test that all required data categories are mapped
        from src.core.compliance.gdpr_compliance import DataCategory
        
        for category in DataCategory:
            assert category in manager.data_mappings
            
            mapping = manager.data_mappings[category]
            assert mapping.retention_period > 0
            assert mapping.purpose is not None
            assert mapping.lawful_basis is not None
    
    @security_test
    @patch('boto3.resource')
    def test_consent_recording(self, mock_dynamodb):
        """Test consent recording"""
        from src.core.compliance.gdpr_compliance import GDPRComplianceManager, DataCategory
        
        mock_table = Mock()
        mock_dynamodb.return_value.Table.return_value = mock_table
        
        manager = GDPRComplianceManager()
        
        consent_id = manager.record_consent(
            customer_id="test-customer",
            data_subject_email="user@example.com",
            purpose="Service delivery",
            data_categories=[DataCategory.CONTACT_INFO, DataCategory.USAGE_DATA]
        )
        
        assert consent_id is not None
        assert consent_id.startswith("consent-")
        mock_table.put_item.assert_called()
    
    @security_test
    def test_privacy_notice_generation(self):
        """Test privacy notice generation"""
        from src.core.compliance.gdpr_compliance import GDPRComplianceManager
        
        manager = GDPRComplianceManager()
        
        privacy_notice = manager.get_privacy_notice()
        
        assert "data_controller" in privacy_notice
        assert "data_processing" in privacy_notice
        assert "individual_rights" in privacy_notice
        
        # Should include all required GDPR rights
        rights = privacy_notice["individual_rights"]
        required_rights = [
            "Right to access",
            "Right to rectify",
            "Right to erase",
            "Right to restrict",
            "Right to data portability",
            "Right to object"
        ]
        
        for required_right in required_rights:
            assert any(required_right.lower() in right.lower() for right in rights)


class TestSOC2Compliance:
    """Unit tests for SOC2 compliance module"""
    
    @security_test
    def test_soc2_control_creation(self):
        """Test SOC2 control creation"""
        from src.core.compliance.soc2_compliance import SOC2Control, ControlCategory, SOC2TrustPrinciple, ControlStatus
        
        control = SOC2Control(
            control_id="CC6.1",
            category=ControlCategory.CC6_LOGICAL_ACCESS,
            principle=SOC2TrustPrinciple.SECURITY,
            description="Logical access controls are implemented",
            implementation_status=ControlStatus.IMPLEMENTED,
            evidence_location="IAM policies",
            responsible_party="Security Team",
            testing_frequency="Quarterly",
            last_tested=None,
            test_results="",
            remediation_notes=None
        )
        
        assert control.control_id == "CC6.1"
        assert control.principle == SOC2TrustPrinciple.SECURITY
        assert control.implementation_status == ControlStatus.IMPLEMENTED
    
    @security_test
    def test_standard_controls_initialization(self):
        """Test standard SOC2 controls initialization"""
        from src.core.compliance.soc2_compliance import SOC2ComplianceManager
        
        manager = SOC2ComplianceManager()
        
        # Should have standard controls
        assert len(manager.standard_controls) > 0
        
        # Should have controls for all major categories
        control_categories = set(control.category for control in manager.standard_controls)
        
        from src.core.compliance.soc2_compliance import ControlCategory
        required_categories = [
            ControlCategory.CC1_CONTROL_ENVIRONMENT,
            ControlCategory.CC6_LOGICAL_ACCESS,
            ControlCategory.CC7_SYSTEM_OPERATIONS
        ]
        
        for category in required_categories:
            assert category in control_categories
    
    @security_test
    @patch('boto3.resource')
    def test_evidence_collection(self, mock_dynamodb):
        """Test SOC2 evidence collection"""
        from src.core.compliance.soc2_compliance import SOC2ComplianceManager
        
        mock_table = Mock()
        mock_dynamodb.return_value.Table.return_value = mock_table
        
        manager = SOC2ComplianceManager()
        
        with patch.object(manager.s3_client, 'put_object') as mock_s3:
            evidence_id = manager.collect_control_evidence(
                control_id="CC6.1",
                evidence_type="policy_document",
                description="IAM access control policies",
                file_content="Policy content here"
            )
            
            assert evidence_id is not None
            assert evidence_id.startswith("evidence-")
            mock_table.put_item.assert_called()
            mock_s3.assert_called()
    
    @security_test
    @patch('boto3.client')
    def test_automated_evidence_collection(self, mock_boto):
        """Test automated evidence collection"""
        from src.core.compliance.soc2_compliance import SOC2ComplianceManager
        
        # Mock AWS clients
        mock_iam = Mock()
        mock_cloudwatch = Mock()
        mock_kms = Mock()
        
        def mock_client(service, **kwargs):
            if service == 'iam':
                return mock_iam
            elif service == 'cloudwatch':
                return mock_cloudwatch
            elif service == 'kms':
                return mock_kms
            return Mock()
        
        mock_boto.side_effect = mock_client
        
        # Mock IAM responses
        mock_iam.list_roles.return_value = {
            'Roles': [{
                'RoleName': 'CloudOpAI-Lambda-Role',
                'CreateDate': datetime.now(timezone.utc)
            }]
        }
        mock_iam.list_attached_role_policies.return_value = {'AttachedPolicies': []}
        mock_iam.list_role_policies.return_value = {'PolicyNames': []}
        
        # Mock CloudWatch responses
        mock_cloudwatch.describe_alarms.return_value = {'MetricAlarms': []}
        
        manager = SOC2ComplianceManager()
        
        with patch.object(manager, 'collect_control_evidence') as mock_collect:
            evidence_collected = manager.generate_automated_evidence()
            
            # Should collect evidence for multiple controls
            assert len(evidence_collected) > 0
            mock_collect.assert_called()


class TestSecurityValidators:
    """Additional unit tests for security validators"""
    
    @security_test
    def test_error_message_sanitization(self):
        """Test error message sanitization"""
        from src.core.utils.security_validators import SecurityValidator
        
        sensitive_error = "Access denied for arn:aws:iam::123456789012:user/sensitive-user with key AKIAIOSFODNN7EXAMPLE"
        
        sanitized = SecurityValidator.sanitize_error_message(sensitive_error)
        
        # Should not contain sensitive information
        assert "AKIAIOSFODNN7EXAMPLE" not in sanitized
        assert "123456789012" not in sanitized
        assert "sensitive-user" not in sanitized
        
        # Should contain generic error description
        assert "access denied" in sanitized.lower() or "unauthorized" in sanitized.lower()
    
    @security_test
    def test_input_length_validation(self):
        """Test input length validation"""
        from src.core.utils.security_validators import SecurityValidator
        
        # Test normal length inputs
        assert SecurityValidator.is_safe_string("normal input") == True
        
        # Test very long inputs
        very_long_input = "A" * 10000
        assert SecurityValidator.is_safe_string(very_long_input) == False
        
        # Test reasonable length limits
        reasonable_input = "A" * 1000
        assert SecurityValidator.is_safe_string(reasonable_input) == True
    
    @security_test
    def test_json_validation(self):
        """Test JSON input validation"""
        from src.core.utils.security_validators import SecurityValidator
        
        # Valid JSON
        valid_json = '{"account_id": "123456789012", "email": "user@example.com"}'
        parsed = SecurityValidator.validate_json_input(valid_json)
        assert parsed["account_id"] == "123456789012"
        
        # Invalid JSON
        invalid_json = '{"account_id": "123456789012", "email": '
        with pytest.raises(ValueError):
            SecurityValidator.validate_json_input(invalid_json)
        
        # JSON with malicious content
        malicious_json = '{"account_id": "<script>alert(1)</script>"}'
        with pytest.raises(ValueError):
            SecurityValidator.validate_json_input(malicious_json)