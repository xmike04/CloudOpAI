"""API Gateway authentication and authorization handler"""
import json
import jwt
import boto3
import hashlib
import base64
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional, Tuple
from dataclasses import dataclass

from src.config.secure_settings import get_secret
from src.core.utils.security_logger import security_logger, SecurityEventType, SecurityLevel
from src.core.utils.audit_logger import audit_logger, AuditEventType
from src.core.utils.rate_limiter import rate_limiter, RateLimitType
from src.core.utils.security_validators import SecurityValidator

@dataclass
class AuthenticationResult:
    """Result of authentication check"""
    authenticated: bool
    authorized: bool
    customer_id: Optional[str] = None
    account_id: Optional[str] = None
    permissions: Optional[list] = None
    error_message: Optional[str] = None
    rate_limit_exceeded: bool = False

class APIGatewayAuthenticator:
    """Handle API Gateway authentication and authorization"""
    
    def __init__(self):
        self.dynamodb = boto3.resource('dynamodb')
        self.api_keys_table = self.dynamodb.Table('CloudOpAI-APIKeys')
        self.customers_table = self.dynamodb.Table('CloudOpAI-Customers')
        
        # JWT configuration
        self.jwt_secret = None
        self.jwt_algorithm = 'HS256'
        self.jwt_expiration_hours = 24
        
    def _get_jwt_secret(self) -> str:
        """Get JWT secret from Secrets Manager"""
        if not self.jwt_secret:
            try:
                secret = get_secret('cloudopai/jwt-config')
                self.jwt_secret = secret.get('jwt_secret')
                if not self.jwt_secret:
                    # Generate a new secret if none exists
                    import secrets
                    self.jwt_secret = secrets.token_urlsafe(64)
                    print("Warning: Generated new JWT secret - this should be stored in Secrets Manager")
            except Exception as e:
                print(f"Failed to get JWT secret: {e}")
                # Fallback - this should be replaced with proper secret management
                self.jwt_secret = "fallback-secret-replace-in-production"
        
        return self.jwt_secret
    
    def lambda_handler(self, event: Dict[str, Any], context: Any) -> Dict[str, Any]:
        """Lambda authorizer handler for API Gateway"""
        try:
            # Extract authentication information
            auth_token = self._extract_auth_token(event)
            api_key = self._extract_api_key(event)
            source_ip = self._get_source_ip(event)
            user_agent = self._get_user_agent(event)
            
            # Log authentication attempt
            request_id = context.aws_request_id if context else 'unknown'
            
            with security_logger.security_context():
                # Perform authentication
                auth_result = self._authenticate_request(auth_token, api_key, source_ip, user_agent)
                
                if not auth_result.authenticated:
                    # Log failed authentication
                    security_logger.log_authentication_failure(
                        account_id=auth_result.account_id or 'unknown',
                        error=auth_result.error_message,
                        source_ip=source_ip,
                        user_agent=user_agent,
                        request_id=request_id
                    )
                    
                    audit_logger.log_audit_event(
                        event_type=AuditEventType.AUTHENTICATION,
                        action="api_authentication",
                        outcome="failure",
                        source_ip=source_ip,
                        user_agent=user_agent,
                        error_message=auth_result.error_message,
                        request_parameters={"method": event.get('httpMethod'), "path": event.get('path')}
                    )
                    
                    return self._generate_deny_policy(auth_result.error_message)
                
                # Log successful authentication
                security_logger.log_authentication_success(
                    account_id=auth_result.account_id,
                    source_ip=source_ip,
                    user_agent=user_agent,
                    customer_id=auth_result.customer_id,
                    request_id=request_id
                )
                
                audit_logger.log_audit_event(
                    event_type=AuditEventType.AUTHENTICATION,
                    action="api_authentication",
                    outcome="success",
                    user_identity=auth_result.customer_id,
                    account_id=auth_result.account_id,
                    source_ip=source_ip,
                    user_agent=user_agent,
                    request_parameters={"method": event.get('httpMethod'), "path": event.get('path')}
                )
                
                # Generate allow policy
                return self._generate_allow_policy(
                    principal_id=auth_result.customer_id,
                    context={
                        'customer_id': auth_result.customer_id,
                        'account_id': auth_result.account_id,
                        'permissions': ','.join(auth_result.permissions or []),
                        'source_ip': source_ip
                    }
                )
                
        except Exception as e:
            print(f"Authentication handler error: {e}")
            security_logger.log_security_event(
                event_type=SecurityEventType.AUTHENTICATION_FAILURE,
                severity=SecurityLevel.HIGH,
                action="api_authentication",
                result="error",
                details={"error": str(e), "event": event}
            )
            
            return self._generate_deny_policy("Authentication service error")
    
    def _extract_auth_token(self, event: Dict[str, Any]) -> Optional[str]:
        """Extract Bearer token from Authorization header"""
        headers = event.get('headers', {})
        auth_header = headers.get('Authorization') or headers.get('authorization')
        
        if auth_header and auth_header.startswith('Bearer '):
            return auth_header[7:]  # Remove 'Bearer ' prefix
        
        return None
    
    def _extract_api_key(self, event: Dict[str, Any]) -> Optional[str]:
        """Extract API key from headers"""
        headers = event.get('headers', {})
        return headers.get('X-API-Key') or headers.get('x-api-key')
    
    def _get_source_ip(self, event: Dict[str, Any]) -> str:
        """Get source IP from request context"""
        request_context = event.get('requestContext', {})
        identity = request_context.get('identity', {})
        return identity.get('sourceIp', 'unknown')
    
    def _get_user_agent(self, event: Dict[str, Any]) -> str:
        """Get user agent from headers"""
        headers = event.get('headers', {})
        return headers.get('User-Agent') or headers.get('user-agent', 'unknown')
    
    def _authenticate_request(
        self, 
        auth_token: Optional[str], 
        api_key: Optional[str], 
        source_ip: str, 
        user_agent: str
    ) -> AuthenticationResult:
        """Authenticate the request using token or API key"""
        
        # Check rate limits first
        identifier = source_ip
        rate_result = rate_limiter.check_rate_limit(identifier, RateLimitType.REQUESTS_PER_MINUTE)
        
        if not rate_result.allowed:
            return AuthenticationResult(
                authenticated=False,
                authorized=False,
                error_message="Rate limit exceeded",
                rate_limit_exceeded=True
            )
        
        # Try JWT token authentication first
        if auth_token:
            jwt_result = self._authenticate_jwt(auth_token, source_ip, user_agent)
            if jwt_result.authenticated:
                return jwt_result
        
        # Try API key authentication
        if api_key:
            api_key_result = self._authenticate_api_key(api_key, source_ip, user_agent)
            if api_key_result.authenticated:
                return api_key_result
        
        # Track failed authentication attempt
        rate_limiter.increment_failed_attempts(identifier)
        
        return AuthenticationResult(
            authenticated=False,
            authorized=False,
            error_message="Invalid or missing authentication credentials"
        )
    
    def _authenticate_jwt(self, token: str, source_ip: str, user_agent: str) -> AuthenticationResult:
        """Authenticate using JWT token"""
        try:
            # Validate token format
            if not SecurityValidator.is_safe_string(token) or len(token) > 2048:
                return AuthenticationResult(
                    authenticated=False,
                    authorized=False,
                    error_message="Invalid token format"
                )
            
            # Decode and verify JWT
            jwt_secret = self._get_jwt_secret()
            payload = jwt.decode(token, jwt_secret, algorithms=[self.jwt_algorithm])
            
            # Validate token claims
            now = datetime.now(timezone.utc)
            exp = datetime.fromtimestamp(payload.get('exp', 0), timezone.utc)
            
            if now > exp:
                return AuthenticationResult(
                    authenticated=False,
                    authorized=False,
                    error_message="Token expired"
                )
            
            customer_id = payload.get('customer_id')
            account_id = payload.get('account_id')
            permissions = payload.get('permissions', [])
            
            if not customer_id or not account_id:
                return AuthenticationResult(
                    authenticated=False,
                    authorized=False,
                    error_message="Invalid token payload"
                )
            
            # Verify customer exists and is active
            customer_info = self._get_customer_info(customer_id)
            if not customer_info or customer_info.get('status') != 'active':
                return AuthenticationResult(
                    authenticated=False,
                    authorized=False,
                    error_message="Customer account inactive"
                )
            
            return AuthenticationResult(
                authenticated=True,
                authorized=True,
                customer_id=customer_id,
                account_id=account_id,
                permissions=permissions
            )
            
        except jwt.ExpiredSignatureError:
            return AuthenticationResult(
                authenticated=False,
                authorized=False,
                error_message="Token expired"
            )
        except jwt.InvalidTokenError as e:
            return AuthenticationResult(
                authenticated=False,
                authorized=False,
                error_message=f"Invalid token: {str(e)}"
            )
        except Exception as e:
            print(f"JWT authentication error: {e}")
            return AuthenticationResult(
                authenticated=False,
                authorized=False,
                error_message="Authentication service error"
            )
    
    def _authenticate_api_key(self, api_key: str, source_ip: str, user_agent: str) -> AuthenticationResult:
        """Authenticate using API key"""
        try:
            # Validate API key format
            if not SecurityValidator.is_safe_string(api_key) or len(api_key) != 64:
                return AuthenticationResult(
                    authenticated=False,
                    authorized=False,
                    error_message="Invalid API key format"
                )
            
            # Hash the API key for lookup
            api_key_hash = hashlib.sha256(api_key.encode()).hexdigest()
            
            # Look up API key in DynamoDB
            response = self.api_keys_table.get_item(
                Key={'api_key_hash': api_key_hash}
            )
            
            if 'Item' not in response:
                return AuthenticationResult(
                    authenticated=False,
                    authorized=False,
                    error_message="Invalid API key"
                )
            
            key_info = response['Item']
            
            # Check if key is active
            if key_info.get('status') != 'active':
                return AuthenticationResult(
                    authenticated=False,
                    authorized=False,
                    error_message="API key inactive"
                )
            
            # Check expiration
            if 'expires_at' in key_info:
                expires_at = datetime.fromisoformat(key_info['expires_at'].replace('Z', '+00:00'))
                if datetime.now(timezone.utc) > expires_at:
                    return AuthenticationResult(
                        authenticated=False,
                        authorized=False,
                        error_message="API key expired"
                    )
            
            # Check IP restrictions
            if 'allowed_ips' in key_info and key_info['allowed_ips']:
                if source_ip not in key_info['allowed_ips']:
                    return AuthenticationResult(
                        authenticated=False,
                        authorized=False,
                        error_message="IP address not authorized"
                    )
            
            customer_id = key_info.get('customer_id')
            account_id = key_info.get('account_id')
            permissions = key_info.get('permissions', [])
            
            # Update last used timestamp
            self.api_keys_table.update_item(
                Key={'api_key_hash': api_key_hash},
                UpdateExpression='SET last_used_at = :timestamp, last_used_ip = :ip',
                ExpressionAttributeValues={
                    ':timestamp': datetime.now(timezone.utc).isoformat(),
                    ':ip': source_ip
                }
            )
            
            return AuthenticationResult(
                authenticated=True,
                authorized=True,
                customer_id=customer_id,
                account_id=account_id,
                permissions=permissions
            )
            
        except Exception as e:
            print(f"API key authentication error: {e}")
            return AuthenticationResult(
                authenticated=False,
                authorized=False,
                error_message="Authentication service error"
            )
    
    def _get_customer_info(self, customer_id: str) -> Optional[Dict[str, Any]]:
        """Get customer information from DynamoDB"""
        try:
            response = self.customers_table.get_item(
                Key={'customer_id': customer_id}
            )
            return response.get('Item')
        except Exception as e:
            print(f"Error getting customer info: {e}")
            return None
    
    def _generate_allow_policy(self, principal_id: str, context: Dict[str, str]) -> Dict[str, Any]:
        """Generate IAM policy to allow access"""
        return {
            "principalId": principal_id,
            "policyDocument": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Action": "execute-api:Invoke",
                        "Effect": "Allow",
                        "Resource": "*"
                    }
                ]
            },
            "context": context
        }
    
    def _generate_deny_policy(self, reason: str) -> Dict[str, Any]:
        """Generate IAM policy to deny access"""
        return {
            "principalId": "unauthorized",
            "policyDocument": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Action": "execute-api:Invoke",
                        "Effect": "Deny",
                        "Resource": "*"
                    }
                ]
            },
            "context": {
                "error": reason
            }
        }
    
    def generate_jwt_token(self, customer_id: str, account_id: str, permissions: list = None) -> str:
        """Generate JWT token for authenticated user"""
        now = datetime.now(timezone.utc)
        payload = {
            'customer_id': customer_id,
            'account_id': account_id,
            'permissions': permissions or ['scan:read', 'scan:write', 'report:read'],
            'iat': int(now.timestamp()),
            'exp': int((now + timedelta(hours=self.jwt_expiration_hours)).timestamp()),
            'iss': 'cloudopai.com',
            'aud': 'api.cloudopai.com'
        }
        
        jwt_secret = self._get_jwt_secret()
        return jwt.encode(payload, jwt_secret, algorithm=self.jwt_algorithm)
    
    def create_api_key(self, customer_id: str, account_id: str, permissions: list = None, expires_days: int = 365) -> str:
        """Create new API key for customer"""
        import secrets
        
        # Generate secure API key
        api_key = secrets.token_urlsafe(48)  # 64 character base64url string
        api_key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        
        # Store in DynamoDB
        expires_at = datetime.now(timezone.utc) + timedelta(days=expires_days)
        
        self.api_keys_table.put_item(
            Item={
                'api_key_hash': api_key_hash,
                'customer_id': customer_id,
                'account_id': account_id,
                'permissions': permissions or ['scan:read', 'scan:write', 'report:read'],
                'status': 'active',
                'created_at': datetime.now(timezone.utc).isoformat(),
                'expires_at': expires_at.isoformat(),
                'allowed_ips': [],  # Empty means all IPs allowed
                'usage_count': 0
            }
        )
        
        # Log API key creation
        audit_logger.log_configuration_change(
            resource_type="api_key",
            resource_id=api_key_hash[:16],
            action="create_api_key",
            changes={
                "customer_id": customer_id,
                "account_id": account_id,
                "permissions": permissions
            },
            user_identity=customer_id
        )
        
        return api_key

# Lambda handler for API Gateway authorizer
def lambda_handler(event, context):
    """Entry point for API Gateway custom authorizer"""
    authenticator = APIGatewayAuthenticator()
    return authenticator.lambda_handler(event, context)