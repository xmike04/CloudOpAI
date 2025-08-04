"""Rate limiting system for CloudOpAI API protection"""
import boto3
import json
import time
import hashlib
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional, Tuple, List
from enum import Enum
from dataclasses import dataclass
from functools import wraps

class RateLimitType(Enum):
    """Types of rate limits"""
    REQUESTS_PER_MINUTE = "requests_per_minute"
    REQUESTS_PER_HOUR = "requests_per_hour"
    REQUESTS_PER_DAY = "requests_per_day"
    SCANS_PER_HOUR = "scans_per_hour"
    SCANS_PER_DAY = "scans_per_day"
    REPORTS_PER_HOUR = "reports_per_hour"
    FAILED_ATTEMPTS = "failed_attempts"

@dataclass
class RateLimit:
    """Rate limit configuration"""
    limit_type: RateLimitType
    max_requests: int
    window_seconds: int
    burst_allowance: int = 0
    block_duration_seconds: int = 300  # 5 minutes default

@dataclass
class RateLimitResult:
    """Result of rate limit check"""
    allowed: bool
    remaining: int
    reset_time: datetime
    retry_after: Optional[int] = None
    limit_type: Optional[RateLimitType] = None
    error_message: Optional[str] = None

class RateLimiter:
    """Redis-backed rate limiting with DynamoDB fallback"""
    
    def __init__(self, table_name: str = "CloudOpAI-RateLimits"):
        self.table_name = table_name
        self.dynamodb = boto3.resource('dynamodb')
        self.table = None
        self._ensure_table_exists()
        
        # Default rate limits
        self.default_limits = {
            RateLimitType.REQUESTS_PER_MINUTE: RateLimit(
                RateLimitType.REQUESTS_PER_MINUTE, 60, 60, 10, 300
            ),
            RateLimitType.REQUESTS_PER_HOUR: RateLimit(
                RateLimitType.REQUESTS_PER_HOUR, 1000, 3600, 50, 900
            ),
            RateLimitType.REQUESTS_PER_DAY: RateLimit(
                RateLimitType.REQUESTS_PER_DAY, 10000, 86400, 100, 3600
            ),
            RateLimitType.SCANS_PER_HOUR: RateLimit(
                RateLimitType.SCANS_PER_HOUR, 10, 3600, 2, 1800
            ),
            RateLimitType.SCANS_PER_DAY: RateLimit(
                RateLimitType.SCANS_PER_DAY, 50, 86400, 5, 3600
            ),
            RateLimitType.REPORTS_PER_HOUR: RateLimit(
                RateLimitType.REPORTS_PER_HOUR, 20, 3600, 5, 900
            ),
            RateLimitType.FAILED_ATTEMPTS: RateLimit(
                RateLimitType.FAILED_ATTEMPTS, 5, 300, 0, 1800
            )
        }
    
    def _ensure_table_exists(self):
        """Ensure DynamoDB table exists for rate limiting"""
        try:
            self.table = self.dynamodb.Table(self.table_name)
            self.table.load()
        except self.dynamodb.meta.client.exceptions.ResourceNotFoundException:
            try:
                self.table = self.dynamodb.create_table(
                    TableName=self.table_name,
                    KeySchema=[
                        {'AttributeName': 'key', 'KeyType': 'HASH'},
                        {'AttributeName': 'window', 'KeyType': 'RANGE'}
                    ],
                    AttributeDefinitions=[
                        {'AttributeName': 'key', 'AttributeType': 'S'},
                        {'AttributeName': 'window', 'AttributeType': 'S'}
                    ],
                    BillingMode='PAY_PER_REQUEST',
                    TimeToLiveSpecification={
                        'AttributeName': 'ttl',
                        'Enabled': True
                    },
                    Tags=[
                        {'Key': 'Application', 'Value': 'CloudOpAI'},
                        {'Key': 'Purpose', 'Value': 'RateLimiting'}
                    ]
                )
                
                # Wait for table to be created
                self.table.wait_until_exists()
                print(f"Created rate limiting table: {self.table_name}")
            except Exception as e:
                print(f"Failed to create rate limiting table: {e}")
                self.table = None
    
    def _generate_key(self, identifier: str, limit_type: RateLimitType, account_id: str = None) -> str:
        """Generate consistent key for rate limiting"""
        key_parts = [limit_type.value, identifier]
        if account_id:
            key_parts.append(account_id)
        
        key_string = ":".join(key_parts)
        return hashlib.sha256(key_string.encode()).hexdigest()[:32]
    
    def _get_window_key(self, window_seconds: int) -> str:
        """Get time window key"""
        now = int(time.time())
        window_start = (now // window_seconds) * window_seconds
        return str(window_start)
    
    def check_rate_limit(
        self,
        identifier: str,
        limit_type: RateLimitType,
        account_id: str = None,
        custom_limit: RateLimit = None
    ) -> RateLimitResult:
        """Check if request is within rate limits"""
        if not self.table:
            # Fallback: allow if table unavailable but log warning
            print("Warning: Rate limiting table unavailable, allowing request")
            return RateLimitResult(
                allowed=True,
                remaining=999,
                reset_time=datetime.now(timezone.utc) + timedelta(minutes=1)
            )
        
        rate_limit = custom_limit or self.default_limits.get(limit_type)
        if not rate_limit:
            return RateLimitResult(
                allowed=False,
                remaining=0,
                reset_time=datetime.now(timezone.utc),
                error_message="Invalid rate limit type"
            )
        
        key = self._generate_key(identifier, limit_type, account_id)
        window_key = self._get_window_key(rate_limit.window_seconds)
        now = int(time.time())
        
        try:
            # Try to get current count
            response = self.table.get_item(
                Key={'key': key, 'window': window_key}
            )
            
            current_count = 0
            if 'Item' in response:
                current_count = response['Item'].get('count', 0)
            
            # Check if blocked
            if current_count >= rate_limit.max_requests:
                # Check if we're still in the same window
                window_start = int(window_key)
                reset_time = datetime.fromtimestamp(
                    window_start + rate_limit.window_seconds, 
                    timezone.utc
                )
                
                if now < window_start + rate_limit.window_seconds:
                    return RateLimitResult(
                        allowed=False,
                        remaining=0,
                        reset_time=reset_time,
                        retry_after=window_start + rate_limit.window_seconds - now,
                        limit_type=limit_type,
                        error_message=f"Rate limit exceeded: {rate_limit.max_requests} {limit_type.value}"
                    )
            
            # Allow request and increment counter
            try:
                self.table.update_item(
                    Key={'key': key, 'window': window_key},
                    UpdateExpression='ADD #count :inc SET #ttl = :ttl',
                    ExpressionAttributeNames={
                        '#count': 'count',
                        '#ttl': 'ttl'
                    },
                    ExpressionAttributeValues={
                        ':inc': 1,
                        ':ttl': now + rate_limit.window_seconds + 300  # TTL with buffer
                    }
                )
                
                new_count = current_count + 1
                remaining = max(0, rate_limit.max_requests - new_count)
                window_start = int(window_key)
                reset_time = datetime.fromtimestamp(
                    window_start + rate_limit.window_seconds,
                    timezone.utc
                )
                
                return RateLimitResult(
                    allowed=True,
                    remaining=remaining,
                    reset_time=reset_time,
                    limit_type=limit_type
                )
                
            except Exception as e:
                print(f"Failed to update rate limit counter: {e}")
                # On error, allow but with warning
                return RateLimitResult(
                    allowed=True,
                    remaining=rate_limit.max_requests - current_count - 1,
                    reset_time=datetime.now(timezone.utc) + timedelta(seconds=rate_limit.window_seconds)
                )
                
        except Exception as e:
            print(f"Failed to check rate limit: {e}")
            # On error, allow but log
            return RateLimitResult(
                allowed=True,
                remaining=999,
                reset_time=datetime.now(timezone.utc) + timedelta(seconds=rate_limit.window_seconds)
            )
    
    def increment_failed_attempts(self, identifier: str, account_id: str = None) -> RateLimitResult:
        """Track failed authentication/authorization attempts"""
        return self.check_rate_limit(identifier, RateLimitType.FAILED_ATTEMPTS, account_id)
    
    def is_blocked(self, identifier: str, limit_type: RateLimitType, account_id: str = None) -> bool:
        """Check if identifier is currently blocked"""
        result = self.check_rate_limit(identifier, limit_type, account_id)
        return not result.allowed
    
    def reset_limits(self, identifier: str, limit_type: RateLimitType = None, account_id: str = None) -> bool:
        """Reset rate limits for an identifier (admin function)"""
        if not self.table:
            return False
        
        try:
            if limit_type:
                # Reset specific limit type
                key = self._generate_key(identifier, limit_type, account_id)
                
                # Delete all windows for this key
                response = self.table.query(
                    KeyConditionExpression=boto3.dynamodb.conditions.Key('key').eq(key)
                )
                
                with self.table.batch_writer() as batch:
                    for item in response['Items']:
                        batch.delete_item(Key={'key': key, 'window': item['window']})
            else:
                # Reset all limits for identifier
                for lt in RateLimitType:
                    key = self._generate_key(identifier, lt, account_id)
                    response = self.table.query(
                        KeyConditionExpression=boto3.dynamodb.conditions.Key('key').eq(key)
                    )
                    
                    with self.table.batch_writer() as batch:
                        for item in response['Items']:
                            batch.delete_item(Key={'key': key, 'window': item['window']})
            
            return True
            
        except Exception as e:
            print(f"Failed to reset rate limits: {e}")
            return False
    
    def get_rate_limit_status(self, identifier: str, account_id: str = None) -> Dict[str, RateLimitResult]:
        """Get current rate limit status for all limit types"""
        status = {}
        for limit_type in RateLimitType:
            # Just check without incrementing
            key = self._generate_key(identifier, limit_type, account_id)
            rate_limit = self.default_limits.get(limit_type)
            if not rate_limit:
                continue
                
            window_key = self._get_window_key(rate_limit.window_seconds)
            
            try:
                response = self.table.get_item(
                    Key={'key': key, 'window': window_key}
                )
                
                current_count = 0
                if 'Item' in response:
                    current_count = response['Item'].get('count', 0)
                
                window_start = int(window_key)
                reset_time = datetime.fromtimestamp(
                    window_start + rate_limit.window_seconds,
                    timezone.utc
                )
                
                status[limit_type.value] = RateLimitResult(
                    allowed=current_count < rate_limit.max_requests,
                    remaining=max(0, rate_limit.max_requests - current_count),
                    reset_time=reset_time,
                    limit_type=limit_type
                )
                
            except Exception as e:
                print(f"Failed to get status for {limit_type.value}: {e}")
                status[limit_type.value] = RateLimitResult(
                    allowed=True,
                    remaining=rate_limit.max_requests,
                    reset_time=datetime.now(timezone.utc) + timedelta(seconds=rate_limit.window_seconds)
                )
        
        return status

# Decorator for rate limiting
def rate_limit(
    identifier_func=None,
    limit_type: RateLimitType = RateLimitType.REQUESTS_PER_MINUTE,
    account_id_func=None,
    custom_limit: RateLimit = None
):
    """Decorator to apply rate limiting to functions"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Get identifier
            if identifier_func:
                identifier = identifier_func(*args, **kwargs)
            else:
                # Default: use source IP from Lambda event
                if args and isinstance(args[0], dict) and 'requestContext' in args[0]:
                    identifier = args[0]['requestContext'].get('identity', {}).get('sourceIp', 'unknown')
                else:
                    identifier = 'default'
            
            # Get account ID
            account_id = None
            if account_id_func:
                account_id = account_id_func(*args, **kwargs)
            elif args and isinstance(args[0], dict) and 'account_id' in args[0]:
                account_id = args[0]['account_id']
            
            # Check rate limit
            limiter = RateLimiter()
            result = limiter.check_rate_limit(identifier, limit_type, account_id, custom_limit)
            
            if not result.allowed:
                # Log rate limit exceeded
                from src.core.utils.security_logger import security_logger, SecurityEventType, SecurityLevel
                security_logger.log_rate_limit_exceeded(
                    account_id=account_id or 'unknown',
                    limit_type=limit_type.value,
                    source_ip=identifier if '.' in identifier else None,
                    retry_after=result.retry_after
                )
                
                # Return rate limit error
                return {
                    'statusCode': 429,
                    'headers': {
                        'X-RateLimit-Limit': str(limiter.default_limits[limit_type].max_requests),
                        'X-RateLimit-Remaining': str(result.remaining),
                        'X-RateLimit-Reset': str(int(result.reset_time.timestamp())),
                        'Retry-After': str(result.retry_after) if result.retry_after else '300'
                    },
                    'body': json.dumps({
                        'error': 'Rate limit exceeded',
                        'message': result.error_message,
                        'retry_after': result.retry_after
                    })
                }
            
            # Add rate limit headers to response
            response = func(*args, **kwargs)
            
            if isinstance(response, dict) and 'headers' in response:
                response['headers'].update({
                    'X-RateLimit-Limit': str(limiter.default_limits[limit_type].max_requests),
                    'X-RateLimit-Remaining': str(result.remaining),
                    'X-RateLimit-Reset': str(int(result.reset_time.timestamp()))
                })
            
            return response
        
        return wrapper
    return decorator

# Global rate limiter instance
rate_limiter = RateLimiter()

# Convenience functions
def check_scan_rate_limit(account_id: str, source_ip: str = None) -> RateLimitResult:
    """Check scan rate limits"""
    identifier = source_ip or account_id
    return rate_limiter.check_rate_limit(identifier, RateLimitType.SCANS_PER_HOUR, account_id)

def check_report_rate_limit(account_id: str, source_ip: str = None) -> RateLimitResult:
    """Check report generation rate limits"""
    identifier = source_ip or account_id
    return rate_limiter.check_rate_limit(identifier, RateLimitType.REPORTS_PER_HOUR, account_id)

def track_failed_attempt(identifier: str, account_id: str = None) -> RateLimitResult:
    """Track failed authentication attempt"""
    return rate_limiter.increment_failed_attempts(identifier, account_id)