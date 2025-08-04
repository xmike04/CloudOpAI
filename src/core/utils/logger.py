"""Secure logging utility that prevents sensitive data exposure"""
import logging
import re
from typing import Any, Dict, Optional

# Patterns to redact sensitive information
SENSITIVE_PATTERNS = [
    (r'AccessKeyId["\s]*[:=]["\s]*([A-Z0-9]{20})', r'AccessKeyId": "[REDACTED]'),
    (r'SecretAccessKey["\s]*[:=]["\s]*([A-Za-z0-9/+=]{40})', r'SecretAccessKey": "[REDACTED]'),
    (r'SessionToken["\s]*[:=]["\s]*([A-Za-z0-9/+=]{100,})', r'SessionToken": "[REDACTED]'),
    (r'arn:aws:iam::\d+:role/[^"]*', r'arn:aws:iam::[ACCOUNT]:role/[ROLE]'),
    (r'i-[0-9a-f]{17}', r'i-[INSTANCE-ID]'),
    (r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', r'[EMAIL-REDACTED]'),
]

class SecureLogger:
    """Logger that automatically redacts sensitive information"""
    
    def __init__(self, name: str):
        self.logger = logging.getLogger(name)
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
            self.logger.setLevel(logging.INFO)
    
    def _sanitize_message(self, message: str) -> str:
        """Remove sensitive information from log messages"""
        sanitized = str(message)
        for pattern, replacement in SENSITIVE_PATTERNS:
            sanitized = re.sub(pattern, replacement, sanitized, flags=re.IGNORECASE)
        return sanitized
    
    def info(self, message: str, extra: Optional[Dict[str, Any]] = None) -> None:
        """Log info message with sensitive data redacted"""
        sanitized = self._sanitize_message(message)
        self.logger.info(sanitized, extra=extra)
    
    def error(self, message: str, extra: Optional[Dict[str, Any]] = None) -> None:
        """Log error message with sensitive data redacted"""
        sanitized = self._sanitize_message(message)
        self.logger.error(sanitized, extra=extra)
    
    def warning(self, message: str, extra: Optional[Dict[str, Any]] = None) -> None:
        """Log warning message with sensitive data redacted"""
        sanitized = self._sanitize_message(message)
        self.logger.warning(sanitized, extra=extra)
    
    def debug(self, message: str, extra: Optional[Dict[str, Any]] = None) -> None:
        """Log debug message with sensitive data redacted"""
        sanitized = self._sanitize_message(message)
        self.logger.debug(sanitized, extra=extra)

def get_logger(name: str) -> SecureLogger:
    """Get a secure logger instance"""
    return SecureLogger(name)