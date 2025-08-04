"""Email notification service with security enhancements"""
import boto3
from typing import Dict, Any

from src.config.settings import EMAIL_SOURCE, AWS_REGION, CALENDLY_LINK
from src.core.models.scan_result import ScanResult
from src.core.utils.logger import get_logger
from src.core.utils.email_security import EmailSecurityManager
from src.core.utils.aws_errors import AWSErrorHandler

logger = get_logger(__name__)


class EmailService:
    """Handle email notifications via AWS SES with security controls"""
    
    def __init__(self):
        self.ses_client = boto3.client('ses', region_name=AWS_REGION)
        
    def send_scan_results(self, email: str, scan_result: ScanResult, report_url: str) -> None:
        """
        Send scan results email to customer with security controls
        
        Args:
            email: Recipient email address
            scan_result: Complete scan results
            report_url: URL to access detailed report
        """
        try:
            # Create secure email content
            subject = EmailSecurityManager.create_secure_subject(scan_result.total_monthly_waste)
            email_bodies = EmailSecurityManager.create_secure_email_body(
                scan_result, report_url, CALENDLY_LINK
            )
            
            # Send email with both text and HTML versions
            self.ses_client.send_email(
                Source=EMAIL_SOURCE,
                Destination={'ToAddresses': [email]},
                Message={
                    'Subject': {'Data': subject},
                    'Body': {
                        'Text': {'Data': email_bodies['text']},
                        'Html': {'Data': email_bodies['html']}
                    }
                }
            )
            
            logger.info("Email notification sent successfully")
            
        except Exception as e:
            success = AWSErrorHandler.handle_ses_error(e, "Send scan results email")
            if not success:
                logger.error("Failed to send email notification: Email service unavailable")
                raise  # Re-raise to let caller handle