"""Email security and data sanitization utilities"""
import re
import html
from typing import Dict, Any, Optional
from src.core.utils.logger import get_logger

logger = get_logger(__name__)

class EmailSecurityManager:
    """Manages email security and data sanitization"""
    
    # Patterns for sensitive data that should be obfuscated
    SENSITIVE_PATTERNS = [
        (r'i-[0-9a-f]{17}', lambda m: f"i-{m.group(0)[2:8]}****"),  # Instance IDs
        (r'\d{12}', lambda m: f"{m.group(0)[:4]}****{m.group(0)[-2:]}"),  # Account IDs
        (r'arn:aws:[^:]*:[^:]*:\d+:', lambda m: "arn:aws:***:***:****:"),  # ARNs
    ]
    
    @staticmethod
    def sanitize_email_content(content: str) -> str:
        """Sanitize email content to remove/obfuscate sensitive data"""
        sanitized = content
        
        # Apply sensitive data obfuscation
        for pattern, replacement in EmailSecurityManager.SENSITIVE_PATTERNS:
            if callable(replacement):
                sanitized = re.sub(pattern, replacement, sanitized)
            else:
                sanitized = re.sub(pattern, replacement, sanitized)
        
        # HTML escape to prevent injection
        sanitized = html.escape(sanitized)
        
        return sanitized
    
    @staticmethod
    def validate_email_content(content: str) -> bool:
        """Validate email content for security issues"""
        # Check for potential injection attempts
        dangerous_patterns = [
            r'<script.*?>.*?</script>',  # Script tags
            r'javascript:',  # JavaScript URLs
            r'vbscript:',   # VBScript URLs
            r'data:text/html',  # Data URLs with HTML
            r'<iframe.*?>',  # Iframe tags
            r'<object.*?>',  # Object tags
            r'<embed.*?>',   # Embed tags
        ]
        
        for pattern in dangerous_patterns:
            if re.search(pattern, content, re.IGNORECASE | re.DOTALL):
                logger.warning(f"Potentially dangerous content detected in email")
                return False
        
        return True
    
    @staticmethod
    def create_secure_email_body(scan_result: Any, report_url: str, calendly_link: str) -> Dict[str, str]:
        """Create secure email body with sanitized data"""
        # Obfuscate account ID in display
        account_display = f"Account: ****{scan_result.account_id[-4:]}" if hasattr(scan_result, 'account_id') else "Your Account"
        
        # Sanitize financial data
        waste_amount = f"${scan_result.total_monthly_waste:,.0f}" if scan_result.total_monthly_waste > 0 else "$0"
        spend_amount = f"${scan_result.total_monthly_gpu_spend:,.0f}" if scan_result.total_monthly_gpu_spend > 0 else "$0"
        annual_savings = f"${scan_result.annual_savings:,.0f}" if scan_result.annual_savings > 0 else "$0"
        
        # Create sanitized text body
        text_body = f"""
Hi there,

Great news! CloudOpAI just analyzed your AWS GPU infrastructure and found significant cost-saving opportunities.

{account_display}

KEY FINDINGS:
- Total Monthly GPU Spend: {spend_amount}
- Identified Monthly Waste: {waste_amount}
- Waste Percentage: {scan_result.waste_percentage:.1f}%
- Potential Annual Savings: {annual_savings}

BREAKDOWN:
- Idle GPUs Found: {scan_result.idle_gpu_count}
- Underutilized GPUs: {scan_result.underutilized_count}
- Total Optimization Opportunities: {len(scan_result.opportunities)}

View your detailed report with specific recommendations:
{report_url}

Ready to implement these savings automatically?
Schedule a quick demo: {calendly_link}

Best regards,
The CloudOpAI Team

P.S. These savings are available immediately. Every day you wait costs you ${scan_result.total_monthly_waste/30:.2f}!

---
This email contains confidential business information. If you received this in error, please delete it immediately.
        """.strip()
        
        # Create sanitized HTML body
        html_body = f"""
<html>
<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto;">
    <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px;">
        <h2 style="margin: 0;">Great News! We Found {waste_amount} in Monthly GPU Savings</h2>
        <p style="margin: 10px 0 0 0; opacity: 0.9;">{account_display}</p>
    </div>
    
    <div style="background: #f8fafc; padding: 20px; border-radius: 8px; margin: 20px 0;">
        <h3 style="margin-top: 0; color: #334155;">Key Findings:</h3>
        <ul style="list-style: none; padding: 0;">
            <li>💰 <strong>Total Monthly GPU Spend:</strong> {spend_amount}</li>
            <li>🚨 <strong>Identified Monthly Waste:</strong> <span style="color: #ef4444;">{waste_amount}</span></li>
            <li>📊 <strong>Waste Percentage:</strong> {scan_result.waste_percentage:.1f}%</li>
            <li>🎯 <strong>Potential Annual Savings:</strong> <span style="color: #22c55e;">{annual_savings}</span></li>
        </ul>
    </div>
    
    <div style="background: #fef3c7; padding: 20px; border-radius: 8px; margin: 20px 0;">
        <h3 style="margin-top: 0; color: #92400e;">Optimization Opportunities:</h3>
        <ul>
            <li>Idle GPUs Found: {scan_result.idle_gpu_count}</li>
            <li>Underutilized GPUs: {scan_result.underutilized_count}</li>
            <li>Total Opportunities: {len(scan_result.opportunities)}</li>
        </ul>
    </div>
    
    <div style="text-align: center; margin: 30px 0;">
        <a href="{html.escape(report_url)}" style="display: inline-block; background: #667eea; color: white; padding: 12px 30px; text-decoration: none; border-radius: 6px; font-weight: bold;">View Detailed Report</a>
    </div>
    
    <p><strong>Ready to implement these savings automatically?</strong></p>
    <p><a href="{html.escape(calendly_link)}" style="color: #667eea;">Schedule a quick 15-minute demo</a> and we'll show you how CloudOpAI can start saving you money immediately.</p>
    
    <p style="color: #666; font-style: italic;">P.S. Every day you wait costs you ${scan_result.total_monthly_waste/30:.2f}!</p>
    
    <hr style="margin: 30px 0; border: none; border-top: 1px solid #e5e7eb;">
    <p style="font-size: 12px; color: #666;">
        This email contains confidential business information. If you received this in error, please delete it immediately.
        <br>CloudOpAI - AWS GPU Cost Optimization
    </p>
</body>
</html>
        """.strip()
        
        # Validate both bodies
        if not EmailSecurityManager.validate_email_content(text_body):
            logger.error("Text email body failed security validation")
            raise ValueError("Email content contains potentially dangerous elements")
        
        if not EmailSecurityManager.validate_email_content(html_body):
            logger.error("HTML email body failed security validation")
            raise ValueError("Email content contains potentially dangerous elements")
        
        return {
            'text': text_body,
            'html': html_body
        }
    
    @staticmethod
    def create_secure_subject(waste_amount: float) -> str:
        """Create secure email subject line"""
        # Sanitize the waste amount
        if waste_amount <= 0:
            return "CloudOpAI GPU Analysis Results"
        elif waste_amount > 100000:  # Don't show extremely large amounts
            return "CloudOpAI Found Significant GPU Savings Opportunity"
        else:
            return f"CloudOpAI Found ${waste_amount:,.0f} in GPU Savings!"