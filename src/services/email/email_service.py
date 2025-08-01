"""Email notification service"""
import boto3
from typing import Dict, Any

from src.config.settings import EMAIL_SOURCE, AWS_REGION, CALENDLY_LINK
from src.core.models.scan_result import ScanResult


class EmailService:
    """Handle email notifications via AWS SES"""
    
    def __init__(self):
        self.ses_client = boto3.client('ses', region_name=AWS_REGION)
        
    def send_scan_results(self, email: str, scan_result: ScanResult, report_url: str) -> None:
        """
        Send scan results email to customer
        
        Args:
            email: Recipient email address
            scan_result: Complete scan results
            report_url: URL to access detailed report
        """
        subject = f"CloudOpAI Found ${scan_result.total_monthly_waste:,.0f} in GPU Savings!"
        
        body_text = f"""
Hi there,

Great news! CloudOpAI just analyzed your AWS GPU infrastructure and found significant cost-saving opportunities.

KEY FINDINGS:
- Total Monthly GPU Spend: ${scan_result.total_monthly_gpu_spend:,.2f}
- Identified Monthly Waste: ${scan_result.total_monthly_waste:,.2f}
- Waste Percentage: {scan_result.waste_percentage:.1f}%
- Potential Annual Savings: ${scan_result.annual_savings:,.2f}

BREAKDOWN:
- Idle GPUs Found: {scan_result.idle_gpu_count}
- Underutilized GPUs: {scan_result.underutilized_count}
- Total Optimization Opportunities: {len(scan_result.opportunities)}

View your detailed report with specific recommendations:
{report_url}

Ready to implement these savings automatically?
Schedule a quick demo: {CALENDLY_LINK}

Best regards,
The CloudOpAI Team

P.S. These savings are available immediately. Every day you wait costs you ${scan_result.total_monthly_waste/30:.2f}!
"""
        
        body_html = f"""
<html>
<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
    <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
        <h2 style="color: #667eea;">Great News! We Found ${scan_result.total_monthly_waste:,.0f} in Monthly GPU Savings</h2>
        
        <p>CloudOpAI just analyzed your AWS GPU infrastructure and found significant cost-saving opportunities.</p>
        
        <div style="background: #f8fafc; padding: 20px; border-radius: 8px; margin: 20px 0;">
            <h3 style="margin-top: 0; color: #334155;">Key Findings:</h3>
            <ul style="list-style: none; padding: 0;">
                <li>💰 <strong>Total Monthly GPU Spend:</strong> ${scan_result.total_monthly_gpu_spend:,.2f}</li>
                <li>🚨 <strong>Identified Monthly Waste:</strong> <span style="color: #ef4444;">${scan_result.total_monthly_waste:,.2f}</span></li>
                <li>📊 <strong>Waste Percentage:</strong> {scan_result.waste_percentage:.1f}%</li>
                <li>🎯 <strong>Potential Annual Savings:</strong> <span style="color: #22c55e;">${scan_result.annual_savings:,.2f}</span></li>
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
            <a href="{report_url}" style="display: inline-block; background: #667eea; color: white; padding: 12px 30px; text-decoration: none; border-radius: 6px; font-weight: bold;">View Detailed Report</a>
        </div>
        
        <p><strong>Ready to implement these savings automatically?</strong></p>
        <p><a href="{CALENDLY_LINK}">Schedule a quick 15-minute demo</a> and we'll show you how CloudOpAI can start saving you money immediately.</p>
        
        <p style="color: #666; font-style: italic;">P.S. Every day you wait costs you ${scan_result.total_monthly_waste/30:.2f}!</p>
    </div>
</body>
</html>
"""
        
        try:
            self.ses_client.send_email(
                Source=EMAIL_SOURCE,
                Destination={'ToAddresses': [email]},
                Message={
                    'Subject': {'Data': subject},
                    'Body': {
                        'Text': {'Data': body_text},
                        'Html': {'Data': body_html}
                    }
                }
            )
        except Exception as e:
            print(f"Failed to send email to {email}: {str(e)}")
            # Don't fail the entire scan if email fails