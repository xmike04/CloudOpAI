"""Report generation and storage service"""
import boto3
import json
from datetime import datetime
from typing import Dict, Any

from src.config.secure_settings import REPORTS_BUCKET, AWS_REGION, CALENDLY_LINK
from src.core.models.scan_result import ScanResult
from src.core.utils.security_validators import SecurityValidator
from src.core.utils.s3_security import S3SecurityManager


class ReportService:
    """Generate and store analysis reports"""
    
    def __init__(self):
        self.s3_client = boto3.client('s3', region_name=AWS_REGION)
        
    def generate_report(self, scan_result: ScanResult) -> str:
        """
        Generate HTML report and store in S3
        
        Args:
            scan_result: Complete scan results
            
        Returns:
            Presigned URL to access the report
        """
        # Generate HTML content
        html_content = self._create_html_report(scan_result)
        
        # Upload to S3 with secure key generation
        report_key = SecurityValidator.create_secure_s3_key(
            scan_result.account_id, 
            scan_result.scan_id, 
            'html'
        )
        
        self.s3_client.put_object(
            Bucket=REPORTS_BUCKET,
            Key=report_key,
            Body=html_content,
            ContentType='text/html',
            CacheControl='no-cache, no-store, must-revalidate',
            Metadata={
                'account_id': scan_result.account_id,
                'scan_timestamp': scan_result.scan_timestamp.isoformat(),
                'total_savings': str(scan_result.total_monthly_waste)
            }
        )
        
        # Generate secure presigned URL (1 hour validity)
        s3_security = S3SecurityManager(REPORTS_BUCKET)
        url = s3_security.generate_secure_presigned_url(report_key, expiration=3600)
        
        return url
    
    def _create_html_report(self, scan_result: ScanResult) -> str:
        """Create formatted HTML report"""
        html = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <meta http-equiv="X-Content-Type-Options" content="nosniff">
            <meta http-equiv="X-Frame-Options" content="DENY">
            <meta http-equiv="X-XSS-Protection" content="1; mode=block">
            <meta http-equiv="Referrer-Policy" content="strict-origin-when-cross-origin">
            <meta http-equiv="Content-Security-Policy" content="default-src 'self'; style-src 'unsafe-inline'; script-src 'none';">
            <title>CloudOpAI GPU Cost Analysis - {scan_result.account_id}</title>
            <style>
                * {{ margin: 0; padding: 0; box-sizing: border-box; }}
                body {{ 
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                    line-height: 1.6;
                    color: #333;
                    background: #f5f5f5;
                }}
                .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
                .header {{
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    padding: 40px;
                    border-radius: 12px;
                    margin-bottom: 30px;
                    box-shadow: 0 4px 6px rgba(0,0,0,0.1);
                }}
                .header h1 {{ font-size: 2.5em; margin-bottom: 10px; }}
                .header p {{ opacity: 0.9; }}
                .summary-grid {{
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                    gap: 20px;
                    margin-bottom: 30px;
                }}
                .metric-card {{
                    background: white;
                    padding: 25px;
                    border-radius: 12px;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                    text-align: center;
                }}
                .metric-card h3 {{ 
                    color: #666;
                    font-size: 0.9em;
                    text-transform: uppercase;
                    margin-bottom: 10px;
                }}
                .metric-value {{ 
                    font-size: 2.5em;
                    font-weight: bold;
                    color: #333;
                }}
                .savings {{ color: #22c55e; }}
                .waste {{ color: #ef4444; }}
                .data-table {{
                    background: white;
                    border-radius: 12px;
                    overflow: hidden;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                    margin-bottom: 30px;
                }}
                table {{ 
                    width: 100%;
                    border-collapse: collapse;
                }}
                th {{
                    background: #f8fafc;
                    padding: 15px;
                    text-align: left;
                    font-weight: 600;
                    color: #475569;
                    border-bottom: 2px solid #e5e7eb;
                }}
                td {{
                    padding: 15px;
                    border-bottom: 1px solid #f1f5f9;
                }}
                tr:hover {{ background: #fafbfc; }}
                .recommendation {{
                    background: #fef3c7;
                    border-left: 4px solid #f59e0b;
                    padding: 15px;
                    margin: 10px 0;
                    border-radius: 4px;
                }}
                .cta {{
                    background: white;
                    padding: 40px;
                    border-radius: 12px;
                    text-align: center;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                }}
                .cta-button {{
                    display: inline-block;
                    background: #667eea;
                    color: white;
                    padding: 15px 40px;
                    border-radius: 8px;
                    text-decoration: none;
                    font-weight: 600;
                    margin-top: 20px;
                    transition: transform 0.2s;
                }}
                .cta-button:hover {{ transform: translateY(-2px); }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>GPU Cost Analysis Report</h1>
                    <p>Generated on {scan_result.scan_timestamp.strftime('%B %d, %Y at %I:%M %p UTC')}</p>
                    <p>Account: {SecurityValidator.sanitize_html_content(f'****{scan_result.account_id[-4:]}')}</p>
                </div>
                
                <div class="summary-grid">
                    <div class="metric-card">
                        <h3>Monthly GPU Spend</h3>
                        <div class="metric-value">${scan_result.total_monthly_gpu_spend:,.0f}</div>
                    </div>
                    <div class="metric-card">
                        <h3>Identified Waste</h3>
                        <div class="metric-value waste">${scan_result.total_monthly_waste:,.0f}</div>
                    </div>
                    <div class="metric-card">
                        <h3>Potential Annual Savings</h3>
                        <div class="metric-value savings">${scan_result.annual_savings:,.0f}</div>
                    </div>
                    <div class="metric-card">
                        <h3>Waste Percentage</h3>
                        <div class="metric-value">{scan_result.waste_percentage:.1f}%</div>
                    </div>
                </div>
                
                <div class="data-table">
                    <table>
                        <thead>
                            <tr>
                                <th>Instance ID</th>
                                <th>Type</th>
                                <th>Issue</th>
                                <th>Utilization</th>
                                <th>Monthly Cost</th>
                                <th>Potential Savings</th>
                            </tr>
                        </thead>
                        <tbody>
        """
        
        # Add opportunities to table
        for opp in scan_result.opportunities:
            html += f"""
                            <tr>
                                <td><code>{SecurityValidator.sanitize_html_content(opp.instance_id[:8] + '****')}</code></td>
                                <td>{opp.instance_type}</td>
                                <td>{opp.issue.value.replace('_', ' ').title()}</td>
                                <td>{opp.utilization:.1f}%</td>
                                <td>${opp.current_cost:,.2f}</td>
                                <td class="savings">${opp.potential_savings:,.2f}</td>
                            </tr>
            """
        
        html += """
                        </tbody>
                    </table>
                </div>
                
                <h2 style="margin: 30px 0 20px;">Detailed Recommendations</h2>
        """
        
        # Add detailed recommendations
        for opp in scan_result.opportunities:
            html += f"""
                <div class="recommendation">
                    <strong>{SecurityValidator.sanitize_html_content(opp.instance_id[:8] + '****')} ({SecurityValidator.sanitize_html_content(opp.instance_type)})</strong><br>
                    {SecurityValidator.sanitize_html_content(opp.recommendation)}<br>
                    <em>Monthly Savings: ${opp.potential_savings:,.2f}</em>
                </div>
            """
        
        html += f"""
                <div class="cta">
                    <h2>Ready to Implement These Savings?</h2>
                    <p>CloudOpAI can automatically optimize your GPU infrastructure and start saving you money immediately.</p>
                    <p><strong>Total identified savings: ${scan_result.total_monthly_waste:,.2f}/month</strong></p>
                    <a href="{CALENDLY_LINK}" class="cta-button">Schedule Demo</a>
                </div>
            </div>
        </body>
        </html>
        """
        
        return html