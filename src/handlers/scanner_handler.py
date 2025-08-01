import json
import boto3
import os
from datetime import datetime
from src.core.analyzers.gpu_analyzer import GPUAnalyzer
from src.services.storage.report_service import ReportGenerator

def lambda_handler(event, context):
    """
    Main entry point for CloudOpAI GPU scanner
    """
    try:
        # Extract customer account info from event
        customer_account_id = event.get('account_id')
        customer_role_arn = event.get('role_arn')
        email = event.get('email')
        
        # Assume customer's role
        sts = boto3.client('sts')
        assumed_role = sts.assume_role(
            RoleArn=customer_role_arn,
            RoleSessionName='CloudOpAI-Scanner'
        )
        
        # Create credentials for customer account
        credentials = assumed_role['Credentials']
        
        # Initialize analyzer with customer credentials
        analyzer = GPUAnalyzer(
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken']
        )
        
        # Run the analysis
        scan_results = analyzer.scan_gpu_resources()
        
        # Generate report
        report_gen = ReportGenerator()
        report_url = report_gen.create_report(scan_results, customer_account_id)
        
        # Send email notification
        if email:
            send_notification_email(email, scan_results, report_url)
        
        # Store results in DynamoDB
        store_scan_results(customer_account_id, scan_results)
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'success': True,
                'total_monthly_waste': scan_results['total_monthly_waste'],
                'savings_opportunities': len(scan_results['opportunities']),
                'report_url': report_url
            })
        }
        
    except Exception as e:
        print(f"Error in scanner: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({
                'success': False,
                'error': str(e)
            })
        }

def send_notification_email(email, results, report_url):
    """Send results email to customer"""
    ses = boto3.client('ses', region_name='us-east-1')
    
    waste_amount = f"${results['total_monthly_waste']:,.2f}"
    
    body = f"""
    Great news! CloudOpAI found {waste_amount} in monthly GPU savings for you.
    
    Key findings:
    - Idle GPUs detected: {results['idle_gpu_count']}
    - Underutilized instances: {results['underutilized_count']}  
    - Immediate savings available: {waste_amount}/month
    
    View your detailed report: {report_url}
    
    Ready to implement these savings? Book a quick call: https://calendly.com/cloudopai/demo
    
    Best,
    The CloudOpAI Team
    """
    
    ses.send_email(
        Source='alerts@cloudopai.com',
        Destination={'ToAddresses': [email]},
        Message={
            'Subject': {'Data': f'CloudOpAI found {waste_amount} in GPU savings!'},
            'Body': {'Text': {'Data': body}}
        }
    )

def store_scan_results(account_id, results):
    """Store results in DynamoDB for future reference"""
    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table(os.environ['SCAN_RESULTS_TABLE'])
    
    table.put_item(
        Item={
            'account_id': account_id,
            'scan_timestamp': datetime.now().isoformat(),
            'total_monthly_waste': str(results['total_monthly_waste']),
            'opportunities': results['opportunities'],
            'scan_id': results['scan_id']
        }
    )