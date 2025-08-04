import json
import boto3
import os
from datetime import datetime
from src.core.analyzers.gpu_analyzer import GPUAnalyzer
from src.services.storage.report_service import ReportGenerator
from src.services.aws.sts_service import STSService
from src.services.email.email_service import EmailService
from src.core.utils.security_validators import SecurityValidator
from src.core.utils.validators import ValidationError
from src.core.utils.aws_errors import AWSErrorHandler
from src.core.utils.dynamodb_security import DynamoDBSecurityManager
from src.core.utils.email_security import EmailSecurityManager
from src.core.utils.logger import get_logger
from botocore.exceptions import ClientError

logger = get_logger(__name__)

def lambda_handler(event, context):
    """
    Main entry point for CloudOpAI GPU scanner
    """
    try:
        logger.info("Starting GPU cost analysis scan")
        
        # Validate and sanitize input
        try:
            validated_event = SecurityValidator.validate_lambda_event(event)
            customer_account_id = validated_event['account_id']
            customer_role_arn = validated_event['role_arn']
            email = validated_event['email']
        except ValidationError as e:
            logger.error(f"Input validation failed: {str(e)}")
            return {
                'statusCode': 400,
                'body': json.dumps({
                    'success': False,
                    'error': 'Invalid input parameters'
                })
            }
        
        # Assume customer's role with ExternalId
        try:
            sts_service = STSService()
            # Use a consistent ExternalId that matches customer CloudFormation
            external_id = "CloudOpAI-Scanner"
            
            credentials_dict = sts_service.assume_customer_role(
                role_arn=customer_role_arn,
                external_id=external_id,
                session_name=f'CloudOpAI-Scanner-{customer_account_id}'
            )
            
            logger.info(f"Successfully assumed role for account: {customer_account_id}")
            
        except Exception as e:
            logger.error(f"Failed to assume customer role: {str(e)}")
            return {
                'statusCode': 403,
                'body': json.dumps({
                    'success': False,
                    'error': 'Unable to access customer account. Please verify role configuration.'
                })
            }
        
        # Initialize analyzer with customer credentials
        try:
            analyzer = GPUAnalyzer(
                aws_access_key_id=credentials_dict['aws_access_key_id'],
                aws_secret_access_key=credentials_dict['aws_secret_access_key'],
                aws_session_token=credentials_dict['aws_session_token']
            )
        except Exception as e:
            error_message = AWSErrorHandler.handle_ec2_error(e, "GPU Analyzer initialization")
            return {
                'statusCode': 500,
                'body': json.dumps({
                    'success': False,
                    'error': 'Failed to initialize analysis service'
                })
            }
        
        # Run the analysis
        scan_results = analyzer.scan_gpu_resources()
        
        # Generate report
        report_gen = ReportGenerator()
        report_url = report_gen.create_report(scan_results, customer_account_id)
        
        # Send secure email notification
        if email:
            try:
                email_service = EmailService()
                # Convert dict to object for compatibility
                from types import SimpleNamespace
                scan_result_obj = SimpleNamespace(**scan_results)
                email_service.send_scan_results(email, scan_result_obj, report_url)
            except Exception as e:
                logger.error(f"Email notification failed: {str(e)}")
                # Don't fail the scan if email fails
        
        # Store results securely in DynamoDB
        try:
            db_security = DynamoDBSecurityManager(os.environ['SCAN_RESULTS_TABLE'])
            db_security.store_scan_results_securely(customer_account_id, scan_results)
        except Exception as e:
            logger.error(f"Failed to store scan results: {str(e)}")
            # Continue execution even if storage fails
        
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
        logger.error(f"Scanner error: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({
                'success': False,
                'error': str(e)
            })
        }

def send_notification_email(email, results, report_url):
    """Send results email to customer"""
    try:
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
        logger.info("Email notification sent successfully")
    except Exception as e:
        success = AWSErrorHandler.handle_ses_error(e, "Email notification")
        if not success:
            logger.warning("Email notification failed, continuing with scan")

def store_scan_results(account_id, results):
    """Store results in DynamoDB for future reference"""
    try:
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
        logger.info(f"Scan results stored for account: {account_id}")
    except Exception as e:
        success = AWSErrorHandler.handle_dynamodb_error(e, "Store scan results")
        if not success:
            logger.error("Failed to store scan results - data may be lost")