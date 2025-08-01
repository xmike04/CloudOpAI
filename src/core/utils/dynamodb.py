"""DynamoDB utilities"""
import boto3
from datetime import datetime

from src.config.settings import SCAN_RESULTS_TABLE, AWS_REGION
from src.core.models.scan_result import ScanResult


def save_scan_results(scan_result: ScanResult) -> None:
    """Save scan results to DynamoDB"""
    dynamodb = boto3.resource('dynamodb', region_name=AWS_REGION)
    table = dynamodb.Table(SCAN_RESULTS_TABLE)
    
    # Convert opportunities to dict format
    opportunities_data = [
        {
            'instance_id': opp.instance_id,
            'instance_type': opp.instance_type,
            'issue': opp.issue.value,
            'current_cost': str(opp.current_cost),
            'potential_savings': str(opp.potential_savings),
            'recommendation': opp.recommendation,
            'utilization': str(opp.utilization)
        }
        for opp in scan_result.opportunities
    ]
    
    table.put_item(
        Item={
            'account_id': scan_result.account_id,
            'scan_timestamp': scan_result.scan_timestamp.isoformat(),
            'scan_id': scan_result.scan_id,
            'total_monthly_gpu_spend': str(scan_result.total_monthly_gpu_spend),
            'total_monthly_waste': str(scan_result.total_monthly_waste),
            'waste_percentage': str(scan_result.waste_percentage),
            'idle_gpu_count': scan_result.idle_gpu_count,
            'underutilized_count': scan_result.underutilized_count,
            'opportunities': opportunities_data,
            'ttl': int((datetime.utcnow().timestamp())) + (90 * 24 * 60 * 60)  # 90 days TTL
        }
    )