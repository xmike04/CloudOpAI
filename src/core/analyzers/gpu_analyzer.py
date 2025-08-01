import boto3
from datetime import datetime, timedelta
from collections import defaultdict
import uuid

class GPUAnalyzer:
    """Core GPU cost analysis engine"""
    
    # GPU instance types and their hourly costs
    GPU_COSTS = {
        'p3.2xlarge': 3.06,
        'p3.8xlarge': 12.24,
        'p3.16xlarge': 24.48,
        'p3dn.24xlarge': 31.212,
        'p4d.24xlarge': 32.77,
        'p4de.24xlarge': 40.96,
        'p5.48xlarge': 98.32,
        'g4dn.xlarge': 0.526,
        'g4dn.2xlarge': 0.752,
        'g4dn.4xlarge': 1.204,
        'g4dn.8xlarge': 2.176,
        'g4dn.12xlarge': 3.912,
        'g4dn.16xlarge': 4.352,
        'g4ad.xlarge': 0.378,
        'g4ad.2xlarge': 0.54,
        'g4ad.4xlarge': 0.864,
        'g5.xlarge': 1.006,
        'g5.2xlarge': 1.212,
        'g5.4xlarge': 1.624,
        'g5.8xlarge': 2.448,
        'g5.12xlarge': 4.896,
        'g5.16xlarge': 4.096,
        'g5.24xlarge': 7.344,
        'g5.48xlarge': 14.688,
    }
    
    def __init__(self, aws_access_key_id, aws_secret_access_key, aws_session_token):
        self.ec2 = boto3.client(
            'ec2',
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            aws_session_token=aws_session_token
        )
        self.cloudwatch = boto3.client(
            'cloudwatch',
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            aws_session_token=aws_session_token
        )
        
    def scan_gpu_resources(self):
        """Main scanning function"""
        scan_id = str(uuid.uuid4())
        opportunities = []
        total_monthly_waste = 0
        idle_gpu_count = 0
        underutilized_count = 0
        
        # Get all GPU instances
        gpu_instances = self._get_gpu_instances()
        
        for instance in gpu_instances:
            instance_id = instance['InstanceId']
            instance_type = instance['InstanceType']
            
            # Get utilization metrics
            utilization = self._get_gpu_utilization(instance_id)
            
            # Analyze for waste
            if utilization['avg_gpu_util'] < 5:
                # Completely idle
                waste = self._calculate_waste(instance_type, 1.0)  # 100% waste
                opportunities.append({
                    'instance_id': instance_id,
                    'instance_type': instance_type,
                    'issue': 'IDLE_GPU',
                    'current_cost': self.GPU_COSTS.get(instance_type, 0) * 730,
                    'potential_savings': waste,
                    'recommendation': 'Terminate this idle GPU instance',
                    'utilization': utilization['avg_gpu_util']
                })
                idle_gpu_count += 1
                total_monthly_waste += waste
                
            elif utilization['avg_gpu_util'] < 30:
                # Underutilized
                waste = self._calculate_waste(instance_type, 0.5)  # 50% waste
                opportunities.append({
                    'instance_id': instance_id,
                    'instance_type': instance_type,
                    'issue': 'UNDERUTILIZED_GPU',
                    'current_cost': self.GPU_COSTS.get(instance_type, 0) * 730,
                    'potential_savings': waste,
                    'recommendation': f'Downsize to smaller GPU instance (currently at {utilization["avg_gpu_util"]:.1f}% utilization)',
                    'utilization': utilization['avg_gpu_util']
                })
                underutilized_count += 1
                total_monthly_waste += waste
        
        return {
            'scan_id': scan_id,
            'scan_timestamp': datetime.now().isoformat(),
            'total_instances_scanned': len(gpu_instances),
            'total_monthly_waste': total_monthly_waste,
            'idle_gpu_count': idle_gpu_count,
            'underutilized_count': underutilized_count,
            'opportunities': opportunities,
            'total_monthly_gpu_spend': sum(
                self.GPU_COSTS.get(i['InstanceType'], 0) * 730 
                for i in gpu_instances
            )
        }
    
    def _get_gpu_instances(self):
        """Get all running GPU instances"""
        gpu_instances = []
        
        # Paginate through all instances
        paginator = self.ec2.get_paginator('describe_instances')
        
        for page in paginator.paginate(
            Filters=[
                {'Name': 'instance-state-name', 'Values': ['running']},
            ]
        ):
            for reservation in page['Reservations']:
                for instance in reservation['Instances']:
                    instance_type = instance['InstanceType']
                    # Check if it's a GPU instance
                    if any(instance_type.startswith(prefix) for prefix in ['p3', 'p4', 'p5', 'g4', 'g5']):
                        gpu_instances.append(instance)
        
        return gpu_instances
    
    def _get_gpu_utilization(self, instance_id):
        """Get GPU utilization metrics from CloudWatch"""
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=24)
        
        try:
            # Try to get GPU utilization metric
            response = self.cloudwatch.get_metric_statistics(
                Namespace='CWAgent',
                MetricName='nvidia_smi_utilization_gpu',
                Dimensions=[
                    {'Name': 'InstanceId', 'Value': instance_id},
                ],
                StartTime=start_time,
                EndTime=end_time,
                Period=3600,  # 1 hour periods
                Statistics=['Average', 'Maximum']
            )
            
            if response['Datapoints']:
                avg_util = sum(d['Average'] for d in response['Datapoints']) / len(response['Datapoints'])
                max_util = max(d['Maximum'] for d in response['Datapoints'])
            else:
                # No GPU metrics available, check CPU as proxy
                response = self.cloudwatch.get_metric_statistics(
                    Namespace='AWS/EC2',
                    MetricName='CPUUtilization',
                    Dimensions=[
                        {'Name': 'InstanceId', 'Value': instance_id},
                    ],
                    StartTime=start_time,
                    EndTime=end_time,
                    Period=3600,
                    Statistics=['Average', 'Maximum']
                )
                
                if response['Datapoints']:
                    # Use CPU as rough proxy (typically GPU util is lower)
                    avg_util = sum(d['Average'] for d in response['Datapoints']) / len(response['Datapoints']) * 0.7
                    max_util = max(d['Maximum'] for d in response['Datapoints']) * 0.7
                else:
                    # No metrics available, assume low utilization
                    avg_util = 10
                    max_util = 20
                    
        except Exception as e:
            print(f"Error getting metrics for {instance_id}: {e}")
            # Conservative estimate if we can't get metrics
            avg_util = 25
            max_util = 50
            
        return {
            'avg_gpu_util': avg_util,
            'max_gpu_util': max_util,
            'measurement_period_hours': 24
        }
    
    def _calculate_waste(self, instance_type, waste_percentage):
        """Calculate monthly waste for an instance"""
        hourly_cost = self.GPU_COSTS.get(instance_type, 0)
        monthly_cost = hourly_cost * 730  # Average hours per month
        return monthly_cost * waste_percentage