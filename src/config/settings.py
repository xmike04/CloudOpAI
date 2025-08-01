"""CloudOpAI configuration settings"""
import os
from typing import Dict

# AWS Configuration
AWS_REGION = os.environ.get('AWS_REGION', 'us-east-1')
SCAN_RESULTS_TABLE = os.environ.get('SCAN_RESULTS_TABLE', 'CloudOpAI-ScanResults')
REPORTS_BUCKET = os.environ.get('REPORTS_BUCKET', 'cloudopai-reports')

# Email Configuration
EMAIL_SOURCE = os.environ.get('EMAIL_SOURCE', 'alerts@cloudopai.com')
CALENDLY_LINK = os.environ.get('CALENDLY_LINK', 'https://calendly.com/cloudopai/demo')

# GPU Pricing (hourly rates in USD)
GPU_INSTANCE_COSTS: Dict[str, float] = {
    # P3 Instances
    'p3.2xlarge': 3.06,
    'p3.8xlarge': 12.24,
    'p3.16xlarge': 24.48,
    'p3dn.24xlarge': 31.212,
    
    # P4 Instances
    'p4d.24xlarge': 32.77,
    'p4de.24xlarge': 40.96,
    
    # P5 Instances (H100)
    'p5.48xlarge': 98.32,
    
    # G4 Instances (T4)
    'g4dn.xlarge': 0.526,
    'g4dn.2xlarge': 0.752,
    'g4dn.4xlarge': 1.204,
    'g4dn.8xlarge': 2.176,
    'g4dn.12xlarge': 3.912,
    'g4dn.16xlarge': 4.352,
    'g4ad.xlarge': 0.378,
    'g4ad.2xlarge': 0.54,
    'g4ad.4xlarge': 0.864,
    
    # G5 Instances (A10G)
    'g5.xlarge': 1.006,
    'g5.2xlarge': 1.212,
    'g5.4xlarge': 1.624,
    'g5.8xlarge': 2.448,
    'g5.12xlarge': 4.896,
    'g5.16xlarge': 4.096,
    'g5.24xlarge': 7.344,
    'g5.48xlarge': 14.688,
}

# Analysis Thresholds
IDLE_THRESHOLD = 5  # GPU utilization % below which instance is considered idle
UNDERUTILIZED_THRESHOLD = 30  # GPU utilization % below which instance is underutilized
ANALYSIS_PERIOD_HOURS = 24  # Hours of data to analyze