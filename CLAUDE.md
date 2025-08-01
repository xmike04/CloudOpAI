# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

CloudOpAI is an AWS Lambda-based GPU cost optimization service that analyzes customer AWS accounts to identify idle and underutilized GPU instances.

## Architecture

The codebase follows a modular structure:

```
src/
├── core/                         # Core business logic
│   ├── analyzers/               # Analysis engines (gpu_analyzer.py)
│   ├── models/                  # Data models (scan_result.py)
│   └── utils/                   # Shared utilities
├── services/                    # External service integrations  
│   ├── aws/                     # AWS service clients (sts_service.py)
│   ├── email/                   # Email service providers
│   └── storage/                 # Storage backends (report_service.py)
├── handlers/                    # Lambda handlers (scanner_handler.py)
└── config/                      # Configuration (settings.py)

infrastructure/
├── cloudformation/              # CloudFormation templates
└── scripts/                     # Deployment scripts
```

## Development Commands

### Deployment
```bash
cd infrastructure/scripts/
./deploy.sh
```

### Local Testing
```bash
pip install -r requirements.txt
python -c "from src.core.analyzers.gpu_analyzer import GPUAnalyzer; # test code"
```

## Key Components

- **Scanner Handler** (`src/handlers/scanner_handler.py`): Main Lambda entry point
- **GPU Analyzer** (`src/core/analyzers/gpu_analyzer.py`): Core analysis engine for GPU instances
- **Report Service** (`src/services/storage/report_service.py`): HTML report generation and S3 storage
- **Settings** (`src/config/settings.py`): Centralized configuration

## Technical Details

- **Dependencies**: `boto3==1.26.137`
- **AWS Services**: Lambda, EC2, CloudWatch, S3, DynamoDB, SES, STS
- **Handler**: `src.handlers.scanner_handler.lambda_handler`
- **Runtime**: Python 3.9

## Environment Variables
- `SCAN_RESULTS_TABLE`: DynamoDB table for scan results
- `REPORTS_BUCKET`: S3 bucket for generated reports
- `AWS_REGION`: AWS region (default: us-east-1)