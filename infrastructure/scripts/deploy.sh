#!/bin/bash

# CloudOpAI MVP Deployment Script
set -e

echo "CloudOpAI MVP Deployment Starting..."

# Configuration
AWS_REGION="us-east-1"
FUNCTION_NAME="CloudOpAI-Scanner"
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

# Create deployment package
echo "Creating deployment package..."
cd ../..
mkdir -p dist
pip install -r requirements.txt -t dist/
cp -r src/* dist/
cd dist
zip -r ../function.zip . -x "*.pyc" "__pycache__/*"
cd ..

# Create S3 bucket for reports
echo "Creating S3 bucket for reports..."
BUCKET_NAME="cloudopai-reports-${ACCOUNT_ID}"
aws s3 mb s3://${BUCKET_NAME} --region ${AWS_REGION} 2>/dev/null || echo "Bucket already exists"

# Create DynamoDB table
echo "Creating DynamoDB table..."
aws dynamodb create-table \
    --table-name CloudOpAI-ScanResults \
    --attribute-definitions \
        AttributeName=account_id,AttributeType=S \
        AttributeName=scan_timestamp,AttributeType=S \
    --key-schema \
        AttributeName=account_id,KeyType=HASH \
        AttributeName=scan_timestamp,KeyType=RANGE \
    --billing-mode PAY_PER_REQUEST \
    --region ${AWS_REGION} 2>/dev/null || echo "Table already exists"

# Create Lambda execution role
echo "Setting up IAM role..."
ROLE_NAME="CloudOpAI-Lambda-Role"
TRUST_POLICY='{
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "lambda.amazonaws.com"},
        "Action": "sts:AssumeRole"
    }]
}'

aws iam create-role \
    --role-name ${ROLE_NAME} \
    --assume-role-policy-document "${TRUST_POLICY}" \
    --region ${AWS_REGION} 2>/dev/null || echo "Role already exists"

# Attach policies
aws iam attach-role-policy \
    --role-name ${ROLE_NAME} \
    --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole

# Create custom policy for our services
POLICY_DOC='{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "sts:AssumeRole"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "dynamodb:PutItem",
                "dynamodb:GetItem",
                "dynamodb:Query"
            ],
            "Resource": "arn:aws:dynamodb:'${AWS_REGION}':'${ACCOUNT_ID}':table/CloudOpAI-ScanResults"
        },
        {
            "Effect": "Allow",
            "Action": [
                "s3:PutObject",
                "s3:GetObject"
            ],
            "Resource": "arn:aws:s3:::'${BUCKET_NAME}'/*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "ses:SendEmail"
            ],
            "Resource": "*"
        }
    ]
}'

aws iam put-role-policy \
    --role-name ${ROLE_NAME} \
    --policy-name CloudOpAI-Services-Policy \
    --policy-document "${POLICY_DOC}"

# Wait for role to propagate
echo "Waiting for IAM role to propagate..."
sleep 10

# Create or update Lambda function
echo "Deploying Lambda function..."
ROLE_ARN="arn:aws:iam::${ACCOUNT_ID}:role/${ROLE_NAME}"

if aws lambda get-function --function-name ${FUNCTION_NAME} --region ${AWS_REGION} 2>/dev/null; then
    echo "Updating existing function..."
    aws lambda update-function-code \
        --function-name ${FUNCTION_NAME} \
        --zip-file fileb://function.zip \
        --region ${AWS_REGION}
    
    aws lambda update-function-configuration \
        --function-name ${FUNCTION_NAME} \
        --handler src.handlers.scanner_handler.lambda_handler \
        --timeout 300 \
        --memory-size 512 \
        --environment Variables="{
            SCAN_RESULTS_TABLE=CloudOpAI-ScanResults,
            REPORTS_BUCKET=${BUCKET_NAME},
            AWS_REGION=${AWS_REGION},
            EMAIL_SOURCE=alerts@cloudopai.com,
            CALENDLY_LINK=https://calendly.com/cloudopai/demo
        }" \
        --region ${AWS_REGION}
else
    echo "Creating new function..."
    aws lambda create-function \
        --function-name ${FUNCTION_NAME} \
        --runtime python3.9 \
        --role ${ROLE_ARN} \
        --handler src.handlers.scanner_handler.lambda_handler \
        --timeout 300 \
        --memory-size 512 \
        --environment Variables="{
            SCAN_RESULTS_TABLE=CloudOpAI-ScanResults,
            REPORTS_BUCKET=${BUCKET_NAME},
            AWS_REGION=${AWS_REGION},
            EMAIL_SOURCE=alerts@cloudopai.com,
            CALENDLY_LINK=https://calendly.com/cloudopai/demo
        }" \
        --zip-file fileb://function.zip \
        --region ${AWS_REGION}
fi

# Clean up
rm -rf dist function.zip

echo "Deployment complete!"
echo ""
echo "Next Steps:"
echo "1. Update your website with the customer onboarding flow"
echo "2. Set up SES for email sending (verify alerts@cloudopai.com)"
echo "3. Test with: aws lambda invoke --function-name ${FUNCTION_NAME} --payload '{\"account_id\":\"test\",\"role_arn\":\"test\",\"email\":\"test@example.com\"}' response.json"
echo ""
echo "Lambda ARN: arn:aws:lambda:${AWS_REGION}:${ACCOUNT_ID}:function:${FUNCTION_NAME}"