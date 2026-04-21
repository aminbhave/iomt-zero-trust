#!/usr/bin/env bash
# ============================================================================
# Deploy the DTSA scoring function as an AWS Lambda.
#
# Prerequisites:
#   - AWS CLI v2 configured
#   - IAM role "IoMT-DTSA-Lambda-Role" with DynamoDB access
#
# Usage:
#   chmod +x deploy_lambda.sh && ./deploy_lambda.sh
# ============================================================================

set -euo pipefail

REGION="ap-south-1"
FUNCTION_NAME="IoMT-DTSA-Scorer"
ROLE_NAME="IoMT-DTSA-Lambda-Role"
TABLE_NAME="DeviceBaselines"
RUNTIME="python3.12"
HANDLER="handler.lambda_handler"
TIMEOUT=10
MEMORY=128

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LAMBDA_DIR="$SCRIPT_DIR/../lambda_dtsa"
PACKAGE_DIR="/tmp/iomt-lambda-package"

echo "=== Deploying DTSA Lambda ==="

# ── 1. Create IAM Role (idempotent) ────────────────────────────────────
echo "[1/4] Ensuring IAM role exists: $ROLE_NAME"
TRUST_POLICY='{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"Service": "lambda.amazonaws.com"},
    "Action": "sts:AssumeRole"
  }]
}'

ROLE_ARN=$(aws iam get-role --role-name "$ROLE_NAME" \
    --query 'Role.Arn' --output text 2>/dev/null || true)

if [ -z "$ROLE_ARN" ] || [ "$ROLE_ARN" = "None" ]; then
    ROLE_ARN=$(aws iam create-role \
        --role-name "$ROLE_NAME" \
        --assume-role-policy-document "$TRUST_POLICY" \
        --query 'Role.Arn' --output text)

    aws iam attach-role-policy --role-name "$ROLE_NAME" \
        --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole
    aws iam attach-role-policy --role-name "$ROLE_NAME" \
        --policy-arn arn:aws:iam::aws:policy/AmazonDynamoDBFullAccess

    echo "  Waiting 10s for IAM propagation..."
    sleep 10
fi
echo "  Role ARN: $ROLE_ARN"

# ── 2. Package Lambda ──────────────────────────────────────────────────
echo "[2/4] Packaging Lambda function"
rm -rf "$PACKAGE_DIR" && mkdir -p "$PACKAGE_DIR"
cp "$LAMBDA_DIR/handler.py" "$PACKAGE_DIR/"
cd "$PACKAGE_DIR" && zip -r /tmp/iomt-dtsa-lambda.zip .

# ── 3. Create or Update Lambda ─────────────────────────────────────────
echo "[3/4] Creating/updating Lambda: $FUNCTION_NAME"
EXISTING=$(aws lambda get-function --region "$REGION" \
    --function-name "$FUNCTION_NAME" 2>/dev/null || true)

if [ -z "$EXISTING" ]; then
    aws lambda create-function \
        --region "$REGION" \
        --function-name "$FUNCTION_NAME" \
        --runtime "$RUNTIME" \
        --role "$ROLE_ARN" \
        --handler "$HANDLER" \
        --zip-file fileb:///tmp/iomt-dtsa-lambda.zip \
        --timeout "$TIMEOUT" \
        --memory-size "$MEMORY" \
        --environment "Variables={DTSA_TABLE_NAME=$TABLE_NAME}"
else
    aws lambda update-function-code \
        --region "$REGION" \
        --function-name "$FUNCTION_NAME" \
        --zip-file fileb:///tmp/iomt-dtsa-lambda.zip

    aws lambda update-function-configuration \
        --region "$REGION" \
        --function-name "$FUNCTION_NAME" \
        --timeout "$TIMEOUT" \
        --memory-size "$MEMORY" \
        --environment "Variables={DTSA_TABLE_NAME=$TABLE_NAME}"
fi

# ── 4. Verify ──────────────────────────────────────────────────────────
echo "[4/4] Testing Lambda invocation"
aws lambda invoke \
    --region "$REGION" \
    --function-name "$FUNCTION_NAME" \
    --payload '{"device_id":"test_dev","packet_freq":1.0,"payload_size":2000}' \
    /tmp/lambda_response.json

echo "  Response:"
cat /tmp/lambda_response.json
echo ""
echo "=== Lambda deployed successfully ==="
