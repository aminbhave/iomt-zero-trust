#!/usr/bin/env bash
# ============================================================================
# Tear down all IoMT Zero Trust AWS resources.
# Run this when you want to clean up to avoid charges.
#
# Usage:
#   chmod +x teardown.sh && ./teardown.sh
# ============================================================================

set -euo pipefail

REGION="ap-south-1"

echo "=== IoMT Zero Trust Infrastructure Teardown ==="
echo "Region: $REGION"
echo ""

# Terminate EC2 instances
echo "[1/5] Terminating EC2 instances..."
INSTANCES=$(aws ec2 describe-instances --region "$REGION" \
    --filters "Name=tag:Project,Values=IoMT-ZeroTrust" "Name=instance-state-name,Values=running,stopped" \
    --query 'Reservations[].Instances[].InstanceId' --output text)

if [ -n "$INSTANCES" ]; then
    aws ec2 terminate-instances --region "$REGION" --instance-ids $INSTANCES
    echo "  Waiting for termination..."
    aws ec2 wait instance-terminated --region "$REGION" --instance-ids $INSTANCES
fi

# Delete security groups, subnets, route tables, IGWs, VPCs
for VPC_NAME in "IoMT-VPC-TenantA" "IoMT-VPC-TenantB"; do
    echo "[2/5] Cleaning up $VPC_NAME..."
    VPC_ID=$(aws ec2 describe-vpcs --region "$REGION" \
        --filters "Name=tag:Name,Values=$VPC_NAME" \
        --query 'Vpcs[0].VpcId' --output text 2>/dev/null || echo "None")

    if [ "$VPC_ID" != "None" ] && [ -n "$VPC_ID" ]; then
        # Detach and delete IGW
        IGW=$(aws ec2 describe-internet-gateways --region "$REGION" \
            --filters "Name=attachment.vpc-id,Values=$VPC_ID" \
            --query 'InternetGateways[0].InternetGatewayId' --output text 2>/dev/null || echo "None")
        if [ "$IGW" != "None" ] && [ -n "$IGW" ]; then
            aws ec2 detach-internet-gateway --region "$REGION" --internet-gateway-id "$IGW" --vpc-id "$VPC_ID"
            aws ec2 delete-internet-gateway --region "$REGION" --internet-gateway-id "$IGW"
        fi

        # Delete subnets
        for SUBNET in $(aws ec2 describe-subnets --region "$REGION" \
            --filters "Name=vpc-id,Values=$VPC_ID" \
            --query 'Subnets[].SubnetId' --output text); do
            aws ec2 delete-subnet --region "$REGION" --subnet-id "$SUBNET"
        done

        # Delete non-default security groups
        for SG in $(aws ec2 describe-security-groups --region "$REGION" \
            --filters "Name=vpc-id,Values=$VPC_ID" \
            --query 'SecurityGroups[?GroupName!=`default`].GroupId' --output text); do
            aws ec2 delete-security-group --region "$REGION" --group-id "$SG"
        done

        # Delete VPC
        aws ec2 delete-vpc --region "$REGION" --vpc-id "$VPC_ID"
        echo "  Deleted $VPC_NAME ($VPC_ID)"
    fi
done

# Delete Lambda
echo "[3/5] Deleting Lambda function..."
aws lambda delete-function --region "$REGION" --function-name "IoMT-DTSA-Scorer" 2>/dev/null || true

# Delete DynamoDB table
echo "[4/5] Deleting DynamoDB table..."
aws dynamodb delete-table --region "$REGION" --table-name "DeviceBaselines" 2>/dev/null || true

# Delete IAM role
echo "[5/5] Cleaning up IAM role..."
aws iam detach-role-policy --role-name "IoMT-DTSA-Lambda-Role" \
    --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole 2>/dev/null || true
aws iam detach-role-policy --role-name "IoMT-DTSA-Lambda-Role" \
    --policy-arn arn:aws:iam::aws:policy/AmazonDynamoDBFullAccess 2>/dev/null || true
aws iam delete-role --role-name "IoMT-DTSA-Lambda-Role" 2>/dev/null || true

echo ""
echo "=== Teardown Complete ==="
