#!/usr/bin/env bash
# ============================================================================
# IoMT Zero Trust -- AWS VPC & Infrastructure Provisioning
#
# Creates two isolated VPCs (Tenant A & B) in ap-south-1, each with:
#   - Public subnet + Internet Gateway
#   - Security group (HTTPS + SSH inbound)
#   - EC2 t2.micro instance running the PEP server
#   - DynamoDB table for DTSA baselines (shared)
#
# Prerequisites:
#   - AWS CLI v2 configured with appropriate IAM permissions
#   - Key pair "Project-Key" already created in ap-south-1
#
# Usage:
#   chmod +x setup_vpc.sh && ./setup_vpc.sh
# ============================================================================

set -euo pipefail

REGION="ap-south-1"
KEY_NAME="Project-Key"
AMI_ID="ami-0dee22c13ea7a9a67"  # Ubuntu 20.04 LTS in ap-south-1 (update if needed)
INSTANCE_TYPE="t2.micro"

echo "=== IoMT Zero Trust Infrastructure Setup ==="
echo "Region: $REGION"

# ── Helper ──────────────────────────────────────────────────────────────
tag() { aws ec2 create-tags --region "$REGION" --resources "$1" --tags "Key=Name,Value=$2" "Key=Project,Value=IoMT-ZeroTrust"; }

# ── 1. DynamoDB Table (shared) ──────────────────────────────────────────
echo "[1/8] Creating DynamoDB table: DeviceBaselines"
aws dynamodb create-table \
    --region "$REGION" \
    --table-name DeviceBaselines \
    --attribute-definitions AttributeName=device_id,AttributeType=S \
    --key-schema AttributeName=device_id,KeyType=HASH \
    --billing-mode PAY_PER_REQUEST \
    2>/dev/null || echo "  (table already exists)"

# ── 2. VPC A (Tenant A) ────────────────────────────────────────────────
echo "[2/8] Creating VPC A (10.0.0.0/16)"
VPC_A=$(aws ec2 create-vpc --region "$REGION" --cidr-block 10.0.0.0/16 \
    --query 'Vpc.VpcId' --output text)
tag "$VPC_A" "IoMT-VPC-TenantA"
aws ec2 modify-vpc-attribute --region "$REGION" --vpc-id "$VPC_A" --enable-dns-support
aws ec2 modify-vpc-attribute --region "$REGION" --vpc-id "$VPC_A" --enable-dns-hostnames

SUBNET_A=$(aws ec2 create-subnet --region "$REGION" --vpc-id "$VPC_A" \
    --cidr-block 10.0.1.0/24 --availability-zone "${REGION}a" \
    --query 'Subnet.SubnetId' --output text)
tag "$SUBNET_A" "IoMT-SubnetA"
aws ec2 modify-subnet-attribute --region "$REGION" --subnet-id "$SUBNET_A" \
    --map-public-ip-on-launch

IGW_A=$(aws ec2 create-internet-gateway --region "$REGION" \
    --query 'InternetGateway.InternetGatewayId' --output text)
aws ec2 attach-internet-gateway --region "$REGION" --internet-gateway-id "$IGW_A" --vpc-id "$VPC_A"

RTB_A=$(aws ec2 describe-route-tables --region "$REGION" \
    --filters "Name=vpc-id,Values=$VPC_A" --query 'RouteTables[0].RouteTableId' --output text)
aws ec2 create-route --region "$REGION" --route-table-id "$RTB_A" \
    --destination-cidr-block 0.0.0.0/0 --gateway-id "$IGW_A"

SG_A=$(aws ec2 create-security-group --region "$REGION" --vpc-id "$VPC_A" \
    --group-name "IoMT-PEP-SG-A" --description "PEP Security Group Tenant A" \
    --query 'GroupId' --output text)
aws ec2 authorize-security-group-ingress --region "$REGION" --group-id "$SG_A" \
    --protocol tcp --port 22 --cidr 0.0.0.0/0
aws ec2 authorize-security-group-ingress --region "$REGION" --group-id "$SG_A" \
    --protocol tcp --port 6000 --cidr 0.0.0.0/0
aws ec2 authorize-security-group-ingress --region "$REGION" --group-id "$SG_A" \
    --protocol tcp --port 443 --cidr 0.0.0.0/0

# ── 3. VPC B (Tenant B) ────────────────────────────────────────────────
echo "[3/8] Creating VPC B (10.1.0.0/16)"
VPC_B=$(aws ec2 create-vpc --region "$REGION" --cidr-block 10.1.0.0/16 \
    --query 'Vpc.VpcId' --output text)
tag "$VPC_B" "IoMT-VPC-TenantB"
aws ec2 modify-vpc-attribute --region "$REGION" --vpc-id "$VPC_B" --enable-dns-support
aws ec2 modify-vpc-attribute --region "$REGION" --vpc-id "$VPC_B" --enable-dns-hostnames

SUBNET_B=$(aws ec2 create-subnet --region "$REGION" --vpc-id "$VPC_B" \
    --cidr-block 10.1.1.0/24 --availability-zone "${REGION}a" \
    --query 'Subnet.SubnetId' --output text)
tag "$SUBNET_B" "IoMT-SubnetB"
aws ec2 modify-subnet-attribute --region "$REGION" --subnet-id "$SUBNET_B" \
    --map-public-ip-on-launch

IGW_B=$(aws ec2 create-internet-gateway --region "$REGION" \
    --query 'InternetGateway.InternetGatewayId' --output text)
aws ec2 attach-internet-gateway --region "$REGION" --internet-gateway-id "$IGW_B" --vpc-id "$VPC_B"

RTB_B=$(aws ec2 describe-route-tables --region "$REGION" \
    --filters "Name=vpc-id,Values=$VPC_B" --query 'RouteTables[0].RouteTableId' --output text)
aws ec2 create-route --region "$REGION" --route-table-id "$RTB_B" \
    --destination-cidr-block 0.0.0.0/0 --gateway-id "$IGW_B"

SG_B=$(aws ec2 create-security-group --region "$REGION" --vpc-id "$VPC_B" \
    --group-name "IoMT-PEP-SG-B" --description "PEP Security Group Tenant B" \
    --query 'GroupId' --output text)
aws ec2 authorize-security-group-ingress --region "$REGION" --group-id "$SG_B" \
    --protocol tcp --port 22 --cidr 0.0.0.0/0
aws ec2 authorize-security-group-ingress --region "$REGION" --group-id "$SG_B" \
    --protocol tcp --port 6000 --cidr 0.0.0.0/0
aws ec2 authorize-security-group-ingress --region "$REGION" --group-id "$SG_B" \
    --protocol tcp --port 443 --cidr 0.0.0.0/0

# ── 4. EC2 User Data (PEP bootstrap script) ────────────────────────────
cat > /tmp/pep_userdata_a.sh << 'USERDATA'
#!/bin/bash
apt-get update -y && apt-get install -y python3-pip git
pip3 install flask pycryptodome pyjwt[crypto] cryptography boto3
cd /home/ubuntu
git clone https://github.com/YOUR_REPO/iomt-zero-trust.git || true
cd iomt-zero-trust
export PEP_TENANT_ID="tenant_A"
export DTSA_TABLE_NAME="DeviceBaselines"
nohup python3 -m cloud.pep.pep_server &
USERDATA

cat > /tmp/pep_userdata_b.sh << 'USERDATA'
#!/bin/bash
apt-get update -y && apt-get install -y python3-pip git
pip3 install flask pycryptodome pyjwt[crypto] cryptography boto3
cd /home/ubuntu
git clone https://github.com/YOUR_REPO/iomt-zero-trust.git || true
cd iomt-zero-trust
export PEP_TENANT_ID="tenant_B"
export DTSA_TABLE_NAME="DeviceBaselines"
nohup python3 -m cloud.pep.pep_server &
USERDATA

# ── 5. Launch EC2 Instances ────────────────────────────────────────────
echo "[4/8] Launching EC2 instance in VPC A"
INSTANCE_A=$(aws ec2 run-instances --region "$REGION" \
    --image-id "$AMI_ID" --instance-type "$INSTANCE_TYPE" \
    --key-name "$KEY_NAME" --subnet-id "$SUBNET_A" \
    --security-group-ids "$SG_A" \
    --user-data file:///tmp/pep_userdata_a.sh \
    --query 'Instances[0].InstanceId' --output text)
tag "$INSTANCE_A" "IoMT-PEP-TenantA"

echo "[5/8] Launching EC2 instance in VPC B"
INSTANCE_B=$(aws ec2 run-instances --region "$REGION" \
    --image-id "$AMI_ID" --instance-type "$INSTANCE_TYPE" \
    --key-name "$KEY_NAME" --subnet-id "$SUBNET_B" \
    --security-group-ids "$SG_B" \
    --user-data file:///tmp/pep_userdata_b.sh \
    --query 'Instances[0].InstanceId' --output text)
tag "$INSTANCE_B" "IoMT-PEP-TenantB"

# ── 6. Wait for instances ──────────────────────────────────────────────
echo "[6/8] Waiting for instances to be running..."
aws ec2 wait instance-running --region "$REGION" --instance-ids "$INSTANCE_A" "$INSTANCE_B"

IP_A=$(aws ec2 describe-instances --region "$REGION" --instance-ids "$INSTANCE_A" \
    --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)
IP_B=$(aws ec2 describe-instances --region "$REGION" --instance-ids "$INSTANCE_B" \
    --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)

# ── 7. Summary ─────────────────────────────────────────────────────────
echo ""
echo "=== Infrastructure Ready ==="
echo "VPC A (Tenant A):  $VPC_A"
echo "  EC2 Instance:    $INSTANCE_A"
echo "  Public IP:       $IP_A"
echo "  PEP Endpoint:    http://$IP_A:6000/verify"
echo ""
echo "VPC B (Tenant B):  $VPC_B"
echo "  EC2 Instance:    $INSTANCE_B"
echo "  Public IP:       $IP_B"
echo "  PEP Endpoint:    http://$IP_B:6000/verify"
echo ""
echo "DynamoDB Table:    DeviceBaselines"
echo ""
echo "--- Update your sidecar config ---"
echo "export IOMT_PEP_ENDPOINT=http://$IP_A:6000/verify"
echo ""
echo "[7/8] No VPC peering created (intentional -- enforces isolation)"
echo "[8/8] Done."
