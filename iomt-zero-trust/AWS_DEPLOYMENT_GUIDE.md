# AWS Deployment Guide -- Step by Step for Beginners

This guide walks you through deploying the IoMT Zero Trust system on AWS
using the browser-based AWS Console. No command-line AWS experience needed.

**Cost: $0** (everything uses Free Tier resources)

---

## OVERVIEW -- What We Are Building on AWS

```
YOUR LAPTOP                          AWS CLOUD (ap-south-1, Mumbai)
============                         ==============================

                                     VPC A (10.0.0.0/16) - Hospital A
                                     +---------------------------+
  Sidecar Proxy  --- internet --->   |  EC2 (PEP Server)         |
  (runs locally)                     |  tenant_A, port 6000      |
                                     +---------------------------+

                                     VPC B (10.1.0.0/16) - Hospital B
                                     +---------------------------+
  Attack Script  --- internet --->   |  EC2 (PEP Server)         |
  (runs locally)                     |  tenant_B, port 6000      |
                                     +---------------------------+

                                     DynamoDB Table
                                     +---------------------------+
                                     |  DeviceBaselines          |
                                     |  (stores EMA mu/sigma)    |
                                     +---------------------------+
```

We create TWO separate VPCs (Virtual Private Clouds) that CANNOT talk to
each other. This is the physical enforcement of the Tenant Isolation Theorem.

---

## PREREQUISITES

1. AWS Account (you have this)
2. GitHub Account (you have this)
3. The `Project-Key.pem` file (you have this)

---

## STEP 1: Push Code to GitHub

Before deploying, the EC2 instances need to download your code.

1. Go to https://github.com/new
2. Create a new repository:
   - Name: `iomt-zero-trust`
   - Visibility: **Private** (this has security keys)
   - Do NOT initialize with README (we already have one)
3. Open a terminal/command prompt and run:

```
cd <path-to-iomt-zero-trust-folder>
git init
git add .
git commit -m "Initial implementation of IoMT Zero Trust Sidecar Proxy"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/iomt-zero-trust.git
git push -u origin main
```

Replace `YOUR_USERNAME` with your actual GitHub username.

---

## STEP 2: Install AWS CLI

1. Download: https://awscli.amazonaws.com/AWSCLIV2.msi
2. Run the installer (Next, Next, Install, Finish)
3. Open a NEW command prompt and verify:

```
aws --version
```

You should see: `aws-cli/2.x.x Python/3.x.x Windows/10 ...`

---

## STEP 3: Configure AWS CLI

1. Log into AWS Console: https://console.aws.amazon.com
2. Click your username (top-right) > "Security Credentials"
3. Under "Access Keys", click "Create access key"
4. Choose "Command Line Interface (CLI)"
5. Check the acknowledgment box, click "Next", then "Create access key"
6. **IMPORTANT**: Copy both the Access Key ID and Secret Access Key (you won't see the secret again!)

7. In your command prompt, run:

```
aws configure
```

Enter:
- AWS Access Key ID: (paste your key)
- AWS Secret Access Key: (paste your secret)
- Default region: `ap-south-1`
- Default output format: `json`

8. Verify it works:

```
aws sts get-caller-identity
```

You should see your account ID.

---

## STEP 4: Create DynamoDB Table

1. Go to: https://console.aws.amazon.com/dynamodb
2. Make sure region is **Asia Pacific (Mumbai) ap-south-1** (top-right dropdown)
3. Click "Create table"
4. Settings:
   - Table name: `DeviceBaselines`
   - Partition key: `device_id` (type: String)
   - Sort key: (leave empty)
   - Table settings: "Default settings"
5. Click "Create table"
6. Wait for status to show "Active" (takes ~30 seconds)

---

## STEP 5: Create VPC A (Tenant A -- Hospital A)

### 5.1 Create the VPC

1. Go to: https://console.aws.amazon.com/vpc
2. Click "Create VPC"
3. Choose "VPC only"
4. Settings:
   - Name: `IoMT-VPC-TenantA`
   - IPv4 CIDR: `10.0.0.0/16`
5. Click "Create VPC"
6. Note the VPC ID (starts with `vpc-`)

### 5.2 Create a Subnet

1. In the VPC dashboard, click "Subnets" (left sidebar)
2. Click "Create subnet"
3. Settings:
   - VPC: select `IoMT-VPC-TenantA`
   - Subnet name: `IoMT-SubnetA`
   - Availability Zone: `ap-south-1a`
   - IPv4 CIDR: `10.0.1.0/24`
4. Click "Create subnet"
5. Select the new subnet > Actions > "Edit subnet settings"
6. Check "Enable auto-assign public IPv4 address" > Save

### 5.3 Create an Internet Gateway

1. Click "Internet gateways" (left sidebar)
2. Click "Create internet gateway"
3. Name: `IoMT-IGW-A`
4. Click "Create"
5. Click "Actions" > "Attach to VPC" > select `IoMT-VPC-TenantA` > "Attach"

### 5.4 Add Route to Internet

1. Click "Route tables" (left sidebar)
2. Find the route table associated with `IoMT-VPC-TenantA` (check the VPC column)
3. Select it > "Routes" tab > "Edit routes"
4. Click "Add route":
   - Destination: `0.0.0.0/0`
   - Target: select "Internet Gateway" > `IoMT-IGW-A`
5. Click "Save changes"

### 5.5 Create Security Group

1. Click "Security groups" (left sidebar)
2. Click "Create security group"
3. Settings:
   - Name: `IoMT-PEP-SG-A`
   - Description: `PEP Security Group for Tenant A`
   - VPC: `IoMT-VPC-TenantA`
4. Inbound rules -- click "Add rule" three times:
   - Rule 1: Type=SSH, Port=22, Source=0.0.0.0/0
   - Rule 2: Type=Custom TCP, Port=6000, Source=0.0.0.0/0
   - Rule 3: Type=HTTPS, Port=443, Source=0.0.0.0/0
5. Click "Create security group"

---

## STEP 6: Create VPC B (Tenant B -- Hospital B)

Repeat STEP 5 with these values:

- VPC name: `IoMT-VPC-TenantB`
- VPC CIDR: `10.1.0.0/16`
- Subnet name: `IoMT-SubnetB`
- Subnet CIDR: `10.1.1.0/24`
- Internet Gateway name: `IoMT-IGW-B`
- Security Group name: `IoMT-PEP-SG-B`
- Same inbound rules (SSH:22, Custom TCP:6000, HTTPS:443)

**IMPORTANT**: Do NOT create any VPC Peering between VPC A and VPC B.
The whole point is that they are ISOLATED. This enforces the Tenant
Isolation Theorem from the paper.

---

## STEP 7: Verify Key Pair

1. Go to: https://console.aws.amazon.com/ec2
2. Click "Key Pairs" (left sidebar, under "Network & Security")
3. Check if `Project-Key` exists in region `ap-south-1`
4. If it does NOT exist, click "Import key pair":
   - Name: `Project-Key`
   - Upload your `Project-Key.pem` file (or paste the public key)

Note: You already have the `.pem` file, so the key pair likely
already exists in your AWS account.

---

## STEP 8: Launch EC2 Instance for Tenant A

1. Go to: https://console.aws.amazon.com/ec2
2. Click "Launch instance"
3. Settings:
   - Name: `IoMT-PEP-TenantA`
   - AMI: Ubuntu Server 24.04 LTS (Free tier eligible)
   - Instance type: `t2.micro` (Free tier eligible)
   - Key pair: `Project-Key`
   - Network settings > Click "Edit":
     - VPC: `IoMT-VPC-TenantA`
     - Subnet: `IoMT-SubnetA`
     - Auto-assign public IP: Enable
     - Security group: select existing > `IoMT-PEP-SG-A`
   - Advanced details > scroll to "User data" and paste:

```bash
#!/bin/bash
apt-get update -y
apt-get install -y python3-pip python3-venv git
cd /home/ubuntu
git clone https://github.com/YOUR_USERNAME/iomt-zero-trust.git
cd iomt-zero-trust
python3 -m venv venv
source venv/bin/activate
pip install flask pycryptodome "pyjwt[crypto]" cryptography boto3
echo 'export PEP_TENANT_ID="tenant_A"' >> /home/ubuntu/.bashrc
echo 'export DTSA_TABLE_NAME="DeviceBaselines"' >> /home/ubuntu/.bashrc
```

   (Replace YOUR_USERNAME with your GitHub username)

4. Click "Launch instance"
5. Wait for "Instance State" to show "Running"
6. Note the **Public IPv4 address** (e.g., `3.110.xxx.xxx`)

---

## STEP 9: Launch EC2 Instance for Tenant B

Repeat STEP 8 with these changes:

- Name: `IoMT-PEP-TenantB`
- VPC: `IoMT-VPC-TenantB`
- Subnet: `IoMT-SubnetB`
- Security group: `IoMT-PEP-SG-B`
- User data: same script but change `PEP_TENANT_ID="tenant_B"`

---

## STEP 10: Connect to EC2 and Start PEP Server

### For Tenant A:

1. Open a command prompt on your laptop
2. Navigate to where your `Project-Key.pem` file is
3. Run:

```bash
ssh -i Project-Key.pem ubuntu@<PUBLIC_IP_A>
```

(Replace `<PUBLIC_IP_A>` with the actual IP from Step 8)

4. If asked about fingerprint, type `yes`
5. Once connected, run:

```bash
cd iomt-zero-trust
source venv/bin/activate
export PEP_TENANT_ID="tenant_A"
nohup python3 -m cloud.pep.pep_server &
```

6. Verify it is running:

```bash
curl http://localhost:6000/health
```

You should see: `{"status":"ok","tenant":"tenant_A"}`

### For Tenant B:

Repeat the same with `<PUBLIC_IP_B>` and `PEP_TENANT_ID="tenant_B"`

---

## STEP 11: Test from Your Laptop

Now both PEP servers are running on AWS. Test from your laptop:

### Test 1: Sidecar -> PEP A (should work)

```bash
cd iomt-zero-trust
set IOMT_PEP_ENDPOINT=http://<PUBLIC_IP_A>:6000/verify
python -m simulator.legacy_device --max-packets 5 --sidecar-url http://localhost:8000/ingest
```

(Run the sidecar proxy in another terminal first:
`python -m uvicorn sidecar.sidecar_proxy:app --port 8000`)

### Test 2: Lateral Movement Attack (should block 100%)

```bash
python -m simulator.attacker_lateral --pep-url http://<PUBLIC_IP_B>:6000/verify --src-tenant tenant_A --packet-count 20
```

---

## STEP 12: Clean Up (IMPORTANT -- avoid charges)

When you are done testing:

1. Go to EC2 Console > select both instances > "Instance state" > "Terminate instance"
2. Go to VPC Console > delete both Internet Gateways (detach first, then delete)
3. Delete both subnets
4. Delete both security groups (non-default ones)
5. Delete both VPCs
6. Go to DynamoDB Console > delete the `DeviceBaselines` table

Or simply run the teardown script if you have WSL/Git Bash later.

---

## TROUBLESHOOTING

### "Connection refused" when SSH-ing
- Wait 2 minutes after launch for the instance to fully boot
- Check security group has port 22 open
- Make sure you are using the correct key: `ssh -i Project-Key.pem ubuntu@<IP>`

### "Permission denied" on SSH
- Run: `chmod 400 Project-Key.pem` (on Linux/Mac)
- On Windows, right-click the .pem file > Properties > Security > Advanced >
  Remove all users except yourself

### PEP health check fails
- SSH into the instance and check: `ps aux | grep pep_server`
- Check logs: `cat nohup.out`
- Make sure port 6000 is open in the security group

### "Module not found" errors on EC2
- Make sure you activated the venv: `source venv/bin/activate`
- Reinstall: `pip install flask pycryptodome "pyjwt[crypto]" cryptography boto3`
