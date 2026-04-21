# Securing Legacy IoMT in Multi-Tenant Healthcare Clouds

A Zero Trust Architecture (ZTA) prototype that wraps legacy medical devices using a **Sidecar Proxy** to enforce identity-based access control and behavioral anomaly detection via the **Dynamic Trust Scoring Algorithm (DTSA)**.

> Based on the IEEE conference paper: *"Securing Legacy IoMT in Multi-Tenant Healthcare Clouds: A Sidecar Proxy Approach with Dynamic Trust Scoring"*

## Architecture

```
Legacy Device  -->  Sidecar Proxy  -->  AWS Cloud PEP  -->  DTSA Lambda
(MIT-BIH ECG)      (JWT + AES-GCM)     (Decrypt/Verify)    (Trust Score)
```

- **Edge Layer**: Python sidecar intercepts cleartext traffic, injects RS256 JWT identity tokens, encrypts with AES-256-GCM
- **Cloud Layer**: Policy Enforcement Point (PEP) on EC2 decrypts, validates JWT, enforces Tenant Isolation Theorem
- **Scoring Engine**: DTSA Lambda computes trust scores from behavioral vectors (packet frequency, payload size, geo-velocity)

## Quick Start

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Run Tests

```bash
python -m pytest tests/ -v
```

### 3. Run Local Benchmark

```bash
python -m simulator.benchmark
```

### 4. Start the Sidecar Proxy (local mode)

```bash
# Terminal 1: Start PEP server
python -m cloud.pep.pep_server

# Terminal 2: Start Sidecar Proxy
uvicorn sidecar.sidecar_proxy:app --host 0.0.0.0 --port 8000

# Terminal 3: Run legacy device simulator
python -m simulator.legacy_device --max-packets 20
```

### 5. Run Attack Simulations

```bash
# Masquerading attack (3-sigma payload spike)
python -m simulator.attacker_masquerade --normal-seconds 10 --attack-packets 10 --rate 2

# Lateral movement attack (cross-tenant)
python -m simulator.attacker_lateral --packet-count 50
```

## Project Structure

```
iomt-zero-trust/
  sidecar/
    config.py             # Configuration (tenant ID, keys, endpoints)
    encryption.py         # AES-256-GCM encrypt/decrypt
    jwt_module.py         # RS256 JWT generation/verification
    interceptor.py        # Packet metadata extraction
    sidecar_proxy.py      # FastAPI proxy (main entry point)
  simulator/
    legacy_device.py      # MIT-BIH ECG data replay
    attacker_masquerade.py  # Masquerading attack script
    attacker_lateral.py     # Lateral movement attack script
    benchmark.py            # Performance benchmark suite
  cloud/
    lambda_dtsa/
      handler.py          # DTSA scoring engine (Lambda-ready)
    pep/
      pep_server.py       # Policy Enforcement Point (Flask)
    infra/
      setup_vpc.sh        # AWS VPC provisioning
      deploy_lambda.sh    # Lambda deployment
      teardown.sh         # Resource cleanup
  tests/
    test_encryption.py    # AES-256-GCM tests
    test_jwt.py           # RS256 JWT tests
    test_dtsa.py          # DTSA algorithm tests
    test_pep.py           # PEP integration tests
    test_integration.py   # End-to-end pipeline tests
  keys/                   # Auto-generated RSA key pair
  results/                # Benchmark CSV logs
```

## Mathematical Core

### Deviation Function (Eq. 2)

```
delta(x) = |x_obs - mu_x| / (sigma_x + epsilon)
```

### Trust Score (Eq. 3)

```
T(d) = 100 - (alpha * delta(v_f) + beta * delta(v_s) + gamma * delta(v_g))
```

Where alpha=30, beta=50, gamma=20 (sum=100).

### Decision Thresholds

| Score Range | Decision | Action |
|-------------|----------|--------|
| T >= 60     | ALLOW    | Forward packet |
| 40 <= T < 60| STEP_UP_AUTH | Trigger MFA |
| T < 40      | QUARANTINE | Sever connection |

## Benchmark Results

| Metric | Target | Achieved |
|--------|--------|----------|
| Detection Latency | < 180ms | ~33ms |
| Detection Rate | 98.5% | 100% |
| False Positive Rate | < 1.5% | 0% |
| Processing Overhead | ~12ms | ~34ms (local, includes full crypto) |

## AWS Deployment

1. Ensure AWS CLI is configured with appropriate IAM permissions
2. Run `bash cloud/infra/setup_vpc.sh` to provision VPCs, EC2, and DynamoDB
3. Run `bash cloud/infra/deploy_lambda.sh` to deploy the DTSA Lambda
4. Update `IOMT_PEP_ENDPOINT` env var with the EC2 public IP
5. To clean up: `bash cloud/infra/teardown.sh`

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `IOMT_TENANT_ID` | `tenant_A` | Tenant identifier |
| `IOMT_DEVICE_ID` | `ecg_monitor_001` | Device identifier |
| `IOMT_AES_KEY_HEX` | (built-in) | 64-char hex AES-256 key |
| `IOMT_PEP_ENDPOINT` | `http://localhost:6000/verify` | PEP URL |
| `PEP_TENANT_ID` | `tenant_A` | PEP's expected tenant |
| `DTSA_TABLE_NAME` | `DeviceBaselines` | DynamoDB table name |
