"""
AWS Deployment Verifier.

Run this script from your laptop AFTER deploying the PEP servers
on EC2 to verify the full cloud pipeline works.

Usage:
    python verify_aws_deployment.py --pep-a http://<IP_A>:6000 --pep-b http://<IP_B>:6000
"""

import argparse
import json
import sys
import time

import requests

sys.path.insert(0, ".")
from sidecar.encryption import encrypt
from sidecar.jwt_module import generate_jwt, _ensure_keypair
from sidecar.config import AES_KEY


def test_health(pep_url: str, label: str) -> bool:
    """Check if the PEP server is reachable."""
    try:
        resp = requests.get(f"{pep_url}/health", timeout=5)
        data = resp.json()
        tenant = data.get("tenant", "?")
        print(f"  [{label}] Health check: OK (tenant={tenant})")
        return True
    except Exception as exc:
        print(f"  [{label}] Health check: FAILED ({exc})")
        return False


def test_legitimate_packet(pep_url: str, tenant_id: str, label: str) -> bool:
    """Send a valid same-tenant packet -- should be ALLOWED."""
    raw = json.dumps({"ecg": [0.5, 0.6, 0.7], "device_id": "test_dev"}).encode()
    token = generate_jwt(tenant_id=tenant_id, device_id="test_dev")
    combined = token.encode() + b"|" + raw
    encrypted = encrypt(combined, AES_KEY)

    try:
        resp = requests.post(
            f"{pep_url}/verify",
            data=encrypted,
            headers={"Content-Type": "application/octet-stream"},
            timeout=10,
        )
        data = resp.json()
        decision = data.get("decision", "?")
        score = data.get("trust_score", "?")
        passed = decision == "ALLOW"
        status = "PASS" if passed else "FAIL"
        print(f"  [{label}] Legitimate packet: {status} (decision={decision}, score={score})")
        return passed
    except Exception as exc:
        print(f"  [{label}] Legitimate packet: FAILED ({exc})")
        return False


def test_lateral_movement(pep_url: str, src_tenant: str, label: str) -> bool:
    """Send a cross-tenant packet -- must be BLOCKED."""
    raw = json.dumps({"probe": "cross-tenant"}).encode()
    token = generate_jwt(tenant_id=src_tenant, device_id="rogue_dev")
    combined = token.encode() + b"|" + raw
    encrypted = encrypt(combined, AES_KEY)

    try:
        resp = requests.post(
            f"{pep_url}/verify",
            data=encrypted,
            headers={"Content-Type": "application/octet-stream"},
            timeout=10,
        )
        data = resp.json()
        decision = data.get("decision", "?")
        reason = data.get("reason", "?")
        passed = decision == "BLOCK" and reason == "lateral_movement"
        status = "PASS" if passed else "FAIL"
        print(f"  [{label}] Lateral movement: {status} (decision={decision}, reason={reason})")
        return passed
    except Exception as exc:
        print(f"  [{label}] Lateral movement: FAILED ({exc})")
        return False


def main():
    parser = argparse.ArgumentParser(description="Verify AWS Deployment")
    parser.add_argument("--pep-a", required=True, help="PEP A URL, e.g. http://3.110.x.x:6000")
    parser.add_argument("--pep-b", required=True, help="PEP B URL, e.g. http://13.233.x.x:6000")
    args = parser.parse_args()

    _ensure_keypair()

    print("=" * 60)
    print("IoMT Zero Trust -- AWS Deployment Verification")
    print("=" * 60)

    results = []

    print("\n--- Step 1: Health Checks ---")
    results.append(test_health(args.pep_a, "PEP-A"))
    results.append(test_health(args.pep_b, "PEP-B"))

    print("\n--- Step 2: Legitimate Traffic (same-tenant) ---")
    results.append(test_legitimate_packet(args.pep_a, "tenant_A", "PEP-A"))
    results.append(test_legitimate_packet(args.pep_b, "tenant_B", "PEP-B"))

    print("\n--- Step 3: Lateral Movement (cross-tenant -- must BLOCK) ---")
    results.append(test_lateral_movement(args.pep_b, "tenant_A", "A->B"))
    results.append(test_lateral_movement(args.pep_a, "tenant_B", "B->A"))

    print("\n" + "=" * 60)
    passed = sum(results)
    total = len(results)
    print(f"Results: {passed}/{total} tests passed")

    if passed == total:
        print("AWS deployment is fully operational!")
    else:
        print("Some tests failed. Check the PEP servers and try again.")
        print("Common issues:")
        print("  - PEP server not running: SSH in and start it")
        print("  - Security group: ensure port 6000 is open")
        print("  - Key mismatch: ensure keys/ folder was deployed to EC2")

    print("=" * 60)
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
