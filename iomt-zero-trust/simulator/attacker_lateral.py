"""
Attack Script B -- Lateral Movement Attack.

An adversary compromises a device in VPC A (tenant_A) and attempts
to send packets to the PEP in VPC B (tenant_B).  The Tenant Isolation
Theorem requires 100% of these cross-tenant packets to be blocked.

Success Criterion (from paper):
    PEP must block 100% of requests where T_src != T_dest.

Usage:
    python -m simulator.attacker_lateral [--pep-url URL]
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
import time
from pathlib import Path

import requests

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sidecar.encryption import encrypt
from sidecar.jwt_module import generate_jwt, _ensure_keypair
from sidecar.config import AES_KEY

RESULTS_DIR = Path(__file__).resolve().parent.parent / "results"


def run_lateral_movement_attack(
    pep_url: str,
    packet_count: int = 100,
    src_tenant: str = "tenant_A",
    dest_tenant: str = "tenant_B",
    device_id: str = "compromised_dev_001",
):
    """Send cross-tenant packets directly to the opposing PEP.

    Each packet carries a JWT signed for *src_tenant* but is sent to
    the PEP that is configured for *dest_tenant*.
    """
    _ensure_keypair()

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    log_path = RESULTS_DIR / "lateral_movement_log.csv"

    results = []
    blocked = 0

    print(
        f"[LateralMovement] Sending {packet_count} cross-tenant packets\n"
        f"  src_tenant={src_tenant}  ->  dest_pep={dest_tenant}\n"
        f"  PEP endpoint: {pep_url}"
    )

    for i in range(packet_count):
        raw = json.dumps({
            "device_id": device_id,
            "tenant_id": src_tenant,
            "timestamp": time.time(),
            "seq": i,
            "probe": "cross-tenant-ping",
        }).encode()

        token = generate_jwt(tenant_id=src_tenant, device_id=device_id)
        combined = token.encode() + b"|" + raw
        encrypted = encrypt(combined, AES_KEY)

        t0 = time.perf_counter()
        try:
            resp = requests.post(
                pep_url,
                data=encrypted,
                headers={"Content-Type": "application/octet-stream"},
                timeout=5,
            )
            latency_ms = (time.perf_counter() - t0) * 1000
            resp_data = resp.json()
        except Exception as exc:
            latency_ms = (time.perf_counter() - t0) * 1000
            resp_data = {"decision": "ERROR", "reason": str(exc)}

        decision = resp_data.get("decision", "unknown")
        reason = resp_data.get("reason", "")

        if decision == "BLOCK" and reason == "lateral_movement":
            blocked += 1

        results.append({
            "timestamp": time.time(),
            "device_id": device_id,
            "event_type": "lateral_movement",
            "src_tenant": src_tenant,
            "dest_tenant": dest_tenant,
            "decision": decision,
            "reason": reason,
            "detection_latency_ms": round(latency_ms, 2),
        })

        if (i + 1) % 10 == 0:
            print(f"  [{i+1}/{packet_count}] decision={decision} reason={reason}")

    # ── Write CSV log ───────────────────────────────────────────────────
    with open(log_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=results[0].keys())
        writer.writeheader()
        writer.writerows(results)

    # ── Summary ─────────────────────────────────────────────────────────
    block_rate = 100 * blocked / packet_count
    print(f"\n=== Lateral Movement Attack Summary ===")
    print(f"  Packets sent:       {packet_count}")
    print(f"  Packets blocked:    {blocked}")
    print(f"  Block rate:         {block_rate:.1f}% {'(100% PASS)' if block_rate == 100 else '(FAIL)'}")
    print(f"  Log saved to:       {log_path}")

    return results


def main():
    parser = argparse.ArgumentParser(description="Lateral Movement Attack Simulator")
    parser.add_argument("--pep-url", default="http://localhost:6000/verify",
                        help="Target PEP endpoint (should be the WRONG tenant's PEP)")
    parser.add_argument("--packet-count", type=int, default=100)
    parser.add_argument("--src-tenant", default="tenant_A")
    parser.add_argument("--dest-tenant", default="tenant_B")
    args = parser.parse_args()

    run_lateral_movement_attack(
        pep_url=args.pep_url,
        packet_count=args.packet_count,
        src_tenant=args.src_tenant,
        dest_tenant=args.dest_tenant,
    )


if __name__ == "__main__":
    main()
