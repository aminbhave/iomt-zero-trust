"""
Attack Script A -- Masquerading Attack.

Simulates a legitimate device for 50 seconds, then injects a sudden
3-sigma (500%) spike in payload size to test the DTSA's anomaly
detection capability.

Success Criterion (from paper):
    The system must detect the anomaly and quarantine the device
    within 180ms.

Usage:
    python -m simulator.attacker_masquerade [--sidecar-url URL]
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
import time
from pathlib import Path

import numpy as np
import requests

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

RESULTS_DIR = Path(__file__).resolve().parent.parent / "results"


def run_masquerade_attack(
    sidecar_url: str,
    normal_seconds: int = 50,
    attack_packets: int = 20,
    rate: float = 1.0,
    device_id: str = "ecg_monitor_001",
    tenant_id: str = "tenant_A",
):
    """Execute the masquerading attack scenario.

    Phase 1: Send normal ECG-sized payloads for *normal_seconds*.
    Phase 2: Inject payloads with 500% (3-sigma) spike in size.
    """
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    log_path = RESULTS_DIR / "masquerade_attack_log.csv"
    interval = 1.0 / rate

    normal_size = 2000   # typical ECG packet bytes
    sigma_size = 200
    attack_size = int(normal_size + 3 * sigma_size * 5)  # 500% spike

    results = []

    # ── Phase 1: Normal traffic ─────────────────────────────────────────
    normal_count = int(normal_seconds * rate)
    print(f"[Masquerade] Phase 1: Sending {normal_count} normal packets ({normal_size} bytes)")

    for i in range(normal_count):
        noise = np.random.normal(0, 50)
        payload = {
            "device_id": device_id,
            "tenant_id": tenant_id,
            "timestamp": time.time(),
            "seq": i,
            "ecg_samples": list(np.random.randn(int(normal_size / 8 + noise)).tolist()),
        }
        raw = json.dumps(payload)

        t0 = time.perf_counter()
        try:
            resp = requests.post(
                sidecar_url,
                data=raw,
                headers={"Content-Type": "application/json"},
                timeout=5,
            )
            latency_ms = (time.perf_counter() - t0) * 1000
            resp_data = resp.json() if resp.headers.get("content-type", "").startswith("application") else {}
        except Exception as exc:
            latency_ms = (time.perf_counter() - t0) * 1000
            resp_data = {"error": str(exc)}

        decision = resp_data.get("decision", resp_data.get("status", "unknown"))
        results.append({
            "timestamp": time.time(),
            "device_id": device_id,
            "event_type": "normal",
            "payload_size": len(raw),
            "trust_score": resp_data.get("trust_score", ""),
            "decision": decision,
            "detection_latency_ms": round(latency_ms, 2),
            "is_false_positive": 1 if decision in ("QUARANTINE", "STEP_UP_AUTH") else 0,
        })

        if (i + 1) % 10 == 0:
            print(f"  [{i+1}/{normal_count}] size={len(raw)} decision={decision}")

        time.sleep(interval)

    # ── Phase 2: Attack traffic (3-sigma spike) ─────────────────────────
    print(f"\n[Masquerade] Phase 2: Injecting {attack_packets} ATTACK packets ({attack_size} bytes)")

    quarantine_detected = False
    detection_latency = None

    for i in range(attack_packets):
        bloated_samples = list(np.random.randn(attack_size // 8).tolist())
        payload = {
            "device_id": device_id,
            "tenant_id": tenant_id,
            "timestamp": time.time(),
            "seq": normal_count + i,
            "ecg_samples": bloated_samples,
        }
        raw = json.dumps(payload)

        t0 = time.perf_counter()
        try:
            resp = requests.post(
                sidecar_url,
                data=raw,
                headers={"Content-Type": "application/json"},
                timeout=5,
            )
            latency_ms = (time.perf_counter() - t0) * 1000
            resp_data = resp.json() if resp.headers.get("content-type", "").startswith("application") else {}
        except Exception as exc:
            latency_ms = (time.perf_counter() - t0) * 1000
            resp_data = {"error": str(exc)}

        decision = resp_data.get("decision", resp_data.get("status", "unknown"))

        if decision == "QUARANTINE" and not quarantine_detected:
            quarantine_detected = True
            detection_latency = latency_ms
            print(f"  *** QUARANTINE detected at packet {i+1} in {latency_ms:.1f}ms ***")

        results.append({
            "timestamp": time.time(),
            "device_id": device_id,
            "event_type": "masquerade_attack",
            "payload_size": len(raw),
            "trust_score": resp_data.get("trust_score", ""),
            "decision": decision,
            "detection_latency_ms": round(latency_ms, 2),
            "is_false_positive": 0,
        })

        print(f"  [ATK {i+1}/{attack_packets}] size={len(raw)} decision={decision} latency={latency_ms:.1f}ms")
        time.sleep(interval)

    # ── Write CSV log ───────────────────────────────────────────────────
    with open(log_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=results[0].keys())
        writer.writeheader()
        writer.writerows(results)

    # ── Summary ─────────────────────────────────────────────────────────
    print("\n=== Masquerade Attack Summary ===")
    print(f"  Normal packets sent:   {normal_count}")
    print(f"  Attack packets sent:   {attack_packets}")
    print(f"  Quarantine detected:   {'YES' if quarantine_detected else 'NO'}")
    if detection_latency is not None:
        print(f"  Detection latency:     {detection_latency:.1f}ms {'(<180ms PASS)' if detection_latency < 180 else '(>180ms FAIL)'}")
    fp = sum(1 for r in results if r["event_type"] == "normal" and r["is_false_positive"])
    print(f"  False positives:       {fp}/{normal_count} ({100*fp/max(normal_count,1):.1f}%)")
    print(f"  Log saved to:          {log_path}")

    return results


def main():
    parser = argparse.ArgumentParser(description="Masquerading Attack Simulator")
    parser.add_argument("--sidecar-url", default="http://localhost:8000/ingest")
    parser.add_argument("--normal-seconds", type=int, default=50)
    parser.add_argument("--attack-packets", type=int, default=20)
    parser.add_argument("--rate", type=float, default=1.0)
    args = parser.parse_args()

    run_masquerade_attack(
        sidecar_url=args.sidecar_url,
        normal_seconds=args.normal_seconds,
        attack_packets=args.attack_packets,
        rate=args.rate,
    )


if __name__ == "__main__":
    main()
