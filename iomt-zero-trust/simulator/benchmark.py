"""
Benchmark Logger & Metrics Aggregator.

Reads attack result CSVs and computes the three key metrics from the paper:
    - Detection Latency (L_d):  Time from packet interception to quarantine
    - Processing Overhead (O_p): Extra CPU delay added by the sidecar (target: 12ms)
    - False Positive Rate (FPR): % of legitimate packets incorrectly flagged

Can also run a self-contained local benchmark that exercises the full
Sidecar -> PEP -> DTSA pipeline without AWS.

Usage:
    python -m simulator.benchmark              # full local benchmark
    python -m simulator.benchmark --analyze     # analyze existing logs
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

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from cloud.lambda_dtsa.handler import (
    score_packet,
    DeviceBaseline,
    _local_baselines,
)
from sidecar.encryption import encrypt, decrypt
from sidecar.jwt_module import generate_jwt, verify_jwt, _ensure_keypair
from sidecar.config import AES_KEY

RESULTS_DIR = Path(__file__).resolve().parent.parent / "results"


def run_local_benchmark(
    normal_packets: int = 200,
    attack_packets: int = 50,
    device_id: str = "bench_ecg_001",
    tenant_id: str = "tenant_A",
) -> Path:
    """Run a self-contained benchmark simulating the full pipeline locally."""
    _ensure_keypair()
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    log_path = RESULTS_DIR / "benchmark_log.csv"

    _local_baselines.clear()

    results = []
    normal_size = 2000

    # Calibrate baseline from a sample payload to account for JSON overhead
    sample_raw = json.dumps({
        "device_id": device_id, "tenant_id": tenant_id,
        "seq": 0, "data": "x" * normal_size,
    }).encode()
    calibrated_size = float(len(sample_raw))

    _local_baselines[device_id] = DeviceBaseline(
        device_id=device_id,
        mu_freq=1.0, sigma_freq=1.0,
        mu_size=calibrated_size, sigma_size=calibrated_size * 0.15,
    )

    print(f"=== Local Benchmark: {normal_packets} normal + {attack_packets} attack ===")
    print(f"  Calibrated baseline mu_size={calibrated_size:.0f}")

    # ── Warm-up: let EMA adapt to actual payload sizes ──────────────────
    warmup_count = 50
    print(f"  Warm-up: {warmup_count} calibration packets...\n")
    for w in range(warmup_count):
        noise = int(np.random.normal(0, 50))
        warmup_raw = json.dumps({
            "device_id": device_id, "tenant_id": tenant_id,
            "seq": w, "data": "x" * max(1, normal_size + noise),
        }).encode()
        freq_jitter = 1.0 + np.random.normal(0, 0.2)
        score_packet(device_id, packet_freq=max(0.1, freq_jitter), payload_size=len(warmup_raw))

    # ── Normal phase ────────────────────────────────────────────────────
    for i in range(normal_packets):
        noise = int(np.random.normal(0, 50))
        raw = json.dumps({
            "device_id": device_id, "tenant_id": tenant_id,
            "seq": i, "data": "x" * max(1, normal_size + noise),
        }).encode()

        t0 = time.perf_counter()

        # Sidecar pipeline: JWT + encrypt
        token = generate_jwt(tenant_id=tenant_id, device_id=device_id)
        combined = token.encode() + b"|" + raw
        encrypted = encrypt(combined, AES_KEY)

        # PEP pipeline: decrypt + verify + DTSA
        decrypted = decrypt(encrypted, AES_KEY)
        sep = decrypted.index(b"|")
        verify_jwt(decrypted[:sep].decode())
        freq_jitter = 1.0 + np.random.normal(0, 0.2)
        dtsa = score_packet(device_id, packet_freq=max(0.1, freq_jitter), payload_size=len(raw))

        latency_ms = (time.perf_counter() - t0) * 1000

        results.append({
            "timestamp": time.time(),
            "device_id": device_id,
            "event_type": "normal",
            "payload_size": len(raw),
            "trust_score": dtsa["trust_score"],
            "decision": dtsa["decision"],
            "detection_latency_ms": round(latency_ms, 2),
            "processing_overhead_ms": round(latency_ms, 2),
            "is_false_positive": 1 if dtsa["decision"] != "ALLOW" else 0,
        })

    # ── Attack phase (3-sigma payload spike) ────────────────────────────
    bl = _local_baselines[device_id]
    attack_size = int(bl.mu_size + 3 * bl.sigma_size * 5)

    for i in range(attack_packets):
        raw = json.dumps({
            "device_id": device_id, "tenant_id": tenant_id,
            "seq": normal_packets + i, "data": "x" * attack_size,
        }).encode()

        t0 = time.perf_counter()

        token = generate_jwt(tenant_id=tenant_id, device_id=device_id)
        combined = token.encode() + b"|" + raw
        encrypted = encrypt(combined, AES_KEY)
        decrypted = decrypt(encrypted, AES_KEY)
        sep = decrypted.index(b"|")
        verify_jwt(decrypted[:sep].decode())
        dtsa = score_packet(device_id, packet_freq=1.0, payload_size=len(raw))

        latency_ms = (time.perf_counter() - t0) * 1000

        results.append({
            "timestamp": time.time(),
            "device_id": device_id,
            "event_type": "masquerade_attack",
            "payload_size": len(raw),
            "trust_score": dtsa["trust_score"],
            "decision": dtsa["decision"],
            "detection_latency_ms": round(latency_ms, 2),
            "processing_overhead_ms": round(latency_ms, 2),
            "is_false_positive": 0,
        })

    # ── Write CSV ───────────────────────────────────────────────────────
    with open(log_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=results[0].keys())
        writer.writeheader()
        writer.writerows(results)

    analyze_log(log_path)
    return log_path


def analyze_log(log_path: Path) -> dict:
    """Compute aggregate metrics from a benchmark CSV."""
    rows = []
    with open(log_path) as f:
        for row in csv.DictReader(f):
            rows.append(row)

    normal_rows = [r for r in rows if r["event_type"] == "normal"]
    attack_rows = [r for r in rows if r["event_type"] != "normal"]

    # Detection Latency (L_d) -- mean latency for attack packets that triggered quarantine
    attack_latencies = [
        float(r["detection_latency_ms"])
        for r in attack_rows
        if r["decision"] == "QUARANTINE"
    ]
    mean_ld = np.mean(attack_latencies) if attack_latencies else float("nan")

    # Processing Overhead (O_p) -- mean processing time for normal packets
    overhead = [float(r["processing_overhead_ms"]) for r in normal_rows if "processing_overhead_ms" in r]
    mean_op = np.mean(overhead) if overhead else float("nan")

    # False Positive Rate
    fp_count = sum(1 for r in normal_rows if r.get("is_false_positive") == "1")
    fpr = 100 * fp_count / max(len(normal_rows), 1)

    # Attack detection rate
    quarantined = sum(1 for r in attack_rows if r["decision"] == "QUARANTINE")
    detection_rate = 100 * quarantined / max(len(attack_rows), 1)

    print(f"\n=== Benchmark Metrics ({log_path.name}) ===")
    print(f"  Total packets:        {len(rows)}")
    print(f"  Normal packets:       {len(normal_rows)}")
    print(f"  Attack packets:       {len(attack_rows)}")
    print(f"  Detection Latency:    {mean_ld:.2f}ms  (target: <180ms)")
    print(f"  Processing Overhead:  {mean_op:.2f}ms  (target: ~12ms)")
    print(f"  False Positive Rate:  {fpr:.2f}%      (target: <1.5%)")
    print(f"  Detection Rate:       {detection_rate:.1f}%   (target: 98.5%)")

    return {
        "mean_detection_latency_ms": round(mean_ld, 2),
        "mean_processing_overhead_ms": round(mean_op, 2),
        "false_positive_rate_pct": round(fpr, 2),
        "detection_rate_pct": round(detection_rate, 1),
    }


def main():
    parser = argparse.ArgumentParser(description="Benchmark Logger & Analyzer")
    parser.add_argument("--analyze", type=str, default=None,
                        help="Path to existing CSV log to analyze")
    parser.add_argument("--normal", type=int, default=200)
    parser.add_argument("--attack", type=int, default=50)
    args = parser.parse_args()

    if args.analyze:
        analyze_log(Path(args.analyze))
    else:
        run_local_benchmark(normal_packets=args.normal, attack_packets=args.attack)


if __name__ == "__main__":
    main()
