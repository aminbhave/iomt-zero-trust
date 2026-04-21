"""
Policy Enforcement Point (PEP) -- Flask server deployed on EC2.

Receives AES-256-GCM encrypted payloads from the Sidecar Proxy,
decrypts them, validates the JWT, enforces the Tenant Isolation
Theorem, and delegates behavioral scoring to the DTSA engine.

Usage:
    python -m cloud.pep.pep_server          (local testing)
    flask --app cloud.pep.pep_server run    (production on EC2)
"""

from __future__ import annotations

import json
import logging
import os
import sys
import time
from collections import defaultdict

from flask import Flask, request, jsonify

# Allow imports from project root when running standalone
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from sidecar.encryption import decrypt
from sidecar.jwt_module import verify_jwt
from sidecar.config import AES_KEY
from cloud.lambda_dtsa.handler import score_packet

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [PEP] %(levelname)s  %(message)s",
)
log = logging.getLogger(__name__)

app = Flask(__name__)

# The tenant this PEP instance is responsible for (set via env var on each EC2)
PEP_TENANT_ID = os.getenv("PEP_TENANT_ID", "tenant_A")

# Sliding window for packet frequency estimation (device_id -> timestamps)
_packet_windows: dict[str, list[float]] = defaultdict(list)
WINDOW_SIZE = 10.0  # seconds


def _compute_packet_freq(device_id: str) -> float:
    """Estimate packets/sec over the last WINDOW_SIZE seconds."""
    now = time.time()
    window = _packet_windows[device_id]
    window.append(now)
    # Prune old entries
    _packet_windows[device_id] = [t for t in window if now - t <= WINDOW_SIZE]
    count = len(_packet_windows[device_id])
    return count / WINDOW_SIZE


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "tenant": PEP_TENANT_ID})


@app.route("/verify", methods=["POST"])
def verify():
    """Core PEP pipeline: decrypt -> JWT validate -> tenant check -> DTSA."""
    t_start = time.perf_counter()

    # ── Step 1: Decrypt ─────────────────────────────────────────────────
    encrypted_payload = request.get_data(as_text=True)
    try:
        decrypted = decrypt(encrypted_payload, AES_KEY)
    except Exception as exc:
        log.error("Decryption failed: %s", exc)
        return jsonify({"decision": "BLOCK", "reason": "decryption_failure"}), 403

    # ── Step 2: Split JWT | raw_data ────────────────────────────────────
    sep = decrypted.find(b"|")
    if sep == -1:
        return jsonify({"decision": "BLOCK", "reason": "malformed_payload"}), 400

    jwt_bytes = decrypted[:sep]
    raw_data = decrypted[sep + 1:]

    # ── Step 3: Validate JWT ────────────────────────────────────────────
    try:
        claims = verify_jwt(jwt_bytes.decode("utf-8"))
    except Exception as exc:
        log.warning("JWT validation failed: %s", exc)
        return jsonify({"decision": "BLOCK", "reason": "jwt_invalid"}), 403

    src_tenant = claims["tid"]
    device_id = claims["did"]

    # ── Step 4: Tenant Isolation Theorem check ──────────────────────────
    # Theorem: IF Tenant(src) != Tenant(dest) -> BLOCK
    if src_tenant != PEP_TENANT_ID:
        log.critical(
            "LATERAL MOVEMENT DETECTED  src_tenant=%s  pep_tenant=%s  device=%s",
            src_tenant,
            PEP_TENANT_ID,
            device_id,
        )
        elapsed_ms = (time.perf_counter() - t_start) * 1000
        return jsonify({
            "decision": "BLOCK",
            "reason": "lateral_movement",
            "src_tenant": src_tenant,
            "pep_tenant": PEP_TENANT_ID,
            "detection_latency_ms": round(elapsed_ms, 2),
        }), 403

    # ── Step 5: DTSA behavioral scoring ─────────────────────────────────
    source_ip = request.headers.get("X-Source-IP", request.remote_addr)
    packet_freq = _compute_packet_freq(device_id)
    payload_size = len(raw_data)

    dtsa_result = score_packet(
        device_id=device_id,
        packet_freq=packet_freq,
        payload_size=payload_size,
        geo_velocity=0.0,  # PoC: derived from IP changes in production
    )

    elapsed_ms = (time.perf_counter() - t_start) * 1000
    dtsa_result["total_latency_ms"] = round(elapsed_ms, 2)
    dtsa_result["src_tenant"] = src_tenant

    status_code = 200 if dtsa_result["decision"] == "ALLOW" else 403
    log.info(
        "device=%s  tenant=%s  score=%.1f  decision=%s  latency=%.1fms",
        device_id,
        src_tenant,
        dtsa_result["trust_score"],
        dtsa_result["decision"],
        elapsed_ms,
    )

    return jsonify(dtsa_result), status_code


if __name__ == "__main__":
    port = int(os.getenv("PEP_PORT", "6000"))
    app.run(host="0.0.0.0", port=port, debug=False)
