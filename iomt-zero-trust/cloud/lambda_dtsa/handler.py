"""
Dynamic Trust Scoring Algorithm (DTSA) -- AWS Lambda Handler.

Implements the mathematical core from the IEEE paper:

    δ(x) = |x_obs - μ_x| / (σ_x + ε)
    T(d) = 100 - (α·δ(v_f) + β·δ(v_s) + γ·δ(v_g))

Baselines (μ, σ) are stored in DynamoDB and updated via Exponential
Moving Average (EMA) on every ALLOW decision.

Can run as a standalone module for local testing or as a Lambda function.
"""

from __future__ import annotations

import json
import logging
import math
import os
import time
from dataclasses import dataclass, field
from typing import Any

log = logging.getLogger(__name__)
log.setLevel(logging.INFO)

# ── DTSA hyper-parameters (from paper, §IV-B) ──────────────────────────

ALPHA = float(os.getenv("DTSA_ALPHA", "30"))     # packet-frequency weight
BETA = float(os.getenv("DTSA_BETA", "50"))         # payload-size weight
GAMMA = float(os.getenv("DTSA_GAMMA", "20"))       # geo-velocity weight
THETA = float(os.getenv("DTSA_THETA", "60"))       # trust threshold
EMA_ALPHA = float(os.getenv("DTSA_EMA_ALPHA", "0.1"))  # EMA smoothing
EPSILON = 1e-6


assert abs(ALPHA + BETA + GAMMA - 100) < 1e-9, "α+β+γ must equal 100"


# ── Data structures ────────────────────────────────────────────────────

@dataclass
class DeviceBaseline:
    """Per-device EMA baselines stored in DynamoDB."""
    device_id: str
    mu_freq: float = 1.0
    sigma_freq: float = 0.1
    mu_size: float = 2000.0
    sigma_size: float = 200.0
    mu_geo: float = 0.0
    sigma_geo: float = 0.01
    packet_count: int = 0
    last_updated: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "device_id": self.device_id,
            "mu_freq": str(self.mu_freq),
            "sigma_freq": str(self.sigma_freq),
            "mu_size": str(self.mu_size),
            "sigma_size": str(self.sigma_size),
            "mu_geo": str(self.mu_geo),
            "sigma_geo": str(self.sigma_geo),
            "packet_count": self.packet_count,
            "last_updated": str(self.last_updated),
        }

    @classmethod
    def from_dynamo(cls, item: dict) -> "DeviceBaseline":
        return cls(
            device_id=item["device_id"],
            mu_freq=float(item.get("mu_freq", 1.0)),
            sigma_freq=float(item.get("sigma_freq", 0.1)),
            mu_size=float(item.get("mu_size", 2000.0)),
            sigma_size=float(item.get("sigma_size", 200.0)),
            mu_geo=float(item.get("mu_geo", 0.0)),
            sigma_geo=float(item.get("sigma_geo", 0.01)),
            packet_count=int(item.get("packet_count", 0)),
            last_updated=float(item.get("last_updated", time.time())),
        )


# ── In-memory baseline store (local/testing fallback) ──────────────────

_local_baselines: dict[str, DeviceBaseline] = {}


def get_baseline(device_id: str, dynamo_table=None) -> DeviceBaseline:
    """Retrieve the baseline for *device_id* from DynamoDB or local cache."""
    if dynamo_table is not None:
        resp = dynamo_table.get_item(Key={"device_id": device_id})
        if "Item" in resp:
            return DeviceBaseline.from_dynamo(resp["Item"])

    if device_id in _local_baselines:
        return _local_baselines[device_id]

    bl = DeviceBaseline(device_id=device_id)
    _local_baselines[device_id] = bl
    return bl


def save_baseline(bl: DeviceBaseline, dynamo_table=None) -> None:
    """Persist the updated baseline."""
    _local_baselines[bl.device_id] = bl
    if dynamo_table is not None:
        dynamo_table.put_item(Item=bl.to_dict())


# ── Core math (paper equations 2 & 3) ──────────────────────────────────

def deviation(x_obs: float, mu: float, sigma: float) -> float:
    """Eq. 2: δ(x) = |x_obs - μ_x| / (σ_x + ε)"""
    return abs(x_obs - mu) / (sigma + EPSILON)


def calculate_trust_score(
    delta_freq: float,
    delta_size: float,
    delta_geo: float,
) -> float:
    """Eq. 3: T(d) = 100 - (α·δ(v_f) + β·δ(v_s) + γ·δ(v_g))"""
    raw = 100.0 - (ALPHA * delta_freq + BETA * delta_size + GAMMA * delta_geo)
    return max(0.0, min(100.0, raw))


def decide(trust_score: float) -> str:
    """Map trust score to an enforcement decision.

    T >= 60   -> ALLOW
    40 <= T   -> STEP_UP_AUTH  (trigger MFA)
    T < 40    -> QUARANTINE    (sever connection)
    """
    if trust_score >= THETA:
        return "ALLOW"
    elif trust_score >= 40:
        return "STEP_UP_AUTH"
    else:
        return "QUARANTINE"


def update_ema(current_mu: float, x_obs: float) -> float:
    """Exponential Moving Average baseline adaptation."""
    return EMA_ALPHA * x_obs + (1.0 - EMA_ALPHA) * current_mu


def update_sigma_ema(current_sigma: float, x_obs: float, mu: float) -> float:
    """EMA-based running standard deviation update.

    Uses a one-sided update: sigma can grow to accommodate observed
    variance, but never shrinks below a floor.  This prevents the
    classic EMA-sigma collapse problem that causes false positives
    from natural payload jitter.
    """
    instantaneous_dev = abs(x_obs - mu)
    ema_sigma = EMA_ALPHA * instantaneous_dev + (1.0 - EMA_ALPHA) * current_sigma
    # Never shrink below the starting sigma
    return max(ema_sigma, current_sigma)


# ── Scoring pipeline ──────────────────────────────────────────────────

def score_packet(
    device_id: str,
    packet_freq: float,
    payload_size: float,
    geo_velocity: float = 0.0,
    dynamo_table=None,
) -> dict[str, Any]:
    """Run the full DTSA pipeline for a single packet.

    Returns a dict with trust_score, decision, deviations, and timing.
    """
    t0 = time.perf_counter()

    bl = get_baseline(device_id, dynamo_table)

    d_freq = deviation(packet_freq, bl.mu_freq, bl.sigma_freq)
    d_size = deviation(payload_size, bl.mu_size, bl.sigma_size)
    d_geo = deviation(geo_velocity, bl.mu_geo, bl.sigma_geo)

    trust = calculate_trust_score(d_freq, d_size, d_geo)
    decision = decide(trust)

    # Update baselines on ALLOW
    if decision == "ALLOW":
        bl.mu_freq = update_ema(bl.mu_freq, packet_freq)
        bl.sigma_freq = update_sigma_ema(bl.sigma_freq, packet_freq, bl.mu_freq)
        bl.mu_size = update_ema(bl.mu_size, payload_size)
        bl.sigma_size = update_sigma_ema(bl.sigma_size, payload_size, bl.mu_size)
        bl.mu_geo = update_ema(bl.mu_geo, geo_velocity)
        bl.sigma_geo = update_sigma_ema(bl.sigma_geo, geo_velocity, bl.mu_geo)
        bl.packet_count += 1
        bl.last_updated = time.time()
        save_baseline(bl, dynamo_table)

    elapsed_ms = (time.perf_counter() - t0) * 1000

    result = {
        "device_id": device_id,
        "trust_score": round(trust, 2),
        "decision": decision,
        "delta_freq": round(d_freq, 4),
        "delta_size": round(d_size, 4),
        "delta_geo": round(d_geo, 4),
        "detection_latency_ms": round(elapsed_ms, 2),
    }

    log.info("DTSA  %s", json.dumps(result))
    return result


# ── AWS Lambda entry point ────────────────────────────────────────────

_dynamo_table = None


def _get_dynamo_table():
    """Lazy-init the DynamoDB table resource (only in Lambda)."""
    global _dynamo_table
    if _dynamo_table is None:
        table_name = os.getenv("DTSA_TABLE_NAME", "DeviceBaselines")
        try:
            import boto3
            _dynamo_table = boto3.resource("dynamodb").Table(table_name)
        except Exception:
            log.warning("DynamoDB unavailable -- using in-memory baselines")
    return _dynamo_table


def lambda_handler(event: dict, context: Any = None) -> dict:
    """AWS Lambda handler.

    Expects:
        {
            "device_id": str,
            "packet_freq": float,
            "payload_size": float,
            "geo_velocity": float  (optional, default 0)
        }
    """
    body = event if isinstance(event, dict) else json.loads(event)

    result = score_packet(
        device_id=body["device_id"],
        packet_freq=body["packet_freq"],
        payload_size=body["payload_size"],
        geo_velocity=body.get("geo_velocity", 0.0),
        dynamo_table=_get_dynamo_table(),
    )

    return {
        "statusCode": 200,
        "body": json.dumps(result),
    }
