"""Integration tests for the Policy Enforcement Point (PEP) server."""

import json
import os
import pytest

# Ensure PEP tenant matches test scenario
os.environ.setdefault("PEP_TENANT_ID", "tenant_A")

from cloud.pep.pep_server import app as flask_app, _packet_windows
from cloud.lambda_dtsa.handler import _local_baselines, DeviceBaseline
from sidecar.encryption import encrypt
from sidecar.jwt_module import generate_jwt, _ensure_keypair
from sidecar.config import AES_KEY


@pytest.fixture
def client():
    flask_app.config["TESTING"] = True
    with flask_app.test_client() as c:
        yield c


@pytest.fixture(autouse=True)
def setup_keys_and_baselines():
    _ensure_keypair()
    _local_baselines.clear()
    _packet_windows.clear()
    yield
    _local_baselines.clear()
    _packet_windows.clear()


def _make_encrypted_payload(tenant_id: str, device_id: str, raw: bytes) -> str:
    """Helper: JWT + raw -> AES-256-GCM encrypted base64 string."""
    token = generate_jwt(tenant_id=tenant_id, device_id=device_id)
    combined = token.encode() + b"|" + raw
    return encrypt(combined, AES_KEY)


class TestPEP:
    def test_health(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json["tenant"] == "tenant_A"

    def test_legitimate_packet_allowed(self, client):
        raw = json.dumps({"ecg": [0.5, 0.6, 0.7]}).encode()
        # Seed baseline matching this payload size and expected frequency
        _local_baselines["ecg_001"] = DeviceBaseline(
            device_id="ecg_001",
            mu_freq=0.1, sigma_freq=0.5,
            mu_size=len(raw), sigma_size=50.0,
        )
        payload = _make_encrypted_payload("tenant_A", "ecg_001", raw)
        resp = client.post(
            "/verify",
            data=payload,
            content_type="application/octet-stream",
        )
        data = resp.json
        assert data["decision"] == "ALLOW"
        assert data["trust_score"] >= 60

    def test_lateral_movement_blocked(self, client):
        """Tenant B device trying to reach Tenant A PEP -> BLOCK."""
        raw = json.dumps({"probe": "cross-tenant"}).encode()
        payload = _make_encrypted_payload("tenant_B", "rogue_device", raw)
        resp = client.post(
            "/verify",
            data=payload,
            content_type="application/octet-stream",
        )
        assert resp.status_code == 403
        assert resp.json["decision"] == "BLOCK"
        assert resp.json["reason"] == "lateral_movement"

    def test_tampered_payload_rejected(self, client):
        payload = _make_encrypted_payload("tenant_A", "dev1", b"data")
        # Corrupt the ciphertext
        corrupted = payload[:10] + "XXXX" + payload[14:]
        resp = client.post(
            "/verify",
            data=corrupted,
            content_type="application/octet-stream",
        )
        assert resp.status_code == 403
        assert resp.json["reason"] == "decryption_failure"

    def test_malformed_payload_rejected(self, client):
        # Encrypt payload without the "|" separator
        from sidecar.encryption import encrypt as enc
        bad = enc(b"no-separator-here", AES_KEY)
        resp = client.post(
            "/verify",
            data=bad,
            content_type="application/octet-stream",
        )
        assert resp.status_code in (400, 403)
