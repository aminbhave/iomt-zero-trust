"""Unit tests for RS256 JWT identity injection module."""

import time
import pytest

from sidecar.jwt_module import generate_jwt, verify_jwt, _ensure_keypair, _load_key
from sidecar import config


@pytest.fixture(autouse=True)
def setup_keys():
    """Ensure RSA key pair exists for all tests."""
    _ensure_keypair()


class TestJWT:
    def test_generate_and_verify(self):
        token = generate_jwt(tenant_id="tenant_A", device_id="ecg_001")
        claims = verify_jwt(token)
        assert claims["tid"] == "tenant_A"
        assert claims["did"] == "ecg_001"
        assert claims["iss"] == config.SIDECAR_ISS

    def test_default_identity(self):
        token = generate_jwt()
        claims = verify_jwt(token)
        assert claims["tid"] == config.TENANT_ID
        assert claims["did"] == config.DEVICE_ID

    def test_expired_token_rejected(self):
        private_key = _load_key(config.PRIVATE_KEY_PATH)
        import jwt as pyjwt

        payload = {
            "iss": "test",
            "iat": int(time.time()) - 600,
            "exp": int(time.time()) - 300,  # expired 5 min ago
            "tid": "tenant_A",
            "did": "device_1",
        }
        token = pyjwt.encode(payload, private_key, algorithm="RS256")

        with pytest.raises(pyjwt.ExpiredSignatureError):
            verify_jwt(token)

    def test_tampered_signature_rejected(self):
        token = generate_jwt(tenant_id="tenant_A", device_id="dev_1")
        parts = token.split(".")
        # Corrupt the signature
        parts[2] = parts[2][::-1]
        tampered = ".".join(parts)

        with pytest.raises(Exception):
            verify_jwt(tampered)

    def test_claims_contain_required_fields(self):
        token = generate_jwt(tenant_id="tenant_B", device_id="pump_002")
        claims = verify_jwt(token)
        for field in ("iss", "iat", "exp", "tid", "did"):
            assert field in claims

    def test_tenant_id_preserved_exactly(self):
        for tid in ("hospital_alpha", "clinic-99", "TENANT_X"):
            token = generate_jwt(tenant_id=tid, device_id="d")
            assert verify_jwt(token)["tid"] == tid
