"""
RS256 JWT identity injection module.

Generates short-lived tokens that cryptographically bind a legacy device
to its tenant identity, enabling the Tenant Isolation Theorem check on
the cloud PEP.
"""

import os
import time

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from . import config


def _ensure_keypair() -> None:
    """Generate an RSA-2048 key pair if one does not already exist."""
    if os.path.exists(config.PRIVATE_KEY_PATH) and os.path.exists(config.PUBLIC_KEY_PATH):
        return

    os.makedirs(config.KEYS_DIR, exist_ok=True)

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    with open(config.PRIVATE_KEY_PATH, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    with open(config.PUBLIC_KEY_PATH, "wb") as f:
        f.write(
            private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )


def _load_key(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


def generate_jwt(
    tenant_id: str | None = None,
    device_id: str | None = None,
    private_key_pem: bytes | None = None,
) -> str:
    """Create a signed JWT containing tenant and device identity.

    Parameters
    ----------
    tenant_id : str, optional
        Defaults to ``config.TENANT_ID``.
    device_id : str, optional
        Defaults to ``config.DEVICE_ID``.
    private_key_pem : bytes, optional
        PEM-encoded RSA private key.  If *None*, loads from disk
        (generating a key pair first if necessary).
    """
    _ensure_keypair()

    tenant_id = tenant_id or config.TENANT_ID
    device_id = device_id or config.DEVICE_ID

    if private_key_pem is None:
        private_key_pem = _load_key(config.PRIVATE_KEY_PATH)

    now = int(time.time())
    payload = {
        "iss": config.SIDECAR_ISS,
        "iat": now,
        "exp": now + config.JWT_EXPIRY_SECONDS,
        "tid": tenant_id,
        "did": device_id,
    }

    return jwt.encode(payload, private_key_pem, algorithm=config.JWT_ALGORITHM)


def verify_jwt(token: str, public_key_pem: bytes | None = None) -> dict:
    """Decode and verify a JWT, returning its claims.

    Raises
    ------
    jwt.ExpiredSignatureError
        If the token has expired.
    jwt.InvalidSignatureError
        If the signature does not match.
    """
    if public_key_pem is None:
        public_key_pem = _load_key(config.PUBLIC_KEY_PATH)

    return jwt.decode(
        token,
        public_key_pem,
        algorithms=[config.JWT_ALGORITHM],
        options={"require": ["exp", "tid", "did"]},
    )
