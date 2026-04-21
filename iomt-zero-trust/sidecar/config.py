"""
Configuration for the IoMT Zero Trust Sidecar Proxy.
Centralizes tenant identity, device metadata, key paths, and cloud endpoints.
"""

import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KEYS_DIR = os.path.join(BASE_DIR, "keys")

# --- Identity ---
TENANT_ID = os.getenv("IOMT_TENANT_ID", "tenant_A")
DEVICE_ID = os.getenv("IOMT_DEVICE_ID", "ecg_monitor_001")
SIDECAR_ISS = os.getenv("IOMT_SIDECAR_ISS", "sidecar-proxy-001")

# --- RSA Keys (RS256 JWT signing) ---
PRIVATE_KEY_PATH = os.path.join(KEYS_DIR, "private_key.pem")
PUBLIC_KEY_PATH = os.path.join(KEYS_DIR, "public_key.pem")

# --- AES-256-GCM Shared Key (32 bytes, hex-encoded in env) ---
# In production this would come from AWS KMS; for PoC we use a static key.
_DEFAULT_AES_HEX = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
AES_KEY = bytes.fromhex(os.getenv("IOMT_AES_KEY_HEX", _DEFAULT_AES_HEX))

# --- JWT Settings ---
JWT_EXPIRY_SECONDS = int(os.getenv("IOMT_JWT_EXPIRY", "300"))
JWT_ALGORITHM = "RS256"

# --- Cloud Endpoints ---
PEP_ENDPOINT = os.getenv("IOMT_PEP_ENDPOINT", "http://localhost:6000/verify")

# --- Sidecar Server ---
SIDECAR_HOST = os.getenv("IOMT_SIDECAR_HOST", "0.0.0.0")
SIDECAR_PORT = int(os.getenv("IOMT_SIDECAR_PORT", "8000"))

# --- DTSA Parameters ---
ALPHA = float(os.getenv("IOMT_DTSA_ALPHA", "30"))   # weight for packet frequency
BETA = float(os.getenv("IOMT_DTSA_BETA", "50"))     # weight for payload size
GAMMA = float(os.getenv("IOMT_DTSA_GAMMA", "20"))   # weight for geo-velocity
THETA = float(os.getenv("IOMT_DTSA_THETA", "60"))   # trust threshold
EMA_SMOOTHING = float(os.getenv("IOMT_EMA_ALPHA", "0.1"))
EPSILON = 1e-6
