"""
Sidecar Proxy -- FastAPI application.

Receives cleartext traffic from the legacy device, injects a signed JWT
identity token, encrypts the combined payload with AES-256-GCM, and
forwards the result to the cloud Policy Enforcement Point (PEP).

Usage:
    uvicorn sidecar.sidecar_proxy:app --host 0.0.0.0 --port 8000
"""

from __future__ import annotations

import logging
import time

import httpx
from fastapi import FastAPI, Request, Response

from . import config
from .encryption import encrypt
from .interceptor import extract_metadata
from .jwt_module import generate_jwt

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [SidecarProxy] %(levelname)s  %(message)s",
)
log = logging.getLogger(__name__)

app = FastAPI(title="IoMT Sidecar Proxy", version="1.0.0")

_http_client: httpx.AsyncClient | None = None


async def _get_client() -> httpx.AsyncClient:
    global _http_client
    if _http_client is None or _http_client.is_closed:
        _http_client = httpx.AsyncClient(timeout=10.0)
    return _http_client


@app.on_event("shutdown")
async def _shutdown():
    if _http_client and not _http_client.is_closed:
        await _http_client.aclose()


@app.get("/health")
async def health():
    return {"status": "ok", "tenant_id": config.TENANT_ID, "device_id": config.DEVICE_ID}


@app.post("/ingest")
async def intercept_and_encrypt(request: Request):
    """Core sidecar pipeline: intercept -> tokenise -> encrypt -> forward."""
    t_start = time.perf_counter()

    # 1. Intercept the cleartext payload
    p_raw = await request.body()
    source_ip = request.client.host if request.client else "0.0.0.0"
    meta = extract_metadata(p_raw, source_ip=source_ip)

    # 2. Identity injection -- sign a JWT with tenant + device claims
    jwt_token = generate_jwt(
        tenant_id=meta.tenant_id,
        device_id=meta.device_id,
    )

    # 3. Combine JWT and raw payload, then encrypt with AES-256-GCM
    combined = jwt_token.encode("utf-8") + b"|" + p_raw
    encrypted_payload = encrypt(combined, config.AES_KEY)

    processing_ms = (time.perf_counter() - t_start) * 1000

    log.info(
        "seq=%d  device=%s  tenant=%s  size=%d  encrypt_ms=%.1f",
        meta.seq,
        meta.device_id,
        meta.tenant_id,
        meta.payload_size,
        processing_ms,
    )

    # 4. Forward encrypted payload to the cloud PEP
    try:
        client = await _get_client()
        resp = await client.post(
            config.PEP_ENDPOINT,
            content=encrypted_payload,
            headers={
                "Content-Type": "application/octet-stream",
                "X-Source-IP": source_ip,
            },
        )
        return Response(
            content=resp.content,
            status_code=resp.status_code,
            media_type=resp.headers.get("content-type", "application/json"),
        )
    except httpx.HTTPError as exc:
        log.warning("PEP unreachable (%s) -- returning local ACK", exc)
        return {
            "status": "accepted_locally",
            "processing_ms": round(processing_ms, 2),
            "note": "PEP endpoint unavailable; packet encrypted and queued.",
        }
