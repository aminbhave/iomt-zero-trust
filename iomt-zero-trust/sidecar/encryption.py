"""
AES-256-GCM authenticated encryption module.

Provides confidentiality and data integrity for legacy IoMT traffic.
Wire format: base64( nonce[12] || tag[16] || ciphertext )
"""

import base64
import os

from Crypto.Cipher import AES


NONCE_SIZE = 12   # 96-bit nonce recommended for GCM
TAG_SIZE = 16     # 128-bit authentication tag


def encrypt(plaintext: bytes, key: bytes) -> str:
    """Encrypt *plaintext* with AES-256-GCM and return a base64 string.

    Returns
    -------
    str
        base64-encoded payload: nonce || tag || ciphertext
    """
    nonce = os.urandom(NONCE_SIZE)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return base64.b64encode(nonce + tag + ciphertext).decode("utf-8")


def decrypt(encoded: str, key: bytes) -> bytes:
    """Decrypt a base64-encoded AES-256-GCM payload.

    Raises
    ------
    ValueError
        If the payload is too short or has been tampered with.
    """
    raw = base64.b64decode(encoded)
    if len(raw) < NONCE_SIZE + TAG_SIZE:
        raise ValueError("Ciphertext too short")

    nonce = raw[:NONCE_SIZE]
    tag = raw[NONCE_SIZE : NONCE_SIZE + TAG_SIZE]
    ciphertext = raw[NONCE_SIZE + TAG_SIZE :]

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)
