"""Unit tests for AES-256-GCM encryption module."""

import os
import pytest

from sidecar.encryption import encrypt, decrypt


@pytest.fixture
def aes_key():
    return os.urandom(32)


class TestAESGCM:
    def test_round_trip(self, aes_key):
        plaintext = b"ECG sample data: 0.512, 0.498, 0.523"
        ciphertext = encrypt(plaintext, aes_key)
        assert decrypt(ciphertext, aes_key) == plaintext

    def test_different_nonces(self, aes_key):
        """Each encryption must produce a unique nonce."""
        plaintext = b"same data"
        c1 = encrypt(plaintext, aes_key)
        c2 = encrypt(plaintext, aes_key)
        assert c1 != c2  # different nonces -> different ciphertexts

    def test_tampered_ciphertext_rejected(self, aes_key):
        plaintext = b"sensitive telemetry"
        encoded = encrypt(plaintext, aes_key)

        # Flip a byte in the ciphertext portion
        raw = list(encoded)
        flip_idx = len(raw) // 2
        raw[flip_idx] = "A" if raw[flip_idx] != "A" else "B"
        tampered = "".join(raw)

        with pytest.raises(Exception):
            decrypt(tampered, aes_key)

    def test_wrong_key_rejected(self, aes_key):
        plaintext = b"heartbeat payload"
        encoded = encrypt(plaintext, aes_key)
        wrong_key = os.urandom(32)

        with pytest.raises(Exception):
            decrypt(encoded, wrong_key)

    def test_empty_plaintext(self, aes_key):
        encoded = encrypt(b"", aes_key)
        assert decrypt(encoded, aes_key) == b""

    def test_large_payload(self, aes_key):
        plaintext = os.urandom(64 * 1024)  # 64 KB
        encoded = encrypt(plaintext, aes_key)
        assert decrypt(encoded, aes_key) == plaintext

    def test_short_ciphertext_raises(self, aes_key):
        import base64
        short = base64.b64encode(b"tooshort").decode()
        with pytest.raises(ValueError, match="too short"):
            decrypt(short, aes_key)
