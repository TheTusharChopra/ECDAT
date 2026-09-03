"""Encrypted document storage for citizen records."""
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

RECORD_KEY = os.urandom(32)  # 256-bit


def seal_record(plaintext: bytes, aad: bytes) -> tuple[bytes, bytes]:
    nonce = os.urandom(12)
    return nonce, AESGCM(RECORD_KEY).encrypt(nonce, plaintext, aad)


def open_record(nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    return AESGCM(RECORD_KEY).decrypt(nonce, ciphertext, aad)
