"""Payroll export. Internal only, 7-year statutory retention."""
import hashlib
import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

EXPORT_KEY = os.urandom(16)


def encrypt_export(data: bytes, iv: bytes) -> bytes:
    """AES-128-CBC -- below policy floor and an unauthenticated mode."""
    cipher = Cipher(algorithms.AES(EXPORT_KEY), modes.CBC(iv))
    enc = cipher.encryptor()
    return enc.update(data) + enc.finalize()


def employee_ref(employee_id: str) -> str:
    # SHA-1 used as an identifier, not a security control.
    return hashlib.sha1(employee_id.encode()).hexdigest()[:12]
