"""TLS and card-data protection for the payment authorisation service."""
import os
import ssl

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PAN_KEY = os.urandom(16)  # 128-bit -- below the 256-bit policy floor


def build_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    ctx.load_cert_chain("certs/payment-gateway.crt", "certs/payment-gateway.key")
    return ctx


def wrap_data_key(recipient_public_key, data_key: bytes) -> bytes:
    """RSA-OAEP key transport -> requires a KEM to migrate, not a cipher swap."""
    return recipient_public_key.encrypt(
        data_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def unwrap_data_key(private_key, wrapped: bytes) -> bytes:
    return private_key.decrypt(
        wrapped,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def encrypt_pan(pan: bytes) -> tuple[bytes, bytes]:
    nonce = os.urandom(12)
    return nonce, AESGCM(PAN_KEY).encrypt(nonce, pan, b"pan-v1")
