"""Citizen authentication: session tokens and document signing."""
import hashlib
import hmac
import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

SESSION_KEY_BITS = 2048


def load_signing_key(path: str):
    with open(path, "rb") as fh:
        return serialization.load_pem_private_key(fh.read(), password=None)


def issue_document_signature(key, document: bytes) -> bytes:
    """Sign a citizen document. Signature must remain verifiable for 10 years."""
    return key.sign(
        document,
        padding.PKCS1v15(),
        hashes.SHA256(),
    )


def rotate_signing_key():
    # Role is evidenced by the .sign() call below -> DIGITAL_SIGNATURE
    key = rsa.generate_private_key(public_exponent=65537, key_size=SESSION_KEY_BITS)
    key.sign(b"self-test", padding.PKCS1v15(), hashes.SHA256())
    return key


def session_tag(session_id: str, secret: bytes) -> str:
    return hmac.new(secret, session_id.encode(), digestmod=hashlib.sha256).hexdigest()


def document_cache_key(blob: bytes) -> str:
    # Non-security use: cache key only, not an integrity control.
    return hashlib.md5(blob).hexdigest()
