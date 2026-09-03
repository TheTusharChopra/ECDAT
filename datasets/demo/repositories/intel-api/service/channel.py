"""Analyst channel: modern primitives, 25-year classification lifetime."""
import os

from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


def establish_channel(peer_public):
    """X25519 key agreement -- classically strong, Shor-vulnerable."""
    private = x25519.X25519PrivateKey.generate()
    shared = private.exchange(peer_public)
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=b"analyst-channel-v2").derive(shared)


def sign_report(report: bytes):
    key = ed25519.Ed25519PrivateKey.generate()
    return key.sign(report)


def verify_report(public_key, signature: bytes, report: bytes) -> bool:
    public_key.verify(signature, report)
    return True


def seal(key: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    nonce = os.urandom(12)
    return nonce, ChaCha20Poly1305(key).encrypt(nonce, plaintext, None)
