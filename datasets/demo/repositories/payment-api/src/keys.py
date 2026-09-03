"""Key custody helpers."""
from cryptography.hazmat.primitives.asymmetric import rsa


def provision_escrow_key():
    """Generated and handed to the HSM operator.

    ECDAT observes no sign/verify/encrypt/decrypt call on this object, so the
    cryptographic role is reported as UNKNOWN rather than guessed.
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key
