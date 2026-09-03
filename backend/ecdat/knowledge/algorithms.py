"""Cryptographic algorithm knowledge base.

Every risk judgement ECDAT makes traces back to a row in this table. Nothing here
is inferred at runtime by a model; it is curated from NIST SP 800-57 Part 1 Rev. 5
(comparable security strengths), FIPS 180-4 / 202 (hashes), FIPS 197 (AES),
SP 800-131A Rev. 2 (transitions) and FIPS 203/204/205 (PQC).

Quantum taxonomy used throughout ECDAT (see PART 38 of the design brief):

    shor_broken        Public-key primitives whose hard problem (IFP/DLP/ECDLP) is
                       solved in polynomial time by Shor's algorithm. These require
                       migration; this is the real PQC driver.
    grover_reduced     Symmetric/hash primitives where Grover-style search gives at
                       most a quadratic speedup. NOT "broken". Judged on remaining
                       strength, not replaced by PQC.
    classically_broken Already weak against classical cryptanalysis. Urgent for
                       reasons that have nothing to do with quantum computing.
    pqc_standardized   Finalised FIPS 203/204/205 algorithms.
    pqc_selected       Selected for standardisation but no final FIPS yet (HQC).
    hybrid_pqt         PQ/T hybrid construction combining a classical and a PQC KEM.

We deliberately never emit the string "quantum-safe" or "quantum-proof".
"""

from __future__ import annotations

from dataclasses import dataclass, field

# --- quantum classification constants -------------------------------------------------
SHOR_BROKEN = "shor_broken"
GROVER_REDUCED = "grover_reduced"
CLASSICALLY_BROKEN = "classically_broken"
PQC_STANDARDIZED = "pqc_standardized"
PQC_SELECTED = "pqc_selected"
HYBRID_PQT = "hybrid_pqt"
UNKNOWN = "unknown"

# --- cryptographic roles ---------------------------------------------------------------
# The canonical 12-role vocabulary lives in ecdat.models.Role and is the ONLY role
# vocabulary in the codebase. The ROLE_* names below are compatibility aliases bound
# to canonical enum *values*, so existing detector code keeps working while emitting
# canonical strings. There is no second vocabulary.
#
# A spec's `roles` tuple declares the roles a primitive is CAPABLE of. An asset's
# `cryptographic_role` is the role actually OBSERVED. Those are different questions,
# and `default_role()` below is the only sanctioned bridge between them.
from ..models import Role

ROLE_KEY_ESTABLISHMENT = Role.KEY_ESTABLISHMENT.value
ROLE_KEY_TRANSPORT = Role.KEY_TRANSPORT.value
ROLE_SIGNATURE = Role.DIGITAL_SIGNATURE.value
ROLE_SIGNATURE_VERIFICATION = Role.SIGNATURE_VERIFICATION.value
ROLE_ENCRYPTION = Role.ENCRYPTION.value
ROLE_DECRYPTION = Role.DECRYPTION.value
ROLE_AUTHENTICATION = Role.AUTHENTICATION.value
ROLE_CERTIFICATE_VALIDATION = Role.CERTIFICATE_VALIDATION.value
ROLE_HASH = Role.HASHING.value
ROLE_MAC = Role.MESSAGE_AUTHENTICATION.value
ROLE_KDF = Role.KEY_DERIVATION.value
ROLE_UNKNOWN = Role.UNKNOWN.value

# Decision families: roles inside one family lead to the SAME migration decision, so
# a primitive whose capabilities all sit in one family can be defaulted safely. A
# primitive spanning families (RSA: key transport AND signature) must not be guessed.
ROLE_FAMILY: dict[str, str] = {
    Role.KEY_ESTABLISHMENT.value: "key-establishment",
    Role.KEY_TRANSPORT.value: "key-establishment",
    Role.DIGITAL_SIGNATURE.value: "signature",
    Role.SIGNATURE_VERIFICATION.value: "signature",
    Role.AUTHENTICATION.value: "signature",
    Role.CERTIFICATE_VALIDATION.value: "signature",
    Role.ENCRYPTION.value: "symmetric",
    Role.DECRYPTION.value: "symmetric",
    Role.HASHING.value: "hash",
    Role.MESSAGE_AUTHENTICATION.value: "hash",
    Role.KEY_DERIVATION.value: "kdf",
    Role.UNKNOWN.value: "unknown",
}


def role_family(role: str | None) -> str:
    return ROLE_FAMILY.get(role or "", "unknown")


def default_role(spec: "AlgorithmSpec | None") -> str:
    """The role to assume when no usage evidence was observed.

    Returns UNKNOWN whenever the primitive's capabilities span more than one
    decision family. This is what stops ECDAT from guessing that an RSA key is a
    signing key when it might be doing key transport -- the two migrate to
    different FIPS standards.
    """
    if spec is None or not spec.roles:
        return ROLE_UNKNOWN
    if len(spec.roles) == 1:
        return spec.roles[0]
    families = {role_family(r) for r in spec.roles}
    if len(families) == 1:
        return spec.roles[0]     # same decision outcome either way: safe default
    return ROLE_UNKNOWN

# --- lifecycle status ------------------------------------------------------------------
ST_APPROVED = "approved"
ST_LEGACY = "legacy"
ST_DEPRECATED = "deprecated"
ST_BROKEN = "broken"
ST_PQC_FINAL = "pqc-standardized"
ST_PQC_SELECTED = "pqc-selected"


@dataclass(frozen=True)
class AlgorithmSpec:
    """One curated cryptographic algorithm."""

    id: str
    name: str
    family: str
    primitive: str  # CycloneDX 1.6 algorithmProperties.primitive enum value
    roles: tuple[str, ...]
    crypto_functions: tuple[str, ...]  # CycloneDX cryptoFunctions enum values
    quantum_class: str
    status: str
    oid: str | None = None
    standard: str | None = None
    # classical security strength in bits at the *default* parameter set
    default_strength: int | None = None
    # bits of security remaining against a large quantum adversary, where a
    # defensible number exists. None => "not expressible as a bit count".
    quantum_strength: int | None = None
    aliases: tuple[str, ...] = ()
    note: str = ""

    @property
    def quantum_vulnerable(self) -> bool:
        """True only for primitives that PQC migration actually replaces."""
        return self.quantum_class == SHOR_BROKEN


def _a(**kw) -> AlgorithmSpec:
    return AlgorithmSpec(**kw)


# =====================================================================================
# PUBLIC KEY  --  Shor-vulnerable. This is the PQC migration surface.
# =====================================================================================
_PUBLIC_KEY: list[AlgorithmSpec] = [
    _a(
        id="rsa", name="RSA", family="RSA", primitive="pke",
        roles=(ROLE_KEY_TRANSPORT, ROLE_SIGNATURE, ROLE_SIGNATURE_VERIFICATION,
               ROLE_ENCRYPTION, ROLE_DECRYPTION),
        crypto_functions=("encrypt", "decrypt", "sign", "verify", "keygen"),
        quantum_class=SHOR_BROKEN, status=ST_LEGACY,
        oid="1.2.840.113549.1.1.1", standard="FIPS 186-5 / PKCS#1",
        default_strength=112,
        note="Integer factorisation; broken in polynomial time by Shor's algorithm. "
             "Role (transport vs signature) must be established from evidence.",
    ),
    _a(
        id="dsa", name="DSA", family="DSA", primitive="signature",
        roles=(ROLE_SIGNATURE, ROLE_SIGNATURE_VERIFICATION), crypto_functions=("sign", "verify", "keygen"),
        quantum_class=SHOR_BROKEN, status=ST_DEPRECATED,
        oid="1.2.840.10040.4.1", standard="FIPS 186-4 (withdrawn for signing in 186-5)",
        default_strength=112,
        note="Finite-field DLP. Disallowed for new signature generation by FIPS 186-5.",
    ),
    _a(
        id="ecdsa", name="ECDSA", family="EC", primitive="signature",
        roles=(ROLE_SIGNATURE, ROLE_SIGNATURE_VERIFICATION), crypto_functions=("sign", "verify", "keygen"),
        quantum_class=SHOR_BROKEN, status=ST_APPROVED,
        oid="1.2.840.10045.2.1", standard="FIPS 186-5",
        default_strength=128,
        note="ECDLP; broken by Shor. Classically strong -- the driver is quantum only.",
    ),
    _a(
        id="ed25519", name="Ed25519", family="EdDSA", primitive="signature",
        roles=(ROLE_SIGNATURE, ROLE_SIGNATURE_VERIFICATION), crypto_functions=("sign", "verify", "keygen"),
        quantum_class=SHOR_BROKEN, status=ST_APPROVED,
        oid="1.3.101.112", standard="FIPS 186-5 / RFC 8032",
        default_strength=128, aliases=("eddsa",),
        note="Edwards-curve DLP; Shor-vulnerable despite being a modern primitive.",
    ),
    _a(
        id="ed448", name="Ed448", family="EdDSA", primitive="signature",
        roles=(ROLE_SIGNATURE, ROLE_SIGNATURE_VERIFICATION), crypto_functions=("sign", "verify", "keygen"),
        quantum_class=SHOR_BROKEN, status=ST_APPROVED,
        oid="1.3.101.113", standard="FIPS 186-5 / RFC 8032", default_strength=224,
    ),
    _a(
        id="dh", name="Diffie-Hellman", family="DH", primitive="key-agree",
        roles=(ROLE_KEY_ESTABLISHMENT,), crypto_functions=("keyderive", "generate"),
        quantum_class=SHOR_BROKEN, status=ST_LEGACY,
        oid="1.2.840.113549.1.3.1", standard="SP 800-56A",
        default_strength=112, aliases=("diffie-hellman", "dhe"),
    ),
    _a(
        id="ecdh", name="ECDH", family="EC", primitive="key-agree",
        roles=(ROLE_KEY_ESTABLISHMENT,), crypto_functions=("keyderive", "generate"),
        quantum_class=SHOR_BROKEN, status=ST_APPROVED,
        oid="1.3.132.1.12", standard="SP 800-56A",
        default_strength=128, aliases=("ecdhe",),
        note="Ephemeral ECDH protects today's traffic classically but is subject to "
             "store-now-decrypt-later: recorded sessions are decryptable once a CRQC exists.",
    ),
    _a(
        id="x25519", name="X25519", family="EC", primitive="key-agree",
        roles=(ROLE_KEY_ESTABLISHMENT,), crypto_functions=("keyderive", "generate"),
        quantum_class=SHOR_BROKEN, status=ST_APPROVED,
        oid="1.3.101.110", standard="RFC 7748 / SP 800-186", default_strength=128,
    ),
    _a(
        id="x448", name="X448", family="EC", primitive="key-agree",
        roles=(ROLE_KEY_ESTABLISHMENT,), crypto_functions=("keyderive", "generate"),
        quantum_class=SHOR_BROKEN, status=ST_APPROVED,
        oid="1.3.101.111", standard="RFC 7748", default_strength=224,
    ),
    _a(
        id="elgamal", name="ElGamal", family="ElGamal", primitive="pke",
        roles=(ROLE_ENCRYPTION, ROLE_DECRYPTION),
        crypto_functions=("encrypt", "decrypt"),
        quantum_class=SHOR_BROKEN, status=ST_LEGACY, default_strength=112,
    ),
]

# =====================================================================================
# SYMMETRIC  --  Grover gives at most a quadratic speedup. Not a PQC replacement target.
# =====================================================================================
_SYMMETRIC: list[AlgorithmSpec] = [
    _a(
        id="aes-128", name="AES-128", family="AES", primitive="block-cipher",
        roles=(ROLE_ENCRYPTION,), crypto_functions=("encrypt", "decrypt"),
        quantum_class=GROVER_REDUCED, status=ST_APPROVED,
        oid="2.16.840.1.101.3.4.1.2", standard="FIPS 197",
        default_strength=128, quantum_strength=64,
        note="Grover halves the exhaustive-search exponent. 2^64 quantum work is a "
             "large margin in practice (Grover parallelises poorly), but CNSA 2.0 "
             "requires AES-256 for national-security systems.",
    ),
    _a(
        id="aes-192", name="AES-192", family="AES", primitive="block-cipher",
        roles=(ROLE_ENCRYPTION,), crypto_functions=("encrypt", "decrypt"),
        quantum_class=GROVER_REDUCED, status=ST_APPROVED,
        oid="2.16.840.1.101.3.4.1.22", standard="FIPS 197",
        default_strength=192, quantum_strength=96,
    ),
    _a(
        id="aes-256", name="AES-256", family="AES", primitive="block-cipher",
        roles=(ROLE_ENCRYPTION,), crypto_functions=("encrypt", "decrypt"),
        quantum_class=GROVER_REDUCED, status=ST_APPROVED,
        oid="2.16.840.1.101.3.4.1.42", standard="FIPS 197",
        default_strength=256, quantum_strength=128,
        note="Comparatively resilient to known quantum speedups. Retain; do not "
             "replace with a PQC algorithm. CNSA 2.0 approved.",
    ),
    _a(
        id="chacha20", name="ChaCha20", family="ChaCha", primitive="stream-cipher",
        roles=(ROLE_ENCRYPTION,), crypto_functions=("encrypt", "decrypt"),
        quantum_class=GROVER_REDUCED, status=ST_APPROVED, standard="RFC 8439",
        default_strength=256, quantum_strength=128,
    ),
    _a(
        id="chacha20-poly1305", name="ChaCha20-Poly1305", family="ChaCha",
        primitive="ae", roles=(ROLE_ENCRYPTION,),
        crypto_functions=("encrypt", "decrypt", "tag"),
        quantum_class=GROVER_REDUCED, status=ST_APPROVED, standard="RFC 8439",
        default_strength=256, quantum_strength=128,
    ),
    _a(
        id="3des", name="3DES (TDEA)", family="DES", primitive="block-cipher",
        roles=(ROLE_ENCRYPTION,), crypto_functions=("encrypt", "decrypt"),
        quantum_class=CLASSICALLY_BROKEN, status=ST_DEPRECATED,
        oid="1.2.840.113549.3.7", standard="SP 800-67 (disallowed after 2023)",
        default_strength=112, aliases=("des-ede3", "tripledes", "desede"),
        note="Disallowed by SP 800-131A Rev.2 after 2023. 64-bit block => Sweet32. "
             "Classical problem, not a quantum one.",
    ),
    _a(
        id="des", name="DES", family="DES", primitive="block-cipher",
        roles=(ROLE_ENCRYPTION,), crypto_functions=("encrypt", "decrypt"),
        quantum_class=CLASSICALLY_BROKEN, status=ST_BROKEN,
        oid="1.3.14.3.2.7", default_strength=56,
        note="56-bit key; brute-forceable classically for decades.",
    ),
    _a(
        id="rc4", name="RC4", family="RC4", primitive="stream-cipher",
        roles=(ROLE_ENCRYPTION,), crypto_functions=("encrypt", "decrypt"),
        quantum_class=CLASSICALLY_BROKEN, status=ST_BROKEN, default_strength=0,
        note="Prohibited in TLS by RFC 7465.",
    ),
    _a(
        id="blowfish", name="Blowfish", family="Blowfish", primitive="block-cipher",
        roles=(ROLE_ENCRYPTION,), crypto_functions=("encrypt", "decrypt"),
        quantum_class=CLASSICALLY_BROKEN, status=ST_DEPRECATED, default_strength=64,
        note="64-bit block; unsuitable for modern volumes.",
    ),
]

# =====================================================================================
# HASHES  --  collision resistance is the binding constraint, not Grover.
# =====================================================================================
_HASH: list[AlgorithmSpec] = [
    _a(
        id="md5", name="MD5", family="MD", primitive="hash",
        roles=(ROLE_HASH,), crypto_functions=("digest",),
        quantum_class=CLASSICALLY_BROKEN, status=ST_BROKEN,
        oid="1.2.840.113549.2.5", default_strength=0,
        note="Practical chosen-prefix collisions. Never acceptable for signatures.",
    ),
    _a(
        id="sha-1", name="SHA-1", family="SHA", primitive="hash",
        roles=(ROLE_HASH,), crypto_functions=("digest",),
        quantum_class=CLASSICALLY_BROKEN, status=ST_BROKEN,
        oid="1.3.14.3.2.26", standard="FIPS 180-4 (disallowed for signatures)",
        default_strength=63, aliases=("sha1",),
        note="SHAttered/chosen-prefix collisions; NIST plans full retirement by 2030. "
             "Classical failure -- fix now regardless of quantum timeline.",
    ),
    _a(
        id="sha-224", name="SHA-224", family="SHA-2", primitive="hash",
        roles=(ROLE_HASH,), crypto_functions=("digest",),
        quantum_class=GROVER_REDUCED, status=ST_APPROVED,
        oid="2.16.840.1.101.3.4.2.4", standard="FIPS 180-4",
        default_strength=112, quantum_strength=112,
    ),
    _a(
        id="sha-256", name="SHA-256", family="SHA-2", primitive="hash",
        roles=(ROLE_HASH,), crypto_functions=("digest",),
        quantum_class=GROVER_REDUCED, status=ST_APPROVED,
        oid="2.16.840.1.101.3.4.2.1", standard="FIPS 180-4",
        default_strength=128, quantum_strength=128,
        note="128-bit collision resistance. NOT quantum-broken. Retain.",
    ),
    _a(
        id="sha-384", name="SHA-384", family="SHA-2", primitive="hash",
        roles=(ROLE_HASH,), crypto_functions=("digest",),
        quantum_class=GROVER_REDUCED, status=ST_APPROVED,
        oid="2.16.840.1.101.3.4.2.2", standard="FIPS 180-4",
        default_strength=192, quantum_strength=192,
        note="CNSA 2.0 approved.",
    ),
    _a(
        id="sha-512", name="SHA-512", family="SHA-2", primitive="hash",
        roles=(ROLE_HASH,), crypto_functions=("digest",),
        quantum_class=GROVER_REDUCED, status=ST_APPROVED,
        oid="2.16.840.1.101.3.4.2.3", standard="FIPS 180-4",
        default_strength=256, quantum_strength=256,
    ),
    _a(
        id="sha3-256", name="SHA3-256", family="SHA-3", primitive="hash",
        roles=(ROLE_HASH,), crypto_functions=("digest",),
        quantum_class=GROVER_REDUCED, status=ST_APPROVED,
        oid="2.16.840.1.101.3.4.2.8", standard="FIPS 202",
        default_strength=128, quantum_strength=128, aliases=("sha3",),
    ),
    _a(
        id="sha3-512", name="SHA3-512", family="SHA-3", primitive="hash",
        roles=(ROLE_HASH,), crypto_functions=("digest",),
        quantum_class=GROVER_REDUCED, status=ST_APPROVED,
        oid="2.16.840.1.101.3.4.2.10", standard="FIPS 202",
        default_strength=256, quantum_strength=256,
    ),
    _a(
        id="shake256", name="SHAKE256", family="SHA-3", primitive="xof",
        roles=(ROLE_HASH,), crypto_functions=("digest",),
        quantum_class=GROVER_REDUCED, status=ST_APPROVED, standard="FIPS 202",
        default_strength=256,
    ),
]

# =====================================================================================
# MAC / KDF
# =====================================================================================
_MAC_KDF: list[AlgorithmSpec] = [
    _a(id="hmac-sha256", name="HMAC-SHA-256", family="HMAC", primitive="mac",
       roles=(ROLE_MAC,), crypto_functions=("tag",), quantum_class=GROVER_REDUCED,
       status=ST_APPROVED, standard="FIPS 198-1", default_strength=128),
    _a(id="hmac-sha1", name="HMAC-SHA-1", family="HMAC", primitive="mac",
       roles=(ROLE_MAC,), crypto_functions=("tag",), quantum_class=GROVER_REDUCED,
       status=ST_LEGACY, standard="FIPS 198-1", default_strength=128,
       note="HMAC-SHA-1 is not broken by SHA-1 collisions (it relies on PRF, not "
            "collision resistance) but is being retired; plan replacement."),
    _a(id="hmac-md5", name="HMAC-MD5", family="HMAC", primitive="mac",
       roles=(ROLE_MAC,), crypto_functions=("tag",), quantum_class=CLASSICALLY_BROKEN,
       status=ST_DEPRECATED, default_strength=64),
    _a(id="pbkdf2", name="PBKDF2", family="PBKDF", primitive="kdf",
       roles=(ROLE_KDF,), crypto_functions=("keyderive",), quantum_class=GROVER_REDUCED,
       status=ST_APPROVED, standard="SP 800-132", default_strength=128),
    _a(id="hkdf", name="HKDF", family="HKDF", primitive="kdf",
       roles=(ROLE_KDF,), crypto_functions=("keyderive",), quantum_class=GROVER_REDUCED,
       status=ST_APPROVED, standard="RFC 5869 / SP 800-56C", default_strength=128),
    _a(id="md5crypt", name="MD5-crypt", family="MD", primitive="kdf",
       roles=(ROLE_KDF,), crypto_functions=("keyderive",),
       quantum_class=CLASSICALLY_BROKEN, status=ST_BROKEN, default_strength=0),
]

# =====================================================================================
# PQC  --  finalised FIPS standards, then selected-but-not-final.
# =====================================================================================
_PQC: list[AlgorithmSpec] = [
    _a(
        id="ml-kem-512", name="ML-KEM-512", family="ML-KEM", primitive="kem",
        roles=(ROLE_KEY_ESTABLISHMENT,),
        crypto_functions=("encapsulate", "decapsulate", "keygen"),
        quantum_class=PQC_STANDARDIZED, status=ST_PQC_FINAL, standard="FIPS 203",
        default_strength=128, aliases=("kyber512",),
        note="NIST PQC security category 1. Predecessor name: Kyber-512.",
    ),
    _a(
        id="ml-kem-768", name="ML-KEM-768", family="ML-KEM", primitive="kem",
        roles=(ROLE_KEY_ESTABLISHMENT,),
        crypto_functions=("encapsulate", "decapsulate", "keygen"),
        quantum_class=PQC_STANDARDIZED, status=ST_PQC_FINAL, standard="FIPS 203",
        default_strength=192, aliases=("kyber768",),
        note="NIST PQC security category 3. The mainstream TLS choice.",
    ),
    _a(
        id="ml-kem-1024", name="ML-KEM-1024", family="ML-KEM", primitive="kem",
        roles=(ROLE_KEY_ESTABLISHMENT,),
        crypto_functions=("encapsulate", "decapsulate", "keygen"),
        quantum_class=PQC_STANDARDIZED, status=ST_PQC_FINAL, standard="FIPS 203",
        default_strength=256, aliases=("kyber1024",),
        note="NIST PQC security category 5. CNSA 2.0 requires ML-KEM-1024.",
    ),
    _a(
        id="ml-dsa-44", name="ML-DSA-44", family="ML-DSA", primitive="signature",
        roles=(ROLE_SIGNATURE, ROLE_SIGNATURE_VERIFICATION), crypto_functions=("sign", "verify", "keygen"),
        quantum_class=PQC_STANDARDIZED, status=ST_PQC_FINAL, standard="FIPS 204",
        default_strength=128, aliases=("dilithium2",),
    ),
    _a(
        id="ml-dsa-65", name="ML-DSA-65", family="ML-DSA", primitive="signature",
        roles=(ROLE_SIGNATURE, ROLE_SIGNATURE_VERIFICATION), crypto_functions=("sign", "verify", "keygen"),
        quantum_class=PQC_STANDARDIZED, status=ST_PQC_FINAL, standard="FIPS 204",
        default_strength=192, aliases=("dilithium3",),
        note="Category 3. General-purpose signature replacement for ECDSA P-256.",
    ),
    _a(
        id="ml-dsa-87", name="ML-DSA-87", family="ML-DSA", primitive="signature",
        roles=(ROLE_SIGNATURE, ROLE_SIGNATURE_VERIFICATION), crypto_functions=("sign", "verify", "keygen"),
        quantum_class=PQC_STANDARDIZED, status=ST_PQC_FINAL, standard="FIPS 204",
        default_strength=256, aliases=("dilithium5",),
        note="Category 5. CNSA 2.0 requires ML-DSA-87.",
    ),
    _a(
        id="slh-dsa-sha2-128s", name="SLH-DSA-SHA2-128s", family="SLH-DSA",
        primitive="signature", roles=(ROLE_SIGNATURE, ROLE_SIGNATURE_VERIFICATION),
        crypto_functions=("sign", "verify", "keygen"),
        quantum_class=PQC_STANDARDIZED, status=ST_PQC_FINAL, standard="FIPS 205",
        default_strength=128, aliases=("sphincs+",),
        note="Hash-based; conservative security assumptions, large signatures and "
             "slow signing. Preferred for firmware/root-of-trust and long-lived "
             "code signing where diversity from lattices is desirable.",
    ),
    _a(
        id="slh-dsa-sha2-192s", name="SLH-DSA-SHA2-192s", family="SLH-DSA",
        primitive="signature", roles=(ROLE_SIGNATURE, ROLE_SIGNATURE_VERIFICATION),
        crypto_functions=("sign", "verify", "keygen"),
        quantum_class=PQC_STANDARDIZED, status=ST_PQC_FINAL, standard="FIPS 205",
        default_strength=192,
    ),
    _a(
        id="hqc", name="HQC", family="HQC", primitive="kem",
        roles=(ROLE_KEY_ESTABLISHMENT,),
        crypto_functions=("encapsulate", "decapsulate", "keygen"),
        quantum_class=PQC_SELECTED, status=ST_PQC_SELECTED,
        standard="NIST 4th-round selection (2025) -- draft FIPS pending",
        default_strength=128,
        note="Code-based KEM selected for standardisation as a backup to ML-KEM. "
             "NOT a finalised FIPS. Do not deploy as the primary mechanism.",
    ),
    _a(
        id="lms", name="LMS", family="HBS", primitive="signature",
        roles=(ROLE_SIGNATURE, ROLE_SIGNATURE_VERIFICATION), crypto_functions=("sign", "verify"),
        quantum_class=PQC_STANDARDIZED, status=ST_APPROVED,
        standard="SP 800-208 / RFC 8554", default_strength=128,
        note="Stateful hash-based signature. Approved for firmware signing; state "
             "management is a hard operational requirement.",
    ),
]

# =====================================================================================
# PQ/T HYBRID KEY AGREEMENT  --  RFC 10024 (Proposed Standard, Aug 2026),
# built on the hybrid framework of RFC 9954. Code points from the IANA
# TLS Supported Groups registry.
# =====================================================================================
_HYBRID: list[AlgorithmSpec] = [
    _a(
        id="x25519mlkem768", name="X25519MLKEM768", family="PQ/T Hybrid",
        primitive="combiner", roles=(ROLE_KEY_ESTABLISHMENT,),
        crypto_functions=("encapsulate", "decapsulate", "keyderive"),
        quantum_class=HYBRID_PQT, status=ST_APPROVED,
        standard="RFC 10024 (TLS group 0x11EC / 4588, Recommended=Y)",
        default_strength=192,
        note="X25519 ECDH combined with ML-KEM-768. The only RFC 10024 group marked "
             "Recommended=Y by IANA; broadly deployed in TLS 1.3 stacks.",
    ),
    _a(
        id="secp256r1mlkem768", name="SecP256r1MLKEM768", family="PQ/T Hybrid",
        primitive="combiner", roles=(ROLE_KEY_ESTABLISHMENT,),
        crypto_functions=("encapsulate", "decapsulate", "keyderive"),
        quantum_class=HYBRID_PQT, status=ST_APPROVED,
        standard="RFC 10024 (TLS group 0x11EB / 4587, Recommended=N)",
        default_strength=192,
        note="secp256r1 ECDH + ML-KEM-768. Intended for deployments that require "
             "FIPS-approved constituent mechanisms.",
    ),
    _a(
        id="secp384r1mlkem1024", name="SecP384r1MLKEM1024", family="PQ/T Hybrid",
        primitive="combiner", roles=(ROLE_KEY_ESTABLISHMENT,),
        crypto_functions=("encapsulate", "decapsulate", "keyderive"),
        quantum_class=HYBRID_PQT, status=ST_APPROVED,
        standard="RFC 10024 (TLS group 0x11ED / 4589, Recommended=N)",
        default_strength=256,
        note="secp384r1 ECDH + ML-KEM-1024 for a larger security margin.",
    ),
    _a(
        id="x25519kyber768draft00", name="X25519Kyber768Draft00",
        family="PQ/T Hybrid (obsolete)", primitive="combiner",
        roles=(ROLE_KEY_ESTABLISHMENT,), crypto_functions=("keyderive",),
        quantum_class=HYBRID_PQT, status=ST_DEPRECATED,
        standard="Obsoleted by RFC 10024 (registry code point 25497, Recommended=D)",
        default_strength=192,
        note="Pre-standard experimental group using draft Kyber, not final ML-KEM. "
             "Finding it in production indicates an early pilot that must be "
             "re-pinned to X25519MLKEM768.",
    ),
]

ALL_ALGORITHMS: list[AlgorithmSpec] = (
    _PUBLIC_KEY + _SYMMETRIC + _HASH + _MAC_KDF + _PQC + _HYBRID
)

BY_ID: dict[str, AlgorithmSpec] = {s.id: s for s in ALL_ALGORITHMS}

_ALIAS_INDEX: dict[str, str] = {}
for _s in ALL_ALGORITHMS:
    _ALIAS_INDEX[_s.id.lower()] = _s.id
    _ALIAS_INDEX[_s.name.lower()] = _s.id
    for _al in _s.aliases:
        _ALIAS_INDEX.setdefault(_al.lower(), _s.id)

OID_INDEX: dict[str, str] = {s.oid: s.id for s in ALL_ALGORITHMS if s.oid}


def get(alg_id: str | None) -> AlgorithmSpec | None:
    if not alg_id:
        return None
    return BY_ID.get(alg_id) or BY_ID.get(_ALIAS_INDEX.get(alg_id.lower(), ""))


def resolve(text: str | None) -> AlgorithmSpec | None:
    """Resolve a loose name ('AES256', 'kyber768', 'sha1') to a curated spec."""
    if not text:
        return None
    key = text.strip().lower().replace("_", "-").replace(" ", "")
    if key in _ALIAS_INDEX:
        return BY_ID[_ALIAS_INDEX[key]]
    # normalise 'aes256' -> 'aes-256', 'sha256' -> 'sha-256'
    for prefix in ("aes", "sha3-", "sha", "rsa", "ml-kem", "ml-dsa"):
        if key.startswith(prefix):
            rest = key[len(prefix):].lstrip("-")
            cand = f"{prefix.rstrip('-')}-{rest}" if rest else prefix
            if cand in _ALIAS_INDEX:
                return BY_ID[_ALIAS_INDEX[cand]]
    return BY_ID.get(_ALIAS_INDEX.get(key.split("-")[0], ""))


# --- parameterised strength ------------------------------------------------------------
# NIST SP 800-57 Part 1 Rev. 5, Table 2 (comparable security strengths).
_RSA_DH_STRENGTH = [(1024, 80), (2048, 112), (3072, 128), (4096, 152), (7680, 192), (15360, 256)]
_CURVE_STRENGTH = {
    "secp192r1": 96, "prime192v1": 96, "p-192": 96,
    "secp224r1": 112, "p-224": 112,
    "secp256r1": 128, "prime256v1": 128, "p-256": 128, "secp256k1": 128,
    "secp384r1": 192, "p-384": 192,
    "secp521r1": 256, "p-521": 256,
    "curve25519": 128, "x25519": 128, "ed25519": 128,
    "curve448": 224, "x448": 224, "ed448": 224,
    "brainpoolp256r1": 128, "brainpoolp384r1": 192,
}


def strength_for(spec: AlgorithmSpec, key_size: int | None = None,
                 curve: str | None = None) -> int | None:
    """Classical security strength in bits for a concrete parameter set."""
    if curve:
        s = _CURVE_STRENGTH.get(curve.strip().lower())
        if s:
            return s
    if key_size and spec.family in ("RSA", "DSA", "DH", "ElGamal"):
        best = None
        for size, bits in _RSA_DH_STRENGTH:
            if key_size >= size:
                best = bits
        if best is None:
            return 40  # below the smallest tabulated modulus: effectively negligible
        return best
    if key_size and spec.family == "AES":
        return {128: 128, 192: 192, 256: 256}.get(key_size, spec.default_strength)
    return spec.default_strength


def curve_strength(curve: str | None) -> int | None:
    return _CURVE_STRENGTH.get((curve or "").strip().lower())


def quantum_strength_for(spec: AlgorithmSpec, key_size: int | None = None,
                         curve: str | None = None) -> int | None:
    """Bits of security against a large quantum adversary, where meaningful.

    Shor-broken primitives return 0 -- the hard problem is solved outright, so no
    increase in key size rescues them. Grover-affected symmetric primitives get
    half of their classical exponent for key search; hash collision resistance is
    reported unchanged because Grover does not beat the classical birthday bound
    by a useful margin under realistic memory/parallelism constraints.
    """
    if spec.quantum_class == SHOR_BROKEN:
        return 0
    if spec.quantum_class == CLASSICALLY_BROKEN:
        return 0
    if spec.primitive == "hash":
        return strength_for(spec, key_size, curve)
    if spec.quantum_class == GROVER_REDUCED:
        classical = strength_for(spec, key_size, curve)
        return classical // 2 if classical else None
    return spec.default_strength


def classical_status(spec: AlgorithmSpec, key_size: int | None = None,
                     curve: str | None = None) -> str:
    """'broken' | 'weak' | 'legacy' | 'acceptable' | 'strong' -- classical only."""
    if spec.status == ST_BROKEN:
        return "broken"
    bits = strength_for(spec, key_size, curve)
    if bits is None:
        return "unknown"
    if bits < 80:
        return "broken"
    if bits < 112:
        return "weak"
    if bits < 128:
        return "legacy"
    if bits < 192:
        return "acceptable"
    return "strong"
