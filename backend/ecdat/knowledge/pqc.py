"""PQC migration knowledge: role-aware target selection and the citation registry.

The single most common technical error in crypto-migration tooling is a flat
algorithm-to-algorithm table (RSA -> ML-KEM). That is wrong: ML-KEM is a key
encapsulation mechanism (FIPS 203) and cannot produce a signature, while ML-DSA
and SLH-DSA (FIPS 204/205) are signature schemes and cannot establish a key.

So migration targets here are keyed on (cryptographic role, required security
category) -- never on the source algorithm name alone.
"""

from __future__ import annotations

from dataclasses import dataclass

from . import algorithms as alg
from .algorithms import (
    ROLE_ENCRYPTION,
    ROLE_HASH,
    ROLE_KEY_ESTABLISHMENT,
    ROLE_MAC,
    ROLE_SIGNATURE,
)


@dataclass(frozen=True)
class Citation:
    key: str
    title: str
    publisher: str
    url: str
    dated: str
    relevance: str


# --------------------------------------------------------------------------------------
# Every standards-dependent claim ECDAT makes points at one of these rows. Each was
# retrieved from the publisher's own site while building this tool.
# --------------------------------------------------------------------------------------
CITATIONS: dict[str, Citation] = {c.key: c for c in [
    Citation("FIPS203", "FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard",
             "NIST", "https://csrc.nist.gov/pubs/fips/203/final", "Aug 2024",
             "Defines ML-KEM. Sole finalised target for key-establishment migration."),
    Citation("FIPS204", "FIPS 204: Module-Lattice-Based Digital Signature Standard",
             "NIST", "https://csrc.nist.gov/pubs/fips/204/final", "Aug 2024",
             "Defines ML-DSA. Primary target for signature migration."),
    Citation("FIPS205", "FIPS 205: Stateless Hash-Based Digital Signature Standard",
             "NIST", "https://csrc.nist.gov/pubs/fips/205/final", "Aug 2024",
             "Defines SLH-DSA. Conservative signature alternative for roots of trust."),
    Citation("IR8547", "NIST IR 8547: Transition to Post-Quantum Cryptography Standards",
             "NIST", "https://csrc.nist.gov/pubs/ir/8547/ipd", "2024 (initial public draft)",
             "Deprecates quantum-vulnerable algorithms and targets removal from NIST "
             "standards by 2035. Supplies ECDAT's default CRQC planning horizon."),
    Citation("IR8545", "NIST IR 8545: Status Report on the Fourth Round of the NIST PQC "
                       "Standardization Process", "NIST",
             "https://csrc.nist.gov/pubs/ir/8545/final", "Mar 2025",
             "Records HQC selection. Basis for labelling HQC 'selected', not 'final'."),
    Citation("NISTPQC", "NIST Post-Quantum Cryptography Project", "NIST",
             "https://csrc.nist.gov/projects/post-quantum-cryptography", "current",
             "'They can and should be put into use now.' Confirms finalised vs "
             "in-progress algorithm status."),
    Citation("SP80057", "SP 800-57 Part 1 Rev. 5: Recommendation for Key Management",
             "NIST", "https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final", "May 2020",
             "Comparable-security-strength table behind ECDAT's bit-strength maths."),
    Citation("SP800131A", "SP 800-131A Rev. 2: Transitioning the Use of Cryptographic "
                          "Algorithms and Key Lengths", "NIST",
             "https://csrc.nist.gov/pubs/sp/800/131/a/r2/final", "Mar 2019",
             "Basis for 'deprecated'/'disallowed' classical status (3DES, SHA-1, "
             "RSA-1024)."),
    Citation("RFC10024", "RFC 10024: Post-Quantum Hybrid ECDHE-MLKEM Key Agreement for "
                         "TLS 1.3", "IETF", "https://datatracker.ietf.org/doc/rfc10024/",
             "Aug 2026 (Proposed Standard)",
             "Defines X25519MLKEM768 (0x11EC, Recommended=Y), SecP256r1MLKEM768 "
             "(0x11EB) and SecP384r1MLKEM1024 (0x11ED). Source of every TLS hybrid "
             "group ECDAT recommends."),
    Citation("RFC9954", "RFC 9954: Hybrid Key Exchange in TLS 1.3", "IETF",
             "https://datatracker.ietf.org/doc/rfc9954/", "2026",
             "The hybrid concatenation framework RFC 10024 instantiates."),
    Citation("CYCLONEDX", "CycloneDX v1.6 Specification (CBOM)", "OWASP / Ecma "
             "International (ECMA-424)", "https://cyclonedx.org/capabilities/cbom/",
             "current",
             "Defines component type 'cryptographic-asset' and cryptoProperties. "
             "ECDAT bundles bom-1.6.schema.json and validates its output against it."),
    Citation("CISA_QR", "Quantum-Readiness: Migration to Post-Quantum Cryptography",
             "CISA / NSA / NIST",
             "https://www.cisa.gov/resources-tools/resources/quantum-readiness-migration-post-quantum-cryptography",
             "Aug 2023",
             "Establishes cryptographic inventory as the required first step -- the "
             "premise of this problem statement."),
    Citation("NSA_CNSA2", "CNSA 2.0 Suite", "NSA",
             "https://www.nsa.gov/Press-Room/Press-Releases-Statements/Press-Release-View/Article/3148990/",
             "2022, updated since",
             "Requires ML-KEM-1024 / ML-DSA-87 / AES-256 / SHA-384 for national "
             "security systems. Drives ECDAT's 'nsa_cnsa2' policy profile."),
    Citation("MOSCA", "Michele Mosca, 'Cybersecurity in an Era with Quantum Computers: "
                      "Will We Be Ready?'", "IEEE Security & Privacy",
             "https://doi.org/10.1109/MSP.2018.3761723", "2018",
             "Source of the x + y > z migration-urgency inequality."),
    Citation("SP1800_38", "NIST SP 1800-38B: Migration to PQC -- Quantum Readiness: "
                          "Cryptographic Discovery", "NIST/NCCoE",
             "https://www.nccoe.nist.gov/crypto-agility-considerations-migrating-post-quantum-cryptographic-algorithms",
             "preliminary draft",
             "Discovery-tooling guidance; informs ECDAT's multi-layer scanner design."),
    Citation("RFC7465", "RFC 7465: Prohibiting RC4 Cipher Suites", "IETF",
             "https://www.rfc-editor.org/rfc/rfc7465", "2015",
             "Basis for treating RC4 as prohibited rather than merely weak."),
    Citation("SP800208", "SP 800-208: Recommendation for Stateful Hash-Based Signature "
                         "Schemes", "NIST",
             "https://csrc.nist.gov/pubs/sp/800/208/final", "Oct 2020",
             "Approves LMS/XMSS for firmware signing; basis for that recommendation path."),
]}


@dataclass(frozen=True)
class MigrationTarget:
    """A concrete, defensible migration destination for one role + strength tier."""

    primary: str                 # algorithm id in the knowledge base
    hybrid: str | None           # PQ/T hybrid where a standardised one exists
    alternative: str | None      # diversity option
    rationale: str
    citations: tuple[str, ...]
    protocol_note: str = ""


# Security category is derived from the classical strength of what is being replaced,
# so we never silently downgrade a P-384 deployment to a category-3 parameter set.
_KEY_ESTABLISHMENT = {
    128: MigrationTarget(
        primary="ml-kem-768", hybrid="x25519mlkem768", alternative="hqc",
        rationale="ML-KEM-768 (FIPS 203, NIST category 3) is the mainstream KEM. For "
                  "TLS 1.3, deploy the PQ/T hybrid X25519MLKEM768 first: it retains "
                  "classical X25519 security if a lattice weakness emerges, and is "
                  "the only RFC 10024 group IANA marks Recommended=Y.",
        citations=("FIPS203", "RFC10024", "RFC9954"),
        protocol_note="TLS 1.3 supported_groups 0x11EC (4588).",
    ),
    192: MigrationTarget(
        primary="ml-kem-768", hybrid="secp384r1mlkem1024", alternative="ml-kem-1024",
        rationale="Matching a P-384-class (192-bit) deployment. Where FIPS-approved "
                  "constituents are mandated, SecP384r1MLKEM1024 pairs secp384r1 "
                  "ECDH with ML-KEM-1024.",
        citations=("FIPS203", "RFC10024"),
        protocol_note="TLS 1.3 supported_groups 0x11ED (4589), IANA Recommended=N.",
    ),
    256: MigrationTarget(
        primary="ml-kem-1024", hybrid="secp384r1mlkem1024", alternative=None,
        rationale="ML-KEM-1024 (category 5) is required by NSA CNSA 2.0 for national "
                  "security systems, which also permit non-hybrid PQC.",
        citations=("FIPS203", "NSA_CNSA2", "RFC10024"),
    ),
}

_SIGNATURE = {
    128: MigrationTarget(
        primary="ml-dsa-65", hybrid=None, alternative="slh-dsa-sha2-128s",
        rationale="ML-DSA-65 (FIPS 204, category 3) is the general-purpose signature "
                  "replacement. SLH-DSA is the conservative alternative where "
                  "signature size and slow signing are tolerable and independence "
                  "from lattice assumptions is valuable.",
        citations=("FIPS204", "FIPS205"),
        protocol_note="No standardised PQ/T hybrid signature exists for TLS "
                      "certificates; migration is driven by CA and PKI support, so "
                      "sequence this after the CA can issue ML-DSA certificates.",
    ),
    192: MigrationTarget(
        primary="ml-dsa-65", hybrid=None, alternative="slh-dsa-sha2-192s",
        rationale="Matches a P-384-class signing key at category 3-5.",
        citations=("FIPS204", "FIPS205"),
    ),
    256: MigrationTarget(
        primary="ml-dsa-87", hybrid=None, alternative="slh-dsa-sha2-192s",
        rationale="ML-DSA-87 (category 5) is the CNSA 2.0 requirement for national "
                  "security systems.",
        citations=("FIPS204", "NSA_CNSA2"),
    ),
}

# Firmware / code signing gets a distinct path: stateful hash-based schemes are
# approved for it, and roots of trust favour conservative assumptions.
_FIRMWARE_SIGNATURE = MigrationTarget(
    primary="slh-dsa-sha2-128s", hybrid=None, alternative="lms",
    rationale="For firmware and long-lived code signing, hash-based signatures rest "
              "on weaker assumptions than lattices. SLH-DSA is stateless (FIPS 205); "
              "LMS is approved by SP 800-208 but demands rigorous state management.",
    citations=("FIPS205", "SP800208"),
)


def _tier(strength: int | None) -> int:
    if strength is None:
        return 128
    if strength >= 256:
        return 256
    if strength >= 192:
        return 192
    return 128


def target_for(role: str, strength: int | None,
               *, firmware: bool = False) -> MigrationTarget | None:
    """Role-aware migration target. Returns None when PQC is not the answer.

    Dispatches on the role's *decision family*, so SIGNATURE_VERIFICATION,
    AUTHENTICATION and CERTIFICATE_VALIDATION all resolve to the signature path,
    and KEY_TRANSPORT resolves alongside KEY_ESTABLISHMENT. UNKNOWN deliberately
    returns None -- the caller must not be handed a target it cannot justify.
    """
    tier = _tier(strength)
    family = alg.role_family(role)
    if family == "key-establishment":
        return _KEY_ESTABLISHMENT[tier]
    if family == "signature":
        return _FIRMWARE_SIGNATURE if firmware else _SIGNATURE[tier]
    return None  # symmetric / hash / kdf / unknown: not a PQC substitution


# --------------------------------------------------------------------------------------
# Policy profiles: what counts as acceptable *today*, independent of quantum timing.
# --------------------------------------------------------------------------------------
@dataclass(frozen=True)
class PolicyProfile:
    id: str
    name: str
    min_symmetric: int
    min_hash: int
    min_classical_pk: int
    require_pqc_by: int          # year by which quantum-vulnerable PK must be gone
    allow_non_hybrid_pqc: bool
    description: str
    citations: tuple[str, ...]


POLICIES: dict[str, PolicyProfile] = {p.id: p for p in [
    PolicyProfile(
        "nist_general", "NIST general purpose", 128, 128, 112, 2035, True,
        "Baseline commercial posture aligned to SP 800-131A Rev. 2 with NIST IR 8547's "
        "2035 removal date for quantum-vulnerable algorithms.",
        ("SP800131A", "IR8547"),
    ),
    PolicyProfile(
        "nsa_cnsa2", "NSA CNSA 2.0 (national security systems)", 256, 384, 192, 2033,
        True,
        "Requires AES-256, SHA-384, ML-KEM-1024 and ML-DSA-87. Under CNSA 2.0 a "
        "hybrid is permitted but not required; the PQC component alone is sufficient.",
        ("NSA_CNSA2",),
    ),
    PolicyProfile(
        "high_assurance_hybrid", "High-assurance PQ/T hybrid first", 256, 256, 128,
        2030, False,
        "Conservative posture for long-lived state secrets: always deploy a PQ/T "
        "hybrid so that a future lattice cryptanalytic result cannot retroactively "
        "expose recorded traffic.",
        ("RFC10024", "RFC9954", "CISA_QR"),
    ),
]}

DEFAULT_POLICY = "nist_general"


def symmetric_or_hash_advice(spec: alg.AlgorithmSpec, strength: int | None,
                             policy: PolicyProfile) -> tuple[str, str]:
    """(action, explanation) for primitives PQC does not replace.

    Kept deliberately separate from `target_for` so the engine can never emit
    'replace AES with ML-KEM'.
    """
    role = spec.roles[0] if spec.roles else ROLE_ENCRYPTION
    floor = policy.min_hash if role in (ROLE_HASH, ROLE_MAC) else policy.min_symmetric

    if spec.quantum_class == alg.CLASSICALLY_BROKEN:
        if spec.family in ("MD", "SHA") or spec.primitive in ("hash", "mac"):
            return ("replace-now",
                    f"{spec.name} is broken against classical cryptanalysis. Replace "
                    f"with SHA-256 or stronger. This is independent of any quantum "
                    f"timeline and should not wait for the PQC programme.")
        return ("replace-now",
                f"{spec.name} is disallowed by SP 800-131A Rev. 2. Replace with "
                f"AES-256-GCM. Classical issue -- fix immediately.")

    if strength is not None and strength < floor:
        return ("strengthen",
                f"{spec.name} provides ~{strength}-bit classical strength, below the "
                f"{policy.name} floor of {floor} bits. Move to a larger parameter set "
                f"(e.g. AES-256-GCM / SHA-384). PQC replacement is NOT applicable: "
                f"Grover offers at most a quadratic speedup, so a larger symmetric "
                f"key is the correct response.")

    return ("retain",
            f"{spec.name} is comparatively resilient to known quantum speedups and "
            f"meets the {policy.name} floor. Retain -- replacing it with a PQC "
            f"algorithm would be a category error.")
