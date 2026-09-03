"""Explainable quantum + classical risk engine (PART 14).

Design commitments:

  * **Deterministic.** Same input, same score, every time. No model, no randomness.
    A government reviewer must be able to recompute a score by hand from the
    factor table shown in the UI.
  * **Decomposed.** The 0-100 score is a weighted sum of six named factors, and the
    contribution of each is returned alongside the total. A number the user cannot
    decompose is a number they cannot act on or challenge.
  * **Separated concerns.** Classical weakness and quantum exposure are scored on
    different axes and never conflated. MD5 is a critical *classical* finding with
    near-zero quantum relevance; ECDSA P-384 is classically strong and a serious
    *quantum* finding. Collapsing those into one "risk" number is the mistake that
    makes crypto tooling useless.
  * **Honest about weights.** The weights below are an engineering judgement,
    documented and configurable -- not an empirically validated model. The UI says
    so, and `WEIGHT_RATIONALE` is surfaced in the API.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..knowledge import algorithms as alg
from ..knowledge import pqc
from ..models import (
    Confidence,
    Role,
    Criticality,
    CryptoAsset,
    DataClassification,
    Exposure,
    MigrationEffort,
    RiskBand,
    risk_band,
)

# ======================================================================================
# Weights. Rationale is part of the product, not a code comment.
# ======================================================================================
WEIGHTS: dict[str, float] = {
    "algorithm_exposure": 0.30,
    "data_sensitivity": 0.18,
    "data_lifetime": 0.20,
    "exposure": 0.14,
    "business_criticality": 0.12,
    "migration_effort": 0.06,
}

WEIGHT_RATIONALE: dict[str, str] = {
    "algorithm_exposure": (
        "Highest weight: if the primitive is not vulnerable, nothing else about the "
        "asset creates quantum risk. This factor is the gate."),
    "data_lifetime": (
        "Second highest, and deliberately above sensitivity. Under a store-now-"
        "decrypt-later threat model, confidentiality that must hold for 20 years is "
        "already failing today if the key exchange is Shor-vulnerable. Lifetime is "
        "what converts a future capability into a present-tense loss."),
    "data_sensitivity": (
        "Scales consequence. Weighted below lifetime because highly sensitive data "
        "with a 30-day useful life is a smaller quantum problem than moderately "
        "sensitive data retained for two decades."),
    "exposure": (
        "Internet-facing services are where traffic can be harvested at scale today "
        "for decryption later. Air-gapped assets carry the same algorithmic weakness "
        "but a far smaller collection opportunity."),
    "business_criticality": (
        "Drives sequencing more than absolute risk: it decides what an organisation "
        "can afford to break during migration."),
    "migration_effort": (
        "Lowest weight, and it *raises* the score rather than lowering it. High-effort "
        "assets must start earlier precisely because they take longer -- this is the "
        "same intuition Mosca's inequality formalises. Effort is not an excuse to "
        "defer; it is a reason to begin."),
}


@dataclass
class RiskFactor:
    name: str
    raw: float          # 0-100 before weighting
    weight: float
    contribution: float
    explanation: str


@dataclass
class RiskAssessment:
    score: float
    band: RiskBand
    quantum_band: RiskBand
    classical_status: str
    quantum_vulnerable: bool
    quantum_class: str
    factors: list[RiskFactor] = field(default_factory=list)
    explanation: list[str] = field(default_factory=list)
    migration_effort: MigrationEffort = MigrationEffort.MODERATE

    def to_dict(self) -> dict:
        return {
            "score": round(self.score, 1),
            "band": self.band.value,
            "quantum_band": self.quantum_band.value,
            "classical_status": self.classical_status,
            "quantum_vulnerable": self.quantum_vulnerable,
            "quantum_class": self.quantum_class,
            "weights_are_engineering_judgement": True,
            "factors": [
                {"name": f.name, "raw": round(f.raw, 1), "weight": f.weight,
                 "contribution": round(f.contribution, 2), "explanation": f.explanation}
                for f in self.factors
            ],
            "explanation": self.explanation,
        }


# ======================================================================================
# Dual-axis assessment (contract §11/§14/§15)
#
# Classical risk and quantum exposure are computed by two functions that share no
# state and never read each other's output. This is the property that keeps the
# product honest:
#
#   MD5            -> classical CRITICAL, quantum INFO
#                     (broken today; a quantum computer adds nothing)
#   ECDSA P-384    -> classical INFO,     quantum CRITICAL
#                     (classically strong; Shor recovers the private key)
#   AES-256-GCM    -> classical INFO,     quantum INFO
#                     (Grover is a quadratic speedup, not a break)
#   RSA-1024       -> classical HIGH,     quantum CRITICAL
#                     (weak parameters AND Shor-vulnerable -- two separate problems)
#
# Collapsing these into one number is the mistake that makes crypto tooling
# unusable: a security team cannot tell "fix this today" from "plan a migration".
# ======================================================================================
@dataclass
class AxisResult:
    band: RiskBand
    reason: str
    detail: dict = field(default_factory=dict)


def classical_risk(asset: CryptoAsset,
                   policy: pqc.PolicyProfile | None = None) -> AxisResult:
    """Exposure to CLASSICAL cryptanalysis available today.

    Quantum computing plays no part in this function. Nothing it returns depends on
    a CRQC horizon, on Shor, or on Grover.
    """
    policy = policy or pqc.POLICIES[pqc.DEFAULT_POLICY]
    spec = alg.get(asset.algorithm)

    # --- certificate hygiene is a classical concern -----------------------------------
    if asset.days_to_expiry is not None:
        if asset.days_to_expiry < 0:
            return AxisResult(
                RiskBand.CRITICAL,
                f"Certificate expired {abs(asset.days_to_expiry)} days ago "
                f"({asset.certificate_expiry}). Relying parties will reject it: this is "
                f"an availability and trust failure now, unrelated to quantum computing.",
                {"days_to_expiry": asset.days_to_expiry, "trigger": "expired-certificate"})
        if asset.days_to_expiry < 30:
            return AxisResult(
                RiskBand.HIGH,
                f"Certificate expires in {asset.days_to_expiry} days. Renew immediately.",
                {"days_to_expiry": asset.days_to_expiry, "trigger": "expiring-certificate"})

    if asset.certificate_sig_algorithm and "sha1" in asset.certificate_sig_algorithm.lower():
        return AxisResult(
            RiskBand.CRITICAL,
            f"Certificate is signed with {asset.certificate_sig_algorithm}. SHA-1 "
            f"chosen-prefix collisions are practical, so the signature does not bind "
            f"the certificate contents. Re-issue under SHA-256 or stronger. This is a "
            f"present-tense classical failure.",
            {"trigger": "sha1-signature"})

    # --- weak cipher suites outrank protocol version -----------------------------------
    # Checked BEFORE the protocol branch: a TLS 1.2 endpoint whose suite list permits
    # RC4 or DES is a HIGH classical finding, and reporting it as "TLS 1.2, acceptable"
    # because the version check ran first would hide the actual exposure.
    if "weak-cipher-suite" in asset.tags:
        return AxisResult(
            RiskBand.HIGH,
            "Cipher-suite configuration permits weak or legacy families "
            "(NULL/EXPORT/DES/RC4/MD5-class). Any peer may negotiate them, so the "
            "effective security is that of the weakest permitted suite, not the "
            "strongest.",
            {"trigger": "weak-cipher-suite"})

    # --- protocol configuration --------------------------------------------------------
    if spec is None and asset.protocol:
        ver = (asset.protocol_version or "").strip()
        proto = asset.protocol.upper()
        if proto == "SSL" or ver in ("2.0", "3.0"):
            return AxisResult(
                RiskBand.CRITICAL,
                f"{proto} {ver} is prohibited (POODLE, DROWN). Exploitable today.",
                {"trigger": "prohibited-protocol"})
        if ver in ("1.0", "1.1"):
            return AxisResult(
                RiskBand.HIGH,
                f"TLS {ver} is deprecated by RFC 8996 and cannot negotiate modern AEAD "
                f"cipher suites.",
                {"trigger": "deprecated-protocol"})
        if ver == "1.2":
            return AxisResult(
                RiskBand.LOW,
                "TLS 1.2 remains classically acceptable when configured with AEAD "
                "suites. (Its inability to carry RFC 10024 hybrid groups is a quantum-"
                "migration blocker, scored on the quantum axis, not here.)",
                {"trigger": "current-protocol"})
        if ver == "1.3":
            return AxisResult(RiskBand.INFO, "TLS 1.3 is the current protocol version.",
                              {"trigger": "current-protocol"})
        return AxisResult(RiskBand.LOW,
                          f"{proto} {ver or 'unspecified version'} configuration detected; "
                          f"negotiated parameters require review.",
                          {"trigger": "protocol-unreviewed"})

    if spec is None:
        return AxisResult(RiskBand.INFO,
                          "No algorithm resolved; no classical assessment possible.",
                          {"trigger": "unresolved"})

    # --- the primitive itself -----------------------------------------------------------
    status = alg.classical_status(spec, asset.key_size, asset.curve)
    strength = alg.strength_for(spec, asset.key_size, asset.curve)

    if spec.status == alg.ST_BROKEN:
        return AxisResult(
            RiskBand.CRITICAL,
            f"{spec.name} is broken against classical cryptanalysis"
            + (f" ({spec.note.split('.')[0]})" if spec.note else "")
            + ". Exploitable now, with no quantum computer required.",
            {"trigger": "broken-primitive", "classical_status": status,
             "strength_bits": strength})

    if spec.quantum_class == alg.CLASSICALLY_BROKEN:
        return AxisResult(
            RiskBand.HIGH,
            f"{spec.name} is deprecated or disallowed by "
            f"{spec.standard or 'SP 800-131A Rev. 2'}. This is a classical weakness "
            f"and must be remediated on the normal vulnerability timeline, not the "
            f"PQC programme's.",
            {"trigger": "deprecated-primitive", "classical_status": status,
             "strength_bits": strength})

    if strength is not None:
        if strength < 80:
            band = RiskBand.CRITICAL
        elif strength < 112:
            band = RiskBand.HIGH
        elif strength < 128:
            band = RiskBand.MEDIUM
        elif strength < 192:
            band = RiskBand.LOW
        else:
            band = RiskBand.INFO

        floor = (policy.min_hash if spec.primitive in ("hash", "mac")
                 else policy.min_symmetric if spec.primitive in
                 ("block-cipher", "stream-cipher", "ae")
                 else policy.min_classical_pk)
        below_floor = strength < floor
        if below_floor and band in (RiskBand.INFO, RiskBand.LOW):
            band = RiskBand.MEDIUM

        reason = (f"{spec.name}"
                  + (f" at {asset.key_size} bits" if asset.key_size else "")
                  + (f" on {asset.curve}" if asset.curve else "")
                  + f" provides approximately {strength}-bit classical security "
                    f"(SP 800-57 Pt.1 Rev.5 comparable strength). Classical status: "
                    f"{status}.")
        if below_floor:
            reason += (f" Below the {floor}-bit floor required by "
                       f"{policy.name}.")
        return AxisResult(band, reason,
                          {"trigger": "parameter-strength", "classical_status": status,
                           "strength_bits": strength, "policy_floor": floor,
                           "below_policy_floor": below_floor})

    return AxisResult(RiskBand.LOW,
                      f"{spec.name}: classical strength not determinable from the "
                      f"evidence available.",
                      {"trigger": "indeterminate", "classical_status": status})


def quantum_exposure(asset: CryptoAsset,
                     policy: pqc.PolicyProfile | None = None) -> AxisResult:
    """Exposure to a cryptographically relevant quantum computer.

    Classical weakness plays no part in this function. MD5 scores INFO here because
    a quantum computer contributes nothing to breaking it -- that does not make MD5
    safe, it makes MD5 someone else's problem (the classical axis, at CRITICAL).
    """
    policy = policy or pqc.POLICIES[pqc.DEFAULT_POLICY]
    spec = alg.get(asset.algorithm)

    if spec is None:
        if asset.protocol == "TLS" and asset.protocol_version in ("1.0", "1.1", "1.2"):
            return AxisResult(
                RiskBand.MEDIUM,
                f"TLS {asset.protocol_version} cannot negotiate the RFC 10024 PQ/T "
                f"hybrid key-exchange groups, which are defined for TLS 1.3 only. The "
                f"protocol version is therefore a structural blocker to post-quantum "
                f"key establishment on this service.",
                {"trigger": "protocol-blocks-pqc"})
        if asset.protocol == "TLS" and asset.protocol_version == "1.3":
            return AxisResult(
                RiskBand.LOW,
                "TLS 1.3 can carry RFC 10024 hybrid groups. Ready to negotiate "
                "post-quantum key establishment once both endpoints support it.",
                {"trigger": "protocol-pqc-capable"})
        return AxisResult(RiskBand.INFO,
                          "No algorithm resolved; no quantum exposure attributable.",
                          {"trigger": "unresolved"})

    # --- Shor: the actual PQC migration surface ------------------------------------------
    if spec.quantum_class == alg.SHOR_BROKEN:
        problem = ("integer factorisation" if spec.family == "RSA"
                   else "the elliptic-curve discrete logarithm problem"
                   if spec.family in ("EC", "EdDSA")
                   else "a discrete logarithm problem")
        reason = (f"{spec.name} rests on {problem}, which Shor's algorithm solves in "
                  f"polynomial time on a CRQC. Increasing the parameter size does not "
                  f"mitigate this")
        if asset.key_size:
            reason += (f" -- {spec.name}-{asset.key_size} is affected identically "
                       f"to smaller parameters")
        reason += ". Replacement with a post-quantum mechanism is the only remedy."

        band = RiskBand.CRITICAL
        detail = {"trigger": "shor-vulnerable", "quantum_strength_bits": 0}

        # Harvest-now-decrypt-later: for key establishment, recorded traffic can be
        # decrypted retroactively, so a long confidentiality requirement means the
        # loss is already accruing. This is contextual amplification of an already
        # critical band, recorded explicitly rather than folded in silently.
        if (asset.cryptographic_role in (Role.KEY_ESTABLISHMENT.value,
                                         Role.KEY_TRANSPORT.value)
                and (asset.data_lifetime_years or 0) >= 5):
            reason += (f" Under a harvest-now-decrypt-later threat model this asset is "
                       f"failing its requirement TODAY: traffic recorded now must stay "
                       f"confidential for {asset.data_lifetime_years} years, and the "
                       f"session key is recoverable once a CRQC exists.")
            detail["harvest_now_decrypt_later"] = True
            detail["data_lifetime_years"] = asset.data_lifetime_years
        elif asset.cryptographic_role in (Role.DIGITAL_SIGNATURE.value,
                                          Role.SIGNATURE_VERIFICATION.value,
                                          Role.AUTHENTICATION.value,
                                          Role.CERTIFICATE_VALIDATION.value):
            reason += (" For a signature, exposure begins when a CRQC exists rather "
                       "than retroactively -- forgery is a future risk, not a "
                       "harvest-now one. Sequence it after key establishment.")
            detail["harvest_now_decrypt_later"] = False
        return AxisResult(band, reason, detail)

    # --- Grover: a quadratic speedup, not a break ------------------------------------------
    if spec.quantum_class == alg.GROVER_REDUCED:
        qs = alg.quantum_strength_for(spec, asset.key_size, asset.curve)
        classical = alg.strength_for(spec, asset.key_size, asset.curve)
        if spec.primitive == "hash":
            reason = (f"{spec.name} offers ~{classical}-bit collision resistance. Grover "
                      f"does not beat the classical birthday bound by a useful margin "
                      f"under realistic memory and parallelism constraints, so this is "
                      f"NOT quantum-broken.")
            band = RiskBand.INFO if (classical or 0) >= policy.min_hash else RiskBand.LOW
            if (classical or 0) < policy.min_hash:
                reason += (f" It is below the {policy.min_hash}-bit floor set by "
                           f"{policy.name}; the response is a larger digest, not PQC.")
            return AxisResult(band, reason,
                              {"trigger": "grover-hash", "quantum_strength_bits": qs})

        if qs is not None and qs < 96:
            return AxisResult(
                RiskBand.MEDIUM,
                f"{spec.name} retains ~{qs} bits against Grover-style key search "
                f"(half the {classical}-bit classical exponent). That is below a "
                f"128-bit post-quantum margin. The correct response is a LARGER "
                f"SYMMETRIC KEY (AES-256), not a PQC algorithm -- PQC replaces "
                f"public-key primitives only.",
                {"trigger": "grover-margin-low", "quantum_strength_bits": qs})

        return AxisResult(
            RiskBand.INFO,
            f"{spec.name} is comparatively resilient to known quantum speedups, "
            f"retaining ~{qs} bits against Grover-style search. Retain it. Substituting "
            f"a PQC algorithm here would be a category error.",
            {"trigger": "grover-adequate", "quantum_strength_bits": qs})

    # --- classically broken: quantum computing is irrelevant --------------------------------
    if spec.quantum_class == alg.CLASSICALLY_BROKEN:
        return AxisResult(
            RiskBand.INFO,
            f"{spec.name} carries no meaningful quantum exposure: it is already broken "
            f"or disallowed classically, so a CRQC adds nothing to an attacker's "
            f"capability. Its urgency comes from the classical axis, where it scores "
            f"far higher.",
            {"trigger": "classical-not-quantum"})

    if spec.quantum_class == alg.PQC_STANDARDIZED:
        return AxisResult(
            RiskBand.INFO,
            f"{spec.name} is a finalised NIST post-quantum standard ({spec.standard}). "
            f"This asset is evidence of migration progress, not exposure.",
            {"trigger": "already-migrated"})

    if spec.quantum_class == alg.PQC_SELECTED:
        return AxisResult(
            RiskBand.LOW,
            f"{spec.name} is selected for standardisation but has no final FIPS "
            f"({spec.standard}). Acceptable as a hybrid component or backup; it must "
            f"not be the sole mechanism protecting production data yet.",
            {"trigger": "pqc-not-final"})

    if spec.quantum_class == alg.HYBRID_PQT:
        if spec.status == alg.ST_DEPRECATED:
            return AxisResult(
                RiskBand.MEDIUM,
                f"{spec.name} is a pre-standard hybrid using draft Kyber rather than "
                f"final ML-KEM; its IANA code point is obsoleted by RFC 10024. It "
                f"provides real post-quantum protection but will not interoperate "
                f"long-term. Re-pin to X25519MLKEM768.",
                {"trigger": "draft-hybrid"})
        return AxisResult(
            RiskBand.INFO,
            f"{spec.name} is a standardised PQ/T hybrid ({spec.standard}) -- the target "
            f"state for key establishment.",
            {"trigger": "hybrid-target-state"})

    return AxisResult(RiskBand.LOW, "Quantum class not determined.",
                      {"trigger": "indeterminate"})


# ======================================================================================
# Factor A -- algorithm exposure
# ======================================================================================
def algorithm_exposure(asset: CryptoAsset) -> tuple[float, str, RiskBand]:
    """0-100 exposure of the primitive itself, plus a quantum-specific band."""
    spec = alg.get(asset.algorithm)

    if spec is None:
        if asset.protocol:
            return _protocol_exposure(asset)
        return 25.0, ("No algorithm resolved for this asset; scored as residual "
                      "uncertainty rather than zero."), RiskBand.LOW

    strength = alg.strength_for(spec, asset.key_size, asset.curve)

    if spec.quantum_class == alg.SHOR_BROKEN:
        # Parameter size does not help: Shor solves the underlying problem outright.
        base = 100.0
        note = (f"{spec.name} rests on {'integer factorisation' if spec.family == 'RSA' else 'a discrete logarithm problem'}, "
                f"which Shor's algorithm solves in polynomial time on a "
                f"cryptographically relevant quantum computer. Increasing the key size "
                f"does not mitigate this")
        if asset.key_size:
            note += f" -- {spec.name}-{asset.key_size} is affected identically to smaller parameters"
        note += ". Replacement with a PQC mechanism is the only remedy."
        return base, note, RiskBand.CRITICAL

    if spec.quantum_class == alg.CLASSICALLY_BROKEN:
        base = 95.0 if spec.status == alg.ST_BROKEN else 80.0
        return base, (
            f"{spec.name} is broken or disallowed against *classical* cryptanalysis "
            f"({spec.standard or 'see SP 800-131A Rev. 2'}). This is not a quantum "
            f"issue and must not wait for the PQC programme -- it is exploitable now."
        ), RiskBand.LOW

    if spec.quantum_class == alg.GROVER_REDUCED:
        qs = alg.quantum_strength_for(spec, asset.key_size, asset.curve)
        if strength is not None and strength < 112:
            return 70.0, (
                f"{spec.name} provides only ~{strength}-bit classical strength, below "
                f"the 112-bit floor in SP 800-131A Rev. 2. Classical concern."
            ), RiskBand.LOW
        if qs is not None and qs < 96:
            return 35.0, (
                f"{spec.name} offers ~{strength}-bit classical strength and ~{qs} bits "
                f"against Grover-style search. Not broken by quantum computing, but "
                f"below a 128-bit post-quantum margin. The correct response is a larger "
                f"symmetric parameter set (e.g. AES-256), not a PQC algorithm."
            ), RiskBand.LOW
        return 10.0, (
            f"{spec.name} is comparatively resilient to known quantum speedups "
            f"(~{qs} bits against Grover-style search). Retain. Replacing it with a "
            f"PQC algorithm would be a category error -- PQC replaces public-key "
            f"primitives, not symmetric ones."
        ), RiskBand.INFO

    if spec.quantum_class == alg.PQC_STANDARDIZED:
        return 3.0, (
            f"{spec.name} is a finalised NIST post-quantum standard ({spec.standard}). "
            f"Already migrated -- this asset is evidence of progress, not risk."
        ), RiskBand.INFO

    if spec.quantum_class == alg.PQC_SELECTED:
        return 30.0, (
            f"{spec.name} is selected for standardisation but has no final FIPS "
            f"({spec.standard}). Acceptable in a hybrid or as a backup, but it must not "
            f"be the sole mechanism protecting production data yet."
        ), RiskBand.LOW

    if spec.quantum_class == alg.HYBRID_PQT:
        if spec.status == alg.ST_DEPRECATED:
            return 45.0, (
                f"{spec.name} is a pre-standard hybrid group using draft Kyber rather "
                f"than final ML-KEM, and its IANA code point is obsoleted by RFC 10024. "
                f"An early pilot that now needs re-pinning to X25519MLKEM768."
            ), RiskBand.MEDIUM
        return 2.0, (
            f"{spec.name} is a PQ/T hybrid ({spec.standard}). Provides post-quantum "
            f"confidentiality while retaining classical security as a hedge. This is "
            f"the target state for TLS key establishment."
        ), RiskBand.INFO

    return 30.0, "Algorithm class not determined.", RiskBand.LOW


def _protocol_exposure(asset: CryptoAsset) -> tuple[float, str, RiskBand]:
    ver = (asset.protocol_version or "").strip()
    proto = (asset.protocol or "").upper()
    if proto == "SSL" or ver in ("2.0", "3.0"):
        return 95.0, (f"{proto} {ver} is prohibited: multiple practical attacks "
                      f"(POODLE, DROWN). Classical, exploitable today."), RiskBand.LOW
    if ver in ("1.0", "1.1"):
        return 82.0, (f"TLS {ver} is deprecated by RFC 8996 and cannot negotiate modern "
                      f"AEAD suites. Classical exposure; also blocks any PQC hybrid, "
                      f"which requires TLS 1.3."), RiskBand.LOW
    if ver == "1.2":
        return 55.0, ("TLS 1.2 is currently acceptable but cannot carry the RFC 10024 "
                      "PQ/T hybrid key-exchange groups -- those are TLS 1.3 only. TLS 1.2 "
                      "is therefore a structural blocker to PQC migration, which is why "
                      "it scores above a purely classical assessment would suggest."
                      ), RiskBand.MEDIUM
    if ver == "1.3":
        return 18.0, ("TLS 1.3 is current and is the only version that can negotiate "
                      "RFC 10024 hybrid groups. Ready to carry PQC once the endpoints "
                      "support it."), RiskBand.LOW
    if proto == "SSH":
        return 40.0, ("SSH detected. Modern OpenSSH offers hybrid PQC key exchange; "
                      "verify the negotiated KEX rather than assuming."), RiskBand.MEDIUM
    return 40.0, f"{proto} {ver} protocol configuration detected.", RiskBand.MEDIUM


# ======================================================================================
# Factor F -- migration effort
# ======================================================================================
def estimate_effort(asset: CryptoAsset) -> tuple[MigrationEffort, str]:
    """Heuristic effort model. Every input is a fact we actually observed."""
    score = 2.0
    reasons: list[str] = []

    if asset.asset_type.value == "certificate":
        score += 1.0
        reasons.append("certificate replacement depends on CA capability and chain "
                       "rollout, not just a code change")
    if asset.asset_type.value == "binary-artifact":
        score += 1.5
        reasons.append("binary-only artefact: requires vendor engagement or a rebuild "
                       "toolchain")
    if asset.protocol_version in ("1.0", "1.1", "1.2") and asset.protocol == "TLS":
        score += 1.0
        reasons.append("protocol upgrade to TLS 1.3 is a prerequisite for hybrid groups")

    if asset.pqc_readiness == "none":
        score += 1.5
        reasons.append("the linked library has no PQC path, so the provider must be "
                       "replaced before migration can start")
    elif asset.pqc_readiness == "provider":
        score += 0.5
        reasons.append("PQC requires a provider upgrade or add-on module")
    elif asset.pqc_readiness == "native":
        score -= 0.5
        reasons.append("the linked library already supports PQC natively")

    if asset.language in ("java", "kotlin", "scala") :
        score += 0.5
        reasons.append("JVM estates typically pin a provider and a JDK version")
    if asset.language in ("c", "cpp"):
        score += 0.5
        reasons.append("native code requires recompilation and redistribution")

    if "crypto-agility-blocker" in asset.tags:
        score += 1.0
        reasons.append("algorithm choice is hard-coded or the image tag floats, so the "
                       "component cannot be re-pinned without a rebuild")
    if "key-material-exposure" in asset.tags:
        score += 0.5
        reasons.append("embedded key material must be extracted and rotated first")
    if asset.business_criticality in (Criticality.MISSION_CRITICAL, Criticality.HIGH):
        score += 0.5
        reasons.append("mission-critical change windows are narrow and require staged "
                       "rollout with rollback")

    buckets = [(2.0, MigrationEffort.TRIVIAL), (2.8, MigrationEffort.LOW),
               (3.8, MigrationEffort.MODERATE), (4.8, MigrationEffort.HIGH)]
    effort = MigrationEffort.VERY_HIGH
    for threshold, value in buckets:
        if score <= threshold:
            effort = value
            break
    return effort, ("Effort = " + effort.value + ". " +
                    ("Drivers: " + "; ".join(reasons) + "." if reasons
                     else "No complicating factors observed."))


# ======================================================================================
# Main entry point
# ======================================================================================
def assess(asset: CryptoAsset, policy_id: str = pqc.DEFAULT_POLICY,
           weights: dict[str, float] | None = None) -> RiskAssessment:
    w = weights or WEIGHTS
    spec = alg.get(asset.algorithm)
    policy = pqc.POLICIES.get(policy_id, pqc.POLICIES[pqc.DEFAULT_POLICY])

    alg_raw, alg_note, qband = algorithm_exposure(asset)
    effort, effort_note = estimate_effort(asset)

    sensitivity = asset.data_classification or DataClassification.INTERNAL
    lifetime = asset.data_lifetime_years if asset.data_lifetime_years is not None else 3
    exposure = asset.exposure or Exposure.INTERNAL
    criticality = asset.business_criticality or Criticality.IMPORTANT

    sens_raw = (sensitivity.score - 1) / 4 * 100
    # Lifetime saturates at 20 years: beyond that the store-now-decrypt-later
    # conclusion is already maximal and further years add no information.
    life_raw = min(lifetime, 20) / 20 * 100
    exp_raw = exposure.score / 4 * 100
    crit_raw = (criticality.score - 1) / 4 * 100
    effort_raw = (effort.score - 1) / 4 * 100

    factors = [
        RiskFactor("algorithm_exposure", alg_raw, w["algorithm_exposure"],
                   alg_raw * w["algorithm_exposure"], alg_note),
        RiskFactor("data_lifetime", life_raw, w["data_lifetime"],
                   life_raw * w["data_lifetime"],
                   f"Protected data has a {lifetime}-year retention/secrecy requirement. "
                   + ("Under a store-now-decrypt-later threat model, traffic captured "
                      "today must still be confidential in "
                      f"{lifetime} years -- so a Shor-vulnerable key exchange is already "
                      "failing that requirement now."
                      if (spec and spec.quantum_vulnerable) else
                      "Lifetime scales consequence but this primitive is not "
                      "Shor-vulnerable.")),
        RiskFactor("data_sensitivity", sens_raw, w["data_sensitivity"],
                   sens_raw * w["data_sensitivity"],
                   f"Data classification: {sensitivity.value} "
                   f"({sensitivity.score}/5 on the operator-declared scale)."),
        RiskFactor("exposure", exp_raw, w["exposure"], exp_raw * w["exposure"],
                   f"Network exposure: {exposure.value} ({exposure.score}/4). "
                   + ("Internet-reachable traffic can be harvested at scale today for "
                      "later decryption." if exposure.score >= 3 else
                      "Limited collection opportunity reduces, but does not remove, "
                      "the algorithmic weakness.")),
        RiskFactor("business_criticality", crit_raw, w["business_criticality"],
                   crit_raw * w["business_criticality"],
                   f"Business criticality: {criticality.value} ({criticality.score}/5). "
                   f"Primarily affects migration sequencing and change-window risk."),
        RiskFactor("migration_effort", effort_raw, w["migration_effort"],
                   effort_raw * w["migration_effort"], effort_note),
    ]

    score = sum(f.contribution for f in factors)

    # ---- confidence damping ---------------------------------------------------------
    # A LOW-confidence lexical hit should not sit at the top of the remediation queue
    # ahead of a parsed certificate. We damp the score by evidence strength and say so.
    damping = {Confidence.HIGH: 1.0, Confidence.MEDIUM: 0.92, Confidence.LOW: 0.78}[
        asset.confidence]
    pre_damp = score
    score *= damping

    explanation: list[str] = []
    explanation.append(alg_note)
    if damping < 1.0:
        explanation.append(
            f"Score damped from {pre_damp:.1f} to {score:.1f} because the supporting "
            f"evidence is {asset.confidence.value} confidence "
            f"({', '.join(asset.detectors)}). ECDAT ranks well-evidenced findings above "
            f"weakly-evidenced ones rather than treating every match as fact.")

    if "suspected-non-security-use" in asset.tags:
        score *= 0.55
        explanation.append(
            "Further reduced: surrounding context suggests a non-security use "
            "(checksum, cache key or test fixture). Flagged for human triage rather "
            "than reported as a vulnerability.")
    if "test-path" in asset.tags:
        score *= 0.7
        explanation.append("Reduced: the finding is in a test or fixture path.")

    classical = alg.classical_status(spec, asset.key_size, asset.curve) if spec else "unknown"

    # Policy floor violations are reported even when quantum risk is low.
    if spec and spec.primitive in ("block-cipher", "stream-cipher", "ae", "hash", "mac"):
        strength = alg.strength_for(spec, asset.key_size, asset.curve)
        floor = (policy.min_hash if spec.primitive in ("hash", "mac")
                 else policy.min_symmetric)
        if strength is not None and strength < floor:
            explanation.append(
                f"Policy: {policy.name} requires at least {floor}-bit strength for this "
                f"primitive class; this asset provides ~{strength} bits.")

    score = max(0.0, min(100.0, score))
    return RiskAssessment(
        score=score,
        band=risk_band(score),
        quantum_band=qband,
        classical_status=classical,
        quantum_vulnerable=bool(spec and spec.quantum_vulnerable),
        quantum_class=spec.quantum_class if spec else "unknown",
        factors=factors,
        explanation=explanation,
        migration_effort=effort,
    )


def apply(asset: CryptoAsset, policy_id: str = pqc.DEFAULT_POLICY) -> RiskAssessment:
    """Assess and write the result back onto the canonical asset.

    Populates the two canonical security fields independently:
      * `classical_risk`    -- exposure to cryptanalysis available today
      * `quantum_exposure`  -- exposure to a CRQC
    `quantum_risk` is retained as an alias of `quantum_exposure` for callers written
    against the earlier field name. `risk_score` remains the composite used for
    ordering, and its band lives in `risk_factors['band']` -- it is deliberately NOT
    written into either axis field, because a composite is not an axis.
    """
    policy = pqc.POLICIES.get(policy_id, pqc.POLICIES[pqc.DEFAULT_POLICY])
    ra = assess(asset, policy_id)

    classical = classical_risk(asset, policy)
    quantum = quantum_exposure(asset, policy)

    asset.risk_score = round(ra.score, 1)
    asset.classical_risk = classical.band
    asset.quantum_exposure = quantum.band
    asset.quantum_risk = quantum.band          # alias, kept in sync
    asset.classical_security_status = ra.classical_status
    asset.quantum_vulnerable = ra.quantum_vulnerable
    asset.quantum_class = ra.quantum_class

    asset.risk_factors = {
        **ra.to_dict(),
        "classical_risk": {
            "band": classical.band.value,
            "reason": classical.reason,
            **classical.detail,
        },
        "quantum_exposure": {
            "band": quantum.band.value,
            "reason": quantum.reason,
            **quantum.detail,
        },
        "axes_are_independent": (
            "classical_risk and quantum_exposure are computed by separate functions "
            "that do not read each other's output. A primitive can be critical on one "
            "axis and informational on the other."),
        "policy": policy.id,
    }
    asset.risk_explanation = [classical.reason, quantum.reason] + ra.explanation

    if not asset.overrides.get("migration_effort"):
        asset.migration_effort = ra.migration_effort
        asset.migration_months = ra.migration_effort.months
    return ra
