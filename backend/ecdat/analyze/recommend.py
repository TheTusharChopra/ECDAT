"""Role-aware PQC / hybrid recommendation engine (PART 16-19).

The engine refuses to emit a mapping it cannot defend. Concretely:

  * Recommendations are keyed on **cryptographic role**, so ML-KEM is never proposed
    as a replacement for a signature and ML-DSA is never proposed for key
    establishment.
  * When the role could not be established from evidence, the engine says so and
    recommends *determining the role* as the next action rather than guessing a
    target. An honest "insufficient evidence" is more useful to an engineer than a
    confident wrong answer.
  * Symmetric and hash primitives are routed to a strength-policy path that cannot
    return a PQC algorithm.
  * Protocol feasibility is checked: a TLS hybrid group is only recommended where
    TLS 1.3 is possible, and library PQC capability is reported as a prerequisite.
  * Every recommendation carries the citation keys backing it.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..knowledge import algorithms as alg
from ..knowledge import libraries as libs
from ..knowledge import pqc
from ..models import CryptoAsset

ACTION_MIGRATE_PQC = "migrate-to-pqc"
ACTION_MIGRATE_HYBRID = "migrate-to-pqt-hybrid"
ACTION_REPLACE_NOW = "replace-now-classical"
ACTION_STRENGTHEN = "strengthen-parameters"
ACTION_RETAIN = "retain"
ACTION_UPGRADE_PROTOCOL = "upgrade-protocol"
ACTION_RENEW_CERT = "renew-certificate"
ACTION_DETERMINE_ROLE = "determine-role-then-migrate"
ACTION_REPIN = "re-pin-to-standard"
ACTION_ROTATE_KEY = "rotate-and-externalise-key"
ACTION_VERIFY = "verify-manually"


@dataclass
class Recommendation:
    action: str
    headline: str
    current: str
    role: str
    why: str
    recommended_pqc: str | None = None
    recommended_hybrid: str | None = None
    alternative: str | None = None
    steps: list[str] = field(default_factory=list)
    citations: list[str] = field(default_factory=list)
    prerequisites: list[str] = field(default_factory=list)
    caveats: list[str] = field(default_factory=list)
    protocol_note: str = ""

    def to_dict(self) -> dict:
        return {
            "action": self.action, "headline": self.headline, "current": self.current,
            "role": self.role, "why": self.why,
            "recommended_pqc": self.recommended_pqc,
            "recommended_hybrid": self.recommended_hybrid,
            "alternative": self.alternative,
            "steps": self.steps, "citations": self.citations,
            "prerequisites": self.prerequisites, "caveats": self.caveats,
            "protocol_note": self.protocol_note,
            "citation_details": [
                {"key": k, **{f: getattr(pqc.CITATIONS[k], f)
                              for f in ("title", "publisher", "url", "dated")}}
                for k in self.citations if k in pqc.CITATIONS
            ],
        }


_GENERIC_STEPS = [
    "Confirm the finding and its cryptographic role against the evidence trail.",
    "Verify that the protocol/library at this component supports the target mechanism.",
    "Benchmark the target: measure handshake latency, CPU and message-size impact "
    "(ML-KEM public keys and ciphertexts are far larger than X25519).",
    "Deploy to a canary in a non-production environment; monitor negotiation failures "
    "and MTU/fragmentation effects.",
    "Roll out progressively with a documented rollback path.",
    "Only after the new mechanism is stable, disable the legacy mechanism.",
    "Re-scan with ECDAT to confirm the asset moved out of the quantum-vulnerable "
    "inventory.",
]


def _is_firmware(asset: CryptoAsset) -> bool:
    hay = " ".join(filter(None, [asset.file, asset.application, asset.usage,
                                 asset.asset_name])).lower()
    return any(k in hay for k in ("firmware", "bootloader", "secureboot", "secure_boot",
                                  "code-sign", "codesign", "image-signing", "uefi"))


def recommend(asset: CryptoAsset, policy_id: str = pqc.DEFAULT_POLICY) -> Recommendation:
    policy = pqc.POLICIES.get(policy_id, pqc.POLICIES[pqc.DEFAULT_POLICY])
    spec = alg.get(asset.algorithm)
    role = asset.cryptographic_role or alg.ROLE_UNKNOWN
    current = asset.asset_name

    # --- key material found in a repo or image ------------------------------------------
    if "key-material-exposure" in asset.tags:
        return Recommendation(
            action=ACTION_ROTATE_KEY,
            headline="Rotate the key and move it out of the artefact",
            current=current, role=role,
            why=("Private key material is stored inside a repository or container image. "
                 "This must be resolved before any PQC work: a key that cannot be rotated "
                 "cannot be migrated, and its exposure is an immediate classical risk "
                 "independent of quantum computing."),
            steps=["Treat the key as compromised and revoke any certificate bound to it.",
                   "Issue a replacement key in an HSM or a managed secret store.",
                   "Inject the key at runtime rather than baking it into the artefact.",
                   "Purge the key from version-control and image history.",
                   "Re-scan to confirm the artefact no longer carries key material."],
            citations=["CISA_QR"],
            caveats=["ECDAT recorded only the presence and location of this material; "
                     "it never read, parsed or stored the key bytes."],
        )

    # --- protocol-only assets ------------------------------------------------------------
    if spec is None and asset.protocol:
        ver = asset.protocol_version or ""
        if asset.protocol == "TLS" and ver in ("1.0", "1.1") or asset.protocol == "SSL":
            return Recommendation(
                action=ACTION_UPGRADE_PROTOCOL,
                headline=f"Retire {asset.protocol} {ver}; move to TLS 1.3",
                current=f"{asset.protocol} {ver}", role="protocol",
                why=(f"{asset.protocol} {ver} is deprecated (RFC 8996 for TLS 1.0/1.1) and "
                     f"cannot negotiate modern AEAD suites. It is also a hard blocker for "
                     f"post-quantum migration: the RFC 10024 hybrid key-exchange groups "
                     f"exist only for TLS 1.3."),
                recommended_hybrid="X25519MLKEM768",
                steps=["Inventory clients still requiring the legacy version.",
                       "Enable TLS 1.2 and 1.3 in parallel; monitor handshake failures.",
                       "Disable TLS 1.0/1.1.",
                       "Once on TLS 1.3, enable the X25519MLKEM768 group (RFC 10024).",
                       "Re-scan to confirm."],
                citations=["RFC10024", "SP800131A"],
                protocol_note="TLS 1.3 is a prerequisite for any PQ/T hybrid group.",
            )
        if asset.protocol == "TLS" and ver == "1.2":
            return Recommendation(
                action=ACTION_UPGRADE_PROTOCOL,
                headline="Enable TLS 1.3 -- prerequisite for PQ/T hybrid key exchange",
                current="TLS 1.2", role="protocol",
                why=("TLS 1.2 is not currently broken, but the RFC 10024 hybrid groups "
                     "(X25519MLKEM768 and the NIST-curve variants) are defined for "
                     "TLS 1.3 only. Any post-quantum key-establishment plan for this "
                     "service therefore starts with a TLS 1.3 upgrade."),
                recommended_hybrid="X25519MLKEM768",
                steps=["Enable TLS 1.3 alongside 1.2 (no client break).",
                       "Confirm the TLS library supports RFC 10024 groups.",
                       "Add X25519MLKEM768 to the supported-groups list.",
                       "Monitor for larger ClientHello / fragmentation issues.",
                       "Shift traffic, then deprecate TLS 1.2."],
                citations=["RFC10024", "RFC9954"],
                protocol_note="IANA supported_groups code point 0x11EC (4588).",
            )
        if asset.protocol == "TLS" and ver == "1.3":
            return Recommendation(
                action=ACTION_MIGRATE_HYBRID,
                headline="TLS 1.3 in place -- enable the X25519MLKEM768 group",
                current="TLS 1.3", role="protocol",
                why=("TLS 1.3 is current and is the version that carries RFC 10024 "
                     "hybrid groups. This service is one configuration change away from "
                     "post-quantum key establishment."),
                recommended_hybrid="X25519MLKEM768",
                steps=["Verify library support (OpenSSL 3.5+, Go current, BoringSSL, NSS).",
                       "Add X25519MLKEM768 to supported_groups, keeping X25519 as fallback.",
                       "Benchmark handshake size and latency.",
                       "Enable in production and monitor negotiated groups."],
                citations=["RFC10024"],
                protocol_note="Only X25519MLKEM768 is marked Recommended=Y by IANA.",
            )
        return Recommendation(
            action=ACTION_VERIFY, headline=f"Verify {asset.protocol} configuration",
            current=f"{asset.protocol} {ver}", role="protocol",
            why="Protocol usage detected; negotiated parameters require manual review.",
            citations=["CISA_QR"],
        )

    # --- library-only assets (dependency / container / linkage) --------------------------
    if spec is None and asset.library:
        lib = libs.get(asset.library)
        cap, note = libs.pqc_capability(lib, asset.library_version)
        if cap == libs.PQC_NATIVE:
            return Recommendation(
                action=ACTION_RETAIN,
                headline=f"{lib.name if lib else asset.library} can already implement PQC",
                current=current, role="crypto-provider",
                why=(f"This component's cryptographic provider supports post-quantum "
                     f"mechanisms natively. {note} No provider change is required -- "
                     f"migration here is a configuration and testing exercise."),
                steps=["Confirm the deployed build has PQC enabled.",
                       "Enable PQ/T hybrid key exchange at the protocol layer.",
                       "Re-scan to confirm the negotiated group changed."],
                citations=["FIPS203", "RFC10024"],
            )
        return Recommendation(
            action=ACTION_MIGRATE_PQC if cap == libs.PQC_NONE else ACTION_VERIFY,
            headline=(f"Provider upgrade required before PQC is possible"
                      if cap != libs.PQC_UNKNOWN else "Verify provider PQC capability"),
            current=current, role="crypto-provider",
            why=(f"{note} A PQC recommendation for any algorithm in this component is "
                 f"not actionable until the provider itself can implement it, so the "
                 f"provider upgrade is the real first task."),
            prerequisites=[f"Upgrade or replace {lib.name if lib else asset.library}"
                           + (f" (PQC from {lib.pqc_since})" if lib and lib.pqc_since else "")],
            steps=["Identify all components sharing this provider.",
                   "Plan the provider upgrade as a single programme item.",
                   "Re-run ECDAT afterwards; PQC readiness should change to 'native'."],
            citations=["FIPS203", "CISA_QR"],
        )

    if spec is None:
        return Recommendation(
            action=ACTION_VERIFY, headline="Manual review required",
            current=current, role=role,
            why="ECDAT could not resolve this artefact to a known algorithm.",
            citations=["CISA_QR"],
        )

    # --- certificate expiry takes precedence over algorithm work ------------------------
    if asset.days_to_expiry is not None and asset.days_to_expiry < 0:
        return Recommendation(
            action=ACTION_RENEW_CERT,
            headline=f"Certificate expired {abs(asset.days_to_expiry)} days ago",
            current=current, role=role,
            why=(f"This certificate expired on {asset.certificate_expiry}. It is an "
                 f"availability and trust failure now. Renew it first; then treat the "
                 f"renewal as the natural opportunity to move the key algorithm forward."),
            steps=["Renew or revoke the certificate immediately.",
                   "Confirm no live service still presents it.",
                   "Use the renewal to adopt a stronger signature algorithm.",
                   "Add expiry monitoring so this cannot recur."],
            citations=["CISA_QR"],
        )

    # --- classically broken --------------------------------------------------------------
    if spec.quantum_class == alg.CLASSICALLY_BROKEN:
        action, why = pqc.symmetric_or_hash_advice(
            spec, alg.strength_for(spec, asset.key_size, asset.curve), policy)
        replacement = ("SHA-256 or SHA-384" if spec.primitive in ("hash", "mac")
                       else "AES-256-GCM")
        return Recommendation(
            action=ACTION_REPLACE_NOW,
            headline=f"Replace {spec.name} now -- classical weakness, not a quantum issue",
            current=current, role=role, why=why,
            alternative=replacement,
            steps=[f"Replace {spec.name} with {replacement}.",
                   "Identify data or signatures already produced with the weak primitive "
                   "and decide whether they must be re-generated.",
                   "Add a CI policy check so the primitive cannot return.",
                   "Re-scan to confirm removal."],
            citations=["SP800131A", "SP80057"] + (["RFC7465"] if spec.id == "rc4" else []),
            caveats=["This is a present-tense classical exposure. Do not schedule it "
                     "behind the PQC programme."],
        )

    # --- already PQC or hybrid -------------------------------------------------------------
    if spec.quantum_class == alg.PQC_STANDARDIZED:
        return Recommendation(
            action=ACTION_RETAIN,
            headline=f"{spec.name} is a finalised NIST PQC standard -- retain",
            current=current, role=role,
            why=f"{spec.name} is standardised in {spec.standard}. Already migrated.",
            steps=["No migration required.",
                   "Record this component as migrated in the programme tracker."],
            citations=["FIPS203" if spec.primitive == "kem" else "FIPS204", "NISTPQC"],
        )

    if spec.quantum_class == alg.HYBRID_PQT:
        if spec.status == alg.ST_DEPRECATED:
            return Recommendation(
                action=ACTION_REPIN,
                headline="Re-pin from the draft hybrid group to X25519MLKEM768",
                current=current, role=role,
                why=(f"{spec.name} uses draft Kyber rather than final ML-KEM, and its "
                     f"IANA code point is obsoleted by RFC 10024 (Recommended field 'D'). "
                     f"It is not interoperable with standards-compliant peers "
                     f"long-term."),
                recommended_hybrid="X25519MLKEM768",
                steps=["Add X25519MLKEM768 (0x11EC) to supported_groups.",
                       "Keep the draft group briefly for peers mid-upgrade.",
                       "Remove the draft group once peers have moved.",
                       "Re-scan to confirm."],
                citations=["RFC10024", "FIPS203"],
            )
        return Recommendation(
            action=ACTION_RETAIN,
            headline=f"{spec.name} is a standardised PQ/T hybrid -- retain",
            current=current, role=role,
            why=f"{spec.name} is defined in {spec.standard}. This is the target state.",
            citations=["RFC10024", "RFC9954"],
        )

    if spec.quantum_class == alg.PQC_SELECTED:
        return Recommendation(
            action=ACTION_VERIFY,
            headline=f"{spec.name} is selected but not yet a finalised FIPS",
            current=current, role=role,
            why=(f"{spec.name}: {spec.note} Suitable as a backup or inside a hybrid, but "
                 f"it must not be the sole mechanism protecting production data until a "
                 f"final standard exists."),
            recommended_pqc="ML-KEM-768",
            steps=["Ensure ML-KEM (FIPS 203) is the primary mechanism.",
                   "Keep this algorithm only as a diversity hedge.",
                   "Track the NIST standardisation timeline."],
            citations=["IR8545", "NISTPQC", "FIPS203"],
        )

    # --- symmetric / hash / MAC: strength policy, never PQC --------------------------------
    if spec.quantum_class == alg.GROVER_REDUCED:
        strength = alg.strength_for(spec, asset.key_size, asset.curve)
        action, why = pqc.symmetric_or_hash_advice(spec, strength, policy)
        if action == "retain":
            return Recommendation(
                action=ACTION_RETAIN,
                headline=f"Retain {spec.name} -- PQC replacement is not applicable",
                current=current, role=role, why=why,
                steps=["No action required for quantum readiness.",
                       "Keep it in the inventory: crypto agility means knowing where it is."],
                citations=["SP80057", "NSA_CNSA2"],
                caveats=["Grover's algorithm gives at most a quadratic speedup against "
                         "symmetric key search, and parallelises poorly. This primitive "
                         "is not 'quantum-broken'."],
            )
        target = "AES-256-GCM" if spec.primitive != "hash" else "SHA-384"
        return Recommendation(
            action=ACTION_STRENGTHEN,
            headline=f"Increase parameter size: {spec.name} -> {target}",
            current=current, role=role, why=why, alternative=target,
            steps=[f"Move to {target}.",
                   "This is a parameter change, not a PQC migration -- far cheaper.",
                   "Re-scan to confirm the stronger parameter set."],
            citations=["SP80057", "NSA_CNSA2"],
            caveats=["Do not substitute a PQC algorithm here: ML-KEM and ML-DSA replace "
                     "public-key primitives, not symmetric ones."],
        )

    # ======================================================================================
    # Shor-vulnerable public key -- the actual PQC migration surface
    # ======================================================================================
    strength = alg.strength_for(spec, asset.key_size, asset.curve) or 128

    if role == alg.ROLE_UNKNOWN:
        return Recommendation(
            action=ACTION_DETERMINE_ROLE,
            headline=f"{spec.name} is quantum-vulnerable, but its role is not evidenced",
            current=current, role=role,
            why=(f"{spec.name} is broken by Shor's algorithm and must be migrated. "
                 f"However, ECDAT did not observe how this key is used, and the correct "
                 f"target depends entirely on that: key establishment migrates to ML-KEM "
                 f"(FIPS 203), signatures to ML-DSA (FIPS 204) or SLH-DSA (FIPS 205). "
                 f"These are not interchangeable, so ECDAT will not guess. Establishing "
                 f"the role is the next task."),
            steps=["Inspect the call sites for this key: sign/verify => signature; "
                   "encrypt/decrypt or derive/exchange => key establishment.",
                   "For a certificate, read the keyUsage and extendedKeyUsage extensions.",
                   "Record the role in ECDAT (or via the API) to obtain a concrete target.",
                   "Then follow the role-specific migration path."],
            citations=["FIPS203", "FIPS204", "FIPS205"],
            caveats=["A tool that mapped RSA straight to ML-KEM without knowing the role "
                     "would be wrong roughly half the time."],
        )

    if alg.role_family(role) in ("hash", "kdf"):
        return Recommendation(
            action=ACTION_VERIFY, headline="Unexpected role for a public-key primitive",
            current=current, role=role,
            why="Role and primitive disagree; manual review required.",
            citations=["FIPS204"],
        )

    firmware = _is_firmware(asset)
    target = pqc.target_for(role, strength, firmware=firmware)

    # RSA key transport / encryption: there is no PQC "drop-in" for RSA-OAEP; the
    # standards answer is to restructure to a KEM.
    if role in (alg.ROLE_KEY_TRANSPORT, alg.ROLE_ENCRYPTION) and spec.family == "RSA":
        return Recommendation(
            action=ACTION_MIGRATE_PQC,
            headline="Restructure RSA key transport into an ML-KEM key encapsulation",
            current=current, role=role,
            why=(f"{current} is used to encrypt/transport a key. RSA key transport is "
                 f"Shor-vulnerable, and there is no post-quantum drop-in replacement with "
                 f"the same API shape: FIPS 203 standardises a KEM, which encapsulates a "
                 f"freshly generated shared secret rather than encrypting a caller-chosen "
                 f"one. The migration is therefore a protocol change, not a library swap -- "
                 f"budget for it accordingly."),
            recommended_pqc="ML-KEM-768",
            recommended_hybrid="X25519MLKEM768" if asset.protocol == "TLS" else None,
            steps=["Identify what the transported key protects and its retention period.",
                   "Redesign the exchange around encapsulate/decapsulate instead of "
                   "encrypt-a-key.",
                   "Where the exchange is TLS, adopt the RFC 10024 hybrid group and the "
                   "problem disappears at the protocol layer.",
                   "For a bespoke protocol, use ML-KEM-768 with an approved KDF.",
                   "Benchmark: ML-KEM-768 keys/ciphertexts are ~1.1-1.2 kB versus 256 B "
                   "for RSA-2048.",
                   "Stage the rollout with a version-negotiated fallback, then retire RSA."],
            citations=["FIPS203", "RFC10024", "IR8547"],
            prerequisites=_prereq(asset),
            caveats=["This is the highest-effort category of PQC migration because it "
                     "changes protocol semantics, not just an algorithm identifier."],
        )

    if target is None:
        return Recommendation(
            action=ACTION_VERIFY, headline="No standardised target for this role",
            current=current, role=role,
            why="No finalised PQC mechanism maps to this role.",
            citations=["NISTPQC"],
        )

    primary_spec = alg.get(target.primary)
    hybrid_spec = alg.get(target.hybrid) if target.hybrid else None
    alt_spec = alg.get(target.alternative) if target.alternative else None

    hybrid_usable = bool(hybrid_spec) and (
        alg.role_family(role) == "key-establishment" and
        (asset.protocol in (None, "TLS") or asset.protocol == "TLS"))
    if policy.allow_non_hybrid_pqc is False:
        hybrid_required = True
    else:
        hybrid_required = False

    if alg.role_family(role) == "signature":
        verb = ("signature verification" if role == alg.ROLE_SIGNATURE_VERIFICATION
                else "certificate validation" if role == alg.ROLE_CERTIFICATE_VALIDATION
                else "signing")
        headline = f"Migrate {current} {verb} to {primary_spec.name}"
        why = (f"{current} is a Shor-vulnerable signature primitive: a CRQC recovers the "
               f"private key from the public key, allowing forgery. "
               f"{target.rationale} ")
        if firmware:
            why += ("This asset looks like firmware or code signing, where signatures must "
                    "remain verifiable for the lifetime of the device -- so the "
                    "conservative hash-based option is preferred over a lattice scheme.")
        else:
            why += ("Note that signature migration is gated by PKI: certificates can only "
                    "carry ML-DSA once your CA can issue them, so sequence CA readiness "
                    "first.")
        if role == alg.ROLE_SIGNATURE_VERIFICATION:
            why += (" This asset VERIFIES signatures rather than producing them, which "
                    "inverts the rollout order: every verifier must accept the new "
                    "algorithm before any signer may emit it, or trust breaks.")
    else:
        headline = (f"Migrate {current} key establishment to "
                    f"{hybrid_spec.name if hybrid_usable and hybrid_spec else primary_spec.name}")
        why = (f"{current} performs key establishment with a Shor-vulnerable primitive. "
               f"This is the highest-priority category under a store-now-decrypt-later "
               f"threat model: an adversary can record the handshake today and recover the "
               f"session key once a CRQC exists, retroactively decrypting everything the "
               f"session carried. {target.rationale}")

    steps: list[str] = []
    if hybrid_usable and hybrid_spec:
        steps.append(f"Enable the PQ/T hybrid group {hybrid_spec.name} "
                     f"({hybrid_spec.standard}) alongside the existing group.")
    else:
        steps.append(f"Introduce {primary_spec.name} support in the component.")
    steps.extend(_GENERIC_STEPS[1:])

    return Recommendation(
        action=ACTION_MIGRATE_HYBRID if (hybrid_usable and hybrid_spec) else ACTION_MIGRATE_PQC,
        headline=headline,
        current=current, role=role, why=why,
        recommended_pqc=primary_spec.name if primary_spec else None,
        recommended_hybrid=hybrid_spec.name if (hybrid_usable and hybrid_spec) else None,
        alternative=alt_spec.name if alt_spec else None,
        steps=steps,
        citations=list(target.citations),
        prerequisites=_prereq(asset),
        protocol_note=target.protocol_note,
        caveats=_caveats(asset, role, hybrid_required, hybrid_usable, primary_spec),
    )


def _prereq(asset: CryptoAsset) -> list[str]:
    out: list[str] = []
    if asset.pqc_readiness == "none":
        out.append(f"Replace the cryptographic provider: {asset.pqc_readiness_note}")
    elif asset.pqc_readiness == "provider":
        out.append(f"Upgrade the provider first: {asset.pqc_readiness_note}")
    if asset.protocol == "TLS" and asset.protocol_version in ("1.0", "1.1", "1.2"):
        out.append("Upgrade to TLS 1.3 -- RFC 10024 hybrid groups require it.")
    if asset.asset_type.value == "certificate":
        out.append("Confirm the issuing CA can issue certificates with the target "
                   "algorithm before scheduling endpoint work.")
    if asset.asset_type.value == "binary-artifact":
        out.append("Binary-only artefact: obtain a vendor roadmap or rebuild from source.")
    return out


def _caveats(asset: CryptoAsset, role: str, hybrid_required: bool,
             hybrid_usable: bool, primary_spec) -> list[str]:
    out: list[str] = []
    if alg.role_family(role) == "key-establishment":
        out.append("ML-KEM public keys and ciphertexts are roughly an order of magnitude "
                   "larger than X25519; expect bigger handshakes and check MTU and "
                   "fragmentation behaviour.")
    if alg.role_family(role) == "signature" and primary_spec and primary_spec.family == "SLH-DSA":
        out.append("SLH-DSA signatures are large (kilobytes) and signing is slow. Verify "
                   "this is acceptable for the transport and device involved.")
    if hybrid_required and not hybrid_usable:
        out.append("The selected policy profile requires a PQ/T hybrid, but no "
                   "standardised hybrid exists for this role -- record a policy exception.")
    if asset.confidence.value != "high":
        out.append(f"This finding rests on {asset.confidence.value}-confidence evidence. "
                   f"Confirm it before committing engineering effort.")
    return out


def apply(asset: CryptoAsset, policy_id: str = pqc.DEFAULT_POLICY) -> Recommendation:
    rec = recommend(asset, policy_id)
    asset.recommended_action = rec.action
    asset.recommended_pqc = rec.recommended_pqc
    asset.recommended_hybrid = rec.recommended_hybrid
    asset.recommendation_rationale = rec.why
    asset.recommendation_citations = rec.citations
    asset.migration_steps = rec.steps
    return rec
