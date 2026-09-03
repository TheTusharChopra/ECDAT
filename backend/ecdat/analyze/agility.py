"""Crypto agility and interoperability (contract §13/§18/§20).

Two deterministic, explainable properties that the migration decision engine needs
and that nothing else in the pipeline produces.

CRYPTO AGILITY answers: *how hard is it to change this algorithm at all?*
    A negotiated TLS group is a configuration line. A hard-coded constant in a
    compiled binary is a vendor conversation. Same algorithm, different worlds.

INTEROPERABILITY answers: *may we change it unilaterally?*
    This is the input that separates HYBRID from PQC-ONLY. An internal service whose
    both ends we control can go straight to a post-quantum mechanism. A public
    endpoint serving arbitrary clients cannot -- it must negotiate, which is exactly
    what a PQ/T hybrid is for.

Both are derived from evidence already on the canonical asset. Every verdict carries
the signals that produced it, so a reviewer can disagree with the conclusion and see
precisely which fact to correct.
"""

from __future__ import annotations

from ..knowledge import algorithms as alg
from ..knowledge import libraries as libs
from ..models import AssetType, CryptoAgility, CryptoAsset, Interoperability, Role


# ======================================================================================
# Crypto agility
# ======================================================================================
def assess_agility(asset: CryptoAsset) -> tuple[CryptoAgility, list[str]]:
    """Return (agility, signals). Signals are human-readable evidence strings.

    Scoring is additive and bounded, then bucketed. Deliberately simple: an operator
    must be able to read the signal list and reconstruct the verdict by hand.
    """
    signals: list[str] = []
    score = 0.0   # negative => more agile, positive => less agile

    # ---- where the algorithm choice physically lives ---------------------------------
    if asset.asset_type is AssetType.BINARY_ARTIFACT:
        score += 2.5
        signals.append(
            "REDUCES agility: algorithm choice is compiled into a binary artefact; changing it requires "
            "a rebuild or a vendor release, not a configuration change.")
    elif asset.asset_type is AssetType.PROTOCOL_CONFIG:
        score -= 2.0
        signals.append(
            "INCREASES agility: the algorithm is selected by a configuration directive, so it can "
            "be changed by editing configuration and reloading the service.")
    elif asset.asset_type is AssetType.CERTIFICATE:
        score += 1.0
        signals.append(
            "REDUCES agility: certificate algorithms change at re-issuance, which depends on CA "
            "capability and a chain rollout rather than on this component alone.")
    elif asset.asset_type in (AssetType.DEPENDENCY, AssetType.CONTAINER_PACKAGE):
        score -= 0.5
        signals.append(
            "The mechanism is supplied by a packaged dependency, so a version bump can "
            "change the available algorithms without touching application code.")
    elif asset.asset_type is AssetType.SOURCE_FINDING:
        # Source is changeable, but the question is whether the algorithm is a
        # literal at the call site or resolved from configuration.
        score += 0.5
        signals.append(
            "REDUCES agility: the algorithm appears at a source call site; changing it is a code "
            "change, review and redeploy.")

    # ---- hard-coded vs externally-selected algorithm ----------------------------------
    from ..models import EvidenceType
    if (asset.asset_type is AssetType.SOURCE_FINDING
            and asset.evidence_type is EvidenceType.SOURCE_API):
        score += 0.5
        signals.append(
            "REDUCES agility: the algorithm was resolved from a literal argument at the "
            "call site, so it is hard-coded rather than read from configuration. "
            "Externalising the choice is a prerequisite for cheap future changes.")

    # ---- protocol negotiation is the strongest agility signal there is ---------------
    if asset.protocol == "TLS":
        if asset.protocol_version == "1.3":
            score -= 1.5
            signals.append(
                "INCREASES agility: TLS 1.3 negotiates the key-exchange group per connection, so a "
                "PQ/T hybrid can be enabled without breaking peers that do not offer it.")
        elif asset.protocol_version in ("1.0", "1.1", "1.2"):
            score += 1.0
            signals.append(
                f"TLS {asset.protocol_version} negotiates cipher suites but cannot "
                f"carry RFC 10024 hybrid groups; a protocol upgrade is required before "
                f"the algorithm becomes changeable.")
    elif asset.protocol in ("SSH", "IKE"):
        score -= 1.0
        signals.append(
            f"{asset.protocol} negotiates algorithms per session, so the preferred list "
            f"can be reordered in configuration.")

    # ---- provider capability ----------------------------------------------------------
    if asset.pqc_readiness == "native":
        score -= 1.5
        signals.append(
            f"INCREASES agility: the cryptographic provider already implements "
            f"post-quantum "
            f"mechanisms natively, so no provider change is needed. "
            f"{asset.pqc_readiness_note or ''}".strip())
    elif asset.pqc_readiness == "provider":
        score += 0.5
        signals.append(
            "REDUCES agility: a provider upgrade or add-on module is required before the target "
            "algorithm can be selected at all.")
    elif asset.pqc_readiness == "none":
        score += 2.0
        signals.append(
            "REDUCES agility strongly: the linked provider has no post-quantum path, so the library itself "
            "must be replaced before any algorithm change is possible.")

    # ---- explicit blockers found during discovery -------------------------------------
    if "crypto-agility-blocker" in asset.tags:
        score += 1.5
        signals.append(
            "REDUCES agility strongly: discovery recorded an agility blocker -- a floating image tag or a "
            "hard-coded algorithm choice -- so the deployed mechanism is not "
            "reproducible or not re-pinnable without a rebuild.")
    if "key-material-exposure" in asset.tags:
        score += 1.0
        signals.append(
            "Key material is embedded in the artefact; a key that cannot be rotated "
            "cannot be migrated.")

    # ---- language / platform friction --------------------------------------------------
    if asset.language in ("c", "cpp"):
        score += 0.75
        signals.append(
            "Native code: an algorithm change requires recompilation and "
            "redistribution to every deployment.")
    elif asset.language in ("java", "kotlin", "scala"):
        score += 0.25
        signals.append(
            "JVM estates typically pin a security provider and JDK version, which adds "
            "coordination to any algorithm change.")
    elif asset.language == "config":
        score -= 1.0
        signals.append("The finding is in declarative configuration.")

    if score <= -1.5:
        agility = CryptoAgility.HIGH
    elif score <= 1.5:
        agility = CryptoAgility.MEDIUM
    else:
        agility = CryptoAgility.LOW

    signals.append(
        f"Computed agility = {agility.value} (weighted signal total {score:+.2f}; "
        f"negative favours agility).")
    return agility, signals


# ======================================================================================
# Interoperability
# ======================================================================================
def assess_interoperability(asset: CryptoAsset) -> tuple[Interoperability, str]:
    """Return (interoperability, reason).

    CONSTRAINED  external parties or a CA pin the mechanism; we cannot change it
                 unilaterally and a hybrid may not even be negotiable.
    NEGOTIATED   the protocol negotiates per connection, so a hybrid degrades
                 gracefully and is the safe migration route.
    OPEN         both ends are under our control; a standalone PQC mechanism is
                 viable without breaking anyone.
    """
    # Certificates are the classic constrained case: the issuing CA and every
    # relying party must accept the algorithm before we may use it.
    if asset.asset_type is AssetType.CERTIFICATE:
        return (Interoperability.CONSTRAINED,
                "Certificate algorithms are constrained by the issuing CA and by every "
                "relying party that must validate the chain. The algorithm cannot be "
                "changed unilaterally; CA support gates the migration.")

    if asset.cryptographic_role == Role.CERTIFICATE_VALIDATION.value:
        return (Interoperability.CONSTRAINED,
                "This asset validates certificates issued by others, so it must accept "
                "whatever algorithms those issuers use. It can only add support, never "
                "unilaterally remove it.")

    # Binary artefacts we cannot rebuild are effectively vendor-pinned.
    if asset.asset_type is AssetType.BINARY_ARTIFACT:
        return (Interoperability.CONSTRAINED,
                "Binary-only artefact: the mechanism is fixed by the vendor's build. "
                "Changing it requires a vendor release or a rebuild from source.")

    # Negotiated protocols: the whole point of a PQ/T hybrid.
    if asset.protocol in ("TLS", "SSH", "IKE"):
        if asset.internet_exposed:
            return (Interoperability.NEGOTIATED,
                    f"{asset.protocol} negotiates algorithms per connection with "
                    f"internet-facing peers whose capabilities we do not control. A "
                    f"PQ/T hybrid is the correct migration route: post-quantum "
                    f"protection for capable peers, uninterrupted service for the rest.")
        return (Interoperability.NEGOTIATED,
                f"{asset.protocol} negotiates algorithms per connection. Peers are "
                f"internal, so the negotiated set can be narrowed once every endpoint "
                f"supports the target mechanism.")

    # Internet-facing without a negotiated protocol => third parties still constrain us.
    if asset.internet_exposed:
        return (Interoperability.NEGOTIATED,
                "The service is externally reachable, so external clients constrain "
                "what may be changed. Introduce the new mechanism alongside the old and "
                "retire the old only once clients have moved.")

    # Signature verification must accept what signers produce.
    if asset.cryptographic_role == Role.SIGNATURE_VERIFICATION.value:
        return (Interoperability.NEGOTIATED,
                "This asset VERIFIES signatures produced elsewhere, so it must accept "
                "the signer's algorithm. Verifiers must support the new algorithm "
                "BEFORE any signer emits it -- this inverts the usual rollout order.")

    # Everything else: both ends under our control.
    return (Interoperability.OPEN,
            "Both ends of this cryptographic operation appear to be under the "
            "organisation's control, with no external peer or CA constraining the "
            "algorithm choice. A standalone post-quantum mechanism is viable here "
            "without a compatibility fallback.")


# ======================================================================================
def apply(asset: CryptoAsset) -> None:
    """Write agility and interoperability onto the canonical asset."""
    if not asset.overrides.get("crypto_agility"):
        agility, signals = assess_agility(asset)
        asset.crypto_agility = agility
        asset.crypto_agility_signals = signals
    if not asset.overrides.get("interoperability"):
        interop, reason = assess_interoperability(asset)
        asset.interoperability = interop
        asset.interoperability_reason = reason
