"""Migration Decision Engine (contract §4/§15/§20).

TWO LEVELS, never collapsed into one:

    migration_decision    RETAIN | HARDEN | UPGRADE | HYBRID | PQC-ONLY
                          The frozen five. Stable, coarse, executive-readable.
                              |
                              v
    recommended_strategy  migrate-to-pqt-hybrid, strengthen-parameters,
                          replace-now-classical, determine-role-then-migrate, ...
                          The specific standards-grounded action, produced by
                          `recommend.py` and preserved verbatim.

This module does NOT re-derive migration advice. `recommend.py` already contains the
role-aware, citation-backed strategy logic; this engine consumes that strategy and
classifies it into one of the five outcomes, then applies the contextual inputs the
contract requires -- interoperability, dependency centrality, crypto agility, data
lifetime, exposure and Mosca urgency -- to decide between HYBRID and PQC-ONLY and to
justify the result.

The engine must be able to say "no PQC replacement required" (contract §20). That is
RETAIN, and roughly half the estate legitimately lands there: symmetric ciphers,
hashes, and anything already migrated.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..knowledge import algorithms as alg
from ..knowledge import pqc
from ..models import (
    CryptoAgility,
    CryptoAsset,
    Interoperability,
    MigrationDecision,
    RemediationStatus,
    RiskBand,
    Role,
)
from . import mosca, recommend

# ======================================================================================
# Strategy -> decision. This is the ONLY place the mapping is defined.
# ======================================================================================
_STRATEGY_DECISION: dict[str, MigrationDecision] = {
    recommend.ACTION_RETAIN:            MigrationDecision.RETAIN,
    recommend.ACTION_STRENGTHEN:        MigrationDecision.HARDEN,
    recommend.ACTION_REPLACE_NOW:       MigrationDecision.UPGRADE,
    recommend.ACTION_UPGRADE_PROTOCOL:  MigrationDecision.UPGRADE,
    recommend.ACTION_RENEW_CERT:        MigrationDecision.HARDEN,
    recommend.ACTION_ROTATE_KEY:        MigrationDecision.HARDEN,
    recommend.ACTION_REPIN:             MigrationDecision.HYBRID,
    recommend.ACTION_MIGRATE_HYBRID:    MigrationDecision.HYBRID,
    recommend.ACTION_MIGRATE_PQC:       MigrationDecision.PQC_ONLY,
    # A role we could not establish is not yet a migration; it is an investigation.
    # HARDEN is the honest holding position: do not weaken anything, do not pretend
    # to know the target.
    recommend.ACTION_DETERMINE_ROLE:    MigrationDecision.HARDEN,
    recommend.ACTION_VERIFY:            MigrationDecision.HARDEN,
}

DECISION_DEFINITION: dict[str, str] = {
    MigrationDecision.RETAIN.value:
        "No cryptographic change required. The mechanism is fit for purpose against "
        "both classical and quantum threat models, or is already post-quantum.",
    MigrationDecision.HARDEN.value:
        "Keep the primitive; change how it is parameterised, configured, operated or "
        "evidenced. Includes strengthening parameters, renewing certificates, "
        "rotating exposed keys and establishing an unknown cryptographic role.",
    MigrationDecision.UPGRADE.value:
        "Replace a broken or deprecated mechanism with a currently-approved classical "
        "one. Driven by present-day cryptanalysis, not by quantum computing.",
    MigrationDecision.HYBRID.value:
        "Deploy a PQ/T hybrid: a post-quantum mechanism alongside a classical one. "
        "Required where peers, CAs or protocol negotiation mean the mechanism cannot "
        "be changed unilaterally.",
    MigrationDecision.PQC_ONLY.value:
        "Deploy a standalone post-quantum mechanism. Viable where both ends are under "
        "our control, or where policy permits non-hybrid PQC.",
}


@dataclass
class Decision:
    decision: MigrationDecision
    strategy: str
    rationale: str
    inputs: dict = field(default_factory=dict)
    blocked_on: str | None = None
    blockers: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "decision": self.decision.value,
            "definition": DECISION_DEFINITION[self.decision.value],
            "strategy": self.strategy,
            "rationale": self.rationale,
            "inputs": self.inputs,
            "blocked_on": self.blocked_on,
            "blockers": self.blockers,
        }


# ======================================================================================
def _collect_blockers(asset: CryptoAsset) -> list[str]:
    """Concrete prerequisites, each phrased as an action someone can own."""
    out: list[str] = []
    if asset.pqc_readiness == "none":
        out.append(f"Replace the cryptographic provider "
                   f"({asset.library or 'unknown library'}): it has no post-quantum path.")
    elif asset.pqc_readiness == "provider":
        out.append(f"Upgrade or extend the provider "
                   f"({asset.library or 'unknown library'}"
                   f"{' ' + asset.library_version if asset.library_version else ''}) "
                   f"before the target mechanism can be selected.")
    if asset.protocol == "TLS" and asset.protocol_version in ("1.0", "1.1", "1.2"):
        out.append("Enable TLS 1.3: RFC 10024 hybrid groups are defined for it only.")
    if asset.asset_type.value == "certificate":
        out.append("Confirm the issuing CA can issue certificates with the target "
                   "algorithm.")
    if asset.asset_type.value == "binary-artifact":
        out.append("Obtain a vendor roadmap or rebuild the artefact from source.")
    if "key-material-exposure" in asset.tags:
        out.append("Rotate the exposed key and move it into an HSM or secret store "
                   "before migrating the algorithm.")
    if "crypto-agility-blocker" in asset.tags:
        out.append("Externalise the algorithm choice (pin the image, move the literal "
                   "into configuration) so it can be changed without a rebuild.")
    if asset.cryptographic_role == Role.UNKNOWN.value and asset.quantum_vulnerable:
        out.append("Determine the cryptographic role: the migration target depends "
                   "entirely on it.")
    return out


def _decision_opening(asset: CryptoAsset, decision: MigrationDecision,
                      strategy: str) -> str:
    """A grounded opening sentence for the decisions that carry no contextual clause.

    HYBRID and PQC-ONLY are always explained by `_hybrid_or_pqc_only`. The other three
    are reached by mapping the strategy, so without this the rationale would state the
    action ("Already migrated") while never saying why the *decision* is what it is --
    and the decision is the field an executive reads.
    """
    name = asset.asset_name or asset.algorithm_label or "this asset"
    if decision is MigrationDecision.RETAIN:
        return (f"Decision RETAIN: {name} needs no cryptographic change, so ECDAT "
                f"attaches no post-quantum target to it. Reporting 'no migration "
                f"required' explicitly is part of the answer -- an inventory that "
                f"flags everything tells a programme nothing about where to spend.")
    if decision is MigrationDecision.HARDEN:
        return (f"Decision HARDEN: the primitive at {name} stays as it is; what "
                f"changes is how it is parameterised, configured, operated or "
                f"evidenced. No algorithm substitution is being proposed here.")
    if decision is MigrationDecision.UPGRADE:
        return (f"Decision UPGRADE: replace the mechanism at {name} with a "
                f"currently-approved classical one. This is driven by present-day "
                f"cryptanalysis rather than by the quantum timeline, so it is not "
                f"scheduled behind the post-quantum programme.")
    return ""


def _hybrid_or_pqc_only(asset: CryptoAsset, policy: pqc.PolicyProfile
                        ) -> tuple[MigrationDecision, str]:
    """The genuinely contextual decision -- everything else follows the strategy.

    Interoperability is the primary input, exactly as the contract specifies: it
    answers "may we change this unilaterally?". Policy can force a hybrid; an OPEN
    ecosystem permits standalone PQC.
    """
    interop = asset.interoperability or Interoperability.NEGOTIATED
    role = asset.cryptographic_role or Role.UNKNOWN.value

    # A PQ/T hybrid is a KEY-ESTABLISHMENT construction. RFC 10024 / RFC 9954 define
    # hybrid key agreement; there is no standardised hybrid signature, and composite
    # signature schemes are still in draft. Routing a signature to HYBRID would
    # promise a mechanism that does not exist, so signature-family roles always take
    # the standalone post-quantum path, gated on PKI readiness rather than on peer
    # negotiation.
    if alg.role_family(role) == "signature":
        return (MigrationDecision.PQC_ONLY,
                "Signature migration takes the standalone post-quantum path: no "
                "standardised PQ/T hybrid signature exists (RFC 10024 defines hybrid "
                "KEY AGREEMENT only, and composite signature schemes remain drafts). "
                "The constraint here is PKI rather than peer negotiation -- verifiers "
                "and the issuing CA must accept the new algorithm before any signer "
                "emits it, so sequence CA readiness first.")

    if not policy.allow_non_hybrid_pqc:
        return (MigrationDecision.HYBRID,
                f"The {policy.name} profile requires a PQ/T hybrid so that a future "
                f"cryptanalytic result against the post-quantum algorithm cannot "
                f"retroactively expose data protected today.")

    if interop is Interoperability.OPEN:
        return (MigrationDecision.PQC_ONLY,
                f"Both ends of this operation are under the organisation's control "
                f"({asset.interoperability_reason}), so a standalone post-quantum "
                f"mechanism can be deployed without a compatibility fallback. That "
                f"avoids permanently carrying two mechanisms.")

    if interop is Interoperability.CONSTRAINED:
        return (MigrationDecision.HYBRID,
                f"External parties constrain this mechanism "
                f"({asset.interoperability_reason}) A hybrid is the only route that "
                f"adds post-quantum protection without breaking peers that cannot yet "
                f"support it.")

    return (MigrationDecision.HYBRID,
            f"The protocol negotiates algorithms per connection with peers whose "
            f"capabilities we do not control. A PQ/T hybrid gives post-quantum "
            f"protection to capable peers while the rest continue to interoperate -- "
            f"this is precisely what RFC 10024 exists for.")


def decide(asset: CryptoAsset, policy_id: str = pqc.DEFAULT_POLICY,
           rec: recommend.Recommendation | None = None) -> Decision:
    """Produce the five-outcome decision and attach the specific strategy."""
    policy = pqc.POLICIES.get(policy_id, pqc.POLICIES[pqc.DEFAULT_POLICY])
    rec = rec or recommend.recommend(asset, policy_id)
    strategy = rec.action

    decision = _STRATEGY_DECISION.get(strategy, MigrationDecision.HARDEN)
    blockers = _collect_blockers(asset)
    blocked_on = None
    parts: list[str] = []

    # ---- provider-only assets are an UPGRADE, not a cryptographic migration ----------
    # A library asset carries no algorithm and no role: the actionable change is
    # replacing or upgrading the dependency so that PQC becomes selectable at all.
    # Classifying it as HYBRID would promise a hybrid deployment for something that
    # is really a package bump, and would leave the target fields empty.
    if (decision in (MigrationDecision.HYBRID, MigrationDecision.PQC_ONLY)
            and asset.algorithm is None and asset.library):
        decision = MigrationDecision.UPGRADE
        parts.append(
            f"This asset is a cryptographic provider, not a concrete algorithm use. "
            f"The actionable change is upgrading or replacing "
            f"{asset.library}{' ' + asset.library_version if asset.library_version else ''} "
            f"so that post-quantum mechanisms become selectable; only then can the "
            f"algorithms it supplies be migrated. Sequenced as an UPGRADE because it "
            f"is a dependency change, and it gates every asset that depends on it.")

    # ---- an asset already ON a hybrid is a hybrid-to-hybrid move --------------------
    # Re-pinning a draft group (X25519Kyber768Draft00) to the standardised RFC 10024
    # group keeps the PQ/T construction; only the code point changes. Passing it
    # through the interoperability re-decision would let an OPEN verdict promote it to
    # PQC-ONLY, which would both discard the classical half nobody asked to remove and
    # strip the hybrid target, leaving the asset with no target at all.
    if strategy == recommend.ACTION_REPIN:
        parts.append(
            f"This asset already deploys a PQ/T hybrid, so the decision stays HYBRID: "
            f"the action changes which hybrid group is negotiated, not whether a "
            f"classical mechanism is retained alongside the post-quantum one. "
            f"Interoperability does not enter this call -- {rec.why}")

    # ---- HYBRID vs PQC-ONLY is decided here, not in the strategy layer --------------
    # `recommend.py` proposes a target from role + strength alone. Only this engine
    # sees interoperability and policy, so it owns the hybrid-vs-standalone call --
    # and must then realign the strategy label, or the asset would carry a decision
    # that contradicts its own stated action.
    elif decision in (MigrationDecision.HYBRID, MigrationDecision.PQC_ONLY):
        decision, why = _hybrid_or_pqc_only(asset, policy)
        parts.append(why)
        if strategy in (recommend.ACTION_MIGRATE_HYBRID, recommend.ACTION_MIGRATE_PQC):
            realigned = (recommend.ACTION_MIGRATE_HYBRID
                         if decision is MigrationDecision.HYBRID
                         else recommend.ACTION_MIGRATE_PQC)
            if realigned != strategy:
                parts.append(
                    f"Strategy adjusted from '{strategy}' to '{realigned}': the "
                    f"role-and-strength analysis proposed the other form, but "
                    f"interoperability and the {policy.name} profile determine whether "
                    f"a classical mechanism must be retained alongside the "
                    f"post-quantum one.")
                strategy = realigned

    # ---- an unresolved role blocks the decision, and says so -------------------------
    if strategy == recommend.ACTION_DETERMINE_ROLE:
        blocked_on = "role-determination"
        parts.append(
            f"{asset.asset_name} is Shor-vulnerable and must eventually migrate, but "
            f"ECDAT observed no use of this key, so the cryptographic role is unknown. "
            f"Key establishment migrates to ML-KEM (FIPS 203) and signatures to ML-DSA "
            f"(FIPS 204) -- these are not interchangeable, so the decision is held at "
            f"HARDEN until the role is established rather than guessed.")

    # ---- classical urgency must never be deferred behind the PQC programme ----------
    if (asset.classical_risk in (RiskBand.CRITICAL, RiskBand.HIGH)
            and decision in (MigrationDecision.HYBRID, MigrationDecision.PQC_ONLY)):
        parts.append(
            f"NOTE: this asset also carries {asset.classical_risk.value.upper()} "
            f"CLASSICAL risk, which is exploitable today and independent of the "
            f"quantum timeline. Remediate that first; it must not wait for the "
            f"migration programme.")

    # ---- contextual amplifiers, all drawn from canonical fields ---------------------
    if asset.mosca_urgency in (mosca.ALREADY_LATE, mosca.CRITICAL):
        gap = asset.mosca_gap_years or 0
        parts.append(
            f"Mosca urgency is {asset.mosca_urgency.upper()}: data lifetime plus "
            f"migration time exceeds the configured horizon by {gap:.1f} years, so the "
            f"migration window has already closed under this scenario.")

    if asset.dependency_centrality >= 5:
        s = asset.affected_summary or {}
        parts.append(
            f"High change-impact coupling: {len(s.get('applications', []))} "
            f"application(s) and {len(s.get('services', []))} service(s) share the "
            f"units of change this asset depends on "
            f"({', '.join(s.get('shared_resources', [])) or 'none'}). Sequencing this "
            f"work as one programme item unblocks all of them together.")

    if asset.crypto_agility is CryptoAgility.LOW:
        parts.append(
            "Crypto agility is LOW, so this asset needs a longer lead time than its "
            "risk score alone suggests -- effort is a reason to start earlier, not a "
            "reason to defer.")

    if not parts:
        opening = _decision_opening(asset, decision, strategy)
        if opening:
            parts.append(opening)
        parts.append(rec.why)

    inputs = {
        "role": asset.cryptographic_role,
        "algorithm": asset.algorithm,
        "classical_risk": asset.classical_risk.value if asset.classical_risk else None,
        "quantum_exposure": (asset.quantum_exposure.value
                             if asset.quantum_exposure else None),
        "data_lifetime_years": asset.data_lifetime_years,
        "data_classification": (asset.data_classification.value
                                if asset.data_classification else None),
        "business_criticality": (asset.business_criticality.value
                                 if asset.business_criticality else None),
        "exposure": asset.exposure.value if asset.exposure else None,
        "dependency_centrality": asset.dependency_centrality,
        "crypto_agility": asset.crypto_agility.value if asset.crypto_agility else None,
        "interoperability": (asset.interoperability.value
                             if asset.interoperability else None),
        "migration_effort": (asset.migration_effort.value
                             if asset.migration_effort else None),
        "mosca_urgency": asset.mosca_urgency,
        "pqc_readiness": asset.pqc_readiness,
        "policy": policy.id,
        "context_source": asset.context_source,
    }

    return Decision(decision=decision, strategy=strategy,
                    rationale=" ".join(parts), inputs=inputs,
                    blocked_on=blocked_on, blockers=blockers)


def apply(asset: CryptoAsset, policy_id: str = pqc.DEFAULT_POLICY) -> Decision:
    """Enrich the canonical asset with the decision and its supporting strategy."""
    rec = recommend.apply(asset, policy_id)     # writes strategy fields
    d = decide(asset, policy_id, rec)

    asset.migration_decision = d.decision
    asset.recommended_strategy = d.strategy
    asset.decision_rationale = d.rationale
    asset.decision_inputs = d.inputs
    asset.decision_blocked_on = d.blocked_on
    asset.migration_blockers = d.blockers

    # Keep the concrete targets coherent with the decision. A PQC-ONLY asset must not
    # advertise a hybrid group, and a HYBRID asset must name one.
    if d.decision is MigrationDecision.PQC_ONLY:
        asset.recommended_hybrid = None
    elif d.decision is MigrationDecision.HYBRID and not asset.recommended_hybrid:
        target = pqc.target_for(asset.cryptographic_role or Role.UNKNOWN.value,
                                asset.security_strength)
        if target and target.hybrid:
            hybrid_spec = alg.get(target.hybrid)
            asset.recommended_hybrid = hybrid_spec.name if hybrid_spec else target.hybrid
    if d.decision in (MigrationDecision.RETAIN, MigrationDecision.HARDEN,
                      MigrationDecision.UPGRADE):
        # These outcomes are not PQC migrations; advertising a PQC target would
        # misrepresent them (contract §20: the engine must be able to say
        # "no PQC replacement required").
        if d.decision is MigrationDecision.RETAIN:
            asset.recommended_pqc = None
            asset.recommended_hybrid = None

    # Advance the remediation lifecycle exactly once, from the initial DETECTED state.
    if asset.remediation_status is RemediationStatus.DETECTED:
        asset.advance_remediation(RemediationStatus.RECOMMENDED, actor="ecdat-engine",
                                  note=f"{d.decision.value} / {d.strategy}")
    return d


def summarize(assets: list[CryptoAsset]) -> dict:
    """Estate-level decision rollup for the dashboard and the roadmap."""
    counts: dict[str, int] = {d.value: 0 for d in MigrationDecision}
    strategies: dict[str, int] = {}
    blocked = 0
    for a in assets:
        if a.migration_decision:
            counts[a.migration_decision.value] += 1
        if a.recommended_strategy:
            strategies[a.recommended_strategy] = strategies.get(
                a.recommended_strategy, 0) + 1
        if a.decision_blocked_on:
            blocked += 1
    return {
        "decisions": counts,
        "definitions": DECISION_DEFINITION,
        "strategies": dict(sorted(strategies.items(), key=lambda kv: -kv[1])),
        "blocked_on_role_determination": blocked,
        "no_pqc_required": counts[MigrationDecision.RETAIN.value],
    }
