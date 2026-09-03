"""Prioritized migration roadmap (contract §17). Derived, never authored.

Phase 9 rebuilds this on top of the canonical fields the earlier stages populate, so
the roadmap is a *projection* of the inventory rather than a second opinion about it:

    migration_decision     which of the frozen five outcomes an asset received
    recommended_strategy   the specific standards-grounded action
    migration_impact       graph-derived reach, prerequisites and gating fan-out
    dependency_centrality  how many units of change an asset sits behind
    crypto_agility         how hard the change is to make at all
    mosca_urgency          when it has to be done by
    classical_risk /       the two independent axes; a classically broken asset is
    quantum_exposure       never queued behind the post-quantum programme

Three properties make this more than a sorted list, and each is tested:

  * **Single placement.** Every in-scope asset lands in exactly one programme phase,
    with `why_this_phase` recording the rule that put it there. A findings list that
    shows the same asset in three phases is not a plan.
  * **Graph-derived sequencing.** Blockers and waves come from `analyze.impact`, which
    reads the asset graph. Nothing here hand-maintains a dependency list.
  * **Two views, one truth.** The P0-P3 *priority bands* (how urgent) and the PH0-PH6
    *programme phases* (what order the work is executed in) are computed from the same
    canonical fields. They answer different questions and are deliberately not merged.

RETAIN assets are reported as a count, not as work. Saying "71 assets need no
cryptographic change" is part of the answer -- an inventory that flags everything tells
a programme nothing about where to spend.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from ..models import (
    Application,
    CryptoAgility,
    CryptoAsset,
    Criticality,
    MigrationDecision,
    Role,
)
from . import impact as impact_mod
from . import mosca, recommend

# Programme phases are PH*, priority bands are P*. The two vocabularies are separate
# on purpose: a P0 asset can sit in PH5 because its prerequisite has not landed yet.
PH_DISCOVER = "PH0"
PH_CLASSIFY = "PH1"
PH_FIX_NOW = "PH2"
PH_ENABLE = "PH3"
PH_PILOT = "PH4"
PH_MIGRATE = "PH5"
PH_RETIRE = "PH6"

_CLASSIFY_STRATEGIES = {recommend.ACTION_VERIFY, recommend.ACTION_DETERMINE_ROLE}
_FIX_NOW_STRATEGIES = {recommend.ACTION_RENEW_CERT, recommend.ACTION_ROTATE_KEY}
_ENABLEMENT_STRATEGIES = {recommend.ACTION_UPGRADE_PROTOCOL,
                          recommend.ACTION_STRENGTHEN}


# ======================================================================================
@dataclass
class RoadmapItem:
    """One asset's place in the programme. Every field is copied from canonical state."""

    asset_id: str
    asset_name: str
    application: str | None
    location: str
    # ---- urgency (P0-P3) ------------------------------------------------------------
    priority: int
    band: str
    urgency: str
    # ---- what to do -----------------------------------------------------------------
    decision: str
    strategy: str
    target: str | None
    # ---- how hard, and how coupled ---------------------------------------------------
    effort: str
    months: int
    coordinated_months: int
    agility: str
    centrality: int
    blast_radius: int
    # ---- sequencing (graph-derived) --------------------------------------------------
    prerequisites: list[str] = field(default_factory=list)
    unblocks: int = 0
    blockers: list[str] = field(default_factory=list)
    change_units: list[str] = field(default_factory=list)
    # ---- placement -------------------------------------------------------------------
    phase: str = PH_MIGRATE
    why_this_phase: str = ""

    def to_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class Phase:
    id: str
    name: str
    objective: str
    duration: str
    items: list[RoadmapItem] = field(default_factory=list)
    deliverables: list[str] = field(default_factory=list)
    exit_criteria: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "id": self.id, "name": self.name, "objective": self.objective,
            "duration": self.duration,
            "asset_count": len(self.items),
            "applications": sorted({i.application for i in self.items if i.application}),
            "bands": {b: sum(1 for i in self.items if i.band == b)
                      for b in ("P0", "P1", "P2", "P3")},
            "decisions": {d: sum(1 for i in self.items if i.decision == d)
                          for d in sorted({i.decision for i in self.items})},
            "longest_coordinated_months": max((i.coordinated_months for i in self.items),
                                              default=0),
            "deliverables": self.deliverables,
            "exit_criteria": self.exit_criteria,
            "items": [i.to_dict() for i in self.items[:60]],
            "items_truncated": max(0, len(self.items) - 60),
        }


# ======================================================================================
# Placement: exactly one phase per asset, with the deciding rule recorded
# ======================================================================================
def _exploitable_today(a: CryptoAsset) -> str:
    """A reason string if this is a present-day exposure, else empty.

    Read off the *classical* axis only. Quantum exposure never routes work here,
    because the two axes are independent and a classically broken primitive must not
    be scheduled behind the post-quantum programme.
    """
    if a.quantum_class == "classically_broken":
        return (f"{a.algorithm_label or a.asset_name} is broken by present-day "
                f"cryptanalysis, independent of the quantum timeline")
    if a.days_to_expiry is not None and a.days_to_expiry < 0:
        return f"certificate expired {abs(a.days_to_expiry)} day(s) ago"
    if "key-material-exposure" in a.tags:
        return "private key material was detected outside a key store"
    if a.migration_decision is MigrationDecision.UPGRADE:
        return ("the decision is UPGRADE: a legacy mechanism is being replaced with a "
                "currently-approved classical one, which is present-day risk reduction")
    return ""


def _is_pilot_candidate(a: CryptoAsset) -> bool:
    """A low-blast-radius asset whose provider can already do PQC.

    Pilots exist to produce real handshake numbers before mission-critical paths are
    touched, so mission-critical assets are deliberately excluded even when they are
    the most urgent.
    """
    return (a.pqc_readiness == "native"
            and a.crypto_agility is CryptoAgility.HIGH
            and a.business_criticality is not Criticality.MISSION_CRITICAL)


def _place(a: CryptoAsset, imp: impact_mod.MigrationImpact | None) -> tuple[str, str]:
    """Return (phase_id, why). Precedence is fixed and documented in the roadmap output.

    The order encodes a programme judgement: you cannot schedule work you have not
    confirmed (PH1), you fix what is already exploitable before what is exploitable
    later (PH2), and you clear shared blockers before the work that waits on them
    (PH3) -- otherwise every dependent team stalls at the same point.
    """
    decision = a.migration_decision
    strategy = a.recommended_strategy or recommend.ACTION_VERIFY
    gates = len(imp.unblocks) if imp else 0

    # 1. Unconfirmed findings are not schedulable work.
    if strategy in _CLASSIFY_STRATEGIES:
        if a.cryptographic_role == Role.UNKNOWN.value and a.quantum_vulnerable:
            return (PH_CLASSIFY,
                    "the cryptographic role is unresolved and the primitive is "
                    "quantum-vulnerable; role decides ML-KEM vs ML-DSA, so the target "
                    "cannot be chosen until it is determined")
        return (PH_CLASSIFY,
                f"the finding needs confirmation before it can be scheduled "
                f"(confidence {a.confidence.value}, strategy {strategy})")

    # 2. Present-day exposure outranks the quantum timeline.
    reason = _exploitable_today(a)
    if reason or strategy in _FIX_NOW_STRATEGIES:
        detail = reason or f"strategy {strategy} addresses an operational exposure"
        if gates:
            detail += (f"; it also gates {gates} other asset(s), so it is sequenced "
                       f"first within this phase")
        return (PH_FIX_NOW, detail)

    # 3. Shared blockers are cleared before the work that waits on them.
    if gates:
        return (PH_ENABLE,
                f"{gates} asset(s) cannot start until this one lands, so its programme "
                f"value is unblocking rather than its own risk score")
    if strategy in _ENABLEMENT_STRATEGIES:
        return (PH_ENABLE,
                f"strategy {strategy} is structural: it changes what the platform is "
                f"capable of negotiating or configuring, not which primitive is called")
    if a.crypto_agility is CryptoAgility.LOW and a.quantum_vulnerable:
        return (PH_ENABLE,
                "crypto agility is LOW: the algorithm choice is not reachable through "
                "configuration, so agility work has to precede any substitution")

    # 4. PQC work: pilot first where it is cheap, then the staged migration.
    if decision in (MigrationDecision.HYBRID, MigrationDecision.PQC_ONLY):
        if _is_pilot_candidate(a):
            return (PH_PILOT,
                    f"provider PQC support is native and agility is HIGH, so this is a "
                    f"low-cost place to obtain real {a.recommended_hybrid or a.recommended_pqc or 'PQC'} "
                    f"performance numbers before mission-critical paths are touched")
        return (PH_MIGRATE,
                f"decision {decision.value} with a named target; scheduled in "
                f"priority-band order ({a.priority_band or 'P3'})")

    # 5. HARDEN that is neither classify nor enablement: parameter/config work.
    if decision is MigrationDecision.HARDEN:
        return (PH_ENABLE,
                "decision HARDEN: the primitive stays, its parameterisation or "
                "handling changes, which is agility and hygiene work")

    return (PH_MIGRATE, f"decision {decision.value if decision else 'undecided'}")


# Phases in which work is actually implemented. PH1 is excluded deliberately:
# classifying a finding does not require its blockers to be cleared first, so a
# dependent sitting in PH1 never drags its prerequisite forward.
_IMPL_ORDER = {PH_FIX_NOW: 2, PH_ENABLE: 3, PH_PILOT: 4, PH_MIGRATE: 5, PH_RETIRE: 6}


def _hoist_prerequisites(items: list[RoadmapItem]) -> int:
    """Pull a blocker forward to the phase of the most urgent asset it blocks.

    Without this the plan can be internally impossible. In the demo estate the issuing
    CA certificate is placed in PH3 (its programme value is unblocking 22 leaves) while
    a SHA-1 leaf it signs is placed in PH2 (broken today) -- which instructs the
    programme to re-issue a leaf before its issuer can sign the new algorithm.

    A prerequisite therefore inherits the earliest implementation phase of anything it
    gates. Iterated to a fixpoint so a chain (leaf -> intermediate -> root) hoists all
    the way, and bounded so cyclic input terminates instead of spinning.
    """
    by_id = {i.asset_id: i for i in items}
    moved = 0
    for _ in range(len(_IMPL_ORDER)):
        changed = False
        for item in items:
            here = _IMPL_ORDER.get(item.phase)
            if here is None:                       # PH1 dependents force nothing
                continue
            for pre_id in item.prerequisites:
                pre = by_id.get(pre_id)
                if pre is None:
                    continue
                there = _IMPL_ORDER.get(pre.phase)
                if there is None or there <= here:  # already early enough
                    continue
                pre.phase = item.phase
                pre.why_this_phase = (
                    f"hoisted to {item.phase}: it blocks {item.asset_name} at "
                    f"{item.location}, which is scheduled in {item.phase}, and a "
                    f"blocker cannot be scheduled after the work that waits on it. "
                    f"Original placement -- {pre.why_this_phase}")
                moved += 1
                changed = True
        if not changed:
            break
    return moved


# ======================================================================================
def build(assets: list[CryptoAsset], applications: list[Application],
          graph=None, impacts: dict | None = None) -> dict:
    """Project the canonical inventory into a phased, prioritized programme.

    `impacts` is the Phase 8 output. If it is absent and a graph is supplied it is
    computed here, so sequencing is always graph-derived rather than guessed. With
    neither, the roadmap still builds but reports its sequencing as unavailable --
    it never falls back to a hand-written blocker list.
    """
    app_by_id = {a.app_id: a for a in applications}
    triaged = [a for a in assets
               if a.triage_state.value not in ("false-positive", "dismissed")]

    if impacts is None and graph is not None:
        impacts = impact_mod.build(graph, triaged)
    impacts = impacts or {}
    sequencing_available = bool(impacts)

    # ---- items ------------------------------------------------------------------------
    items: list[RoadmapItem] = []
    scheduled: list[RoadmapItem] = []
    retained: list[CryptoAsset] = []
    for a in triaged:
        imp = impacts.get(a.asset_id)
        if a.migration_decision is MigrationDecision.RETAIN:
            retained.append(a)
            continue
        phase_id, why = _place(a, imp)
        item = RoadmapItem(
            asset_id=a.asset_id, asset_name=a.asset_name, application=a.application,
            location=a.location,
            priority=a.migration_priority or 0, band=a.priority_band or "P3",
            urgency=a.mosca_urgency or mosca.NOT_APPLICABLE,
            decision=(a.migration_decision.value if a.migration_decision else "undecided"),
            strategy=a.recommended_strategy or recommend.ACTION_VERIFY,
            target=a.recommended_hybrid or a.recommended_pqc,
            effort=(a.migration_effort.value if a.migration_effort else "moderate"),
            months=a.migration_months or 12,
            coordinated_months=(imp.coordinated_effort_months if imp
                                else (a.migration_months or 12)),
            agility=(a.crypto_agility.value if a.crypto_agility else "medium"),
            centrality=a.dependency_centrality or 0,
            blast_radius=(imp.blast_radius if imp else 0),
            prerequisites=([p.asset_id for p in imp.prerequisites] if imp else []),
            unblocks=(len(imp.unblocks) if imp else 0),
            blockers=list(a.migration_blockers) + (
                [f"{p.kind}:{p.asset_name}" for p in imp.prerequisites] if imp else []),
            change_units=(list(imp.change_units) if imp else []),
            phase=phase_id, why_this_phase=why,
        )
        items.append(item)
        scheduled.append(item)

    # A blocker scheduled after the work it blocks makes the plan impossible to
    # execute, so prerequisites are pulled forward before phases are assembled.
    hoisted = _hoist_prerequisites(items)

    by_phase: dict[str, list[RoadmapItem]] = defaultdict(list)
    for i in items:
        by_phase[i.phase].append(i)
    for group in by_phase.values():
        # Within a phase: what unblocks the most first, then by urgency.
        group.sort(key=lambda i: (-i.unblocks, -i.priority))

    # ---- phases ------------------------------------------------------------------------
    n_classify = len(by_phase[PH_CLASSIFY])
    n_fix = len(by_phase[PH_FIX_NOW])
    n_enable = len(by_phase[PH_ENABLE])
    n_pilot = len(by_phase[PH_PILOT])
    n_migrate = len(by_phase[PH_MIGRATE])

    phases = [
        Phase(PH_DISCOVER, "Phase 0 -- Discover",
              "Establish an evidence-backed cryptographic inventory across code, "
              "dependencies, containers, binaries and PKI.",
              "Complete (this scan)",
              deliverables=["Cryptographic inventory", "CycloneDX 1.6 CBOM",
                            "Evidence trail per finding"],
              exit_criteria=[
                  f"{len(assets)} cryptographic assets catalogued with evidence",
                  f"{len(triaged)} in scope after triage",
                  "Coverage gaps recorded explicitly (skipped files, unparsed formats)"]),

        Phase(PH_CLASSIFY, "Phase 1 -- Classify & Validate",
              "Confirm findings and resolve unknown cryptographic roles. Until a role "
              "is known the migration target cannot be chosen, so this phase gates the "
              "correctness of everything after it.",
              "2-6 weeks",
              items=by_phase[PH_CLASSIFY],
              deliverables=["Triaged inventory", "Confirmed cryptographic roles",
                            "Operator-declared data lifetime and criticality per "
                            "application"],
              exit_criteria=[
                  f"{sum(1 for i in by_phase[PH_CLASSIFY] if i.strategy == recommend.ACTION_DETERMINE_ROLE)}"
                  f" assets with unresolved roles determined (role decides ML-KEM vs "
                  f"ML-DSA)",
                  f"{sum(1 for i in by_phase[PH_CLASSIFY] if i.strategy == recommend.ACTION_VERIFY)}"
                  f" findings requiring manual verification accepted or dismissed",
                  "No application left with default-guessed business context"]),

        Phase(PH_FIX_NOW, "Phase 2 -- Fix What Is Broken Today",
              "Remove classically broken primitives, renew expired certificates and "
              "move exposed key material into a key store. These are exploitable now "
              "and independent of the quantum timeline, so they are not queued behind "
              "the post-quantum programme.",
              "1-3 months",
              items=by_phase[PH_FIX_NOW],
              deliverables=["Classically broken primitives removed from active use",
                            "Expired certificates renewed or revoked",
                            "Key material moved to an HSM or secret store"],
              exit_criteria=[
                  f"{sum(1 for i in by_phase[PH_FIX_NOW] if i.decision == 'UPGRADE')}"
                  f" UPGRADE decisions completed",
                  f"{sum(1 for i in by_phase[PH_FIX_NOW] if i.unblocks)}"
                  f" of these also unblock downstream work and are sequenced first",
                  "Re-scan shows zero classically broken primitives in active paths"]),

        Phase(PH_ENABLE, "Phase 3 -- Crypto-Agility Enablement",
              "Clear the structural blockers that gate every downstream migration: "
              "cryptographic provider upgrades, TLS 1.3 availability, hard-coded "
              "algorithm choices moved into configuration, and parameter hardening.",
              "3-9 months (parallel with Phase 2)",
              items=by_phase[PH_ENABLE],
              deliverables=[
                  "Shared provider and protocol blockers cleared",
                  "TLS 1.3 available wherever an RFC 10024 hybrid group is targeted",
                  "Algorithm selection externalised to configuration"],
              exit_criteria=[
                  f"{sum(i.unblocks for i in by_phase[PH_ENABLE])} dependent asset(s) "
                  f"unblocked by {n_enable} enablement item(s)",
                  f"{sum(1 for i in by_phase[PH_ENABLE] if i.agility == 'low')} "
                  f"low-agility assets made configurable",
                  "No remaining asset blocked on a provider that cannot do PQC"]),

        Phase(PH_PILOT, "Phase 4 -- Pilot PQ/T Hybrid",
              "Deploy the RFC 10024 hybrid groups on lower-criticality services whose "
              "provider already supports PQC natively. Build operational confidence "
              "and measured performance numbers before mission-critical paths.",
              "3-6 months",
              items=by_phase[PH_PILOT],
              deliverables=["Hybrid key establishment live on pilot services",
                            "Measured handshake latency, CPU and packet-size deltas",
                            "Runbook and rollback procedure validated"],
              exit_criteria=[
                  f"{n_pilot} pilot candidate(s) with native provider PQC support "
                  f"migrated",
                  "Negotiation-failure rate within the agreed threshold",
                  "Performance impact documented and formally accepted"]),

        Phase(PH_MIGRATE, "Phase 5 -- Staged Migration",
              "Migrate the remaining quantum-vulnerable assets in priority-band order. "
              "Key establishment on internet-facing, long-retention systems leads "
              "(harvest-now-decrypt-later); signature roles follow PKI readiness, "
              "because no PQ/T hybrid signature is standardised.",
              "12-36 months",
              items=by_phase[PH_MIGRATE],
              deliverables=["Key establishment on RFC 10024 hybrid groups",
                            "Signature roles on ML-DSA / SLH-DSA as PKI allows",
                            "Per-wave verification re-scans"],
              exit_criteria=[
                  f"P0 wave: {sum(1 for i in by_phase[PH_MIGRATE] if i.band == 'P0')} "
                  f"asset(s)",
                  f"P1 wave: {sum(1 for i in by_phase[PH_MIGRATE] if i.band == 'P1')} "
                  f"asset(s)",
                  f"P2/P3 waves: "
                  f"{sum(1 for i in by_phase[PH_MIGRATE] if i.band in ('P2', 'P3'))} "
                  f"asset(s)"]),

        Phase(PH_RETIRE, "Phase 6 -- Retire Quantum-Vulnerable Cryptography",
              "Disable classical-only key establishment, remove downgrade fallbacks, "
              "and enforce the target state in CI so regression is impossible. NIST IR "
              "8547 (Initial Public Draft) targets removal of quantum-vulnerable "
              "algorithms from NIST standards by 2035.",
              "Aligned to the 2035 policy deadline",
              deliverables=["Legacy key-exchange groups disabled",
                            "CI policy gate rejecting quantum-vulnerable primitives",
                            "Continuous CBOM tracking in the build pipeline"],
              exit_criteria=[
                  "Zero quantum-vulnerable key establishment on external services",
                  "CBOM regenerated on every build and diffed against policy"]),
    ]

    # ---- enablement waves, grouped by the graph's shared units of change --------------
    waves: list[dict] = []
    if sequencing_available:
        gating = [i for i in items if i.unblocks]
        for item in sorted(gating, key=lambda i: -i.unblocks):
            downstream = impacts[item.asset_id].unblocks
            waves.append({
                "gating_asset": item.asset_id,
                "gating_asset_name": item.asset_name,
                "phase": item.phase,
                "decision": item.decision,
                "strategy": item.strategy,
                "change_units": item.change_units,
                "dependent_assets": len(downstream),
                "applications": sorted({impacts[d].applications[0]
                                        for d in downstream
                                        if impacts.get(d) and impacts[d].applications}),
                "months": item.coordinated_months,
                "rationale": ("One change unblocks all of these assets, so it is "
                              "sequenced as a single programme item rather than "
                              "repeated per service. Derived from the asset graph."),
            })

    # ---- priority-band view (P0-P3) ----------------------------------------------------
    bands: dict[str, dict] = {}
    for band in ("P0", "P1", "P2", "P3"):
        members = [i for i in scheduled if i.band == band]
        bands[band] = {
            "band": band,
            "assets": len(members),
            "decisions": {d: sum(1 for i in members if i.decision == d)
                          for d in sorted({i.decision for i in members})},
            "phases": {p: sum(1 for i in members if i.phase == p)
                       for p in sorted({i.phase for i in members})},
            "applications": sorted({i.application for i in members if i.application}),
            "longest_coordinated_months": max((i.coordinated_months for i in members),
                                              default=0),
            "top_items": [i.to_dict() for i in
                          sorted(members, key=lambda i: -i.priority)[:15]],
        }

    # ---- per-application rollup ---------------------------------------------------------
    per_app: dict[str, dict] = {}
    for a in triaged:
        if not a.application:
            continue
        rec = per_app.setdefault(a.application, {
            "application": a.application,
            "name": (app_by_id[a.application].name if a.application in app_by_id
                     else a.application),
            "owner": a.owner, "business_unit": a.business_unit,
            "assets": 0, "quantum_vulnerable": 0, "retain": 0,
            "p0": 0, "p1": 0, "max_priority": 0,
            "worst_urgency": mosca.NOT_APPLICABLE,
            "effort_months": 0, "decisions": {},
        })
        rec["assets"] += 1
        if a.quantum_vulnerable:
            rec["quantum_vulnerable"] += 1
        if a.migration_decision is MigrationDecision.RETAIN:
            rec["retain"] += 1
        if a.priority_band == "P0":
            rec["p0"] += 1
        elif a.priority_band == "P1":
            rec["p1"] += 1
        rec["max_priority"] = max(rec["max_priority"], a.migration_priority or 0)
        if mosca.URGENCY_ORDER.get(a.mosca_urgency or mosca.NOT_APPLICABLE, 9) < \
                mosca.URGENCY_ORDER.get(rec["worst_urgency"], 9):
            rec["worst_urgency"] = a.mosca_urgency
        imp = impacts.get(a.asset_id)
        rec["effort_months"] = max(
            rec["effort_months"],
            imp.coordinated_effort_months if imp else (a.migration_months or 0))
        if a.migration_decision:
            key = a.migration_decision.value
            rec["decisions"][key] = rec["decisions"].get(key, 0) + 1

    return {
        "phases": [p.to_dict() for p in phases],
        "bands": bands,
        "enablement_waves": waves,
        "applications": sorted(per_app.values(), key=lambda r: -r["max_priority"]),
        "totals": {
            "assets": len(assets),
            "in_scope": len(triaged),
            "scheduled": len(scheduled),
            "no_action_required": len(retained),
            "quantum_vulnerable": sum(1 for a in triaged if a.quantum_vulnerable),
            "classically_broken": sum(1 for a in triaged
                                      if a.quantum_class == "classically_broken"),
            "gating_assets": sum(1 for i in items if i.unblocks),
            "p0": sum(1 for a in triaged if a.priority_band == "P0"),
            "p1": sum(1 for a in triaged if a.priority_band == "P1"),
            "p2": sum(1 for a in triaged if a.priority_band == "P2"),
            "p3": sum(1 for a in triaged if a.priority_band == "P3"),
        },
        "method": {
            "placement": ("Every scheduled asset appears in exactly one programme "
                          "phase. `why_this_phase` records the rule that placed it."),
            "precedence": [
                "PH1 Classify -- an unconfirmed finding or unresolved role is not "
                "schedulable work",
                "PH2 Fix now -- present-day exploitability outranks the quantum "
                "timeline (the two risk axes are independent)",
                "PH3 Enable -- an asset that gates others is sequenced by its "
                "unblocking value, not its own score",
                "PH4 Pilot -- native provider PQC support and HIGH agility, excluding "
                "mission-critical paths",
                "PH5 Migrate -- everything else with a named post-quantum target, in "
                "priority-band order",
            ],
            "sequencing_source": ("asset graph via analyze.impact" if sequencing_available
                                  else "UNAVAILABLE -- no graph supplied; blockers and "
                                       "waves are omitted rather than guessed"),
            "prerequisites_hoisted": hoisted,
            "hoist_rule": ("A blocker inherits the earliest implementation phase of "
                           "anything it blocks, so no prerequisite is ever scheduled "
                           "after the work waiting on it. PH1 (classify) is exempt as a "
                           "dependent: confirming a finding does not require its "
                           "blockers to be cleared."),
            "bands_vs_phases": ("P0-P3 is urgency (Mosca + business context). PH0-PH6 "
                                "is execution order. A P0 asset can sit in PH5 because "
                                "its prerequisite has not landed."),
            "effort_note": impact_mod.EFFORT_RULE,
            "retain_note": (f"{len(retained)} asset(s) received decision RETAIN and are "
                            f"reported as needing no cryptographic change rather than "
                            f"as work items."),
        },
    }
