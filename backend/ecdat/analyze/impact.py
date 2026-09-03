"""Migration impact analysis (contract §16/§17). GRAPH-DERIVED, by construction.

The question this module answers is the one that turns a finding into a work item:

    "If we change this, what else changes, who owns it, what has to happen first,
     and how long does the whole thing take?"

Every answer here is produced by traversing the cryptographic asset graph. There are
no hand-maintained impact tables, and nothing in this file invents a cryptographic
fact: impact is an OUTPUT of the canonical model, in the same category as the roadmap
and the CBOM. Concretely, the traversals are:

    reach          walk UP from the asset node (file -> repository -> application ->
                   owner) and DOWN from each application (-> service, business
                   function). That is the set of estate units a change touches.

    coupling       out-edges to LIBRARY / PROTOCOL / CERTIFICATE nodes -- the shared
                   *units of change* -- then back in to every other asset attached to
                   the same node. Those assets change together, so their reach is part
                   of this asset's blast radius.

    scope          out-edges to the ALGORITHM node, then back in. Reported separately
                   as `algorithm_siblings`: "39 other call sites use this primitive" is
                   useful scope, but it is not coupling, because no single action
                   changes them all.

    sequencing     provider assets behind a shared LIBRARY node, issuer certificates
                   along ISSUED_BY edges, and protocol-config assets on a shared
                   PROTOCOL node are PREREQUISITES -- they must move first, and the
                   graph says so without anyone writing the dependency down.

Effort is the one number this module aggregates rather than reads. Per-asset
`migration_effort` stays canonical in `analyze/risk.py`; what impact adds is a
*coordinated* duration for the whole coupled set, under an explicitly stated rule
(parallel within a change unit, serial across prerequisites). It is labelled DERIVED
so it is never mistaken for a measured figure.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from ..graph import CENTRALITY_RESOURCE_TYPES, CryptoGraph, NodeType, node_id
from ..models import CryptoAsset, MigrationDecision, MigrationEffort
from . import recommend

# Estate unit types that constitute "reach". A change to an asset is felt by these.
_REACH_TYPES = (NodeType.FILE, NodeType.REPOSITORY, NodeType.CONTAINER,
                NodeType.APPLICATION, NodeType.OWNER)
_REACH_DOWN_TYPES = (NodeType.SERVICE, NodeType.BUSINESS_FUNCTION)

_MAX_UP_DEPTH = 4          # asset -> file -> repository -> application -> owner
_MAX_CHAIN_DEPTH = 8       # prerequisite chain bound; guards against cyclic data

EFFORT_RULE = (
    "DERIVED estimate. Assets coupled through one unit of change are migrated as a "
    "single programme item, so their durations do not add -- the coordinated duration "
    "is the longest of them. Prerequisites are serial: a provider upgrade or a CA "
    "re-issuance must complete before the dependent work can start, so the longest "
    "prerequisite chain is added on top. Per-asset effort itself is not recomputed "
    "here; it is read from the canonical asset."
)


# ======================================================================================
@dataclass
class Prerequisite:
    asset_id: str
    asset_name: str
    kind: str                  # provider | pki | protocol
    reason: str

    def to_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class MigrationImpact:
    """What changes when this asset changes. Every list is a traversal result."""

    asset_id: str
    asset_name: str
    decision: str | None = None

    # ---- reach ------------------------------------------------------------------------
    applications: list[str] = field(default_factory=list)
    services: list[str] = field(default_factory=list)
    repositories: list[str] = field(default_factory=list)
    containers: list[str] = field(default_factory=list)
    files: list[str] = field(default_factory=list)
    owners: list[str] = field(default_factory=list)
    business_units: list[str] = field(default_factory=list)
    business_functions: list[str] = field(default_factory=list)

    # ---- shared cryptographic units of change -----------------------------------------
    libraries: list[str] = field(default_factory=list)
    protocols: list[str] = field(default_factory=list)
    certificates: list[str] = field(default_factory=list)
    change_units: list[str] = field(default_factory=list)

    # ---- coupling vs scope -------------------------------------------------------------
    dependent_assets: list[str] = field(default_factory=list)
    algorithm_siblings: list[str] = field(default_factory=list)

    # ---- sequencing ---------------------------------------------------------------------
    prerequisites: list[Prerequisite] = field(default_factory=list)
    unblocks: list[str] = field(default_factory=list)

    # ---- effort -------------------------------------------------------------------------
    own_effort: str | None = None
    own_effort_months: int = 0
    coordinated_effort_months: int = 0
    prerequisite_months: int = 0
    effort_rule: str = EFFORT_RULE
    effort_drivers: list[str] = field(default_factory=list)

    # ---- blockers and scoring ------------------------------------------------------------
    blockers: list[str] = field(default_factory=list)
    blast_radius: int = 0
    blast_radius_score: float = 0.0
    explanation: str = ""
    traversal: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        d["prerequisites"] = [p.to_dict() for p in self.prerequisites]
        return d

    def headline(self) -> str:
        """One line for a table row."""
        return (f"{len(self.applications)} application(s), {len(self.services)} "
                f"service(s), {len(self.dependent_assets)} coupled asset(s); "
                f"{self.coordinated_effort_months} month(s) coordinated")


# ======================================================================================
# Traversal primitives
# ======================================================================================
class _Traverser:
    """Memoized graph walks. One instance per estate-wide impact run."""

    def __init__(self, graph: CryptoGraph, assets: list[CryptoAsset]) -> None:
        self.g = graph
        self.assets = assets
        self.by_id = {a.asset_id: a for a in assets}
        self._reach: dict[str, dict[NodeType, set[str]]] = {}
        # resource node -> asset ids attached to it
        self._resource_assets: dict[str, set[str]] = defaultdict(set)
        self._algorithm_assets: dict[str, set[str]] = defaultdict(set)
        for a in assets:
            anid = node_id(NodeType.ASSET, a.asset_id)
            for rnid in graph.out_neighbors(anid):
                node = graph.nodes.get(rnid)
                if node is None:
                    continue
                if node.type in CENTRALITY_RESOURCE_TYPES:
                    self._resource_assets[rnid].add(a.asset_id)
                elif node.type is NodeType.ALGORITHM:
                    self._algorithm_assets[rnid].add(a.asset_id)

    # ---- reach --------------------------------------------------------------------------
    def reach(self, asset_id: str) -> dict[NodeType, set[str]]:
        """Estate units containing this asset: up the containment chain, then down
        from each owning application to the services it runs."""
        cached = self._reach.get(asset_id)
        if cached is not None:
            return cached
        anid = node_id(NodeType.ASSET, asset_id)
        out: dict[NodeType, set[str]] = defaultdict(set)
        if anid in self.g.nodes:
            seen = {anid}
            frontier = [anid]
            for _ in range(_MAX_UP_DEPTH):
                nxt: list[str] = []
                for nid in frontier:
                    for parent in self.g.in_neighbors(nid):
                        if parent in seen:
                            continue
                        seen.add(parent)
                        node = self.g.nodes.get(parent)
                        if node is None or node.type not in _REACH_TYPES:
                            continue
                        out[node.type].add(parent)
                        nxt.append(parent)
                frontier = nxt
                if not frontier:
                    break
            for app_nid in list(out[NodeType.APPLICATION]):
                for child in self.g.out_neighbors(app_nid):
                    node = self.g.nodes.get(child)
                    if node and node.type in _REACH_DOWN_TYPES:
                        out[node.type].add(child)
        self._reach[asset_id] = out
        return out

    # ---- coupling ------------------------------------------------------------------------
    def resources(self, asset_id: str) -> list[str]:
        """The shared units of change this asset depends on."""
        anid = node_id(NodeType.ASSET, asset_id)
        return [rnid for rnid in sorted(self.g.out_neighbors(anid))
                if (n := self.g.nodes.get(rnid)) and n.type in CENTRALITY_RESOURCE_TYPES]

    def coupled(self, asset_id: str) -> set[str]:
        """Other assets that change together with this one."""
        out: set[str] = set()
        for rnid in self.resources(asset_id):
            out |= self._resource_assets.get(rnid, set())
        out.discard(asset_id)
        return out

    def algorithm_siblings(self, asset_id: str) -> set[str]:
        """Assets using the same primitive. Scope, deliberately NOT coupling."""
        anid = node_id(NodeType.ASSET, asset_id)
        out: set[str] = set()
        for nid in self.g.out_neighbors(anid):
            node = self.g.nodes.get(nid)
            if node and node.type is NodeType.ALGORITHM:
                out |= self._algorithm_assets.get(nid, set())
        out.discard(asset_id)
        return out

    def assets_on(self, resource_nid: str) -> set[str]:
        return self._resource_assets.get(resource_nid, set())


# ======================================================================================
# Prerequisites -- read off the graph, never written down by hand
# ======================================================================================
def _provider_prerequisites(t: _Traverser, asset: CryptoAsset) -> list[Prerequisite]:
    """A provider asset behind a shared LIBRARY node must be dealt with first.

    The asset that *is* the library (a dependency or container package with no
    algorithm of its own) gates every asset that draws its primitives from it. The
    reason text distinguishes the two cases honestly: an UPGRADE provider is a change
    that has to land, whereas a HARDEN provider is usually a capability that has to be
    *confirmed*. Calling a verification task a change would overstate the work.
    """
    out: list[Prerequisite] = []
    for rnid in t.resources(asset.asset_id):
        node = t.g.nodes.get(rnid)
        if node is None or node.type is not NodeType.LIBRARY:
            continue
        for other_id in t.assets_on(rnid):
            other = t.by_id.get(other_id)
            if other is None or other_id == asset.asset_id:
                continue
            # A provider-only asset: it supplies primitives, it does not use one.
            if other.algorithm is not None:
                continue
            if other.migration_decision is MigrationDecision.UPGRADE:
                reason = (f"{other.asset_name} supplies this asset's cryptographic "
                          f"primitives and is itself decided UPGRADE. That provider "
                          f"change has to land first: until it does, the target "
                          f"mechanism cannot be selected here at all.")
            elif other.migration_decision is MigrationDecision.HARDEN:
                reason = (f"{other.asset_name} supplies this asset's cryptographic "
                          f"primitives and is decided HARDEN via "
                          f"'{other.recommended_strategy}'. What gates this asset is "
                          f"confirming what that provider version actually supports -- "
                          f"a verification step, not necessarily a code change -- "
                          f"because a target cannot be committed to against an "
                          f"unconfirmed capability.")
            else:
                continue
            out.append(Prerequisite(
                asset_id=other_id, asset_name=other.asset_name, kind="provider",
                reason=reason))
    return out


def _pki_prerequisites(t: _Traverser, asset: CryptoAsset) -> list[Prerequisite]:
    """Along ISSUED_BY edges: an issuer must carry the target algorithm before a leaf
    signed by it can. Rolling a leaf ahead of its issuer breaks chain validation."""
    out: list[Prerequisite] = []
    cert_to_asset: dict[str, str] = {}
    for aid in t.by_id:
        for rnid in t.resources(aid):
            node = t.g.nodes.get(rnid)
            if node and node.type is NodeType.CERTIFICATE:
                cert_to_asset.setdefault(rnid, aid)

    for rnid in t.resources(asset.asset_id):
        node = t.g.nodes.get(rnid)
        if node is None or node.type is not NodeType.CERTIFICATE:
            continue
        for issuer_nid in t.g.out_neighbors(rnid):
            issuer = t.g.nodes.get(issuer_nid)
            if issuer is None or issuer.type is not NodeType.CERTIFICATE:
                continue
            issuer_asset_id = cert_to_asset.get(issuer_nid)
            if not issuer_asset_id or issuer_asset_id == asset.asset_id:
                continue
            issuer_asset = t.by_id.get(issuer_asset_id)
            if issuer_asset is None:
                continue
            out.append(Prerequisite(
                asset_id=issuer_asset_id, asset_name=issuer_asset.asset_name,
                kind="pki",
                reason=(f"This certificate is issued by {issuer.label}. A leaf cannot "
                        f"present an algorithm its issuer cannot sign, so the issuing "
                        f"certificate migrates first and the chain is re-issued "
                        f"top-down.")))
    return out


def _protocol_prerequisites(t: _Traverser, asset: CryptoAsset) -> list[Prerequisite]:
    """RFC 10024 hybrid groups exist for TLS 1.3 only. Where a protocol-config asset
    on the same PROTOCOL node still has to reach 1.3, it gates the algorithm work."""
    out: list[Prerequisite] = []
    if asset.recommended_strategy == recommend.ACTION_UPGRADE_PROTOCOL:
        return out          # this asset IS the protocol upgrade
    for rnid in t.resources(asset.asset_id):
        node = t.g.nodes.get(rnid)
        if node is None or node.type is not NodeType.PROTOCOL:
            continue
        if node.attrs.get("protocol") != "TLS":
            continue
        if node.attrs.get("version") not in ("1.0", "1.1", "1.2"):
            continue
        for other_id in t.assets_on(rnid):
            other = t.by_id.get(other_id)
            if (other is None or other_id == asset.asset_id
                    or other.recommended_strategy != recommend.ACTION_UPGRADE_PROTOCOL):
                continue
            out.append(Prerequisite(
                asset_id=other_id, asset_name=other.asset_name, kind="protocol",
                reason=(f"This asset negotiates {node.label}, and the RFC 10024 hybrid "
                        f"groups are defined for TLS 1.3 only. The protocol upgrade at "
                        f"{other.location} is therefore a hard prerequisite, not a "
                        f"parallel task.")))
    return out


# ======================================================================================
# Per-asset impact
# ======================================================================================
def analyze(t: _Traverser, asset: CryptoAsset) -> MigrationImpact:
    reach = t.reach(asset.asset_id)
    coupled = t.coupled(asset.asset_id)
    siblings = t.algorithm_siblings(asset.asset_id)
    resources = t.resources(asset.asset_id)

    # Blast radius = own reach UNION the reach of everything coupled to it.
    merged: dict[NodeType, set[str]] = {k: set(v) for k, v in reach.items()}
    for other_id in coupled:
        for k, v in t.reach(other_id).items():
            merged.setdefault(k, set()).update(v)

    def labels(kind: NodeType) -> list[str]:
        return sorted({t.g.nodes[n].label for n in merged.get(kind, set())
                       if n in t.g.nodes})

    def keys(kind: NodeType) -> list[str]:
        return sorted({n.split(":", 1)[1] for n in merged.get(kind, set())})

    applications = keys(NodeType.APPLICATION)
    services = labels(NodeType.SERVICE)
    repositories = labels(NodeType.REPOSITORY)
    containers = labels(NodeType.CONTAINER)
    files = labels(NodeType.FILE)
    owners = labels(NodeType.OWNER)
    functions = labels(NodeType.BUSINESS_FUNCTION)

    # Business units come from the applications the traversal reached, so they cannot
    # disagree with the estate manifest.
    units = sorted({t.g.nodes[n].attrs.get("business_unit")
                    for n in merged.get(NodeType.APPLICATION, set())
                    if n in t.g.nodes and t.g.nodes[n].attrs.get("business_unit")}
                   - {"unassigned"})

    libraries = [t.g.nodes[r].label for r in resources
                 if t.g.nodes[r].type is NodeType.LIBRARY]
    protocols = [t.g.nodes[r].label for r in resources
                 if t.g.nodes[r].type is NodeType.PROTOCOL]
    certificates = [t.g.nodes[r].label for r in resources
                    if t.g.nodes[r].type is NodeType.CERTIFICATE]

    prereqs = (_provider_prerequisites(t, asset)
               + _pki_prerequisites(t, asset)
               + _protocol_prerequisites(t, asset))
    # De-duplicate: one prerequisite asset, the first reason recorded for it.
    seen_pre: dict[str, Prerequisite] = {}
    for p in prereqs:
        seen_pre.setdefault(p.asset_id, p)
    prereqs = list(seen_pre.values())

    own_months = asset.migration_months or (
        asset.migration_effort or MigrationEffort.MODERATE).months
    coupled_months = max(
        [own_months] + [(t.by_id[c].migration_months
                         or (t.by_id[c].migration_effort
                             or MigrationEffort.MODERATE).months)
                        for c in coupled if c in t.by_id])
    prereq_months = max(
        [0] + [(t.by_id[p.asset_id].migration_months
                or (t.by_id[p.asset_id].migration_effort
                    or MigrationEffort.MODERATE).months)
               for p in prereqs if p.asset_id in t.by_id])

    blast = (len(applications) + len(services) + len(repositories)
             + len(containers) + len(certificates))

    unit_labels = [t.g.nodes[r].label for r in resources]
    explanation = (
        f"Changing {asset.asset_name} at {asset.location} touches "
        f"{len(applications)} application(s), {len(services)} service(s) and "
        f"{len(repositories)} repository(ies), across {len(units) or 0} business "
        f"unit(s), with {len(owners)} accountable owner(s). "
        + (f"It is coupled to {len(coupled)} other asset(s) through "
           f"{len(resources)} shared unit(s) of change "
           f"({', '.join(unit_labels)}), so those move as one programme item. "
           if coupled else
           "No other asset shares its units of change, so it can be migrated in "
           "isolation. ")
        + (f"{len(prereqs)} prerequisite(s) must land first. " if prereqs else "")
        + (f"A further {len(siblings)} asset(s) use the same primitive but are not "
           f"coupled to this change." if siblings else ""))

    return MigrationImpact(
        asset_id=asset.asset_id, asset_name=asset.asset_name,
        decision=asset.migration_decision.value if asset.migration_decision else None,
        applications=applications, services=services, repositories=repositories,
        containers=containers, files=files, owners=owners, business_units=units,
        business_functions=functions,
        libraries=libraries, protocols=protocols, certificates=certificates,
        change_units=unit_labels,
        dependent_assets=sorted(coupled), algorithm_siblings=sorted(siblings),
        prerequisites=prereqs,
        own_effort=asset.migration_effort.value if asset.migration_effort else None,
        own_effort_months=own_months,
        coordinated_effort_months=coupled_months + prereq_months,
        prerequisite_months=prereq_months,
        effort_drivers=list(asset.migration_blockers),
        blockers=list(asset.migration_blockers),
        blast_radius=blast,
        explanation=explanation,
        traversal={
            "asset_node": node_id(NodeType.ASSET, asset.asset_id),
            "resource_nodes": resources,
            "reach_nodes": sum(len(v) for v in merged.values()),
            "coupled_assets": len(coupled),
            "method": ("up-traversal for containment, resource in-edges for coupling, "
                       "ISSUED_BY / LIBRARY / PROTOCOL edges for sequencing"),
        },
    )


# ======================================================================================
# Estate-wide
# ======================================================================================
def build(graph: CryptoGraph, assets: list[CryptoAsset]) -> dict[str, MigrationImpact]:
    """Compute impact for every asset. Returns a map keyed by asset_id."""
    t = _Traverser(graph, assets)
    impacts = {a.asset_id: analyze(t, a) for a in assets}

    # `unblocks` is the inverse of `prerequisites`; deriving it rather than collecting
    # it twice keeps the two directions from disagreeing.
    for imp in impacts.values():
        for p in imp.prerequisites:
            upstream = impacts.get(p.asset_id)
            if upstream is not None and imp.asset_id not in upstream.unblocks:
                upstream.unblocks.append(imp.asset_id)
    for imp in impacts.values():
        imp.unblocks.sort()

    peak = max((i.blast_radius for i in impacts.values()), default=0)
    for imp in impacts.values():
        imp.blast_radius_score = (round(100.0 * imp.blast_radius / peak, 1)
                                  if peak else 0.0)
    return impacts


def critical_path(impacts: dict[str, MigrationImpact], asset_id: str) -> list[str]:
    """The longest prerequisite chain ending at this asset, in execution order.

    Depth-bounded and cycle-safe: pathological input (a certificate loop, a mutual
    provider dependency) must degrade to a truncated path, never hang.
    """
    best: list[str] = []

    def walk(aid: str, path: list[str], seen: frozenset[str]) -> None:
        nonlocal best
        imp = impacts.get(aid)
        if imp is None or len(path) > _MAX_CHAIN_DEPTH:
            if len(path) > len(best):
                best = list(path)
            return
        upstream = [p.asset_id for p in imp.prerequisites if p.asset_id not in seen]
        if not upstream:
            if len(path) > len(best):
                best = list(path)
            return
        for up in upstream:
            walk(up, [up] + path, seen | {up})

    walk(asset_id, [asset_id], frozenset({asset_id}))
    return best


def summarize(impacts: dict[str, MigrationImpact],
              assets: list[CryptoAsset]) -> dict:
    """Estate-level rollup: which single changes unblock the most work.

    This is the view the roadmap sequences from -- one provider upgrade that clears
    nine services is a different programme item from nine unrelated code changes,
    even though a flat finding list renders them identically.
    """
    by_id = {a.asset_id: a for a in assets}

    # Change units, aggregated across the assets attached to them.
    units: dict[str, dict] = {}
    for imp in impacts.values():
        for label in imp.change_units:
            rec = units.setdefault(label, {
                "unit": label, "assets": 0, "applications": set(),
                "services": set(), "owners": set(), "max_blast_radius": 0,
            })
            rec["assets"] += 1
            rec["applications"].update(imp.applications)
            rec["services"].update(imp.services)
            rec["owners"].update(imp.owners)
            rec["max_blast_radius"] = max(rec["max_blast_radius"], imp.blast_radius)
    change_units = sorted(
        ({"unit": r["unit"], "assets": r["assets"],
          "applications": sorted(r["applications"]),
          "services": sorted(r["services"]),
          "owners": sorted(r["owners"]),
          "max_blast_radius": r["max_blast_radius"],
          "rationale": ("One change to this unit is one programme item; every asset "
                        "attached to it moves with it.")}
         for r in units.values()),
        key=lambda r: (-r["assets"], r["unit"]))

    gating = sorted((i for i in impacts.values() if i.unblocks),
                    key=lambda i: (-len(i.unblocks), i.asset_id))
    widest = sorted(impacts.values(), key=lambda i: (-i.blast_radius, i.asset_id))

    owners: dict[str, dict] = {}
    for imp in impacts.values():
        a = by_id.get(imp.asset_id)
        for owner in imp.owners:
            rec = owners.setdefault(owner, {"owner": owner, "assets": 0,
                                            "applications": set(),
                                            "coordinated_months": 0})
            rec["assets"] += 1
            rec["applications"].update(imp.applications)
            rec["coordinated_months"] = max(rec["coordinated_months"],
                                            imp.coordinated_effort_months)

    return {
        "assets": len(impacts),
        "change_units": change_units[:20],
        "change_unit_count": len(units),
        "gating_assets": [
            {"asset_id": i.asset_id, "asset_name": i.asset_name,
             "decision": i.decision, "unblocks": len(i.unblocks),
             "applications": i.applications,
             "rationale": (f"{len(i.unblocks)} asset(s) cannot start until this one "
                           f"lands; sequence it first regardless of its own risk "
                           f"score.")}
            for i in gating[:15]],
        "widest_blast_radius": [
            {"asset_id": i.asset_id, "asset_name": i.asset_name,
             "decision": i.decision, "blast_radius": i.blast_radius,
             "blast_radius_score": i.blast_radius_score,
             "headline": i.headline()}
            for i in widest[:15]],
        "owners": sorted(
            ({"owner": r["owner"], "assets": r["assets"],
              "applications": sorted(r["applications"]),
              "longest_coordinated_months": r["coordinated_months"]}
             for r in owners.values()),
            key=lambda r: -r["assets"]),
        "effort_rule": EFFORT_RULE,
        "notes": [
            "Impact is derived by graph traversal on every run; no impact list is "
            "stored or hand-maintained.",
            "`dependent_assets` is coupling (they change together). "
            "`algorithm_siblings` is scope (same primitive, separate changes).",
        ],
    }
