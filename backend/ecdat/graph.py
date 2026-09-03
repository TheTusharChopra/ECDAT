"""Cryptographic asset graph (contract §10/§12).

The graph is analytical infrastructure, not a picture. Three downstream features are
impossible without it:

  * `dependency_centrality` -- how much of the estate rides on one cryptographic
    resource. "This OpenSSL build serves 9 services across 3 business units" is the
    number that turns a list of findings into a migration sequence.
  * migration impact -- which applications, services, repositories and certificates
    are touched by acting on one asset.
  * evidence tracing in the UI -- selecting a node answers WHAT / WHERE / WHY /
    WHAT DOES IT AFFECT.

Implementation is a plain in-memory adjacency structure (stdlib only). A graph
database would add operational weight for an MVP whose largest realistic graph is a
few tens of thousands of nodes, and NetworkX is not installable in the target
air-gapped environment.

Critically: the graph stores *references* to canonical assets, never copies of
cryptographic facts. `NodeType.ASSET` nodes hold an `asset_id` and nothing else that
could drift from the canonical model.
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable

from .models import Application, CryptoAsset


class NodeType(str, Enum):
    APPLICATION = "application"
    SERVICE = "service"
    BUSINESS_FUNCTION = "business-function"
    DATA = "data"
    REPOSITORY = "repository"
    CONTAINER = "container"
    FILE = "file"
    ASSET = "crypto-asset"
    ALGORITHM = "algorithm"
    LIBRARY = "library"
    PROTOCOL = "protocol"
    CERTIFICATE = "certificate"
    OWNER = "owner"


class EdgeType(str, Enum):
    OWNS = "owns"                     # application -> repository
    RUNS = "runs"                     # application -> service
    DEPLOYS = "deploys"               # application -> container
    PROTECTS = "protects"             # application -> data
    SERVES = "serves"                 # application -> business function
    ACCOUNTABLE_FOR = "accountable-for"   # owner -> application
    CONTAINS = "contains"             # repository -> file
    DECLARES = "declares"             # file/container/repo -> crypto asset
    USES_ALGORITHM = "uses-algorithm"   # asset -> algorithm
    PROVIDED_BY = "provided-by"       # asset -> library
    NEGOTIATES = "negotiates"         # asset -> protocol
    BOUND_TO = "bound-to"             # asset -> certificate
    ISSUED_BY = "issued-by"           # certificate -> certificate (chain)


# Resource node types that can be *shared* between applications. Sharing is what
# creates centrality: a file belongs to one repository, but a library or an
# algorithm can be common to the whole estate.
SHARED_RESOURCE_TYPES = (NodeType.ALGORITHM, NodeType.LIBRARY,
                         NodeType.PROTOCOL, NodeType.CERTIFICATE)

# Resource types that represent a genuine UNIT OF CHANGE -- something an engineer
# upgrades, re-issues or reconfigures once, affecting everything attached to it.
#
# ALGORITHM is deliberately excluded. Every application uses SHA-256, so counting
# algorithm sharing makes SHA-256 the most "central" asset in any estate, which is
# both true and useless: there is no single action that changes SHA-256 everywhere,
# and SHA-256 is a RETAIN asset anyway. Coupling that actually drives migration cost
# comes from shared implementations (one library upgrade), shared PKI (one
# re-issuance) and shared protocol configuration.
#
# Algorithm sharing is still reported, as `algorithm_siblings`, because "39 other
# call sites use this primitive" is useful scope information -- it is just not
# coupling.
CENTRALITY_RESOURCE_TYPES = (NodeType.LIBRARY, NodeType.PROTOCOL,
                             NodeType.CERTIFICATE)


@dataclass
class Node:
    id: str
    type: NodeType
    label: str
    attrs: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {"id": self.id, "type": self.type.value, "label": self.label,
                **self.attrs}


@dataclass
class Edge:
    src: str
    dst: str
    type: EdgeType

    def to_dict(self) -> dict:
        return {"source": self.src, "target": self.dst, "type": self.type.value}


# ======================================================================================
def _nid(kind: NodeType, key: str) -> str:
    return f"{kind.value}:{key}"


class CryptoGraph:
    def __init__(self) -> None:
        self.nodes: dict[str, Node] = {}
        self.edges: list[Edge] = []
        self._out: dict[str, set[str]] = defaultdict(set)
        self._in: dict[str, set[str]] = defaultdict(set)
        self._edge_set: set[tuple[str, str, str]] = set()

    # -- construction ------------------------------------------------------------------
    def add_node(self, kind: NodeType, key: str, label: str, **attrs) -> str:
        nid = _nid(kind, key)
        existing = self.nodes.get(nid)
        if existing is None:
            self.nodes[nid] = Node(nid, kind, label, dict(attrs))
        else:
            # merge attributes; never silently replace a label with a worse one
            existing.attrs.update({k: v for k, v in attrs.items() if v is not None})
        return nid

    def add_edge(self, src: str, dst: str, kind: EdgeType) -> None:
        if src not in self.nodes or dst not in self.nodes or src == dst:
            return
        key = (src, dst, kind.value)
        if key in self._edge_set:
            return
        self._edge_set.add(key)
        self.edges.append(Edge(src, dst, kind))
        self._out[src].add(dst)
        self._in[dst].add(src)

    # -- traversal ---------------------------------------------------------------------
    def out_neighbors(self, nid: str) -> set[str]:
        return self._out.get(nid, set())

    def in_neighbors(self, nid: str) -> set[str]:
        return self._in.get(nid, set())

    def neighbors(self, nid: str) -> set[str]:
        return self.out_neighbors(nid) | self.in_neighbors(nid)

    def reachable(self, start: str, *, direction: str = "both",
                  max_depth: int = 6,
                  node_filter: Iterable[NodeType] | None = None) -> set[str]:
        """Breadth-first reachability with a depth bound.

        The depth bound matters: without it, traversing through a shared library
        node reaches essentially the whole estate and centrality becomes a constant.
        """
        allowed = set(node_filter) if node_filter else None
        seen: set[str] = {start}
        frontier = deque([(start, 0)])
        out: set[str] = set()
        while frontier:
            nid, depth = frontier.popleft()
            if depth >= max_depth:
                continue
            if direction == "out":
                nxt = self.out_neighbors(nid)
            elif direction == "in":
                nxt = self.in_neighbors(nid)
            else:
                nxt = self.neighbors(nid)
            for n in nxt:
                if n in seen:
                    continue
                seen.add(n)
                node = self.nodes.get(n)
                if node is None:
                    continue
                if allowed is None or node.type in allowed:
                    out.add(n)
                frontier.append((n, depth + 1))
        return out

    # -- serialization -----------------------------------------------------------------
    def to_dict(self, node_ids: set[str] | None = None) -> dict:
        if node_ids is None:
            nodes = list(self.nodes.values())
            edges = self.edges
        else:
            nodes = [n for nid, n in self.nodes.items() if nid in node_ids]
            edges = [e for e in self.edges
                     if e.src in node_ids and e.dst in node_ids]
        return {
            "nodes": [n.to_dict() for n in nodes],
            "edges": [e.to_dict() for e in edges],
            "counts": {"nodes": len(nodes), "edges": len(edges)},
        }

    def stats(self) -> dict:
        by_type: dict[str, int] = defaultdict(int)
        for n in self.nodes.values():
            by_type[n.type.value] += 1
        by_edge: dict[str, int] = defaultdict(int)
        for e in self.edges:
            by_edge[e.type.value] += 1
        return {"nodes": len(self.nodes), "edges": len(self.edges),
                "nodes_by_type": dict(sorted(by_type.items())),
                "edges_by_type": dict(sorted(by_edge.items()))}


# ======================================================================================
# Build
# ======================================================================================
def build(assets: list[CryptoAsset], applications: list[Application]) -> CryptoGraph:
    g = CryptoGraph()
    app_by_id = {a.app_id: a for a in applications}

    # ---- business layer ---------------------------------------------------------------
    for app in applications:
        app_nid = g.add_node(
            NodeType.APPLICATION, app.app_id, app.name,
            owner=app.owner, business_unit=app.business_unit,
            environment=app.environment, criticality=app.criticality.value,
            exposure=app.exposure.value,
            data_classification=app.data_classification.value,
            data_lifetime_years=app.data_lifetime_years,
            context_source=app.context_source)

        if app.owner and app.owner != "unassigned":
            owner_nid = g.add_node(NodeType.OWNER, app.owner, app.owner,
                                   business_unit=app.business_unit)
            g.add_edge(owner_nid, app_nid, EdgeType.ACCOUNTABLE_FOR)

        data_nid = g.add_node(
            NodeType.DATA, app.app_id,
            f"{app.data_classification.value} / {app.data_lifetime_years}y",
            classification=app.data_classification.value,
            lifetime_years=app.data_lifetime_years,
            context_source=app.context_source)
        g.add_edge(app_nid, data_nid, EdgeType.PROTECTS)

        if app.business_function:
            bf_nid = g.add_node(NodeType.BUSINESS_FUNCTION, app.app_id,
                                app.business_function)
            g.add_edge(app_nid, bf_nid, EdgeType.SERVES)

        for svc in app.services:
            svc_nid = g.add_node(NodeType.SERVICE, svc, svc, application=app.app_id)
            g.add_edge(app_nid, svc_nid, EdgeType.RUNS)
        for repo in app.repositories:
            repo_nid = g.add_node(NodeType.REPOSITORY, repo, repo,
                                  application=app.app_id)
            g.add_edge(app_nid, repo_nid, EdgeType.OWNS)
        for cont in app.containers:
            c_nid = g.add_node(NodeType.CONTAINER, cont, cont, application=app.app_id)
            g.add_edge(app_nid, c_nid, EdgeType.DEPLOYS)

    # ---- asset layer ------------------------------------------------------------------
    for a in assets:
        # The asset node deliberately carries only identity + presentation fields.
        # Everything analytical stays on the canonical CryptoAsset.
        asset_nid = g.add_node(
            NodeType.ASSET, a.asset_id, a.asset_name,
            asset_type=a.asset_type.value,
            role=a.cryptographic_role,
            confidence=a.confidence.value,
            application=a.application)

        if a.application and a.application in app_by_id:
            app_nid = _nid(NodeType.APPLICATION, a.application)
            if a.repository:
                repo_nid = g.add_node(NodeType.REPOSITORY, a.repository, a.repository,
                                      application=a.application)
                g.add_edge(app_nid, repo_nid, EdgeType.OWNS)
            if a.file:
                file_nid = g.add_node(NodeType.FILE, a.file, a.file,
                                      application=a.application,
                                      language=a.language)
                parent = (_nid(NodeType.REPOSITORY, a.repository) if a.repository
                          else app_nid)
                g.add_edge(parent, file_nid, EdgeType.CONTAINS)
                g.add_edge(file_nid, asset_nid, EdgeType.DECLARES)
            else:
                g.add_edge(app_nid, asset_nid, EdgeType.DECLARES)
            if a.container:
                c_nid = g.add_node(NodeType.CONTAINER, a.container, a.container,
                                   application=a.application)
                g.add_edge(app_nid, c_nid, EdgeType.DEPLOYS)
                g.add_edge(c_nid, asset_nid, EdgeType.DECLARES)

        # ---- shared cryptographic resources ------------------------------------------
        if a.algorithm:
            alg_nid = g.add_node(NodeType.ALGORITHM, a.algorithm,
                                 a.algorithm_label or a.algorithm,
                                 family=a.algorithm_family, primitive=a.primitive,
                                 quantum_class=a.quantum_class)
            g.add_edge(asset_nid, alg_nid, EdgeType.USES_ALGORITHM)

        if a.library:
            key = f"{a.library}@{a.library_version}" if a.library_version else a.library
            lib_nid = g.add_node(NodeType.LIBRARY, key,
                                 f"{a.library}{' ' + a.library_version if a.library_version else ''}",
                                 library=a.library, version=a.library_version,
                                 pqc_readiness=a.pqc_readiness)
            g.add_edge(asset_nid, lib_nid, EdgeType.PROVIDED_BY)

        if a.protocol:
            key = f"{a.protocol}/{a.protocol_version or 'unspecified'}"
            proto_nid = g.add_node(NodeType.PROTOCOL, key, key,
                                   protocol=a.protocol, version=a.protocol_version)
            g.add_edge(asset_nid, proto_nid, EdgeType.NEGOTIATES)

        if a.certificate_serial:
            cert_nid = g.add_node(
                NodeType.CERTIFICATE, a.certificate_serial,
                a.certificate_subject or a.certificate_serial,
                subject=a.certificate_subject, issuer=a.certificate_issuer,
                not_after=a.certificate_expiry, days_to_expiry=a.days_to_expiry,
                self_signed=a.certificate_self_signed)
            g.add_edge(asset_nid, cert_nid, EdgeType.BOUND_TO)

    # ---- certificate chain edges -------------------------------------------------------
    # Subject -> issuer, matched on distinguished names discovered by the X.509 parser.
    subject_to_cert: dict[str, str] = {}
    for a in assets:
        if a.certificate_serial and a.certificate_subject:
            subject_to_cert[a.certificate_subject] = _nid(NodeType.CERTIFICATE,
                                                          a.certificate_serial)
    for a in assets:
        if not (a.certificate_serial and a.certificate_issuer):
            continue
        child = _nid(NodeType.CERTIFICATE, a.certificate_serial)
        issuer = subject_to_cert.get(a.certificate_issuer)
        if issuer and issuer != child:
            g.add_edge(child, issuer, EdgeType.ISSUED_BY)

    return g


# ======================================================================================
# Dependency centrality
# ======================================================================================
def compute_centrality(graph: CryptoGraph, assets: list[CryptoAsset]) -> None:
    """Write `dependency_centrality`, its normalized score, and `affected_assets`.

    Centrality counts the distinct applications AND services coupled to this asset
    through a shared *unit of change* -- a library build, a certificate, or a
    protocol configuration. Rationale: replacing an asset in isolation is cheap; the
    cost and the blast radius come from everything else that changes with it. One
    OpenSSL upgrade is one action that unblocks many services, and this number is
    what makes that visible in the roadmap.

    Shared *algorithms* are counted separately as `algorithm_siblings`: knowing 39
    call sites use SHA-256 is useful scope, but it is not coupling, because there is
    no single action that changes them all.

    An asset's own application and services always count, so centrality is never
    zero for a mapped asset.
    """
    # resource node -> asset_ids using it (change-units only)
    resource_assets: dict[str, set[str]] = defaultdict(set)
    algorithm_assets: dict[str, set[str]] = defaultdict(set)
    for a in assets:
        anid = _nid(NodeType.ASSET, a.asset_id)
        for rnid in graph.out_neighbors(anid):
            node = graph.nodes.get(rnid)
            if not node:
                continue
            if node.type in CENTRALITY_RESOURCE_TYPES:
                resource_assets[rnid].add(a.asset_id)
            elif node.type is NodeType.ALGORITHM:
                algorithm_assets[rnid].add(a.asset_id)

    asset_by_id = {a.asset_id: a for a in assets}

    def dependents_of_asset(asset_id: str) -> set[str]:
        """Application + service nodes that own the asset using this resource.

        Services attach to their application, not to the asset, so they are
        collected by walking down from each owning application rather than by
        traversing further outward from the resource.
        """
        a = asset_by_id.get(asset_id)
        if a is None or not a.application:
            return set()
        app_nid = _nid(NodeType.APPLICATION, a.application)
        out = {app_nid}
        for svc in graph.out_neighbors(app_nid):
            n = graph.nodes.get(svc)
            if n and n.type is NodeType.SERVICE:
                out.add(svc)
        return out

    resource_dependents: dict[str, set[str]] = {
        rnid: set().union(*(dependents_of_asset(aid) for aid in aids)) if aids else set()
        for rnid, aids in resource_assets.items()
    }

    raw: dict[str, int] = {}
    for a in assets:
        anid = _nid(NodeType.ASSET, a.asset_id)
        dependents: set[str] = set()
        siblings: set[str] = set()
        alg_siblings: set[str] = set()
        resources: list[str] = []

        for rnid in graph.out_neighbors(anid):
            node = graph.nodes.get(rnid)
            if not node:
                continue
            if node.type in CENTRALITY_RESOURCE_TYPES:
                resources.append(rnid)
                dependents |= resource_dependents.get(rnid, set())
                siblings |= resource_assets.get(rnid, set())
            elif node.type is NodeType.ALGORITHM:
                alg_siblings |= algorithm_assets.get(rnid, set())

        dependents |= dependents_of_asset(a.asset_id)
        siblings.discard(a.asset_id)
        alg_siblings.discard(a.asset_id)

        apps = sorted({graph.nodes[d].id.split(":", 1)[1] for d in dependents
                       if graph.nodes[d].type is NodeType.APPLICATION})
        services = sorted({graph.nodes[d].label for d in dependents
                           if graph.nodes[d].type is NodeType.SERVICE})
        units = sorted({asset_by_id[s].business_unit for s in siblings
                        if s in asset_by_id and asset_by_id[s].business_unit}
                       | ({a.business_unit} if a.business_unit else set()))
        units = [u for u in units if u and u != "unassigned"]

        raw[a.asset_id] = len(dependents)
        a.dependency_centrality = len(dependents)
        a.affected_assets = sorted(siblings)
        a.affected_summary = {
            "applications": apps,
            "services": services,
            "business_units": units,
            "shared_resources": [graph.nodes[r].label for r in resources],
            "sibling_assets": len(siblings),
            "algorithm_siblings": len(alg_siblings),
            "explanation": (
                f"{len(apps)} application(s) and {len(services)} service(s) are coupled "
                f"to this asset through {len(resources)} shared unit(s) of change "
                f"({', '.join(graph.nodes[r].label for r in resources) or 'none'}); "
                f"{len(siblings)} other asset(s) change with it. "
                f"A further {len(alg_siblings)} asset(s) use the same algorithm but "
                f"are not coupled to this change."),
        }

    # Normalize to 0-100 across the estate so the score is comparable between assets.
    peak = max(raw.values()) if raw else 0
    for a in assets:
        a.dependency_centrality_score = (
            round(100.0 * raw[a.asset_id] / peak, 1) if peak else 0.0)


def subgraph_for_asset(graph: CryptoGraph, asset_id: str, depth: int = 3) -> dict:
    """The neighbourhood the UI renders when an asset is selected."""
    start = _nid(NodeType.ASSET, asset_id)
    if start not in graph.nodes:
        return {"nodes": [], "edges": [], "counts": {"nodes": 0, "edges": 0}}
    ids = graph.reachable(start, direction="both", max_depth=depth) | {start}
    data = graph.to_dict(ids)
    data["focus"] = start
    return data


def node_id(kind: NodeType, key: str) -> str:
    """Public helper so callers do not hand-build node ids."""
    return _nid(kind, key)
