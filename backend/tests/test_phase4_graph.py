"""Phase 4 invariants: crypto asset graph, centrality, impact traversal."""

from __future__ import annotations

import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from ecdat import graph as G
from ecdat.engine import Engine, demo_request

_C: dict[str, object] = {}


def built():
    if "g" not in _C:
        r = Engine().discover(demo_request())
        g = G.build(r.assets, r.applications)
        G.compute_centrality(g, r.assets)
        _C["r"], _C["g"] = r, g
    return _C["r"], _C["g"]


class TestGraphStructure(unittest.TestCase):

    def test_graph_builds_with_all_layers(self):
        _, g = built()
        types = {n.type for n in g.nodes.values()}
        for required in (G.NodeType.APPLICATION, G.NodeType.SERVICE, G.NodeType.DATA,
                         G.NodeType.REPOSITORY, G.NodeType.FILE, G.NodeType.ASSET,
                         G.NodeType.ALGORITHM, G.NodeType.LIBRARY,
                         G.NodeType.PROTOCOL, G.NodeType.CERTIFICATE,
                         G.NodeType.OWNER, G.NodeType.BUSINESS_FUNCTION):
            self.assertIn(required, types, f"{required.value} layer missing")

    def test_every_asset_has_a_node(self):
        r, g = built()
        for a in r.assets:
            self.assertIn(G.node_id(G.NodeType.ASSET, a.asset_id), g.nodes)

    def test_asset_nodes_do_not_duplicate_cryptographic_facts(self):
        """Contract §3: the graph references the canonical asset, never copies it."""
        _, g = built()
        forbidden = {"key_size", "security_strength", "risk_score", "quantum_exposure",
                     "migration_decision", "data_lifetime_years", "evidence",
                     "recommended_strategy", "classical_risk"}
        for n in g.nodes.values():
            if n.type is not G.NodeType.ASSET:
                continue
            leaked = forbidden & set(n.attrs)
            self.assertEqual(leaked, set(),
                             f"asset node {n.id} duplicates canonical fields: {leaked}")

    def test_no_dangling_edges(self):
        _, g = built()
        for e in g.edges:
            self.assertIn(e.src, g.nodes)
            self.assertIn(e.dst, g.nodes)

    def test_no_self_loops(self):
        _, g = built()
        self.assertFalse([e for e in g.edges if e.src == e.dst])

    def test_certificate_chain_edges_resolve(self):
        r, g = built()
        chain = [e for e in g.edges if e.type is G.EdgeType.ISSUED_BY]
        self.assertTrue(chain, "no certificate chain edges built")
        # a leaf must reach a self-signed root by following issued-by
        roots = {n.id for n in g.nodes.values()
                 if n.type is G.NodeType.CERTIFICATE and n.attrs.get("self_signed")}
        self.assertTrue(roots, "no self-signed root certificate in the graph")
        leaf = next(e.src for e in chain)
        reached = g.reachable(leaf, direction="out", max_depth=4,
                              node_filter=(G.NodeType.CERTIFICATE,))
        self.assertTrue(reached & roots, "leaf certificate does not chain to a root")

    def test_traversal_depth_is_bounded(self):
        _, g = built()
        start = next(n.id for n in g.nodes.values() if n.type is G.NodeType.ASSET)
        shallow = g.reachable(start, max_depth=1)
        deep = g.reachable(start, max_depth=5)
        self.assertLessEqual(len(shallow), len(deep))


class TestCentrality(unittest.TestCase):

    def test_every_mapped_asset_has_nonzero_centrality(self):
        r, _ = built()
        for a in r.assets:
            if a.application:
                self.assertGreater(a.dependency_centrality, 0, a.asset_id)

    def test_centrality_discriminates(self):
        """A metric where every asset scores the same is worthless."""
        r, _ = built()
        values = {a.dependency_centrality for a in r.assets}
        self.assertGreaterEqual(len(values), 4,
                                f"centrality has too little spread: {sorted(values)}")

    def test_algorithm_sharing_is_excluded_from_centrality(self):
        """SHA-256 ubiquity must not dominate: it is scope, not coupling."""
        r, _ = built()
        sha = [a for a in r.assets
               if a.algorithm == "sha-256" and not a.library and not a.protocol]
        self.assertTrue(sha, "no library-free SHA-256 asset to test with")
        top = max(a.dependency_centrality for a in r.assets)
        for a in sha:
            self.assertLess(a.dependency_centrality, top,
                            "a bare algorithm asset must not be the most central")
            self.assertGreater(a.affected_summary["algorithm_siblings"], 0,
                               "algorithm scope should still be reported")

    def test_shared_library_outranks_isolated_asset(self):
        r, _ = built()
        shared = [a for a in r.assets if a.library == "openssl"]
        isolated = [a for a in r.assets
                    if not a.library and not a.protocol and not a.certificate_serial]
        self.assertTrue(shared and isolated)
        self.assertGreater(max(a.dependency_centrality for a in shared),
                           min(a.dependency_centrality for a in isolated))

    def test_centrality_score_is_normalized(self):
        r, _ = built()
        scores = [a.dependency_centrality_score for a in r.assets]
        self.assertAlmostEqual(max(scores), 100.0, places=1)
        self.assertTrue(all(0.0 <= s <= 100.0 for s in scores))

    def test_affected_summary_counts_services_not_only_applications(self):
        r, _ = built()
        self.assertTrue(any(a.affected_summary.get("services")
                            for a in r.assets),
                        "services never counted -- traversal direction bug")

    def test_affected_assets_are_real_asset_ids(self):
        r, _ = built()
        ids = {a.asset_id for a in r.assets}
        for a in r.assets:
            self.assertTrue(set(a.affected_assets) <= ids)
            self.assertNotIn(a.asset_id, a.affected_assets, "asset affects itself")

    def test_affected_summary_explains_itself(self):
        r, _ = built()
        for a in r.assets[:20]:
            self.assertIn("coupled to this asset", a.affected_summary["explanation"])


class TestSubgraph(unittest.TestCase):

    def test_subgraph_includes_focus_and_business_context(self):
        r, g = built()
        target = max(r.assets, key=lambda a: a.dependency_centrality)
        sub = G.subgraph_for_asset(g, target.asset_id, depth=3)
        self.assertEqual(sub["focus"], G.node_id(G.NodeType.ASSET, target.asset_id))
        self.assertGreater(sub["counts"]["nodes"], 1)
        types = {n["type"] for n in sub["nodes"]}
        self.assertIn("application", types,
                      "asset subgraph must reach its application for the UI story")

    def test_subgraph_for_unknown_asset_is_empty_not_an_error(self):
        _, g = built()
        sub = G.subgraph_for_asset(g, "ca-doesnotexist")
        self.assertEqual(sub["counts"]["nodes"], 0)

    def test_subgraph_edges_reference_only_included_nodes(self):
        r, g = built()
        target = r.assets[0]
        sub = G.subgraph_for_asset(g, target.asset_id, depth=2)
        ids = {n["id"] for n in sub["nodes"]}
        for e in sub["edges"]:
            self.assertIn(e["source"], ids)
            self.assertIn(e["target"], ids)


if __name__ == "__main__":
    unittest.main(verbosity=2)
