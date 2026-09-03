"""Phase 8 invariants: migration impact is GRAPH-DERIVED, never hand-maintained.

The contract for this stage (§16/§17) is short and strict: impact must be produced by
traversing the cryptographic asset graph, it must not restate a cryptographic fact, and
it must not mint a second per-asset effort value. These tests defend exactly those
properties, plus the two-way consistency the roadmap depends on (`unblocks` is the
inverse of `prerequisites`) and the effort aggregation rule (coordinate by max, sequence
prerequisites serially).

The load-bearing test is `test_coupling_equals_centrality_affected_assets`: impact's
`dependent_assets` is computed by an independent traversal, yet it must land on exactly
the same set as `graph.compute_centrality`, because both read the same edges. If someone
ever replaces the traversal with a hand-maintained list, that set will drift and this
fails.
"""

from __future__ import annotations

import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from ecdat import graph as G
from ecdat.analyze import impact as IM
from ecdat.engine import Engine, demo_request
from ecdat.graph import EdgeType, NodeType, node_id
from ecdat.models import AssetType, MigrationDecision, MigrationEffort

_C: dict[str, object] = {}


def pipeline():
    """Full pipeline through Phase 8, run once."""
    if "e" not in _C:
        e = Engine()
        r = e.run(demo_request())
        _C["e"], _C["r"] = e, r
        _C["by"] = {a.asset_id: a for a in r.assets}
        _C["summary"] = e.impact()
    return _C["e"], _C["r"]


# ======================================================================================
class TestImpactPopulated(unittest.TestCase):

    def test_every_asset_has_an_impact(self):
        e, r = pipeline()
        self.assertEqual(len(e.impacts), len(r.assets))
        for a in r.assets:
            self.assertIn(a.asset_id, e.impacts, a.asset_name)

    def test_impact_never_restates_the_decision_it_only_copies_it(self):
        """Impact carries the decision for display, but must equal the canonical one --
        it must never re-derive or contradict it."""
        e, r = pipeline()
        by = _C["by"]
        for imp in e.impacts.values():
            a = by[imp.asset_id]
            canonical = a.migration_decision.value if a.migration_decision else None
            self.assertEqual(imp.decision, canonical, a.asset_name)

    def test_impact_carries_no_cryptographic_fact(self):
        """The impact record must not contain an algorithm, risk band or quantum verdict
        of its own -- those live on the canonical asset. Reach only."""
        e, _ = pipeline()
        forbidden = {"algorithm", "quantum_class", "classical_risk", "quantum_exposure",
                     "risk_band", "primitive", "key_size"}
        for imp in e.impacts.values():
            keys = set(imp.to_dict().keys())
            self.assertEqual(keys & forbidden, set(),
                             f"impact leaked a crypto fact: {keys & forbidden}")


class TestGraphDerived(unittest.TestCase):
    """The defining property of the phase: everything is a traversal result."""

    def test_coupling_equals_centrality_affected_assets(self):
        """`dependent_assets` (impact) and `affected_assets` (centrality) read the same
        edges, so they must agree asset-for-asset. Drift = someone stopped traversing."""
        e, r = pipeline()
        by = _C["by"]
        for imp in e.impacts.values():
            self.assertEqual(
                sorted(imp.dependent_assets),
                sorted(by[imp.asset_id].affected_assets),
                f"{imp.asset_name}: coupling drifted from graph centrality")

    def test_reach_is_recomputable_from_the_graph(self):
        """Re-run the traversal against the same graph; identical result. A stored list
        would not reproduce under a fresh traverser."""
        e, r = pipeline()
        fresh = IM.build(e.graph, r.assets)
        for aid, imp in e.impacts.items():
            self.assertEqual(imp.applications, fresh[aid].applications, aid)
            self.assertEqual(imp.services, fresh[aid].services, aid)
            self.assertEqual(imp.dependent_assets, fresh[aid].dependent_assets, aid)

    def test_removing_a_shared_resource_edge_collapses_coupling(self):
        """Rebuild the graph without the LIBRARY layer; assets that were coupled only
        through a shared library must lose that coupling. Proves the edge is the source,
        not a hand-kept table."""
        e, r = pipeline()
        # Find an asset coupled through a library.
        by = _C["by"]
        lib_coupled = None
        for imp in e.impacts.values():
            if imp.libraries and imp.dependent_assets:
                lib_coupled = imp
                break
        self.assertIsNotNone(lib_coupled, "no library-coupled asset in demo estate")

        stripped = G.build(r.assets, r.applications)
        # Drop every PROVIDED_BY edge and its library nodes.
        stripped.edges = [ed for ed in stripped.edges
                          if ed.type is not EdgeType.PROVIDED_BY]
        stripped._out.clear(); stripped._in.clear(); stripped._edge_set.clear()
        for ed in stripped.edges:
            stripped._out[ed.src].add(ed.dst)
            stripped._in[ed.dst].add(ed.src)
            stripped._edge_set.add((ed.src, ed.dst, ed.type.value))
        stripped.nodes = {nid: n for nid, n in stripped.nodes.items()
                          if n.type is not NodeType.LIBRARY}

        without = IM.build(stripped, r.assets)
        self.assertLess(
            len(without[lib_coupled.asset_id].libraries),
            len(lib_coupled.libraries),
            "library resource survived edge removal -- impact is not reading the graph")

    def test_change_units_are_the_shared_resource_labels(self):
        """A change unit is exactly a LIBRARY / PROTOCOL / CERTIFICATE the asset is
        attached to -- nothing invented."""
        e, _ = pipeline()
        for imp in e.impacts.values():
            self.assertEqual(
                sorted(imp.change_units),
                sorted(imp.libraries + imp.protocols + imp.certificates),
                imp.asset_name)


class TestCouplingVsScope(unittest.TestCase):
    """Coupling (change together) and scope (same primitive) must stay separate."""

    def test_dependent_assets_and_algorithm_siblings_are_disjoint_in_meaning(self):
        e, _ = pipeline()
        # An algorithm sibling is only *also* a dependent if it happens to share a
        # library/protocol/cert too. The two lists are computed from different edges.
        any_with_both = [i for i in e.impacts.values()
                         if i.dependent_assets and i.algorithm_siblings]
        self.assertTrue(any_with_both,
                        "expected some assets to have both coupling and scope")

    def test_algorithm_is_never_a_coupling_edge(self):
        """ALGORITHM is deliberately excluded from coupling (it is scope). If two assets
        share only an algorithm, they must not appear in each other's dependent_assets."""
        e, r = pipeline()
        by = _C["by"]
        for imp in e.impacts.values():
            a = by[imp.asset_id]
            for dep_id in imp.dependent_assets:
                dep = by[dep_id]
                # A coupled pair must share at least one non-algorithm unit of change.
                keys_a = {a.library, a.protocol, a.certificate_serial} - {None, ""}
                keys_d = {dep.library, dep.protocol, dep.certificate_serial} - {None, ""}
                self.assertTrue(
                    keys_a & keys_d,
                    f"{a.asset_name} coupled to {dep.asset_name} with no shared unit")


class TestPrerequisites(unittest.TestCase):
    """Sequencing is read off the graph: providers, ISSUED_BY chains, protocol floors."""

    def test_provider_upgrade_gates_its_consumers(self):
        e, _ = pipeline()
        prov = [i for i in e.impacts.values()
                if any(p.kind == "provider" for p in i.prerequisites)]
        self.assertTrue(prov, "expected provider-gated assets in the demo estate")
        for imp in prov:
            for p in imp.prerequisites:
                if p.kind == "provider":
                    self.assertIn("supplies", p.reason)

    def test_pki_chain_orders_issuer_before_leaf(self):
        """A leaf certificate must list its issuing CA as a prerequisite, following the
        ISSUED_BY edge -- never the reverse."""
        e, r = pipeline()
        by = _C["by"]
        # The demo estate has an issuing CA that signs leaf certs.
        pki = [i for i in e.impacts.values()
               if any(p.kind == "pki" for p in i.prerequisites)]
        self.assertTrue(pki, "expected a PKI chain in the demo estate")
        for imp in pki:
            for p in imp.prerequisites:
                if p.kind == "pki":
                    self.assertIn("issued by", p.reason)

    def test_unblocks_is_the_exact_inverse_of_prerequisites(self):
        """If A lists B as a prerequisite, B must list A in unblocks, and vice versa.
        The roadmap sequences on this, so the two directions cannot disagree."""
        e, _ = pipeline()
        forward = set()
        for imp in e.impacts.values():
            for p in imp.prerequisites:
                forward.add((p.asset_id, imp.asset_id))   # (upstream, downstream)
        inverse = set()
        for imp in e.impacts.values():
            for down in imp.unblocks:
                inverse.add((imp.asset_id, down))
        self.assertEqual(forward, inverse,
                         "prerequisites and unblocks disagree on an edge")

    def test_gating_asset_unblocks_many(self):
        """The estate's provider library should unblock a large fan of consumers -- the
        'one action clears N' signal the roadmap needs."""
        e, _ = pipeline()
        top = max(e.impacts.values(), key=lambda i: len(i.unblocks))
        self.assertGreater(len(top.unblocks), 5, top.asset_name)


class TestEffortAggregation(unittest.TestCase):

    def test_per_asset_effort_is_read_not_recomputed(self):
        """own_effort_months must equal the canonical asset's value exactly -- impact
        does not run a second effort model."""
        e, _ = pipeline()
        by = _C["by"]
        for imp in e.impacts.values():
            a = by[imp.asset_id]
            expected = a.migration_months or (
                a.migration_effort or MigrationEffort.MODERATE).months
            self.assertEqual(imp.own_effort_months, expected, a.asset_name)

    def test_coordinated_effort_is_max_not_sum(self):
        """Coupled assets move as one item, so coordinated months = max(coupled), plus
        the serial prerequisite chain -- never the sum of coupled durations."""
        e, _ = pipeline()
        by = _C["by"]
        for imp in e.impacts.values():
            if not imp.dependent_assets:
                continue
            coupled_months = [imp.own_effort_months] + [
                (by[c].migration_months
                 or (by[c].migration_effort or MigrationEffort.MODERATE).months)
                for c in imp.dependent_assets]
            self.assertEqual(
                imp.coordinated_effort_months,
                max(coupled_months) + imp.prerequisite_months,
                imp.asset_name)
            self.assertLessEqual(
                imp.coordinated_effort_months - imp.prerequisite_months,
                sum(coupled_months),
                "coordinated effort should never exceed the naive sum")

    def test_effort_rule_is_labelled_derived(self):
        e, _ = pipeline()
        for imp in list(e.impacts.values())[:5]:
            self.assertIn("DERIVED", imp.effort_rule)


class TestCriticalPath(unittest.TestCase):

    def test_critical_path_ends_at_the_asset(self):
        e, _ = pipeline()
        for imp in e.impacts.values():
            if imp.prerequisites:
                path = IM.critical_path(e.impacts, imp.asset_id)
                self.assertEqual(path[-1], imp.asset_id, imp.asset_name)
                self.assertGreaterEqual(len(path), 2)

    def test_critical_path_is_cycle_safe(self):
        """A fabricated mutual-prerequisite cycle must terminate, not hang."""
        a = IM.MigrationImpact(asset_id="A", asset_name="A")
        b = IM.MigrationImpact(asset_id="B", asset_name="B")
        a.prerequisites = [IM.Prerequisite("B", "B", "provider", "x")]
        b.prerequisites = [IM.Prerequisite("A", "A", "provider", "x")]
        path = IM.critical_path({"A": a, "B": b}, "A")
        self.assertIn("A", path)
        self.assertLessEqual(len(path), IM._MAX_CHAIN_DEPTH + 2)


class TestSummaryIntegrity(unittest.TestCase):

    def test_summary_counts_match(self):
        e, _ = pipeline()
        s = _C["summary"]
        self.assertEqual(s["assets"], len(e.impacts))

    def test_gating_assets_are_sorted_by_reach(self):
        _, _ = pipeline()
        s = _C["summary"]
        unblocks = [g["unblocks"] for g in s["gating_assets"]]
        self.assertEqual(unblocks, sorted(unblocks, reverse=True))

    def test_change_units_aggregate_every_attached_asset(self):
        e, _ = pipeline()
        s = _C["summary"]
        # Each reported change unit's asset count must match how many impacts name it.
        for unit in s["change_units"]:
            actual = sum(1 for i in e.impacts.values()
                         if unit["unit"] in i.change_units)
            self.assertEqual(unit["assets"], actual, unit["unit"])

    def test_summary_states_it_is_graph_derived(self):
        _, _ = pipeline()
        s = _C["summary"]
        joined = " ".join(s["notes"]).lower()
        self.assertIn("graph traversal", joined)
        self.assertIn("no impact list is stored", joined)


class TestDeterminism(unittest.TestCase):

    def test_two_runs_produce_identical_impact(self):
        e, r = pipeline()
        again = IM.build(e.graph, r.assets)
        for aid in e.impacts:
            self.assertEqual(e.impacts[aid].to_dict(), again[aid].to_dict(), aid)

    def test_no_fabricated_reach(self):
        """Every named application/owner must exist as a node in the graph -- impact may
        not invent an estate unit that isn't there."""
        e, _ = pipeline()
        app_keys = {nid.split(":", 1)[1] for nid, n in e.graph.nodes.items()
                    if n.type is NodeType.APPLICATION}
        for imp in e.impacts.values():
            for app in imp.applications:
                self.assertIn(app, app_keys, f"fabricated application {app}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
