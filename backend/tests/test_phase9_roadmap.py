"""Phase 9 invariants: the roadmap is a projection, and it is executable.

Two families of property are defended here.

**It is a projection, not a second opinion.** Every field on a roadmap item is copied
from canonical state, the sequencing comes from `analyze.impact` (which reads the graph),
and with no graph supplied the module reports its sequencing as UNAVAILABLE rather than
falling back to a hand-written blocker list.

**It is executable.** The load-bearing test is
`test_no_prerequisite_is_scheduled_after_its_dependent`. A plan that puts an issuing CA
in a later phase than the SHA-1 leaf it has to sign is internally impossible, and that
is exactly what the pre-hoist implementation did. `_hoist_prerequisites` pulls a blocker
forward to the earliest implementation phase of anything it blocks; these tests pin that
behaviour, including the cascade up a certificate chain and the deliberate PH1 exemption.

Also pinned: every scheduled asset appears in exactly one phase with a recorded reason,
RETAIN assets are reported as a count rather than as work, and a classically broken
primitive is never queued behind the post-quantum programme.
"""

from __future__ import annotations

import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from ecdat.analyze import impact as IM
from ecdat.analyze import recommend
from ecdat.analyze import roadmap as RM
from ecdat.engine import Engine, demo_request
from ecdat.models import CryptoAgility, MigrationDecision, Role

_C: dict[str, object] = {}

_PHASES = (RM.PH_DISCOVER, RM.PH_CLASSIFY, RM.PH_FIX_NOW, RM.PH_ENABLE,
           RM.PH_PILOT, RM.PH_MIGRATE, RM.PH_RETIRE)


def planned():
    """Full pipeline through Phase 9, run once."""
    if "e" not in _C:
        e = Engine()
        r = e.run(demo_request())
        _C["e"], _C["r"] = e, r
        _C["rm"] = e.roadmap
        _C["by"] = {a.asset_id: a for a in r.assets}
        items = {}
        for p in e.roadmap["phases"]:
            for i in p["items"]:
                items[i["asset_id"]] = i
        _C["items"] = items
    return _C["e"], _C["rm"]


# ======================================================================================
class TestSinglePlacement(unittest.TestCase):

    def test_phase_counts_sum_to_scheduled(self):
        _, rm = planned()
        self.assertEqual(sum(p["asset_count"] for p in rm["phases"]),
                         rm["totals"]["scheduled"])

    def test_no_asset_appears_in_two_phases(self):
        _, rm = planned()
        seen: dict[str, str] = {}
        for p in rm["phases"]:
            for i in p["items"]:
                self.assertNotIn(i["asset_id"], seen,
                                 f"{i['asset_name']} is in both {seen.get(i['asset_id'])} "
                                 f"and {p['id']}")
                seen[i["asset_id"]] = p["id"]

    def test_every_item_records_why_it_is_there(self):
        _, rm = planned()
        for p in rm["phases"]:
            for i in p["items"]:
                self.assertTrue(i["why_this_phase"], f"{i['asset_name']} in {p['id']}")
                self.assertGreater(len(i["why_this_phase"]), 30,
                                   f"{i['asset_name']}: reason is a stub")

    def test_scheduled_plus_retained_equals_in_scope(self):
        _, rm = planned()
        t = rm["totals"]
        self.assertEqual(t["scheduled"] + t["no_action_required"], t["in_scope"])


class TestRetainIsNotWork(unittest.TestCase):
    """Reporting "no change required" is part of the answer, not an omission."""

    def test_no_retain_asset_is_scheduled(self):
        e, rm = planned()
        by = _C["by"]
        for p in rm["phases"]:
            for i in p["items"]:
                self.assertIsNot(by[i["asset_id"]].migration_decision,
                                 MigrationDecision.RETAIN,
                                 f"{i['asset_name']} is RETAIN but was scheduled")

    def test_retain_count_matches_the_canonical_decision(self):
        e, rm = planned()
        expected = sum(1 for a in e.assets()
                       if a.migration_decision is MigrationDecision.RETAIN
                       and a.triage_state.value not in ("false-positive", "dismissed"))
        self.assertEqual(rm["totals"]["no_action_required"], expected)

    def test_retain_is_explained_not_hidden(self):
        _, rm = planned()
        self.assertIn("no cryptographic change", rm["method"]["retain_note"])


class TestExecutableOrdering(unittest.TestCase):
    """A blocker scheduled after the work it blocks makes the plan impossible."""

    def test_no_prerequisite_is_scheduled_after_its_dependent(self):
        _, rm = planned()
        items = _C["items"]
        impl = RM._IMPL_ORDER
        violations = []
        for i in items.values():
            here = impl.get(i["phase"])
            if here is None:
                continue
            for pre_id in i["prerequisites"]:
                pre = items.get(pre_id)
                if pre is None:
                    continue
                there = impl.get(pre["phase"])
                if there is not None and there > here:
                    violations.append(
                        f"{pre['asset_name']} ({pre['phase']}) blocks "
                        f"{i['asset_name']} ({i['phase']})")
        self.assertEqual(violations, [],
                         f"plan is not executable: {violations[:5]}")

    def test_hoisting_actually_happened_and_is_recorded(self):
        """The demo estate contains a CA chain that requires hoisting; if the count is
        zero the mechanism has silently stopped working."""
        _, rm = planned()
        self.assertGreater(rm["method"]["prerequisites_hoisted"], 0)
        hoisted = [i for i in _C["items"].values()
                   if i["why_this_phase"].startswith("hoisted")]
        self.assertTrue(hoisted, "hoist count is non-zero but no item records it")

    def test_hoist_preserves_the_original_reason(self):
        """Honesty: the item must still say where it would otherwise have gone."""
        _, rm = planned()
        for i in _C["items"].values():
            if i["why_this_phase"].startswith("hoisted"):
                self.assertIn("Original placement --", i["why_this_phase"])

    def test_hoist_cascades_up_a_chain(self):
        """root CA -> intermediate CA -> leaf must all end up no later than the leaf."""
        a = RM.RoadmapItem(
            asset_id="leaf", asset_name="leaf", application=None, location="l",
            priority=90, band="P0", urgency="critical", decision="UPGRADE",
            strategy=recommend.ACTION_RENEW_CERT, target=None, effort="low", months=6,
            coordinated_months=6, agility="medium", centrality=0, blast_radius=1,
            phase=RM.PH_FIX_NOW, why_this_phase="broken today",
            prerequisites=["mid"])
        b = RM.RoadmapItem(
            asset_id="mid", asset_name="mid", application=None, location="m",
            priority=50, band="P1", urgency="urgent", decision="UPGRADE",
            strategy=recommend.ACTION_RENEW_CERT, target=None, effort="low", months=6,
            coordinated_months=6, agility="medium", centrality=0, blast_radius=1,
            phase=RM.PH_MIGRATE, why_this_phase="gates others",
            prerequisites=["root"])
        c = RM.RoadmapItem(
            asset_id="root", asset_name="root", application=None, location="r",
            priority=40, band="P2", urgency="plan-now", decision="UPGRADE",
            strategy=recommend.ACTION_RENEW_CERT, target=None, effort="low", months=6,
            coordinated_months=6, agility="medium", centrality=0, blast_radius=1,
            phase=RM.PH_MIGRATE, why_this_phase="gates others",
            prerequisites=[])
        moved = RM._hoist_prerequisites([a, b, c])
        self.assertEqual(moved, 2)
        self.assertEqual(b.phase, RM.PH_FIX_NOW)
        self.assertEqual(c.phase, RM.PH_FIX_NOW, "hoist did not cascade to the root")

    def test_hoist_terminates_on_a_cycle(self):
        a = RM.RoadmapItem(
            asset_id="a", asset_name="a", application=None, location="a", priority=1,
            band="P0", urgency="u", decision="UPGRADE", strategy="x", target=None,
            effort="low", months=1, coordinated_months=1, agility="medium",
            centrality=0, blast_radius=0, phase=RM.PH_FIX_NOW, why_this_phase="w",
            prerequisites=["b"])
        b = RM.RoadmapItem(
            asset_id="b", asset_name="b", application=None, location="b", priority=1,
            band="P0", urgency="u", decision="UPGRADE", strategy="x", target=None,
            effort="low", months=1, coordinated_months=1, agility="medium",
            centrality=0, blast_radius=0, phase=RM.PH_MIGRATE, why_this_phase="w",
            prerequisites=["a"])
        RM._hoist_prerequisites([a, b])      # must not spin
        self.assertEqual(b.phase, RM.PH_FIX_NOW)

    def test_classify_dependents_do_not_force_a_hoist(self):
        """Confirming a finding does not require its blocker to be cleared first, so a
        PH1 dependent must leave its prerequisite where it is."""
        dep = RM.RoadmapItem(
            asset_id="d", asset_name="d", application=None, location="d", priority=1,
            band="P1", urgency="u", decision="HARDEN",
            strategy=recommend.ACTION_VERIFY, target=None, effort="low", months=1,
            coordinated_months=1, agility="medium", centrality=0, blast_radius=0,
            phase=RM.PH_CLASSIFY, why_this_phase="needs confirmation",
            prerequisites=["p"])
        pre = RM.RoadmapItem(
            asset_id="p", asset_name="p", application=None, location="p", priority=1,
            band="P2", urgency="u", decision="HYBRID", strategy="x", target="ML-KEM",
            effort="low", months=1, coordinated_months=1, agility="medium",
            centrality=0, blast_radius=0, phase=RM.PH_MIGRATE, why_this_phase="w",
            prerequisites=[])
        self.assertEqual(RM._hoist_prerequisites([dep, pre]), 0)
        self.assertEqual(pre.phase, RM.PH_MIGRATE)

    def test_within_a_phase_unblocking_work_comes_first(self):
        _, rm = planned()
        for p in rm["phases"]:
            keys = [(-i["unblocks"], -i["priority"]) for i in p["items"]]
            self.assertEqual(keys, sorted(keys), f"{p['id']} is not ordered")


class TestClassicalRiskIsNotDeferred(unittest.TestCase):
    """The two risk axes are independent; a broken primitive is not PQC work."""

    def test_classically_broken_never_lands_in_a_pqc_phase(self):
        e, rm = planned()
        by = _C["by"]
        for i in _C["items"].values():
            a = by[i["asset_id"]]
            if a.quantum_class == "classically_broken":
                self.assertIn(i["phase"], (RM.PH_CLASSIFY, RM.PH_FIX_NOW, RM.PH_ENABLE),
                              f"{a.asset_name} is broken today but sits in {i['phase']}")

    def test_upgrade_decisions_are_present_day_work(self):
        e, rm = planned()
        by = _C["by"]
        for i in _C["items"].values():
            if by[i["asset_id"]].migration_decision is MigrationDecision.UPGRADE:
                self.assertIn(i["phase"], (RM.PH_CLASSIFY, RM.PH_FIX_NOW, RM.PH_ENABLE),
                              f"{i['asset_name']}: UPGRADE queued behind PQC work")

    def test_exploitable_today_reads_only_the_classical_axis(self):
        """Quantum exposure must never be the thing that routes work into PH2."""
        src = (pathlib.Path(RM.__file__)).read_text()
        fn = src.split("def _exploitable_today")[1].split("def ")[0]
        self.assertNotIn("quantum_exposure", fn)
        self.assertNotIn("mosca", fn)


class TestGraphDerivedSequencing(unittest.TestCase):

    def test_sequencing_source_names_the_graph(self):
        _, rm = planned()
        self.assertIn("graph", rm["method"]["sequencing_source"])

    def test_without_a_graph_sequencing_is_declared_unavailable(self):
        """It must degrade honestly, never fall back to a hand-written blocker list."""
        e, _ = planned()
        bare = RM.build(e.assets(), e.result.applications)
        self.assertIn("UNAVAILABLE", bare["method"]["sequencing_source"])
        self.assertEqual(bare["enablement_waves"], [])
        for p in bare["phases"]:
            for i in p["items"]:
                self.assertEqual(i["prerequisites"], [])
                self.assertEqual(i["unblocks"], 0)

    def test_no_hand_written_blocker_strings_remain(self):
        """The pre-Phase-9 implementation built blockers with literal prefixes. Those
        must be gone -- blockers now come from decide() and the graph."""
        src = pathlib.Path(RM.__file__).read_text()
        for literal in ('"protocol:TLS 1.3 upgrade"', '"pki:CA must support',
                        '"vendor:binary-only artefact"', 'f"provider:{lib.name'):
            self.assertNotIn(literal, src, f"hand-maintained blocker survives: {literal}")

    def test_waves_come_from_impact(self):
        e, rm = planned()
        for w in rm["enablement_waves"]:
            imp = e.impacts[w["gating_asset"]]
            self.assertEqual(w["dependent_assets"], len(imp.unblocks), w["gating_asset_name"])
            self.assertEqual(w["change_units"], list(imp.change_units))

    def test_waves_are_ordered_by_reach(self):
        _, rm = planned()
        counts = [w["dependent_assets"] for w in rm["enablement_waves"]]
        self.assertEqual(counts, sorted(counts, reverse=True))

    def test_blockers_are_decision_or_graph_derived(self):
        """Every blocker string must be traceable to decide() or an impact prerequisite."""
        e, rm = planned()
        by = _C["by"]
        for i in _C["items"].values():
            imp = e.impacts.get(i["asset_id"])
            allowed = set(by[i["asset_id"]].migration_blockers)
            if imp:
                allowed |= {f"{p.kind}:{p.asset_name}" for p in imp.prerequisites}
            self.assertEqual(set(i["blockers"]) - allowed, set(),
                             f"{i['asset_name']} has an untraceable blocker")


class TestConsumesTheCanonicalFields(unittest.TestCase):
    """Phase 9's stated purpose: consume the fields the earlier phases populate."""

    def test_items_carry_decision_agility_centrality_and_coordinated_effort(self):
        e, rm = planned()
        by = _C["by"]
        for i in _C["items"].values():
            a = by[i["asset_id"]]
            self.assertEqual(i["decision"], a.migration_decision.value)
            self.assertEqual(i["strategy"], a.recommended_strategy)
            self.assertEqual(i["agility"], a.crypto_agility.value)
            self.assertEqual(i["centrality"], a.dependency_centrality or 0)
            self.assertEqual(i["band"], a.priority_band or "P3")
            self.assertEqual(i["urgency"], a.mosca_urgency)

    def test_coordinated_months_comes_from_impact_not_recomputed(self):
        e, rm = planned()
        for i in _C["items"].values():
            imp = e.impacts[i["asset_id"]]
            self.assertEqual(i["coordinated_months"], imp.coordinated_effort_months,
                             i["asset_name"])

    def test_roadmap_invents_no_cryptographic_target(self):
        e, rm = planned()
        by = _C["by"]
        for i in _C["items"].values():
            a = by[i["asset_id"]]
            self.assertEqual(i["target"], a.recommended_hybrid or a.recommended_pqc,
                             f"{i['asset_name']}: roadmap altered the target")

    def test_low_agility_quantum_vulnerable_assets_are_routed_to_enablement(self):
        """Placement must actually read crypto_agility, not just report it."""
        a = _mk_asset(agility=CryptoAgility.LOW, quantum_vulnerable=True,
                      decision=MigrationDecision.PQC_ONLY,
                      strategy=recommend.ACTION_MIGRATE_PQC)
        phase, why = RM._place(a, None)
        self.assertEqual(phase, RM.PH_ENABLE)
        self.assertIn("agility is LOW", why)

    def test_unresolved_role_is_routed_to_classification(self):
        a = _mk_asset(strategy=recommend.ACTION_DETERMINE_ROLE,
                      decision=MigrationDecision.HARDEN, quantum_vulnerable=True,
                      role=Role.UNKNOWN.value)
        phase, why = RM._place(a, None)
        self.assertEqual(phase, RM.PH_CLASSIFY)
        self.assertIn("ML-KEM vs ML-DSA", why)

    def test_module_uses_the_canonical_role_enum(self):
        src = pathlib.Path(RM.__file__).read_text()
        self.assertIn("Role.UNKNOWN.value", src)
        self.assertNotIn('"unknown-role"', src)


class TestBandsAndPhasesAreSeparate(unittest.TestCase):

    def test_band_membership_sums_to_scheduled(self):
        _, rm = planned()
        self.assertEqual(sum(b["assets"] for b in rm["bands"].values()),
                         rm["totals"]["scheduled"])

    def test_a_band_can_span_several_phases(self):
        """If bands and phases were the same thing, one of them would be redundant."""
        _, rm = planned()
        spans = [b for b in rm["bands"].values() if len(b["phases"]) > 1]
        self.assertTrue(spans, "no band spans multiple phases -- the two views collapsed")

    def test_the_distinction_is_documented(self):
        _, rm = planned()
        note = rm["method"]["bands_vs_phases"]
        self.assertIn("urgency", note)
        self.assertIn("execution order", note)

    def test_band_labels_never_collide_with_phase_ids(self):
        _, rm = planned()
        self.assertEqual(set(rm["bands"]) & set(_PHASES), set())


class TestHonesty(unittest.TestCase):

    def test_no_unsupportable_claims(self):
        _, rm = planned()
        import json
        blob = json.dumps(rm).lower()
        for phrase in ("quantum-proof", "quantum proof", "100% accurate", "guaranteed",
                       "fully compliant", "unbreakable", "future-proof"):
            self.assertNotIn(phrase, blob, f"unsupportable claim: {phrase}")

    def test_effort_is_labelled_derived(self):
        _, rm = planned()
        self.assertIn("DERIVED", rm["method"]["effort_note"])

    def test_ir_8547_is_labelled_a_draft(self):
        _, rm = planned()
        retire = [p for p in rm["phases"] if p["id"] == RM.PH_RETIRE][0]
        self.assertIn("Initial Public Draft", retire["objective"])

    def test_deliverables_and_exit_criteria_exist_for_every_phase(self):
        _, rm = planned()
        for p in rm["phases"]:
            self.assertTrue(p["deliverables"], p["id"])
            self.assertTrue(p["exit_criteria"], p["id"])


class TestDeterminism(unittest.TestCase):

    def test_two_builds_are_identical(self):
        e, rm = planned()
        again = RM.build(e.assets(), e.result.applications, graph=e.graph,
                         impacts=e.impacts)
        self.assertEqual(again["totals"], rm["totals"])
        self.assertEqual([p["asset_count"] for p in again["phases"]],
                         [p["asset_count"] for p in rm["phases"]])

    def test_engine_run_populates_the_roadmap(self):
        e, rm = planned()
        self.assertIsNotNone(e.roadmap)
        self.assertEqual(e.progress.stage, "complete")
        stages = [ev["stage"] for ev in e.progress.events]
        self.assertIn("impact", stages)
        self.assertIn("roadmap", stages)
        self.assertLess(stages.index("impact"), stages.index("roadmap"),
                        "roadmap must run after impact -- it consumes its output")


# ======================================================================================
def _mk_asset(*, agility=CryptoAgility.MEDIUM, quantum_vulnerable=False,
              decision=MigrationDecision.HARDEN, strategy=recommend.ACTION_VERIFY,
              role=Role.KEY_ESTABLISHMENT.value):
    from ecdat.models import AssetType, Confidence, CryptoAsset
    a = CryptoAsset(asset_id="t", asset_type=AssetType.SOURCE_FINDING, asset_name="x",
                    confidence=Confidence.HIGH, cryptographic_role=role)
    a.crypto_agility = agility
    a.quantum_vulnerable = quantum_vulnerable
    a.migration_decision = decision
    a.recommended_strategy = strategy
    return a


if __name__ == "__main__":
    unittest.main(verbosity=2)
