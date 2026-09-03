"""Phase 6 invariants: crypto agility, interoperability, Mosca urgency, simulator."""

from __future__ import annotations

import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from ecdat.analyze import agility as AG
from ecdat.analyze import mosca as MO
from ecdat.engine import Engine, demo_request
from ecdat.models import (
    AssetType,
    Confidence,
    CryptoAgility,
    CryptoAsset,
    Criticality,
    DataClassification,
    EvidenceType,
    Exposure,
    Interoperability,
    MigrationEffort,
    Role,
)

_C: dict[str, object] = {}


def pipeline():
    if "e" not in _C:
        e = Engine()
        r = e.discover(demo_request())
        e.build_graph()
        e.assess()
        e.apply_scenario()
        _C["e"], _C["r"] = e, r
    return _C["e"], _C["r"]


def mk(**kw) -> CryptoAsset:
    base = dict(asset_id="t", asset_type=AssetType.SOURCE_FINDING, asset_name="x",
                confidence=Confidence.HIGH)
    base.update(kw)
    a = CryptoAsset(**base)
    AG.apply(a)
    return a


class TestAgilityPopulated(unittest.TestCase):

    def test_every_asset_has_agility_and_interoperability(self):
        _, r = pipeline()
        for a in r.assets:
            self.assertIsInstance(a.crypto_agility, CryptoAgility, a.asset_id)
            self.assertIsInstance(a.interoperability, Interoperability, a.asset_id)
            self.assertTrue(a.crypto_agility_signals, a.asset_id)
            self.assertTrue(a.interoperability_reason, a.asset_id)

    def test_agility_discriminates(self):
        _, r = pipeline()
        self.assertGreaterEqual(
            len({a.crypto_agility.value for a in r.assets}), 3,
            "agility must produce more than one verdict across a mixed estate")

    def test_signals_are_directional_not_verdicts(self):
        """A signal says which way it pushes; only the last line states the verdict."""
        _, r = pipeline()
        for a in r.assets[:40]:
            for sig in a.crypto_agility_signals[:-1]:
                self.assertFalse(sig.startswith(("LOW:", "HIGH:", "MEDIUM:")),
                                 f"signal reads as a verdict: {sig[:60]}")
            self.assertIn("Computed agility =", a.crypto_agility_signals[-1])

    def test_verdict_is_reconstructible_from_the_signal_total(self):
        _, r = pipeline()
        for a in r.assets[:40]:
            final = a.crypto_agility_signals[-1]
            total = float(final.split("total ")[1].split(";")[0])
            expected = (CryptoAgility.HIGH if total <= -1.5
                        else CryptoAgility.MEDIUM if total <= 1.5
                        else CryptoAgility.LOW)
            self.assertEqual(a.crypto_agility, expected, a.asset_id)


class TestAgilityDerivation(unittest.TestCase):

    def test_tls13_config_is_high_agility(self):
        a = mk(asset_type=AssetType.PROTOCOL_CONFIG, protocol="TLS",
               protocol_version="1.3", language="config")
        self.assertEqual(a.crypto_agility, CryptoAgility.HIGH)

    def test_binary_without_pqc_path_is_low_agility(self):
        a = mk(asset_type=AssetType.BINARY_ARTIFACT, language="c",
               pqc_readiness="none")
        self.assertEqual(a.crypto_agility, CryptoAgility.LOW)

    def test_pqc_native_provider_offsets_binary_penalty(self):
        """Explainability check: two binaries differ only by provider capability."""
        no_pqc = mk(asset_type=AssetType.BINARY_ARTIFACT, pqc_readiness="none")
        native = mk(asset_type=AssetType.BINARY_ARTIFACT, pqc_readiness="native")
        self.assertGreater(no_pqc.crypto_agility.score, native.crypto_agility.score)

    def test_agility_blocker_tag_reduces_agility(self):
        plain = mk(asset_type=AssetType.CONTAINER_PACKAGE)
        blocked = mk(asset_type=AssetType.CONTAINER_PACKAGE,
                     tags=["crypto-agility-blocker"])
        self.assertGreaterEqual(blocked.crypto_agility.score, plain.crypto_agility.score)

    def test_hardcoded_literal_reduces_agility(self):
        soft = mk(evidence_type=EvidenceType.SOURCE_LEXICAL)
        hard = mk(evidence_type=EvidenceType.SOURCE_API)
        self.assertGreaterEqual(hard.crypto_agility.score, soft.crypto_agility.score)

    def test_operator_override_is_respected(self):
        a = CryptoAsset(asset_id="t", asset_type=AssetType.BINARY_ARTIFACT,
                        asset_name="x", pqc_readiness="none")
        a.set_override("crypto_agility", CryptoAgility.HIGH, actor="architect",
                       reason="vendor confirmed configurable")
        AG.apply(a)
        self.assertEqual(a.crypto_agility, CryptoAgility.HIGH,
                         "an explicit operator override must not be recomputed away")


class TestInteroperability(unittest.TestCase):
    """This field is what separates HYBRID from PQC-ONLY in Phase 7."""

    def test_certificate_is_constrained_by_ca_and_relying_parties(self):
        a = mk(asset_type=AssetType.CERTIFICATE)
        self.assertEqual(a.interoperability, Interoperability.CONSTRAINED)
        self.assertIn("issuing CA", a.interoperability_reason)

    def test_binary_only_is_constrained(self):
        a = mk(asset_type=AssetType.BINARY_ARTIFACT)
        self.assertEqual(a.interoperability, Interoperability.CONSTRAINED)

    def test_internet_facing_tls_is_negotiated(self):
        a = mk(protocol="TLS", protocol_version="1.3", internet_exposed=True)
        self.assertEqual(a.interoperability, Interoperability.NEGOTIATED)
        self.assertIn("PQ/T hybrid", a.interoperability_reason)

    def test_internal_non_protocol_asset_is_open(self):
        a = mk(algorithm="rsa", cryptographic_role=Role.KEY_TRANSPORT.value,
               internet_exposed=False)
        self.assertEqual(a.interoperability, Interoperability.OPEN)
        self.assertIn("standalone post-quantum mechanism", a.interoperability_reason)

    def test_verifier_rollout_order_is_explained(self):
        a = mk(cryptographic_role=Role.SIGNATURE_VERIFICATION.value)
        self.assertEqual(a.interoperability, Interoperability.NEGOTIATED)
        self.assertIn("BEFORE any signer", a.interoperability_reason)

    def test_requires_hybrid_property_matches_verdict(self):
        self.assertTrue(Interoperability.NEGOTIATED.requires_hybrid)
        self.assertTrue(Interoperability.CONSTRAINED.requires_hybrid)
        self.assertFalse(Interoperability.OPEN.requires_hybrid)


class TestMosca(unittest.TestCase):

    def test_urgency_set_on_every_asset(self):
        _, r = pipeline()
        for a in r.assets:
            self.assertIsNotNone(a.mosca_urgency, a.asset_id)
            self.assertIn("inequality", a.mosca_detail)

    def test_not_applicable_for_non_quantum_vulnerable(self):
        _, r = pipeline()
        for a in r.assets:
            if not a.quantum_vulnerable:
                self.assertEqual(a.mosca_urgency, MO.NOT_APPLICABLE, a.asset_name)

    def test_md5_is_never_given_a_quantum_deadline(self):
        _, r = pipeline()
        for a in r.assets:
            if a.algorithm == "md5":
                self.assertEqual(a.mosca_urgency, MO.NOT_APPLICABLE)
                self.assertIn("not the applicable instrument", a.mosca_detail["explanation"])

    def test_breach_is_arithmetically_correct(self):
        a = CryptoAsset(asset_id="t", asset_type=AssetType.SOURCE_FINDING,
                        asset_name="RSA", algorithm="rsa", key_size=2048,
                        quantum_vulnerable=True,
                        cryptographic_role=Role.KEY_ESTABLISHMENT.value,
                        data_lifetime_years=20,
                        migration_effort=MigrationEffort.HIGH, migration_months=24)
        res = MO.evaluate(a, MO.Scenario(crqc_year=2035))
        self.assertTrue(res.applicable)
        self.assertAlmostEqual(res.x_data_lifetime, 20.0, places=1)
        self.assertAlmostEqual(res.y_migration_years, 2.0, places=1)
        self.assertGreater(res.gap, 0, "20y + 2y + 1y margin must breach a 2035 horizon")
        self.assertIn(res.urgency, (MO.ALREADY_LATE, MO.CRITICAL))

    def test_short_lifetime_does_not_breach(self):
        a = CryptoAsset(asset_id="t", asset_type=AssetType.SOURCE_FINDING,
                        asset_name="RSA", algorithm="rsa", quantum_vulnerable=True,
                        cryptographic_role=Role.KEY_ESTABLISHMENT.value,
                        data_lifetime_years=1,
                        migration_effort=MigrationEffort.LOW, migration_months=6)
        res = MO.evaluate(a, MO.Scenario(crqc_year=2045))
        self.assertLessEqual(res.gap, 0)
        self.assertIn(res.urgency, (MO.MONITOR, MO.PLAN_NOW, MO.URGENT))

    def test_no_crqc_prediction_is_asserted(self):
        sc = MO.Scenario(crqc_year=2035)
        rationale = sc.to_dict()["crqc_rationale"]
        self.assertIn("policy deadline", rationale)
        self.assertNotIn("will arrive", rationale.lower())

    def test_classically_broken_gets_at_least_p1(self):
        """A quantum-driven score must never bury an exploitable classical finding."""
        _, r = pipeline()
        broken = [a for a in r.assets
                  if a.quantum_class == "classically_broken"
                  and a.confidence is Confidence.HIGH
                  and "suspected-non-security-use" not in a.tags
                  and "test-path" not in a.tags]
        self.assertTrue(broken, "no classically broken assets to check")
        for a in broken:
            self.assertIn(a.priority_band, ("P0", "P1"), f"{a.asset_name} @ {a.location}")


class TestExposureSimulator(unittest.TestCase):
    """Moving the horizon must change priorities monotonically -- the WOW moment."""

    def test_earlier_horizon_produces_more_critical_assets(self):
        e, r = pipeline()
        counts = {}
        for yr in (2045, 2040, 2035, 2030):
            e.apply_scenario(MO.Scenario(crqc_year=yr))
            counts[yr] = sum(1 for a in r.assets
                             if a.mosca_urgency in (MO.ALREADY_LATE, MO.CRITICAL))
        self.assertLess(counts[2045], counts[2035])
        self.assertLessEqual(counts[2035], counts[2030])
        e.apply_scenario(MO.Scenario())   # restore default

    def test_p0_count_increases_as_horizon_nears(self):
        e, r = pipeline()
        far = None
        for yr in (2045, 2030):
            e.apply_scenario(MO.Scenario(crqc_year=yr))
            p0 = sum(1 for a in r.assets if a.priority_band == "P0")
            if far is None:
                far = p0
            else:
                self.assertGreater(p0, far)
        e.apply_scenario(MO.Scenario())

    def test_scenario_overrides_are_honoured(self):
        e, r = pipeline()
        e.apply_scenario(MO.Scenario(crqc_year=2035, data_lifetime_years=30,
                                     migration_months=36))
        qv = [a for a in r.assets if a.quantum_vulnerable]
        self.assertTrue(qv)
        for a in qv:
            self.assertEqual(a.mosca_detail["x_data_lifetime_years"], 30.0)
            self.assertAlmostEqual(a.mosca_detail["y_migration_years"], 3.0, places=1)
        e.apply_scenario(MO.Scenario())

    def test_simulator_does_not_require_a_rescan(self):
        """Re-running only the scenario stage must not change discovery output."""
        e, r = pipeline()
        before = [a.asset_id for a in r.assets]
        e.apply_scenario(MO.Scenario(crqc_year=2030))
        self.assertEqual([a.asset_id for a in r.assets], before)
        e.apply_scenario(MO.Scenario())


if __name__ == "__main__":
    unittest.main(verbosity=2)
