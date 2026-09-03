"""Phase 7 invariants: the five-outcome migration decision layer.

The contract freezes two things that this file exists to defend:

  1. `migration_decision` has EXACTLY five values. No sixth may appear, and no
     existing strategy may be deleted to make room for one.
  2. The two levels never contradict each other. A PQC-ONLY asset must not advertise
     a hybrid group; a HYBRID asset must name one; a RETAIN asset must advertise no
     post-quantum target at all. An asset carrying a decision that disagrees with its
     own stated action is worse than no advice, because it looks authoritative.
"""

from __future__ import annotations

import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from ecdat.analyze import agility as AG
from ecdat.analyze import decide as D
from ecdat.analyze import mosca as MO
from ecdat.analyze import recommend as REC
from ecdat.analyze import risk as R
from ecdat.engine import Engine, demo_request
from ecdat.knowledge import algorithms as alg
from ecdat.knowledge import pqc
from ecdat.models import (
    AssetType,
    Confidence,
    Criticality,
    CryptoAgility,
    CryptoAsset,
    DataClassification,
    Exposure,
    Interoperability,
    MigrationDecision,
    RemediationStatus,
    RiskBand,
    Role,
)

_C: dict[str, object] = {}


def decided():
    """The full pipeline through Phase 7, run once."""
    if "r" not in _C:
        e = Engine()
        r = e.run(demo_request())
        _C["e"], _C["r"] = e, r
        _C["summary"] = D.summarize(r.assets)
    return _C["r"]


def summary() -> dict:
    decided()
    return _C["summary"]


def mk(**kw) -> CryptoAsset:
    """A single asset carried through the same stage order the engine uses."""
    base = dict(asset_id="t", asset_type=AssetType.SOURCE_FINDING,
                asset_name=kw.pop("name", None) or str(kw.get("algorithm") or "x"),
                confidence=Confidence.HIGH, data_lifetime_years=5,
                data_classification=DataClassification.SENSITIVE,
                business_criticality=Criticality.IMPORTANT,
                exposure=Exposure.INTERNAL)
    policy = kw.pop("policy", pqc.DEFAULT_POLICY)
    base.update(kw)
    a = CryptoAsset(**base)
    R.apply(a, policy)
    AG.apply(a)
    MO.apply(a)
    a.migration_priority, a.priority_band = MO.priority(a)
    D.apply(a, policy)
    return a


# ======================================================================================
class TestFrozenVocabulary(unittest.TestCase):
    """§4: the five outcomes are frozen. This is a contract test, not a unit test."""

    def test_exactly_five_decisions_exist(self):
        self.assertEqual(len(list(MigrationDecision)), 5)
        self.assertEqual(
            {d.value for d in MigrationDecision},
            {"RETAIN", "HARDEN", "UPGRADE", "HYBRID", "PQC-ONLY"})

    def test_every_decision_is_defined_in_prose(self):
        for d in MigrationDecision:
            self.assertIn(d.value, D.DECISION_DEFINITION)
            self.assertGreater(len(D.DECISION_DEFINITION[d.value]), 60,
                               f"{d.value} needs a definition an executive can read")

    def test_no_asset_carries_a_decision_outside_the_five(self):
        for a in decided().assets:
            self.assertIsInstance(a.migration_decision, MigrationDecision, a.asset_id)

    def test_every_strategy_maps_to_a_decision(self):
        """A new strategy must not silently default into HARDEN."""
        actions = {getattr(REC, n) for n in dir(REC) if n.startswith("ACTION_")}
        self.assertGreaterEqual(len(actions), 11)
        unmapped = actions - set(D._STRATEGY_DECISION)
        self.assertEqual(unmapped, set(),
                         f"strategies with no explicit decision mapping: {unmapped}")

    def test_no_strategy_was_deleted_to_build_the_decision_layer(self):
        """§3 of the directive: the strategy vocabulary is preserved verbatim."""
        for name in ("ACTION_MIGRATE_PQC", "ACTION_MIGRATE_HYBRID", "ACTION_REPLACE_NOW",
                     "ACTION_STRENGTHEN", "ACTION_RETAIN", "ACTION_UPGRADE_PROTOCOL",
                     "ACTION_RENEW_CERT", "ACTION_DETERMINE_ROLE", "ACTION_REPIN",
                     "ACTION_ROTATE_KEY", "ACTION_VERIFY"):
            self.assertTrue(hasattr(REC, name), f"{name} was removed")


# ======================================================================================
class TestBothLevelsPopulated(unittest.TestCase):

    def test_every_asset_has_a_decision_and_a_strategy(self):
        for a in decided().assets:
            self.assertIsNotNone(a.migration_decision, a.asset_id)
            self.assertTrue(a.recommended_strategy, a.asset_id)
            self.assertTrue(a.decision_rationale, a.asset_id)
            self.assertTrue(a.decision_inputs, a.asset_id)

    def test_strategy_is_finer_grained_than_decision(self):
        """If both levels had the same cardinality, one of them would be redundant."""
        r = decided()
        decisions = {a.migration_decision.value for a in r.assets}
        strategies = {a.recommended_strategy for a in r.assets}
        self.assertGreater(len(strategies), len(decisions))

    def test_recommended_action_and_strategy_agree_or_realignment_is_explained(self):
        for a in decided().assets:
            if a.recommended_action != a.recommended_strategy:
                self.assertIn("Strategy adjusted", a.decision_rationale,
                              f"{a.asset_id}: strategy changed without explanation")

    def test_decision_inputs_carry_every_contextual_input_the_contract_names(self):
        for a in decided().assets[:40]:
            for key in ("role", "classical_risk", "quantum_exposure",
                        "data_lifetime_years", "business_criticality", "exposure",
                        "dependency_centrality", "crypto_agility", "interoperability",
                        "migration_effort", "mosca_urgency", "pqc_readiness", "policy",
                        "context_source"):
                self.assertIn(key, a.decision_inputs, f"{a.asset_id} missing {key}")

    def test_rationale_is_prose_not_a_field_dump(self):
        for a in decided().assets[:40]:
            self.assertGreater(len(a.decision_rationale), 80, a.asset_id)
            self.assertIn(" ", a.decision_rationale.strip())


# ======================================================================================
class TestCoherence(unittest.TestCase):
    """The defining property of Phase 7: decision, strategy and target must agree."""

    def test_pqc_only_never_advertises_a_hybrid_group(self):
        for a in decided().assets:
            if a.migration_decision is MigrationDecision.PQC_ONLY:
                self.assertIsNone(a.recommended_hybrid, f"{a.asset_id} @ {a.location}")

    def test_pqc_only_names_a_concrete_post_quantum_target(self):
        for a in decided().assets:
            if a.migration_decision is MigrationDecision.PQC_ONLY:
                self.assertTrue(a.recommended_pqc,
                                f"{a.asset_id} decided PQC-ONLY with no target")

    def test_hybrid_names_a_concrete_hybrid_group(self):
        for a in decided().assets:
            if a.migration_decision is MigrationDecision.HYBRID:
                self.assertTrue(a.recommended_hybrid,
                                f"{a.asset_id} decided HYBRID with no hybrid group")

    def test_retain_advertises_no_migration_target(self):
        for a in decided().assets:
            if a.migration_decision is MigrationDecision.RETAIN:
                self.assertIsNone(a.recommended_pqc, a.asset_id)
                self.assertIsNone(a.recommended_hybrid, a.asset_id)

    def test_zero_incoherent_pairs_across_the_whole_estate(self):
        """The single headline number: any incoherence at all is a defect."""
        bad = []
        for a in decided().assets:
            d = a.migration_decision
            if d is MigrationDecision.PQC_ONLY and (a.recommended_hybrid
                                                    or not a.recommended_pqc):
                bad.append((a.asset_id, d.value, a.recommended_strategy))
            if d is MigrationDecision.HYBRID and not a.recommended_hybrid:
                bad.append((a.asset_id, d.value, a.recommended_strategy))
            if d is MigrationDecision.RETAIN and (a.recommended_pqc
                                                  or a.recommended_hybrid):
                bad.append((a.asset_id, d.value, a.recommended_strategy))
        self.assertEqual(bad, [], f"{len(bad)} incoherent decision/target pairs")

    def test_upgrade_with_a_pqc_strategy_explains_that_it_is_a_provider_change(self):
        """UPGRADE + migrate-to-pqc is legitimate but must say why the levels differ."""
        for a in decided().assets:
            if (a.migration_decision is MigrationDecision.UPGRADE
                    and a.recommended_strategy in (REC.ACTION_MIGRATE_PQC,
                                                   REC.ACTION_MIGRATE_HYBRID)):
                self.assertIn("provider", a.decision_rationale.lower(),
                              f"{a.asset_id}: unexplained level mismatch")


# ======================================================================================
class TestSignatureTakesTheStandaloneePath(unittest.TestCase):
    """There is no standardised PQ/T hybrid SIGNATURE. Routing one to HYBRID would
    promise a mechanism that does not exist."""

    def test_signature_role_is_never_decided_hybrid(self):
        for a in decided().assets:
            if alg.role_family(a.cryptographic_role or "") == "signature":
                self.assertIsNot(a.migration_decision, MigrationDecision.HYBRID,
                                 f"{a.asset_id} @ {a.location}")

    def test_ecdsa_signature_goes_pqc_only_with_ml_dsa(self):
        a = mk(algorithm="ecdsa", curve="secp256r1",
               cryptographic_role=Role.DIGITAL_SIGNATURE.value)
        self.assertIs(a.migration_decision, MigrationDecision.PQC_ONLY)
        self.assertEqual(a.recommended_pqc, "ML-DSA-65")
        self.assertIsNone(a.recommended_hybrid)

    def test_signature_rationale_states_why_no_hybrid_exists(self):
        a = mk(algorithm="ecdsa", cryptographic_role=Role.DIGITAL_SIGNATURE.value)
        self.assertIn("RFC 10024 defines hybrid KEY AGREEMENT only",
                      a.decision_rationale)
        self.assertIn("CA readiness", a.decision_rationale)

    def test_internet_facing_signature_still_takes_pqc_only(self):
        """Peer negotiation is not the constraint for signatures -- PKI is."""
        a = mk(algorithm="rsa", key_size=2048,
               cryptographic_role=Role.DIGITAL_SIGNATURE.value,
               internet_exposed=True, exposure=Exposure.EXTERNAL,
               protocol="TLS", protocol_version="1.3")
        self.assertIs(a.migration_decision, MigrationDecision.PQC_ONLY)


# ======================================================================================
class TestHybridVsPqcOnly(unittest.TestCase):
    """Interoperability is the input that separates the two PQC outcomes."""

    def test_open_interoperability_permits_standalone_pqc(self):
        a = mk(algorithm="ecdh", cryptographic_role=Role.KEY_ESTABLISHMENT.value,
               internet_exposed=False)
        self.assertIs(a.interoperability, Interoperability.OPEN)
        self.assertIs(a.migration_decision, MigrationDecision.PQC_ONLY)

    def test_negotiated_protocol_requires_a_hybrid(self):
        a = mk(algorithm="ecdh", cryptographic_role=Role.KEY_ESTABLISHMENT.value,
               protocol="TLS", protocol_version="1.3", internet_exposed=True)
        self.assertIs(a.interoperability, Interoperability.NEGOTIATED)
        self.assertIs(a.migration_decision, MigrationDecision.HYBRID)
        self.assertIn("RFC 10024", a.decision_rationale)

    def test_constrained_interoperability_requires_a_hybrid(self):
        a = mk(algorithm="rsa", key_size=2048, asset_type=AssetType.BINARY_ARTIFACT,
               cryptographic_role=Role.KEY_ESTABLISHMENT.value)
        self.assertIs(a.interoperability, Interoperability.CONSTRAINED)
        self.assertIs(a.migration_decision, MigrationDecision.HYBRID)

    def test_policy_can_forbid_standalone_pqc_and_force_a_hybrid(self):
        """CNSA 2.0-style profiles: the hybrid is a policy requirement, not a
        compatibility workaround."""
        kw = dict(algorithm="ecdh", cryptographic_role=Role.KEY_ESTABLISHMENT.value,
                  internet_exposed=False)
        lenient = mk(policy="nist_general", **kw)
        for pid, prof in pqc.POLICIES.items():
            if not prof.allow_non_hybrid_pqc:
                strict = mk(policy=pid, **kw)
                self.assertIs(strict.migration_decision, MigrationDecision.HYBRID,
                              f"{pid} forbids standalone PQC but produced "
                              f"{strict.migration_decision}")
                self.assertIn(prof.name, strict.decision_rationale)
                break
        else:
            self.skipTest("no policy profile forbids standalone PQC")
        self.assertIs(lenient.migration_decision, MigrationDecision.PQC_ONLY)

    def test_hybrid_decision_is_explained_by_interoperability_not_by_score(self):
        a = mk(algorithm="ecdh", cryptographic_role=Role.KEY_ESTABLISHMENT.value,
               protocol="TLS", protocol_version="1.3", internet_exposed=True)
        self.assertTrue(
            any(w in a.decision_rationale for w in ("negotiat", "peers")),
            "the hybrid rationale must reference interoperability")


# ======================================================================================
class TestAlreadyHybridStaysHybrid(unittest.TestCase):
    """Regression: an OPEN verdict used to promote a draft-hybrid asset to PQC-ONLY,
    which stripped its hybrid target and left it with no target at all."""

    def test_draft_hybrid_repin_stays_hybrid_internally(self):
        a = mk(algorithm="x25519kyber768draft00",
               cryptographic_role=Role.KEY_ESTABLISHMENT.value,
               internet_exposed=False)
        self.assertIs(a.interoperability, Interoperability.OPEN)
        self.assertIs(a.migration_decision, MigrationDecision.HYBRID)
        self.assertEqual(a.recommended_strategy, REC.ACTION_REPIN)
        self.assertEqual(a.recommended_hybrid, "X25519MLKEM768")

    def test_draft_hybrid_repin_stays_hybrid_when_negotiated(self):
        a = mk(algorithm="x25519kyber768draft00",
               cryptographic_role=Role.KEY_ESTABLISHMENT.value,
               protocol="TLS", protocol_version="1.3", internet_exposed=True)
        self.assertIs(a.migration_decision, MigrationDecision.HYBRID)
        self.assertEqual(a.recommended_hybrid, "X25519MLKEM768")

    def test_repin_rationale_says_the_hybrid_construction_is_retained(self):
        a = mk(algorithm="x25519kyber768draft00",
               cryptographic_role=Role.KEY_ESTABLISHMENT.value)
        self.assertIn("already deploys a PQ/T hybrid", a.decision_rationale)

    def test_standardised_hybrid_is_retained_outright(self):
        a = mk(algorithm="x25519mlkem768",
               cryptographic_role=Role.KEY_ESTABLISHMENT.value)
        self.assertIs(a.migration_decision, MigrationDecision.RETAIN)


# ======================================================================================
class TestNoPqcRequired(unittest.TestCase):
    """§20: the engine must be able to say "no PQC replacement required"."""

    def test_strong_symmetric_is_retained(self):
        a = mk(algorithm="aes-256", cryptographic_role=Role.ENCRYPTION.value)
        self.assertIs(a.migration_decision, MigrationDecision.RETAIN)

    def test_sha256_is_retained_not_migrated(self):
        a = mk(algorithm="sha-256", cryptographic_role=Role.HASHING.value)
        self.assertIs(a.migration_decision, MigrationDecision.RETAIN)

    def test_aes_128_is_hardened_not_migrated_to_pqc(self):
        """Grover is a parameter-size argument, never a PQC-substitution argument."""
        a = mk(algorithm="aes-128", cryptographic_role=Role.ENCRYPTION.value,
               policy="nsa_cnsa2")
        self.assertIn(a.migration_decision,
                      (MigrationDecision.HARDEN, MigrationDecision.RETAIN))
        self.assertIsNone(a.recommended_pqc)

    def test_classically_broken_is_an_upgrade_not_a_pqc_migration(self):
        for algid in ("md5", "sha-1", "3des", "rc4"):
            a = mk(algorithm=algid, cryptographic_role=Role.HASHING.value
                   if algid in ("md5", "sha-1") else Role.ENCRYPTION.value)
            self.assertIs(a.migration_decision, MigrationDecision.UPGRADE, algid)
            self.assertIsNone(a.recommended_pqc, algid)

    def test_summary_reports_a_no_pqc_required_count(self):
        s = summary()
        self.assertEqual(s["no_pqc_required"],
                         s["decisions"][MigrationDecision.RETAIN.value])
        self.assertGreater(s["no_pqc_required"], 0,
                           "a real estate always contains assets needing no PQC work")


# ======================================================================================
class TestBlockedDecisions(unittest.TestCase):

    def test_unknown_role_blocks_on_role_determination(self):
        a = mk(algorithm="rsa", key_size=2048,
               cryptographic_role=Role.UNKNOWN.value)
        self.assertIs(a.migration_decision, MigrationDecision.HARDEN)
        self.assertEqual(a.decision_blocked_on, "role-determination")
        self.assertIsNone(a.recommended_pqc,
                          "a blocked decision must not guess a target")

    def test_blocked_rationale_names_both_candidate_targets(self):
        a = mk(algorithm="rsa", key_size=2048, cryptographic_role=Role.UNKNOWN.value)
        self.assertIn("ML-KEM", a.decision_rationale)
        self.assertIn("ML-DSA", a.decision_rationale)
        self.assertIn("not interchangeable", a.decision_rationale)

    def test_every_blocked_asset_in_the_estate_is_held_at_harden(self):
        for a in decided().assets:
            if a.decision_blocked_on:
                self.assertIs(a.migration_decision, MigrationDecision.HARDEN,
                              f"{a.asset_id} is blocked but was still given a target")

    def test_blocked_count_matches_the_summary(self):
        r = decided()
        self.assertEqual(summary()["blocked_on_role_determination"],
                         sum(1 for a in r.assets if a.decision_blocked_on))

    def test_blockers_are_phrased_as_owned_actions(self):
        a = mk(algorithm="rsa", key_size=2048, asset_type=AssetType.CERTIFICATE,
               cryptographic_role=Role.DIGITAL_SIGNATURE.value)
        self.assertTrue(a.migration_blockers)
        for b in a.migration_blockers:
            self.assertRegex(b, r"^[A-Z]", f"blocker is not a sentence: {b}")


# ======================================================================================
class TestProviderOnlyAssets(unittest.TestCase):
    """A dependency with no PQC path is a package bump, not a cryptographic migration."""

    def test_provider_without_pqc_path_is_an_upgrade(self):
        a = mk(name="pycryptodome", library="pycryptodome",
               asset_type=AssetType.DEPENDENCY, pqc_readiness="none")
        self.assertIs(a.migration_decision, MigrationDecision.UPGRADE)

    def test_provider_upgrade_rationale_says_it_gates_dependents(self):
        a = mk(name="pycryptodome", library="pycryptodome",
               asset_type=AssetType.DEPENDENCY, pqc_readiness="none")
        self.assertIn("gates", a.decision_rationale)

    def test_pqc_native_provider_is_retained(self):
        a = mk(name="openssl 3.5.0", library="openssl", library_version="3.5.0",
               asset_type=AssetType.DEPENDENCY, pqc_readiness="native")
        self.assertIs(a.migration_decision, MigrationDecision.RETAIN)


# ======================================================================================
class TestClassicalRiskIsNotDeferred(unittest.TestCase):

    def test_pqc_decision_with_high_classical_risk_says_fix_that_first(self):
        a = mk(algorithm="rsa", key_size=1024,
               cryptographic_role=Role.KEY_ESTABLISHMENT.value)
        self.assertIn(a.classical_risk, (RiskBand.HIGH, RiskBand.CRITICAL))
        self.assertIn("CLASSICAL risk", a.decision_rationale)
        self.assertIn("must not wait", a.decision_rationale)

    def test_no_classical_note_when_classical_risk_is_low(self):
        a = mk(algorithm="ecdh", curve="secp384r1",
               cryptographic_role=Role.KEY_ESTABLISHMENT.value)
        self.assertNotIn("CLASSICAL risk", a.decision_rationale)


# ======================================================================================
class TestContextualAmplifiers(unittest.TestCase):

    def test_mosca_breach_is_quoted_in_the_rationale(self):
        a = mk(algorithm="rsa", key_size=2048,
               cryptographic_role=Role.KEY_ESTABLISHMENT.value,
               data_lifetime_years=25, migration_months=24)
        self.assertIn(a.mosca_urgency, (MO.ALREADY_LATE, MO.CRITICAL))
        self.assertIn("Mosca urgency", a.decision_rationale)

    def test_low_agility_is_framed_as_start_earlier_not_defer(self):
        a = mk(algorithm="rsa", key_size=2048, asset_type=AssetType.BINARY_ARTIFACT,
               cryptographic_role=Role.KEY_ESTABLISHMENT.value, pqc_readiness="none",
               language="c")
        self.assertIs(a.crypto_agility, CryptoAgility.LOW)
        self.assertIn("start earlier", a.decision_rationale)

    def test_high_centrality_is_quoted_when_the_graph_supplies_it(self):
        r = decided()
        central = [a for a in r.assets if a.dependency_centrality >= 5]
        self.assertTrue(central, "demo estate should contain coupled assets")
        for a in central[:10]:
            self.assertIn("change-impact coupling", a.decision_rationale)

    def test_centrality_text_is_graph_derived_not_invented(self):
        r = decided()
        for a in r.assets:
            if a.dependency_centrality >= 5:
                s = a.affected_summary or {}
                self.assertIn(f"{len(s.get('applications', []))} application(s)",
                              a.decision_rationale)


# ======================================================================================
class TestRemediationLifecycle(unittest.TestCase):

    def test_decision_advances_detected_to_recommended(self):
        for a in decided().assets:
            self.assertIsNot(a.remediation_status, RemediationStatus.DETECTED,
                             f"{a.asset_id} still sits at DETECTED after deciding")

    def test_advance_is_audited_with_the_decision_it_came_from(self):
        a = mk(algorithm="ecdh", cryptographic_role=Role.KEY_ESTABLISHMENT.value)
        self.assertEqual(a.remediation_status, RemediationStatus.RECOMMENDED)
        self.assertTrue(a.remediation_history)
        entry = a.remediation_history[-1]
        self.assertEqual(entry["actor"], "ecdat-engine")
        self.assertIn(a.migration_decision.value, entry["note"])

    def test_deciding_twice_does_not_double_advance(self):
        a = mk(algorithm="ecdh", cryptographic_role=Role.KEY_ESTABLISHMENT.value)
        before = len(a.remediation_history)
        D.apply(a)
        self.assertEqual(len(a.remediation_history), before,
                         "re-running the decision must be idempotent on the lifecycle")


# ======================================================================================
class TestSummaryIntegrity(unittest.TestCase):

    def test_decision_counts_sum_to_the_asset_count(self):
        r = decided()
        self.assertEqual(sum(summary()["decisions"].values()), len(r.assets))

    def test_strategy_counts_sum_to_the_asset_count(self):
        r = decided()
        self.assertEqual(sum(summary()["strategies"].values()), len(r.assets))

    def test_summary_counts_match_recomputation_from_canonical_fields(self):
        """The rollup must be derived, never separately maintained."""
        r = decided()
        for value, count in summary()["decisions"].items():
            self.assertEqual(
                count,
                sum(1 for a in r.assets if a.migration_decision.value == value),
                value)

    def test_every_decision_is_represented_in_a_mixed_estate(self):
        counts = summary()["decisions"]
        missing = [k for k, v in counts.items() if v == 0]
        self.assertEqual(missing, [],
                         f"demo estate exercises only {5 - len(missing)}/5 outcomes; "
                         f"missing {missing}")


# ======================================================================================
class TestDeterminismAndHonesty(unittest.TestCase):

    def test_same_asset_yields_the_same_decision(self):
        kw = dict(algorithm="rsa", key_size=2048,
                  cryptographic_role=Role.KEY_TRANSPORT.value)
        first, second = mk(**kw), mk(**kw)
        self.assertEqual(first.migration_decision, second.migration_decision)
        self.assertEqual(first.recommended_strategy, second.recommended_strategy)
        self.assertEqual(first.decision_rationale, second.decision_rationale)

    def test_no_forbidden_claims_in_any_rationale(self):
        """§49: nothing is 'quantum-proof', 'quantum-safe' or '100% accurate'."""
        banned = ("quantum-proof", "quantum proof", "quantum-safe", "quantum safe",
                  "100% accurate", "fully compliant", "guaranteed")
        for a in decided().assets:
            low = a.decision_rationale.lower()
            for phrase in banned:
                self.assertNotIn(phrase, low, f"{a.asset_id}: '{phrase}'")

    def test_rationale_never_claims_compliance_status(self):
        for a in decided().assets:
            low = a.decision_rationale.lower()
            self.assertNotIn("non-compliant", low, a.asset_id)
            self.assertNotIn("is compliant", low, a.asset_id)

    def test_decision_records_the_provenance_of_its_business_inputs(self):
        """§36: a defaulted input must never read as a discovered fact."""
        for a in decided().assets:
            self.assertIn(a.decision_inputs["context_source"],
                          ("operator-declared", "default", "discovered",
                           "operator-override"), a.asset_id)


if __name__ == "__main__":
    unittest.main(verbosity=2)
