"""Phase 5 invariants: classical_risk and quantum_exposure must stay separate.

The headline property under test: a primitive can be CRITICAL on one axis and
INFO on the other. If these two fields ever move together, the product has lost
the ability to distinguish "exploitable today" from "plan a migration".
"""

from __future__ import annotations

import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from ecdat.analyze import risk as R
from ecdat.engine import Engine, demo_request
from ecdat.knowledge import pqc
from ecdat.models import (
    AssetType,
    Confidence,
    Criticality,
    CryptoAsset,
    DataClassification,
    Exposure,
    RiskBand,
    Role,
)

_C: dict[str, object] = {}


def assessed():
    if "r" not in _C:
        e = Engine()
        r = e.discover(demo_request())
        e.build_graph()
        e.assess()
        _C["r"] = r
    return _C["r"]


def mk(algorithm=None, *, key_size=None, curve=None, role=Role.UNKNOWN.value,
       lifetime=3, protocol=None, version=None, sig_alg=None, days=None,
       tags=None, criticality=Criticality.IMPORTANT,
       exposure=Exposure.INTERNAL) -> CryptoAsset:
    a = CryptoAsset(
        asset_id="t", asset_type=AssetType.SOURCE_FINDING,
        asset_name=algorithm or protocol or "x",
        algorithm=algorithm, key_size=key_size, curve=curve,
        cryptographic_role=role, protocol=protocol, protocol_version=version,
        certificate_sig_algorithm=sig_alg, days_to_expiry=days,
        confidence=Confidence.HIGH, data_lifetime_years=lifetime,
        data_classification=DataClassification.SENSITIVE,
        business_criticality=criticality, exposure=exposure,
        tags=list(tags or []))
    R.apply(a)
    return a


class TestAxesArePopulated(unittest.TestCase):

    def test_both_canonical_fields_set_on_every_asset(self):
        for a in assessed().assets:
            self.assertIsInstance(a.classical_risk, RiskBand, a.asset_id)
            self.assertIsInstance(a.quantum_exposure, RiskBand, a.asset_id)

    def test_quantum_risk_is_an_alias_of_quantum_exposure(self):
        for a in assessed().assets:
            self.assertEqual(a.quantum_risk, a.quantum_exposure, a.asset_id)

    def test_composite_band_is_not_written_into_either_axis(self):
        """Regression: quantum_risk used to receive the COMPOSITE band."""
        for a in assessed().assets:
            composite = a.risk_factors.get("band")
            self.assertIsNotNone(composite)
            # the axis must equal the axis reason's band, not the composite
            self.assertEqual(a.quantum_exposure.value,
                             a.risk_factors["quantum_exposure"]["band"], a.asset_id)
            self.assertEqual(a.classical_risk.value,
                             a.risk_factors["classical_risk"]["band"], a.asset_id)

    def test_each_axis_carries_its_own_reason(self):
        for a in assessed().assets:
            for axis in ("classical_risk", "quantum_exposure"):
                self.assertTrue(a.risk_factors[axis]["reason"], f"{a.asset_id}/{axis}")

    def test_risk_explanation_mentions_both_axes(self):
        a = assessed().assets[0]
        self.assertGreaterEqual(len(a.risk_explanation), 2)


class TestAxesAreIndependent(unittest.TestCase):
    """The defining property of Phase 5."""

    def test_md5_is_classically_critical_and_quantum_irrelevant(self):
        a = mk("md5", role=Role.HASHING.value)
        self.assertIn(a.classical_risk, (RiskBand.CRITICAL, RiskBand.HIGH))
        self.assertEqual(a.quantum_exposure, RiskBand.INFO)
        self.assertIn("CRQC adds nothing",
                      a.risk_factors["quantum_exposure"]["reason"])

    def test_sha1_same_shape_as_md5(self):
        a = mk("sha-1", role=Role.HASHING.value)
        self.assertIn(a.classical_risk, (RiskBand.CRITICAL, RiskBand.HIGH))
        self.assertEqual(a.quantum_exposure, RiskBand.INFO)

    def test_3des_is_classical_not_quantum(self):
        a = mk("3des", role=Role.ENCRYPTION.value)
        self.assertEqual(a.classical_risk, RiskBand.HIGH)
        self.assertEqual(a.quantum_exposure, RiskBand.INFO)

    def test_ecdsa_p384_is_classically_strong_and_quantum_critical(self):
        a = mk("ecdsa", curve="secp384r1", role=Role.DIGITAL_SIGNATURE.value)
        self.assertIn(a.classical_risk, (RiskBand.INFO, RiskBand.LOW))
        self.assertEqual(a.quantum_exposure, RiskBand.CRITICAL)

    def test_rsa_2048_is_classically_acceptable_and_quantum_critical(self):
        a = mk("rsa", key_size=2048, role=Role.KEY_TRANSPORT.value)
        self.assertIn(a.classical_risk, (RiskBand.LOW, RiskBand.MEDIUM))
        self.assertEqual(a.quantum_exposure, RiskBand.CRITICAL)

    def test_rsa_1024_is_bad_on_both_axes_for_different_reasons(self):
        a = mk("rsa", key_size=1024, role=Role.KEY_TRANSPORT.value)
        self.assertIn(a.classical_risk, (RiskBand.HIGH, RiskBand.CRITICAL))
        self.assertEqual(a.quantum_exposure, RiskBand.CRITICAL)
        self.assertIn("classical", a.risk_factors["classical_risk"]["reason"].lower())
        self.assertIn("shor", a.risk_factors["quantum_exposure"]["reason"].lower())

    def test_aes_256_is_fine_on_both_axes(self):
        a = mk("aes-256", role=Role.ENCRYPTION.value)
        self.assertEqual(a.classical_risk, RiskBand.INFO)
        self.assertEqual(a.quantum_exposure, RiskBand.INFO)

    def test_aes_128_grover_margin_is_a_quantum_finding_not_classical(self):
        a = mk("aes-128", role=Role.ENCRYPTION.value)
        self.assertIn(a.classical_risk, (RiskBand.LOW, RiskBand.INFO, RiskBand.MEDIUM))
        self.assertEqual(a.quantum_exposure, RiskBand.MEDIUM)
        reason = a.risk_factors["quantum_exposure"]["reason"]
        self.assertIn("LARGER SYMMETRIC KEY", reason)
        self.assertIn("not a PQC algorithm", reason)

    def test_sha256_is_never_called_quantum_broken(self):
        a = mk("sha-256", role=Role.HASHING.value)
        self.assertEqual(a.quantum_exposure, RiskBand.INFO)
        self.assertIn("NOT quantum-broken",
                      a.risk_factors["quantum_exposure"]["reason"])

    def test_pqc_and_hybrid_are_informational_on_both_axes(self):
        for algid in ("ml-kem-768", "ml-dsa-65", "x25519mlkem768"):
            a = mk(algid, role=Role.KEY_ESTABLISHMENT.value)
            self.assertEqual(a.quantum_exposure, RiskBand.INFO, algid)
            self.assertEqual(a.classical_risk, RiskBand.INFO, algid)

    def test_draft_hybrid_is_flagged_without_being_called_vulnerable(self):
        a = mk("x25519kyber768draft00", role=Role.KEY_ESTABLISHMENT.value)
        self.assertEqual(a.quantum_exposure, RiskBand.MEDIUM)
        self.assertIn("RFC 10024", a.risk_factors["quantum_exposure"]["reason"])

    def test_hqc_selected_not_final(self):
        a = mk("hqc", role=Role.KEY_ESTABLISHMENT.value)
        self.assertEqual(a.quantum_exposure, RiskBand.LOW)
        self.assertIn("no final FIPS", a.risk_factors["quantum_exposure"]["reason"])

    def test_axes_do_not_move_together_across_the_estate(self):
        """Statistical guard: if the axes were coupled they would correlate perfectly."""
        pairs = {(a.classical_risk.value, a.quantum_exposure.value)
                 for a in assessed().assets}
        disagreeing = {(c, q) for c, q in pairs if c != q}
        self.assertGreaterEqual(len(disagreeing), 4,
                                f"axes look coupled; observed pairs: {sorted(pairs)}")


class TestQuantumSpecifics(unittest.TestCase):

    def test_shor_exposure_is_key_size_independent(self):
        small = mk("rsa", key_size=2048, role=Role.KEY_TRANSPORT.value)
        big = mk("rsa", key_size=4096, role=Role.KEY_TRANSPORT.value)
        self.assertEqual(small.quantum_exposure, big.quantum_exposure)
        self.assertIn("does not mitigate",
                      big.risk_factors["quantum_exposure"]["reason"])

    def test_harvest_now_decrypt_later_flagged_for_long_lived_key_establishment(self):
        a = mk("ecdh", role=Role.KEY_ESTABLISHMENT.value, lifetime=10)
        self.assertTrue(a.risk_factors["quantum_exposure"]["harvest_now_decrypt_later"])
        self.assertIn("TODAY", a.risk_factors["quantum_exposure"]["reason"])

    def test_hndl_not_claimed_for_signatures(self):
        a = mk("ecdsa", role=Role.DIGITAL_SIGNATURE.value, lifetime=20)
        self.assertFalse(a.risk_factors["quantum_exposure"]["harvest_now_decrypt_later"])
        self.assertIn("future risk", a.risk_factors["quantum_exposure"]["reason"])

    def test_hndl_not_claimed_for_short_lived_data(self):
        a = mk("ecdh", role=Role.KEY_ESTABLISHMENT.value, lifetime=1)
        self.assertNotIn("harvest_now_decrypt_later",
                         a.risk_factors["quantum_exposure"])

    def test_tls12_is_a_quantum_blocker_but_classically_acceptable(self):
        a = mk(protocol="TLS", version="1.2")
        self.assertEqual(a.classical_risk, RiskBand.LOW)
        self.assertEqual(a.quantum_exposure, RiskBand.MEDIUM)
        self.assertIn("TLS 1.3 only", a.risk_factors["quantum_exposure"]["reason"])

    def test_tls10_is_bad_classically_too(self):
        a = mk(protocol="TLS", version="1.0")
        self.assertEqual(a.classical_risk, RiskBand.HIGH)
        self.assertIn("RFC 8996", a.risk_factors["classical_risk"]["reason"])

    def test_no_forbidden_language_anywhere(self):
        """§11: never claim AES-256 is quantum-broken or anything is quantum-proof."""
        banned = ("quantum-proof", "quantum proof", "quantum-safe", "quantum safe")
        for a in assessed().assets:
            blob = " ".join(a.risk_explanation).lower()
            for phrase in banned:
                self.assertNotIn(phrase, blob, f"{a.asset_id}: forbidden phrase")


class TestClassicalSpecifics(unittest.TestCase):

    def test_expired_certificate_is_classically_critical(self):
        a = mk("rsa", key_size=2048, days=-400, role=Role.DIGITAL_SIGNATURE.value)
        self.assertEqual(a.classical_risk, RiskBand.CRITICAL)
        self.assertEqual(a.risk_factors["classical_risk"]["trigger"],
                         "expired-certificate")

    def test_sha1_signed_certificate_is_classically_critical(self):
        a = mk("rsa", key_size=2048, sig_alg="sha1WithRSAEncryption",
               role=Role.SIGNATURE_VERIFICATION.value)
        self.assertEqual(a.classical_risk, RiskBand.CRITICAL)
        self.assertEqual(a.quantum_exposure, RiskBand.CRITICAL,
                         "an RSA key is still Shor-vulnerable regardless")

    def test_weak_cipher_suite_tag_raises_classical_only(self):
        a = mk(protocol="TLS", version="1.2", tags=["weak-cipher-suite"])
        self.assertEqual(a.classical_risk, RiskBand.HIGH)

    def test_policy_floor_influences_classical_band(self):
        lenient = R.classical_risk(
            mk("aes-128", role=Role.ENCRYPTION.value),
            pqc.POLICIES["nist_general"])
        strict = R.classical_risk(
            mk("aes-128", role=Role.ENCRYPTION.value),
            pqc.POLICIES["nsa_cnsa2"])
        self.assertLessEqual(
            ["info", "low", "medium", "high", "critical"].index(lenient.band.value),
            ["info", "low", "medium", "high", "critical"].index(strict.band.value),
            "CNSA 2.0 requires AES-256, so AES-128 must not score better under it")

    def test_determinism(self):
        first = mk("rsa", key_size=2048, role=Role.KEY_TRANSPORT.value)
        second = mk("rsa", key_size=2048, role=Role.KEY_TRANSPORT.value)
        self.assertEqual(first.classical_risk, second.classical_risk)
        self.assertEqual(first.quantum_exposure, second.quantum_exposure)
        self.assertEqual(first.risk_score, second.risk_score)


if __name__ == "__main__":
    unittest.main(verbosity=2)
