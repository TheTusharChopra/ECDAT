"""Phase 2 invariants: evidence, confidence, provenance, correlation, dedup.

Covers the adversarial cases the directive calls out in §25: RSA with unknown role,
OpenSSL linked without proof of use, duplicate detections, conflicting evidence,
and missing key size / protocol / business context.
"""

from __future__ import annotations

import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from ecdat.detect.base import Detection
from ecdat.models import (
    Application,
    AssetType,
    Confidence,
    Criticality,
    DataClassification,
    EvidenceType,
    Exposure,
    Role,
)
from ecdat.normalize import Normalizer


def det(**kw) -> Detection:
    kw.setdefault("detector", "lexical-context")
    kw.setdefault("method", "regex")
    kw.setdefault("confidence", Confidence.LOW)
    return Detection(**kw)


APP = Application(
    app_id="payments", name="Payment API", owner="Payments Team",
    business_unit="Retail Banking", criticality=Criticality.MISSION_CRITICAL,
    exposure=Exposure.INTERNET_CRITICAL,
    data_classification=DataClassification.SENSITIVE, data_lifetime_years=8,
    repositories=["payments"], description="Card authorisation",
)


def norm(dets, source="demo-enterprise"):
    n = Normalizer(applications=[APP], repo_to_app={"payments": "payments"}, source=source)
    return n.normalize(dets)


# ======================================================================================
class TestEvidenceContract(unittest.TestCase):

    def test_every_asset_has_evidence(self):
        assets = norm([det(algorithm="rsa", file="payments/a.py", line=4)])
        self.assertTrue(assets)
        for a in assets:
            self.assertTrue(a.evidence, "asset produced with no evidence")

    def test_evidence_carries_type_and_confidence(self):
        assets = norm([det(detector="python-ast", method="ast-call",
                           confidence=Confidence.HIGH, algorithm="rsa",
                           role=Role.DIGITAL_SIGNATURE.value,
                           file="payments/auth.py", line=184)])
        ev = assets[0].evidence[0]
        self.assertEqual(ev.evidence_type, EvidenceType.SOURCE_API)
        self.assertEqual(ev.confidence, Confidence.HIGH)
        self.assertEqual(ev.location, "payments/auth.py:184")

    def test_source_and_provenance_are_populated(self):
        a = norm([det(algorithm="rsa", file="payments/a.py", line=1)])[0]
        self.assertEqual(a.source, "demo-enterprise")
        self.assertIn("detection(s) via", a.provenance)
        self.assertIn("lexical-context", a.provenance)

    def test_asset_confidence_is_max_over_evidence(self):
        assets = norm([
            det(algorithm="rsa", file="payments/a.py", line=10, confidence=Confidence.LOW),
            det(detector="python-ast", method="ast-call", confidence=Confidence.HIGH,
                algorithm="rsa", file="payments/a.py", line=10),
        ])
        self.assertEqual(len(assets), 1)
        self.assertEqual(assets[0].confidence, Confidence.HIGH)
        self.assertEqual(len(assets[0].evidence), 2)

    def test_evidence_type_ranked_by_what_it_proves_not_scan_order(self):
        """A LOW binary string must not outrank a HIGH certificate parse."""
        assets = norm([
            det(detector="binary-format", method="strings", confidence=Confidence.LOW,
                algorithm="rsa", file="payments/svc", line=None),
            det(detector="certificate-x509", method="x509-parse",
                confidence=Confidence.HIGH, algorithm="rsa", file="payments/svc",
                certificate={"serial": "AB", "san": []},
                extra={"cert_component": "subject-public-key"}),
        ])
        cert_assets = [a for a in assets if a.asset_type is AssetType.CERTIFICATE]
        self.assertTrue(cert_assets)
        self.assertEqual(cert_assets[0].evidence_type, EvidenceType.CERTIFICATE)


# ======================================================================================
class TestPresenceOnlyEvidence(unittest.TestCase):
    """§10: a linked crypto library does NOT prove an operation executed."""

    def test_linkage_only_is_marked_presence_only(self):
        a = norm([det(detector="binary-format", method="dynamic-linkage",
                      confidence=Confidence.HIGH, library="openssl",
                      file="payments/gateway")])[0]
        self.assertIn("presence-only-evidence", a.tags)
        self.assertIn("NO evidence here proves", a.provenance)
        self.assertFalse(a.evidence[0].proves_execution)

    def test_symbol_evidence_is_also_presence_only(self):
        a = norm([det(detector="binary-format", method="symbol-table",
                      confidence=Confidence.MEDIUM, algorithm="rsa",
                      file="payments/gateway")])[0]
        self.assertIn("presence-only-evidence", a.tags)

    def test_ast_call_is_not_presence_only(self):
        a = norm([det(detector="python-ast", method="ast-call",
                      confidence=Confidence.HIGH, algorithm="rsa",
                      role=Role.DIGITAL_SIGNATURE.value,
                      file="payments/auth.py", line=12)])[0]
        self.assertNotIn("presence-only-evidence", a.tags)
        self.assertTrue(a.evidence[0].proves_execution)
        self.assertIn("reachable", a.provenance)

    def test_config_directive_proves_deployed_behaviour(self):
        a = norm([det(detector="config-semantic", method="config-directive",
                      confidence=Confidence.HIGH, protocol="TLS",
                      protocol_version="1.2", file="payments/nginx.conf", line=3)])[0]
        self.assertTrue(a.evidence[0].proves_execution)


# ======================================================================================
class TestCorrelationAndDedup(unittest.TestCase):
    """§11: four detectors finding related evidence => ONE asset, not four."""

    def test_same_fact_from_multiple_detectors_collapses(self):
        assets = norm([
            det(algorithm="rsa", key_size=2048, file="payments/tls.py", line=84),
            det(detector="python-ast", method="ast-call", confidence=Confidence.HIGH,
                algorithm="rsa", key_size=2048, role=Role.DIGITAL_SIGNATURE.value,
                file="payments/tls.py", line=84),
        ])
        self.assertEqual(len(assets), 1)
        self.assertEqual(assets[0].duplicate_count, 2)
        self.assertEqual(sorted(assets[0].detectors),
                         ["lexical-context", "python-ast"])

    def test_distinct_locations_stay_distinct(self):
        assets = norm([
            det(algorithm="rsa", file="payments/a.py", line=10),
            det(algorithm="rsa", file="payments/b.py", line=10),
        ])
        self.assertEqual(len(assets), 2)

    def test_conflicting_key_size_resolved_by_evidence_strength(self):
        """LOW says 1024, HIGH says 2048 -> HIGH wins, regardless of order."""
        for order in (0, 1):
            ds = [
                det(algorithm="rsa", key_size=1024, file="payments/c.py", line=5,
                    confidence=Confidence.LOW),
                det(detector="python-ast", method="ast-call", confidence=Confidence.HIGH,
                    algorithm="rsa", key_size=2048, file="payments/c.py", line=5),
            ]
            if order:
                ds.reverse()
            a = norm(ds)[0]
            self.assertEqual(a.key_size, 2048, f"order={order}")

    def test_conflicting_role_prefers_evidenced_over_placeholder(self):
        a = norm([
            det(algorithm="rsa", role=Role.UNKNOWN.value, file="payments/d.py", line=7,
                confidence=Confidence.MEDIUM),
            det(detector="python-ast", method="ast-call", confidence=Confidence.HIGH,
                algorithm="rsa", role=Role.KEY_TRANSPORT.value,
                file="payments/d.py", line=7),
        ])[0]
        self.assertEqual(a.cryptographic_role, Role.KEY_TRANSPORT.value)

    def test_stable_ids_survive_rescan(self):
        d = det(algorithm="rsa", key_size=2048, file="payments/tls.py", line=84)
        first = norm([d])[0].asset_id
        second = norm([d])[0].asset_id
        self.assertEqual(first, second, "asset_id must be stable for delta re-scans")


# ======================================================================================
class TestAdversarialCases(unittest.TestCase):

    def test_rsa_found_role_unknown_is_not_guessed(self):
        a = norm([det(detector="python-ast", method="ast-call",
                      confidence=Confidence.HIGH, algorithm="rsa", key_size=2048,
                      role=Role.UNKNOWN.value, file="payments/keys.py", line=3)])[0]
        self.assertEqual(a.cryptographic_role, Role.UNKNOWN.value)

    def test_missing_key_size_does_not_fabricate_one(self):
        a = norm([det(algorithm="rsa", file="payments/e.py", line=2)])[0]
        self.assertIsNone(a.key_size)
        # strength falls back to the family default, not to a guessed modulus
        self.assertEqual(a.asset_name, "RSA")

    def test_missing_protocol_version_is_preserved_as_none(self):
        a = norm([det(detector="config-semantic", method="config-directive",
                      confidence=Confidence.HIGH, protocol="SSH",
                      file="payments/sshd_config", line=1)])[0]
        self.assertEqual(a.protocol, "SSH")
        self.assertIsNone(a.protocol_version)

    def test_missing_business_context_marked_default_not_discovered(self):
        """An asset outside any known repository must not inherit fake context."""
        a = norm([det(algorithm="rsa", file="unmapped/x.py", line=1)])[0]
        self.assertIsNone(a.application)
        self.assertIsNone(a.data_classification)
        self.assertIsNone(a.business_criticality)
        self.assertEqual(a.context_source, "default")

    def test_business_context_attached_when_repository_maps(self):
        a = norm([det(algorithm="rsa", file="payments/f.py", line=1)])[0]
        self.assertEqual(a.application, "payments")
        self.assertEqual(a.data_lifetime_years, 8)
        self.assertEqual(a.business_criticality, Criticality.MISSION_CRITICAL)
        self.assertTrue(a.internet_exposed)

    def test_private_key_material_is_never_stored_in_evidence(self):
        leak = ("-----BEGIN RSA PRIVATE KEY-----\n"
                "MIIEowIBAAKCAQEA3Zx9fakekeymaterialdonotstore==\n"
                "-----END RSA PRIVATE KEY-----")
        a = norm([det(detector="certificate-x509", method="pem-scan",
                      confidence=Confidence.HIGH, file="payments/id_rsa",
                      snippet=leak, matched="private key material",
                      extra={"key_material_in_repo": True})])[0]
        blob = repr(a.to_dict())
        self.assertNotIn("MIIEowIBAAKCAQEA", blob)
        self.assertIn("REDACTED", a.evidence[0].snippet)
        self.assertIn("key-material-exposure", a.tags)


if __name__ == "__main__":
    unittest.main(verbosity=2)
