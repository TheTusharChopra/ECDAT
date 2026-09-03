"""Phase 3 invariants: end-to-end discovery integration on the demo estate.

These are the tests that prove the pipeline actually works on real files rather
than on hand-built Detection objects.
"""

from __future__ import annotations

import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from ecdat.engine import Engine, demo_paths, demo_request
from ecdat.models import AssetType, Confidence, EvidenceType, Role

_CACHE: dict[str, object] = {}


def scanned():
    """Scan once, share across tests (discovery is deterministic)."""
    if "result" not in _CACHE:
        eng = Engine()
        _CACHE["result"] = eng.discover(demo_request())
        _CACHE["engine"] = eng
    return _CACHE["result"]


def find(pred):
    return [a for a in scanned().assets if pred(a)]


class TestDiscoveryIntegration(unittest.TestCase):

    def test_demo_dataset_exists(self):
        p = demo_paths()
        for key in ("estate", "repositories", "certificates", "binaries"):
            self.assertTrue(pathlib.Path(p[key]).exists(),
                            f"demo {key} missing -- run datasets/demo/generate_repositories.py")

    def test_scan_completes_without_errors(self):
        self.assertEqual(scanned().stats.errors, [])

    def test_detection_accounting_balances(self):
        s = scanned().stats
        self.assertEqual(s.raw_detections, len(scanned().assets) + s.deduplicated)

    def test_repository_count_matches_estate(self):
        self.assertEqual(scanned().stats.repositories, 12)

    def test_all_five_discovery_sources_contributed(self):
        d = scanned().stats.detector_counts
        for detector in ("python-ast", "config-semantic", "certificate-x509",
                         "binary-format", "dependency-manifest", "container",
                         "lexical-context"):
            self.assertIn(detector, d, f"{detector} produced nothing")
            self.assertGreater(d[detector], 0)

    def test_every_asset_has_an_application(self):
        orphans = [a.asset_name for a in scanned().assets if not a.application]
        self.assertEqual(orphans, [], f"unmapped assets: {orphans[:5]}")

    def test_every_asset_has_evidence_and_provenance(self):
        for a in scanned().assets:
            self.assertTrue(a.evidence, f"{a.asset_id} has no evidence")
            self.assertTrue(a.provenance, f"{a.asset_id} has no provenance")
            self.assertIsNotNone(a.source)

    def test_scan_is_deterministic(self):
        eng = Engine()
        second = eng.discover(demo_request())
        first_ids = sorted(a.asset_id for a in scanned().assets)
        second_ids = sorted(a.asset_id for a in second.assets)
        self.assertEqual(first_ids, second_ids,
                         "asset ids must be stable across scans for delta analysis")


class TestExpectedFindings(unittest.TestCase):
    """The seeded cryptography must actually be discovered."""

    def test_rsa_key_transport_found_in_payment_api(self):
        hits = find(lambda a: a.application == "payment-api"
                    and a.cryptographic_role == Role.KEY_TRANSPORT.value)
        self.assertTrue(hits, "RSA-OAEP key transport not discovered")
        self.assertEqual(hits[0].confidence, Confidence.HIGH)
        self.assertEqual(hits[0].evidence_type, EvidenceType.SOURCE_API)

    def test_unused_rsa_escrow_key_role_is_unknown(self):
        hits = find(lambda a: (a.file or "").endswith("payment-api/src/keys.py")
                    and a.algorithm == "rsa")
        self.assertTrue(hits, "escrow key not discovered")
        self.assertEqual(hits[0].cryptographic_role, Role.UNKNOWN.value,
                         "role must not be guessed when no usage is observed")

    def test_signing_role_evidenced_in_citizen_portal(self):
        hits = find(lambda a: a.application == "citizen-portal"
                    and a.cryptographic_role == Role.DIGITAL_SIGNATURE.value
                    and a.algorithm == "rsa")
        self.assertTrue(hits, "RSA signing role not evidenced by dataflow")

    def test_classically_broken_primitives_found_in_legacy_portal(self):
        algs = {a.algorithm for a in find(lambda a: a.application == "legacy-portal")}
        for expected in ("3des", "md5", "sha-1"):
            self.assertIn(expected, algs, f"{expected} not found in legacy portal")

    def test_already_migrated_hybrid_is_discovered(self):
        hits = find(lambda a: a.algorithm == "x25519mlkem768")
        self.assertTrue(hits, "RFC 10024 hybrid group not discovered")
        apps = {a.application for a in hits}
        self.assertTrue({"file-exchange", "k8s-platform"} & apps)

    def test_tls_versions_discovered_from_config(self):
        versions = {(a.protocol, a.protocol_version)
                    for a in find(lambda a: a.asset_type is AssetType.PROTOCOL_CONFIG)}
        flat = {v for _, v in versions}
        self.assertTrue({"1.2", "1.3"} & flat, f"got {versions}")

    def test_certificates_parsed_with_expiry(self):
        certs = find(lambda a: a.asset_type is AssetType.CERTIFICATE)
        self.assertGreaterEqual(len(certs), 20)
        self.assertTrue(any(a.days_to_expiry is not None and a.days_to_expiry < 0
                            for a in certs), "no expired certificate detected")
        self.assertTrue(any(a.certificate_sig_algorithm
                            and "sha1" in a.certificate_sig_algorithm.lower()
                            for a in certs), "SHA-1 signed certificate not detected")

    def test_binary_findings_are_presence_only(self):
        bins = find(lambda a: a.asset_type is AssetType.BINARY_ARTIFACT)
        self.assertTrue(bins)
        for a in bins:
            self.assertIn("presence-only-evidence", a.tags)
            self.assertEqual(a.cryptographic_role, Role.UNKNOWN.value,
                             "no role may be claimed from a binary")

    def test_dependency_manifests_resolved_to_libraries(self):
        deps = find(lambda a: a.asset_type is AssetType.DEPENDENCY)
        self.assertTrue(deps)
        libs = {a.library for a in deps}
        self.assertTrue({"python-cryptography", "bouncycastle"} & libs, f"got {libs}")

    def test_pqc_readiness_recorded_from_library_version(self):
        hits = find(lambda a: a.pqc_readiness is not None)
        self.assertTrue(hits, "no PQC readiness assessed from any library")


class TestFalsePositiveControls(unittest.TestCase):
    """The seeded minefield must not produce confident findings."""

    def test_docs_site_prose_is_low_confidence_only(self):
        hits = find(lambda a: a.application == "docs-site")
        self.assertTrue(hits, "docs-site produced nothing (expected lexical hits)")
        high = [a for a in hits if a.confidence is Confidence.HIGH
                and a.asset_type is AssetType.SOURCE_FINDING]
        self.assertEqual(high, [],
                         f"prose mentioning algorithms produced HIGH confidence: "
                         f"{[a.asset_name for a in high]}")

    def test_md5_cache_key_flagged_as_suspected_non_security(self):
        hits = find(lambda a: a.algorithm == "md5"
                    and a.application in ("citizen-portal", "notify-service"))
        self.assertTrue(hits, "MD5 cache-key usage not discovered")
        self.assertTrue(any("suspected-non-security-use" in a.tags for a in hits),
                        "MD5 used as a cache key was not flagged for triage")

    def test_test_vector_file_is_marked_test_path(self):
        hits = find(lambda a: "tests/" in (a.file or "")
                    or "test_vectors" in (a.file or ""))
        self.assertTrue(hits, "test-vector file produced no findings")
        self.assertTrue(any("test-path" in a.tags for a in hits))


class TestSecurityOfEcdat(unittest.TestCase):
    """§24: never expose or persist private key material."""

    def test_no_private_key_bytes_in_serialized_output(self):
        import json
        blob = json.dumps(scanned().to_dict(), default=str)
        for marker in ("BEGIN RSA PRIVATE KEY", "BEGIN PRIVATE KEY",
                       "BEGIN EC PRIVATE KEY", "BEGIN OPENSSH PRIVATE KEY"):
            self.assertNotIn(marker, blob, f"{marker} leaked into output")

    def test_scanned_code_is_never_executed(self):
        """Structural guard: no exec/eval/import of scanned content in the scanners."""
        src_dir = pathlib.Path(__file__).resolve().parents[1] / "ecdat"
        banned = ("exec(", "eval(", "importlib.import_module(", "__import__(",
                  "subprocess.Popen", "os.system")
        offenders = []
        for f in list((src_dir / "scan").rglob("*.py")) + list((src_dir / "detect").rglob("*.py")):
            text = f.read_text()
            for b in banned:
                if b in text:
                    offenders.append(f"{f.name}:{b}")
        self.assertEqual(offenders, [], f"unsafe construct in a scanner: {offenders}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
