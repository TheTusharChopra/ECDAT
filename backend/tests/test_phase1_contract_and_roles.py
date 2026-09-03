"""Phase 1 invariants: canonical asset contract + single role vocabulary.

Uses stdlib unittest (not pytest) so the test suite has the same zero-third-party
dependency property as the analysis core. Run from `backend/`:

    python3 -m unittest discover -s tests -v
"""

from __future__ import annotations

import dataclasses
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from ecdat import models as M
from ecdat.detect.python_ast import PythonAstDetector
from ecdat.knowledge import algorithms as alg
from ecdat.knowledge import pqc
from ecdat.models import Role

SRC_DIR = pathlib.Path(__file__).resolve().parents[1] / "ecdat"

# The frozen canonical contract (directive §5), transcribed once.
CONTRACT_FIELDS = {
    "IDENTITY": ["asset_id", "name", "type"],
    "CRYPTO": ["algorithm", "algorithm_family", "role", "primitive", "mode", "key_size",
               "security_strength", "protocol", "library", "library_version",
               "certificate"],
    "EVIDENCE": ["evidence", "evidence_type", "source", "repository", "file", "line",
                 "detector", "provenance", "confidence"],
    "BUSINESS": ["application", "owner", "business_unit", "data_classification",
                 "data_lifetime_years", "business_criticality", "exposure"],
    "SECURITY": ["classical_risk", "quantum_exposure", "risk_factors"],
    "MIGRATION": ["dependency_centrality", "crypto_agility", "interoperability",
                  "migration_effort", "migration_decision", "recommended_strategy",
                  "migration_priority", "affected_assets"],
    "GOVERNANCE": ["compliance_tags", "remediation_status", "notes"],
}

DIRECTIVE_ROLES = [
    "DIGITAL_SIGNATURE", "SIGNATURE_VERIFICATION", "KEY_ESTABLISHMENT",
    "KEY_TRANSPORT", "ENCRYPTION", "DECRYPTION", "AUTHENTICATION",
    "CERTIFICATE_VALIDATION", "HASHING", "KEY_DERIVATION", "UNKNOWN",
]


def analyse(source: str, path: str = "svc/crypto.py"):
    """Run the AST detector over a source snippet."""
    return PythonAstDetector().detect(path, source)


def role_of(dets, algorithm: str) -> str | None:
    for d in dets:
        if d.algorithm == algorithm:
            return d.role
    return None


# ======================================================================================
class TestCanonicalAssetContract(unittest.TestCase):
    """Every frozen contract field must be reachable on CryptoAsset."""

    def setUp(self):
        self.stored = {f.name for f in dataclasses.fields(M.CryptoAsset)}
        self.props = {n for n in dir(M.CryptoAsset)
                      if isinstance(getattr(M.CryptoAsset, n, None), property)}
        self.reachable = self.stored | self.props

    def test_all_44_contract_fields_present(self):
        missing = [(g, n) for g, names in CONTRACT_FIELDS.items()
                   for n in names if n not in self.reachable]
        self.assertEqual(missing, [], f"contract fields unreachable: {missing}")

    def test_contract_field_count_is_44(self):
        self.assertEqual(sum(len(v) for v in CONTRACT_FIELDS.values()), 44)

    def test_no_competing_models_exist(self):
        """Contract §5: no RiskFinding / MigrationObject / GraphCryptoAsset."""
        for banned in ("RiskFinding", "MigrationObject", "GraphCryptoAsset"):
            hits = [f.name for f in SRC_DIR.rglob("*.py")
                    if f"class {banned}" in f.read_text()]
            self.assertEqual(hits, [], f"competing model {banned} found in {hits}")

    def test_migration_decision_has_exactly_five_outcomes(self):
        self.assertEqual([d.value for d in M.MigrationDecision],
                         ["RETAIN", "HARDEN", "UPGRADE", "HYBRID", "PQC-ONLY"])

    def test_aliases_resolve_to_stored_fields(self):
        a = M.CryptoAsset(asset_id="x", asset_type=M.AssetType.SOURCE_FINDING,
                          asset_name="RSA-2048", cryptographic_role=Role.DIGITAL_SIGNATURE.value,
                          triage_notes="n", data_lifetime_years=8)
        self.assertEqual(a.name, "RSA-2048")
        self.assertEqual(a.type, M.AssetType.SOURCE_FINDING)
        self.assertEqual(a.role, Role.DIGITAL_SIGNATURE.value)
        self.assertEqual(a.notes, "n")
        self.assertEqual(a.data_lifetime, 8)

    def test_remediation_lifecycle_is_audited(self):
        a = M.CryptoAsset(asset_id="x", asset_type=M.AssetType.SOURCE_FINDING, asset_name="t")
        self.assertEqual(a.remediation_status, M.RemediationStatus.DETECTED)
        a.advance_remediation(M.RemediationStatus.ACCEPTED, actor="tester")
        a.advance_remediation(M.RemediationStatus.IN_PROGRESS, actor="tester")
        a.advance_remediation(M.RemediationStatus.ACCEPTED, actor="tester", note="rollback")
        self.assertEqual(len(a.remediation_history), 3)
        self.assertEqual([h["direction"] for h in a.remediation_history],
                         ["forward", "forward", "backward"])

    def test_override_is_recorded_and_marks_context_operator_declared(self):
        a = M.CryptoAsset(asset_id="x", asset_type=M.AssetType.SOURCE_FINDING, asset_name="t",
                          data_lifetime_years=3)
        a.set_override("data_lifetime_years", 15, actor="risk-owner", reason="archival")
        self.assertEqual(a.data_lifetime_years, 15)
        self.assertEqual(a.overrides["data_lifetime_years"]["previous"], 3)
        self.assertEqual(a.context_source, "operator-declared")


# ======================================================================================
class TestRoleVocabulary(unittest.TestCase):
    """The 12-role canonical enum must be the only live role vocabulary."""

    def test_all_directive_roles_implemented(self):
        impl = {r.name for r in Role}
        self.assertEqual([r for r in DIRECTIVE_ROLES if r not in impl], [])

    def test_extra_role_is_justified(self):
        extra = [r.name for r in Role if r.name not in DIRECTIVE_ROLES]
        self.assertEqual(extra, ["MESSAGE_AUTHENTICATION"])
        # justified only because the knowledge base actually carries MAC primitives
        macs = [s.id for s in alg.ALL_ALGORITHMS if s.primitive == "mac"]
        self.assertTrue(macs, "MESSAGE_AUTHENTICATION retained but no MAC primitives exist")

    def test_legacy_role_aliases_bind_to_canonical_values(self):
        self.assertEqual(alg.ROLE_SIGNATURE, Role.DIGITAL_SIGNATURE.value)
        self.assertEqual(alg.ROLE_HASH, Role.HASHING.value)
        self.assertEqual(alg.ROLE_MAC, Role.MESSAGE_AUTHENTICATION.value)
        self.assertEqual(alg.ROLE_KDF, Role.KEY_DERIVATION.value)
        self.assertEqual(alg.ROLE_UNKNOWN, Role.UNKNOWN.value)
        # the pre-migration literals must no longer be role values anywhere
        for dead in ("unknown-role", "mac", "kdf"):
            self.assertNotIn(dead, {r.value for r in Role})

    def test_every_spec_role_is_canonical(self):
        canonical = {r.value for r in Role}
        for spec in alg.ALL_ALGORITHMS:
            for r in spec.roles:
                self.assertIn(r, canonical, f"{spec.id} declares non-canonical role {r!r}")

    def test_roadmap_no_longer_depends_on_unknown_role_literal(self):
        src = (SRC_DIR / "analyze" / "roadmap.py").read_text()
        self.assertNotIn('"unknown-role"', src)
        self.assertNotIn("'unknown-role'", src)
        self.assertIn("Role.UNKNOWN.value", src)

    def test_no_module_emits_the_dead_unknown_role_literal(self):
        offenders = [f"{f.relative_to(SRC_DIR)}" for f in SRC_DIR.rglob("*.py")
                     if "unknown-role" in f.read_text()]
        self.assertEqual(offenders, [], f"dead role literal still present in {offenders}")


# ======================================================================================
class TestRoleInference(unittest.TestCase):
    """Dataflow role refinement must distinguish sign from verify."""

    def test_sign_yields_digital_signature(self):
        dets = analyse(
            "from cryptography.hazmat.primitives.asymmetric import rsa\n"
            "key = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"
            "sig = key.sign(payload, pad, hashes.SHA256())\n")
        self.assertEqual(role_of(dets, "rsa"), Role.DIGITAL_SIGNATURE.value)

    def test_verify_yields_signature_verification(self):
        dets = analyse(
            "from cryptography.hazmat.primitives.asymmetric import rsa\n"
            "key = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"
            "key.verify(sig, payload, pad, hashes.SHA256())\n")
        self.assertEqual(role_of(dets, "rsa"), Role.SIGNATURE_VERIFICATION.value)

    def test_decrypt_yields_decryption_not_signature(self):
        dets = analyse(
            "from cryptography.hazmat.primitives.asymmetric import rsa\n"
            "key = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"
            "pt = key.decrypt(ct, padding.OAEP(mgf, algorithm, label))\n")
        self.assertEqual(role_of(dets, "rsa"), Role.DECRYPTION.value)

    def test_exchange_yields_key_establishment(self):
        dets = analyse(
            "from cryptography.hazmat.primitives.asymmetric import x25519\n"
            "priv = x25519.X25519PrivateKey.generate()\n"
            "shared = priv.exchange(peer_public)\n")
        self.assertEqual(role_of(dets, "x25519"), Role.KEY_ESTABLISHMENT.value)

    def test_hmac_yields_message_authentication(self):
        dets = analyse("import hmac, hashlib\n"
                       "tag = hmac.new(k, msg, digestmod=hashlib.sha256)\n")
        roles = [d.role for d in dets if d.algorithm and d.algorithm.startswith("hmac")]
        self.assertIn(Role.MESSAGE_AUTHENTICATION.value, roles)

    def test_hash_yields_hashing(self):
        dets = analyse("import hashlib\nd = hashlib.sha256(b'x').hexdigest()\n")
        self.assertEqual(role_of(dets, "sha-256"), Role.HASHING.value)

    def test_unused_rsa_key_yields_unknown_not_a_guess(self):
        """The headline honesty property: no usage observed => no role claimed."""
        dets = analyse(
            "from cryptography.hazmat.primitives.asymmetric import rsa\n"
            "key = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"
            "store(key)\n")
        self.assertEqual(role_of(dets, "rsa"), Role.UNKNOWN.value)

    def test_unknown_role_blocks_a_pqc_target(self):
        """pqc.target_for must refuse to return a target for UNKNOWN."""
        self.assertIsNone(pqc.target_for(Role.UNKNOWN.value, 112))

    def test_target_dispatch_is_family_based(self):
        """KEY_TRANSPORT and SIGNATURE_VERIFICATION must route like their families."""
        kt = pqc.target_for(Role.KEY_TRANSPORT.value, 128)
        ke = pqc.target_for(Role.KEY_ESTABLISHMENT.value, 128)
        self.assertIsNotNone(kt)
        self.assertEqual(kt.primary, ke.primary)
        sv = pqc.target_for(Role.SIGNATURE_VERIFICATION.value, 128)
        ds = pqc.target_for(Role.DIGITAL_SIGNATURE.value, 128)
        self.assertIsNotNone(sv)
        self.assertEqual(sv.primary, ds.primary)
        # and a KEM is never proposed for a signature role
        self.assertNotIn("kem", ds.primary)
        self.assertIn("kem", ke.primary)

    def test_rsa_capabilities_span_families_so_never_auto_defaulted(self):
        self.assertEqual(alg.default_role(alg.get("rsa")), Role.UNKNOWN.value)

    def test_unambiguous_primitives_still_default(self):
        """Regression guard: the finer vocabulary must not flood UNKNOWN."""
        for aid, expected in [("ecdsa", Role.DIGITAL_SIGNATURE),
                              ("ed25519", Role.DIGITAL_SIGNATURE),
                              ("ecdh", Role.KEY_ESTABLISHMENT),
                              ("x25519", Role.KEY_ESTABLISHMENT),
                              ("ml-kem-768", Role.KEY_ESTABLISHMENT),
                              ("ml-dsa-65", Role.DIGITAL_SIGNATURE),
                              ("aes-256", Role.ENCRYPTION),
                              ("sha-256", Role.HASHING),
                              ("hmac-sha256", Role.MESSAGE_AUTHENTICATION),
                              ("pbkdf2", Role.KEY_DERIVATION)]:
            self.assertEqual(alg.default_role(alg.get(aid)), expected.value, aid)


# ======================================================================================
class TestNoLegacyRoleReachesDecisionLayer(unittest.TestCase):
    """End-to-end: roles crossing into the decision layer are canonical only."""

    def test_full_detector_sweep_emits_only_canonical_roles(self):
        from ecdat.detect.config import ConfigDetector
        from ecdat.detect.lexical import LexicalDetector

        canonical = {r.value for r in Role} | {None, "protocol"}
        samples = [
            ("svc/a.py", "import hashlib\nh=hashlib.md5(x)\nsig=key.sign(m)\n"),
            ("svc/b.java", 'Cipher c = Cipher.getInstance("AES/GCM/NoPadding");\n'
                           'Signature s = Signature.getInstance("SHA256withRSA");\n'),
            ("svc/c.js", "const h = crypto.createHmac('sha256', k);\n"
                         "const e = crypto.createCipheriv('aes-256-gcm', k, iv);\n"),
            ("svc/nginx.conf", "ssl_protocols TLSv1.2 TLSv1.3;\n"
                               "ssl_ciphers ECDHE-RSA-AES256-GCM-SHA384:!MD5;\n"
                               "ssl_ecdh_curve X25519MLKEM768:secp384r1;\n"),
        ]
        seen = set()
        for det in (PythonAstDetector(), ConfigDetector(), LexicalDetector()):
            for path, text in samples:
                if not det.supports(path):
                    continue
                for d in det.detect(path, text):
                    seen.add(d.role)
        self.assertTrue(seen, "detector sweep produced no roles at all")
        bad = seen - canonical
        self.assertEqual(bad, set(), f"non-canonical roles reached the decision layer: {bad}")

    def test_recommend_accepts_every_canonical_role_without_crashing(self):
        from ecdat.analyze import recommend as R
        for role in Role:
            a = M.CryptoAsset(
                asset_id="t", asset_type=M.AssetType.SOURCE_FINDING,
                asset_name="RSA-2048", algorithm="rsa", key_size=2048,
                cryptographic_role=role.value, confidence=M.Confidence.HIGH,
                data_classification=M.DataClassification.SENSITIVE,
                data_lifetime_years=10, business_criticality=M.Criticality.HIGH,
                exposure=M.Exposure.INTERNET_CRITICAL)
            rec = R.recommend(a)
            self.assertTrue(rec.action, f"no action produced for role {role.value}")
            # ML-KEM must never be offered for a signature-family role
            if alg.role_family(role.value) == "signature":
                self.assertNotIn("ML-KEM", (rec.recommended_pqc or ""),
                                 f"KEM proposed for signature role {role.value}")

    def test_unknown_role_recommendation_refuses_to_pick_a_target(self):
        from ecdat.analyze import recommend as R
        a = M.CryptoAsset(asset_id="t", asset_type=M.AssetType.SOURCE_FINDING,
                          asset_name="RSA-2048", algorithm="rsa", key_size=2048,
                          cryptographic_role=Role.UNKNOWN.value,
                          confidence=M.Confidence.HIGH)
        rec = R.recommend(a)
        self.assertEqual(rec.action, R.ACTION_DETERMINE_ROLE)
        self.assertIsNone(rec.recommended_pqc)
        self.assertIsNone(rec.recommended_hybrid)


if __name__ == "__main__":
    unittest.main(verbosity=2)
