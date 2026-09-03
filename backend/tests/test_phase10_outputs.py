"""Phase 10 invariants: OUTPUTS are a pure projection of the canonical model.

The contract for this stage is that a CBOM, a JSON/CSV export or a report may serialise a
cryptographic fact but must never mint one, and must never leak what §30 forbids: source
code and private-key material. These tests defend exactly those properties.

The load-bearing tests are:

  * `test_every_component_traces_to_a_canonical_record` -- every component in the CBOM
    (except the estate root and declared applications) must carry a bom-ref that maps
    back to an asset in the inventory. A synthesised component is a second inventory.

  * `test_no_dependency_ref_dangles` -- every ref and every dependsOn/provides target
    must resolve to a component in the document. A dangling ref is the other way a
    second inventory sneaks in.

  * `test_generated_cbom_validates` -- the generator's output validates against the
    vendored schema, using ECDAT's own stdlib validator.

  * `test_enum_mirrors_match_the_schema` -- the enum vocabularies hard-coded in
    generate.py are asserted equal to the schema's, so they cannot drift.

  * `test_no_snippet_in_any_export` / `test_no_key_material_value_in_cbom` -- the two
    exfiltration guards.
"""

from __future__ import annotations

import csv
import io
import json
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from ecdat import export as EX
from ecdat import reports as RP
from ecdat.cbom import generate as GEN
from ecdat.cbom import validate as VAL
from ecdat.engine import Engine, demo_request
from ecdat.models import (
    AssetType, Confidence, CryptoAsset, Evidence, EvidenceType, ScanResult, ScanStats,
    stable_id,
)

_C: dict[str, object] = {}


def pipeline():
    """Full pipeline through Phase 10, run once."""
    if "e" not in _C:
        e = Engine()
        r = e.run(demo_request())
        _C["e"], _C["r"] = e, r
        _C["cbom"] = e.cbom
        _C["by"] = {a.asset_id: a for a in r.assets}
    return _C["e"], _C["r"]


# ======================================================================================
class TestCbomStructure(unittest.TestCase):

    def test_top_level_shape_is_cyclonedx_16(self):
        pipeline()
        doc = _C["cbom"]
        self.assertEqual(doc["bomFormat"], "CycloneDX")
        self.assertEqual(doc["specVersion"], "1.6")
        self.assertRegex(doc["serialNumber"],
                         r"^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
                         r"[0-9a-f]{4}-[0-9a-f]{12}$")
        self.assertGreaterEqual(doc["version"], 1)
        self.assertIn("metadata", doc)
        self.assertIn("components", doc)

    def test_metadata_carries_the_honesty_legend(self):
        """The CBOM must state, in itself, that its analysis fields are ECDAT-derived and
        not a compliance verdict (§36)."""
        pipeline()
        props = {p["name"]: p["value"] for p in _C["cbom"]["metadata"]["properties"]}
        self.assertIn("ecdat:derivation", props)
        self.assertIn("ecdat:assessment-status", props)
        joined = " ".join(props.values()).lower()
        self.assertIn("not a compliance", joined)

    def test_tool_is_identified(self):
        pipeline()
        tools = _C["cbom"]["metadata"]["tools"]["components"]
        self.assertTrue(any(t["name"] == "ECDAT" for t in tools))


class TestPureProjection(unittest.TestCase):
    """The defining property: outputs restate canonical facts, never invent them."""

    def test_every_component_traces_to_a_canonical_record(self):
        """Every crypto/library component's bom-ref must be a real asset id; every
        application component's ref must be a real app id. Nothing is synthesised."""
        e, r = pipeline()
        asset_ids = {a.asset_id for a in r.assets}
        app_ids = {app.app_id for app in r.applications}
        for comp in _C["cbom"]["components"]:
            ref = comp.get("bom-ref")
            self.assertIsNotNone(ref, comp.get("name"))
            if comp["type"] == "application":
                self.assertIn(ref, app_ids, f"fabricated application {ref}")
            else:
                self.assertIn(ref, asset_ids, f"fabricated component {ref}")

    def test_component_count_matches_inventory(self):
        """One component per asset, plus one per application. No more, no fewer."""
        e, r = pipeline()
        comps = _C["cbom"]["components"]
        asset_comps = [c for c in comps if c["type"] != "application"]
        app_comps = [c for c in comps if c["type"] == "application"]
        self.assertEqual(len(asset_comps), len(r.assets))
        self.assertEqual(len(app_comps), len(r.applications))

    def test_no_dependency_ref_dangles(self):
        """Every ref, dependsOn and provides target must resolve to a component or the
        estate root. A dangling ref would point at an inventory that isn't there."""
        e, r = pipeline()
        doc = _C["cbom"]
        known = {c["bom-ref"] for c in doc["components"]}
        known.add(doc["metadata"]["component"]["bom-ref"])       # estate root
        for dep in doc["dependencies"]:
            self.assertIn(dep["ref"], known, f"dangling ref {dep['ref']}")
            for target in dep.get("dependsOn", []) + dep.get("provides", []):
                self.assertIn(target, known, f"dangling target {target}")

    def test_crypto_properties_do_not_restate_a_new_fact(self):
        """A component's primitive/curve/mode must equal the canonical asset's, not a
        re-derived value."""
        e, r = pipeline()
        by = _C["by"]
        for comp in _C["cbom"]["components"]:
            cp = comp.get("cryptoProperties")
            if not cp or cp["assetType"] != "algorithm":
                continue
            a = by[comp["bom-ref"]]
            ap = cp.get("algorithmProperties", {})
            if "primitive" in ap and a.primitive:
                self.assertEqual(ap["primitive"], str(a.primitive).lower())
            if "curve" in ap:
                self.assertEqual(ap["curve"], a.curve)

    def test_decision_property_equals_canonical(self):
        """The migration decision carried in properties must be the canonical one."""
        e, r = pipeline()
        by = _C["by"]
        for comp in _C["cbom"]["components"]:
            if comp["type"] == "application":
                continue
            props = {p["name"]: p["value"] for p in comp.get("properties", [])}
            carried = props.get("ecdat:migration-decision")
            a = by[comp["bom-ref"]]
            canonical = a.migration_decision.value if a.migration_decision else None
            self.assertEqual(carried, canonical, a.asset_name)


class TestSchemaConformance(unittest.TestCase):

    def test_generated_cbom_validates(self):
        pipeline()
        errors = VAL.validate(_C["cbom"])
        self.assertEqual(errors, [], f"CBOM failed schema validation: {errors[:5]}")

    def test_validator_actually_rejects_malformed_documents(self):
        """A validator that passes everything is worthless. Prove it fails on real
        violations: missing required field, bad enum, extra property, bad pattern."""
        pipeline()
        base = _C["cbom"]

        missing = {k: v for k, v in base.items() if k != "specVersion"}
        self.assertTrue(VAL.validate(missing), "missing specVersion should fail")

        bad_enum = json.loads(json.dumps(base))
        for c in bad_enum["components"]:
            cp = c.get("cryptoProperties", {})
            if cp.get("assetType") == "algorithm":
                cp["algorithmProperties"]["primitive"] = "not-a-primitive"
                break
        self.assertTrue(VAL.validate(bad_enum), "bad primitive enum should fail")

        extra = json.loads(json.dumps(base))
        extra["components"][0]["totally-made-up"] = "x"
        self.assertTrue(VAL.validate(extra), "additional property should fail")

        bad_serial = json.loads(json.dumps(base))
        bad_serial["serialNumber"] = "not-a-urn-uuid"
        self.assertTrue(VAL.validate(bad_serial), "bad serialNumber should fail")

    def test_validator_raises_on_unimplemented_keyword(self):
        """The validator must refuse to silently under-validate."""
        from ecdat.cbom.validate import SchemaFeatureError, Validator
        v = Validator({"allOf": [{"type": "string"}]})
        with self.assertRaises(SchemaFeatureError):
            v.validate("x")

    def test_enum_mirrors_match_the_schema(self):
        """The enum vocabularies hard-coded in generate.py must equal the schema's, or
        the generator could emit a value it believes is legal but isn't."""
        schema = VAL.load_schema()
        cp = schema["definitions"]["cryptoProperties"]["properties"]
        ap = cp["algorithmProperties"]["properties"]

        self.assertEqual(GEN.PRIMITIVES, frozenset(ap["primitive"]["enum"]))
        self.assertEqual(GEN.MODES, frozenset(ap["mode"]["enum"]))
        self.assertEqual(GEN.PADDINGS, frozenset(ap["padding"]["enum"]))
        self.assertEqual(GEN.CRYPTO_FUNCTIONS,
                         frozenset(ap["cryptoFunctions"]["items"]["enum"]))
        self.assertEqual(GEN.ASSET_TYPES, frozenset(cp["assetType"]["enum"]))
        pp = cp["protocolProperties"]["properties"]
        self.assertEqual(GEN.PROTOCOL_TYPES, frozenset(pp["type"]["enum"]))
        rm = cp["relatedCryptoMaterialProperties"]["properties"]
        self.assertEqual(GEN.MATERIAL_TYPES, frozenset(rm["type"]["enum"]))
        self.assertEqual(GEN.MATERIAL_STATES, frozenset(rm["state"]["enum"]))

    def test_determinism(self):
        """Re-generating from the same result yields byte-identical JSON, so a CBOM can
        be diffed across scans."""
        e, r = pipeline()
        again = GEN.build(r, estate_name=e.estate.name, demo=e.estate.demo,
                          notice=e.estate.notice)
        self.assertEqual(json.dumps(_C["cbom"], sort_keys=True),
                         json.dumps(again, sort_keys=True))


class TestSecurityRedaction(unittest.TestCase):
    """§30: no source code, no key material leaves the tool."""

    def test_no_snippet_in_any_export(self):
        """Evidence snippets are scanned source. They must not appear in the JSON export."""
        e, r = pipeline()
        doc = json.loads(EX.full_json(r, roadmap=e.roadmap, impacts=e.impacts))
        for a in doc["assets"]:
            for ev in a.get("evidence", []):
                self.assertNotIn("snippet", ev, f"snippet leaked in {a['asset_id']}")

    def test_export_declares_its_redactions(self):
        e, r = pipeline()
        doc = json.loads(EX.full_json(r))
        self.assertIn("redactions", doc)
        self.assertIn("snippet", doc["redactions"]["evidence_fields_removed"])

    def test_evidence_survives_minus_the_snippet(self):
        """Redaction must not gut the evidence -- detector/method/matched stay so a
        finding is still reproducible."""
        e, r = pipeline()
        doc = json.loads(EX.full_json(r))
        with_ev = [a for a in doc["assets"] if a.get("evidence")]
        self.assertTrue(with_ev)
        sample = with_ev[0]["evidence"][0]
        self.assertIn("detector", sample)
        self.assertIn("matched", sample)

    def test_no_key_material_value_in_cbom(self):
        """relatedCryptoMaterialProperties.value must never be populated, at any
        confidence, for any asset."""
        e, r = pipeline()
        for comp in _C["cbom"]["components"]:
            cp = comp.get("cryptoProperties", {})
            if cp.get("assetType") == "related-crypto-material":
                rm = cp.get("relatedCryptoMaterialProperties", {})
                for forbidden in GEN.FORBIDDEN_MATERIAL_FIELDS:
                    self.assertNotIn(forbidden, rm,
                                     f"key material field {forbidden} leaked")

    def test_synthetic_private_key_is_metadata_only(self):
        """Build an asset that IS detected key material and confirm the CBOM records its
        presence but never a value."""
        asset = CryptoAsset(
            asset_id="km-test-0001", asset_type=AssetType.KEY_MATERIAL,
            asset_name="private key material", file="repo/secrets/id_rsa", line=1,
            primitive="private-key", key_size=2048,
            tags=["key-material-exposure"],
            evidence=[Evidence(
                detector="certificate-x509", method="pem-scan",
                location="repo/secrets/id_rsa",
                evidence_type=EvidenceType.KEY_MATERIAL, confidence=Confidence.HIGH,
                snippet="-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIB...SECRET...",
                matched="private key material")])
        result = ScanResult(
            scan_id=stable_id("kmtest", 0.0, prefix="scan"), started_at="2026-01-01",
            target="t", assets=[asset], applications=[], stats=ScanStats(),
            policy="nist_general")
        doc = GEN.build(result)
        comp = doc["components"][0]
        cp = comp["cryptoProperties"]
        self.assertEqual(cp["assetType"], "related-crypto-material")
        rm = cp["relatedCryptoMaterialProperties"]
        self.assertEqual(rm.get("state"), "compromised")     # committed to a repo
        self.assertNotIn("value", rm)
        # The secret from the snippet must appear nowhere in the serialised document.
        self.assertNotIn("SECRET", json.dumps(doc))
        self.assertNotIn("BEGIN RSA PRIVATE KEY", json.dumps(doc))


class TestExports(unittest.TestCase):

    def test_assets_csv_has_one_row_per_asset(self):
        e, r = pipeline()
        rows = list(csv.DictReader(io.StringIO(EX.assets_csv(r.assets))))
        self.assertEqual(len(rows), len(r.assets))

    def test_csv_keeps_the_two_decision_levels_separate(self):
        """migration_decision and recommended_strategy are two columns, never collapsed."""
        e, r = pipeline()
        header = EX.assets_csv(r.assets).splitlines()[0]
        self.assertIn("migration_decision", header)
        self.assertIn("recommended_strategy", header)

    def test_csv_carries_business_context_source(self):
        """A defaulted business context must be distinguishable in the flat export."""
        e, r = pipeline()
        header = EX.assets_csv(r.assets).splitlines()[0]
        self.assertIn("business_context_source", header)

    def test_roadmap_csv_row_count_matches_scheduled(self):
        e, r = pipeline()
        rows = list(csv.DictReader(io.StringIO(EX.roadmap_csv(e.roadmap))))
        self.assertEqual(len(rows), e.roadmap["totals"]["scheduled"]
                         - EX.truncated_items(e.roadmap))

    def test_impact_csv_has_one_row_per_asset(self):
        e, r = pipeline()
        rows = list(csv.DictReader(io.StringIO(EX.impact_csv(e.impacts))))
        self.assertEqual(len(rows), len(e.impacts))

    def test_csv_uses_proper_quoting(self):
        """A value with a comma must not split a column -- proof the csv module is used,
        not hand-joined strings."""
        asset = CryptoAsset(
            asset_id="q-0001", asset_type=AssetType.SOURCE_FINDING,
            asset_name="thing, with comma", algorithm_label="AES, 256")
        out = EX.assets_csv([asset])
        rows = list(csv.DictReader(io.StringIO(out)))
        self.assertEqual(rows[0]["asset_name"], "thing, with comma")


class TestDashboardAndReport(unittest.TestCase):

    def test_dashboard_counts_are_consistent(self):
        e, r = pipeline()
        d = e.dashboard()
        self.assertEqual(d["estate"]["assets"], len(r.assets))
        self.assertEqual(sum(d["migration_decisions"].values()), len(r.assets))

    def test_dashboard_separates_the_two_risk_axes(self):
        e, r = pipeline()
        d = e.dashboard()
        self.assertIn("classical_axis", d)
        self.assertIn("quantum_axis", d)
        self.assertNotEqual(d["classical_axis"], d["quantum_axis"])

    def test_report_leads_with_a_legend(self):
        e, r = pipeline()
        txt = e.text_report()
        self.assertIn("HOW TO READ THIS REPORT", txt)
        self.assertIn("not a compliance", txt.lower())

    def test_report_states_crqc_is_not_a_prediction(self):
        e, r = pipeline()
        txt = e.text_report()
        self.assertIn("not a prediction", txt.lower())

    def test_report_avoids_banned_absolutes(self):
        """§49: never 'quantum-proof', 'unbreakable', '100% accurate', 'guaranteed'."""
        e, r = pipeline()
        txt = e.text_report().lower()
        for banned in ("quantum-proof", "quantum proof", "unbreakable",
                       "100% accurate", "guaranteed secure", "unhackable",
                       "future-proof"):
            self.assertNotIn(banned, txt, f"banned absolute in report: {banned}")

    def test_dashboard_marks_defaulted_business_context(self):
        e, r = pipeline()
        d = e.dashboard()
        self.assertIn("business_context_defaulted", d["estate"])
        self.assertIn("business_context_note", d["estate"])


class TestNistCategory(unittest.TestCase):
    """The one place the generator adds a standards number, it must be honest about it."""

    def test_nist_category_only_for_known_pqc(self):
        """nistQuantumSecurityLevel appears only where the algorithm is a known PQC
        parameter set -- never fabricated for a classical algorithm."""
        e, r = pipeline()
        by = _C["by"]
        for comp in _C["cbom"]["components"]:
            cp = comp.get("cryptoProperties", {})
            ap = cp.get("algorithmProperties", {}) if cp else {}
            if "nistQuantumSecurityLevel" in ap:
                a = by[comp["bom-ref"]]
                key = str(a.algorithm or a.algorithm_label or "").lower()
                self.assertIn(key, GEN._NIST_CATEGORY,
                              f"fabricated NIST category for {a.asset_name}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
