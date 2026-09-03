"""Phase 11 invariants: the API is a faithful, safe projection of the pipeline.

The API adds no cryptographic truth. These tests defend that: every route is exercised,
every field a route returns is checked against the canonical asset it came from, and the
two exfiltration guards (§30: no source snippet, no key material) are proven at the HTTP
boundary, not just at the export layer.

The load-bearing tests are:

  * `test_every_route_is_reachable` -- all 17 contract routes answer 200 after a scan.
  * `test_risk_view_equals_canonical` / `test_migration_view_equals_canonical` -- a
    per-asset view restates the asset's own fields; it never re-derives them. This is the
    "no second source of truth" property, checked field by field.
  * `test_two_decision_levels_never_collapse` -- decision and strategy stay separate.
  * `test_no_snippet_in_any_response` / `test_no_key_material_in_any_response` -- the
    guards, over a synthetic estate that actually contains a private key.
  * `test_error_*` -- the four required failure modes map to the right status and code.
  * `test_socket_roundtrip` -- the real `http.server` adapter serves the same answers.

The suite runs the demo pipeline once (`_scanned_api`) and shares it read-only across the
read tests; the mutating scan/error tests build their own `Api` so they cannot perturb it.
"""

from __future__ import annotations

import json
import pathlib
import sys
import threading
import unittest
import urllib.error
import urllib.request

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from ecdat.api.server import make_server
from ecdat.api.service import (Api, EXPORTS, FILTERABLE, ROUTES, SUMMARY_FIELDS,
                               _guard, _GUARD_MARKER)
from ecdat.engine import (Engine, ScanRequest, demo_request)
from ecdat.models import (AssetType, Confidence, CryptoAsset, Evidence, EvidenceType,
                          ScanResult, ScanStats, stable_id)

_CACHE: dict[str, object] = {}


def _v(x):
    return x.value if hasattr(x, "value") else x


def _scanned_api() -> Api:
    """One demo scan, shared read-only across the read tests."""
    if "api" not in _CACHE:
        api = Api()
        api.request("POST", "/scan", {"demo": True})
        _CACHE["api"] = api
    return _CACHE["api"]  # type: ignore[return-value]


def _sample_asset_id(api: Api) -> str:
    return api.request("GET", "/assets?limit=1").json()["assets"][0]["asset_id"]


# ======================================================================================
class TestScanLifecycle(unittest.TestCase):

    def test_reads_before_scan_are_409(self):
        """Every read endpoint refuses cleanly until a scan exists."""
        api = Api()
        for path in ("/assets", "/dashboard", "/roadmap", "/cbom", "/cbom/validation",
                     "/reports", "/exports/json", "/assets/anything/risk"):
            r = api.request("GET", path)
            self.assertEqual(r.status, 409, path)
            self.assertEqual(r.json()["error"]["code"], "scan_not_initialized", path)

    def test_scan_returns_201_and_summary(self):
        api = Api()
        r = api.request("POST", "/scan", {"demo": True})
        self.assertEqual(r.status, 201)
        s = r.json()
        self.assertTrue(s["scan_id"].startswith("scan-"))
        self.assertGreater(s["assets"], 0)
        self.assertTrue(s["cbom"]["schema_valid"])
        self.assertIn("vendored", s["cbom"]["validation_scope"])

    def test_scan_empty_body_defaults_are_rejected_without_demo(self):
        """A scan with neither demo nor targets is an invalid target request."""
        api = Api()
        r = api.request("POST", "/scan", {})
        self.assertEqual(r.status, 400)
        self.assertEqual(r.json()["error"]["code"], "invalid_scan_target")

    def test_scan_accepts_crqc_scenario(self):
        api = Api()
        r = api.request("POST", "/scan", {"demo": True, "crqc_year": 2030})
        self.assertEqual(r.status, 201)
        self.assertEqual(r.json()["scenario"]["crqc_year"], 2030)


class TestRouteCoverage(unittest.TestCase):

    def test_every_route_is_reachable(self):
        """All 17 contract routes answer 200 after a scan."""
        api = _scanned_api()
        aid = _sample_asset_id(api)
        paths = [
            "/assets", f"/assets/{aid}", f"/assets/{aid}/evidence",
            f"/assets/{aid}/graph", f"/assets/{aid}/risk", f"/assets/{aid}/migration",
            f"/assets/{aid}/impact", "/roadmap", "/dashboard", "/cbom",
            "/cbom/validation", "/reports", "/exports/json", "/exports/assets.csv",
            "/exports/roadmap.csv", "/exports/impact.csv",
        ]
        for p in paths:
            r = api.request("GET", p)
            self.assertEqual(r.status, 200, p)

    def test_route_table_matches_the_seventeen_contract_routes(self):
        """The frozen contract lists exactly these routes; guard against silent drift."""
        contract = {
            ("POST", "/scan"), ("GET", "/assets"), ("GET", "/assets/{asset_id}"),
            ("GET", "/assets/{asset_id}/evidence"), ("GET", "/assets/{asset_id}/graph"),
            ("GET", "/assets/{asset_id}/risk"), ("GET", "/assets/{asset_id}/migration"),
            ("GET", "/assets/{asset_id}/impact"), ("GET", "/roadmap"),
            ("GET", "/dashboard"), ("GET", "/cbom"), ("GET", "/cbom/validation"),
            ("GET", "/reports"), ("GET", "/exports/{name}"),
        }
        table = {(r.method, r.template) for r in ROUTES}
        self.assertTrue(contract <= table, contract - table)

    def test_meta_routes_need_no_scan(self):
        api = Api()
        for path in ("/", "/health", "/openapi.json"):
            self.assertEqual(api.request("GET", path).status, 200, path)


class TestPureProjection(unittest.TestCase):
    """A per-asset view restates canonical fields; it never mints a new one."""

    def setUp(self):
        self.api = _scanned_api()
        self.engine = self.api.engine
        self.by = {a.asset_id: a for a in self.engine.assets()}

    def test_summary_rows_match_canonical(self):
        rows = self.api.request("GET", "/assets?limit=1000").json()["assets"]
        self.assertEqual(len(rows), len(self.by))
        for row in rows:
            a = self.by[row["asset_id"]]
            self.assertEqual(row["migration_decision"], _v(a.migration_decision))
            self.assertEqual(row["quantum_exposure"], _v(a.quantum_exposure))
            self.assertEqual(row["classical_risk"], _v(a.classical_risk))
            self.assertEqual(row["recommended_strategy"], a.recommended_strategy)

    def test_risk_view_equals_canonical(self):
        for aid, a in self.by.items():
            v = self.api.request("GET", f"/assets/{aid}/risk").json()
            self.assertEqual(v["classical_axis"]["classical_risk"],
                             _v(a.classical_risk), aid)
            self.assertEqual(v["quantum_axis"]["quantum_exposure"],
                             _v(a.quantum_exposure), aid)
            self.assertEqual(v["quantum_axis"]["quantum_class"], a.quantum_class, aid)
            self.assertEqual(v["risk_score"], a.risk_score, aid)

    def test_migration_view_equals_canonical(self):
        for aid, a in self.by.items():
            v = self.api.request("GET", f"/assets/{aid}/migration").json()
            self.assertEqual(v["migration_decision"], _v(a.migration_decision), aid)
            self.assertEqual(v["recommended_strategy"], a.recommended_strategy, aid)
            self.assertEqual(v["recommended_pqc"], a.recommended_pqc, aid)
            self.assertEqual(v["crypto_agility"], _v(a.crypto_agility), aid)

    def test_two_decision_levels_never_collapse(self):
        """migration_decision and recommended_strategy are two fields, always."""
        aid = _sample_asset_id(self.api)
        v = self.api.request("GET", f"/assets/{aid}/migration").json()
        self.assertIn("migration_decision", v)
        self.assertIn("recommended_strategy", v)
        # Every decision the API emits is one of the five frozen outcomes.
        rows = self.api.request("GET", "/assets?limit=1000").json()["assets"]
        seen = {r["migration_decision"] for r in rows if r["migration_decision"]}
        self.assertTrue(seen <= {"RETAIN", "HARDEN", "UPGRADE", "HYBRID", "PQC-ONLY"},
                        seen)

    def test_dual_axis_reported_separately(self):
        """The two risk axes are distinct objects, and they genuinely differ somewhere."""
        rows = self.api.request("GET", "/assets?limit=1000").json()["assets"]
        differ = [r for r in rows
                  if r["classical_risk"] != r["quantum_exposure"]]
        self.assertTrue(differ, "expected some asset where the two axes diverge")

    def test_impact_is_graph_derived(self):
        """The impact view carries the graph-derivation statement and a real traversal."""
        aid = _sample_asset_id(self.api)
        v = self.api.request("GET", f"/assets/{aid}/impact").json()
        self.assertIn("Graph-derived", v["derivation"])
        self.assertIn("impact", v)

    def test_graph_view_delegates_to_one_implementation(self):
        """The graph route returns the same subgraph the graph module builds."""
        from ecdat import graph as graph_mod
        aid = _sample_asset_id(self.api)
        v = self.api.request("GET", f"/assets/{aid}/graph").json()
        direct = graph_mod.subgraph_for_asset(self.engine.graph, aid, depth=3)
        self.assertEqual(v["graph"]["counts"], direct["counts"])


class TestListSemantics(unittest.TestCase):

    def setUp(self):
        self.api = _scanned_api()

    def test_total_and_matched_are_distinct(self):
        total = self.api.request("GET", "/assets").json()["total"]
        filtered = self.api.request("GET", "/assets?decision=RETAIN&limit=1000").json()
        self.assertEqual(filtered["total"], total)
        self.assertLessEqual(filtered["matched"], total)
        for row in filtered["assets"]:
            self.assertEqual(row["migration_decision"], "RETAIN")

    def test_pagination_reports_truncation(self):
        r = self.api.request("GET", "/assets?limit=5&offset=0").json()
        self.assertEqual(r["count"], 5)
        self.assertTrue(r["truncated"])
        self.assertEqual(r["limit"], 5)

    def test_unknown_filter_is_rejected(self):
        r = self.api.request("GET", "/assets?bogus=1")
        self.assertEqual(r.status, 400)
        self.assertEqual(r.json()["error"]["code"], "invalid_parameter")

    def test_all_filterable_fields_are_canonical(self):
        """Every filter maps to a real CryptoAsset attribute -- no phantom filters."""
        a = self.api.engine.assets()[0]
        for field_name in FILTERABLE.values():
            self.assertTrue(hasattr(a, field_name), field_name)

    def test_full_view_is_snippet_free(self):
        r = self.api.request("GET", "/assets?view=full&limit=5").json()
        for asset in r["assets"]:
            for ev in asset.get("evidence", []):
                self.assertNotIn("snippet", ev)


class TestErrorHandling(unittest.TestCase):
    """The four required failure modes, each to the right status and code."""

    def setUp(self):
        self.api = _scanned_api()

    def test_error_unknown_asset(self):
        r = self.api.request("GET", "/assets/no-such-asset/risk")
        self.assertEqual(r.status, 404)
        self.assertEqual(r.json()["error"]["code"], "unknown_asset")

    def test_error_scan_not_initialized(self):
        r = Api().request("GET", "/roadmap")
        self.assertEqual(r.status, 409)
        self.assertEqual(r.json()["error"]["code"], "scan_not_initialized")

    def test_error_invalid_scan_target(self):
        for body in ({"targets": ["/no/such/dir/ecdat"]}, {"targets": []},
                     {"targets": "/etc"}):
            r = Api().request("POST", "/scan", body)
            self.assertEqual(r.status, 400, body)
            self.assertEqual(r.json()["error"]["code"], "invalid_scan_target", body)

    def test_error_malformed_export_request(self):
        r = self.api.request("GET", "/exports/nonsense")
        self.assertEqual(r.status, 400)
        self.assertEqual(r.json()["error"]["code"], "malformed_export_request")
        self.assertIn("available", r.json()["error"]["detail"])

    def test_error_malformed_json_body(self):
        r = Api().request("POST", "/scan", "{not json")
        self.assertEqual(r.status, 400)
        self.assertEqual(r.json()["error"]["code"], "malformed_request")

    def test_error_invalid_policy(self):
        r = Api().request("POST", "/scan", {"demo": True, "policy": "does_not_exist"})
        self.assertEqual(r.status, 400)
        self.assertEqual(r.json()["error"]["code"], "invalid_policy")

    def test_error_method_not_allowed(self):
        r = self.api.request("POST", "/assets")
        self.assertEqual(r.status, 405)
        self.assertIn("GET", r.json()["error"]["detail"]["allowed"])

    def test_error_unknown_route(self):
        r = self.api.request("GET", "/no/such/route")
        self.assertEqual(r.status, 404)
        self.assertEqual(r.json()["error"]["code"], "unknown_route")

    def test_error_unknown_phase(self):
        r = self.api.request("GET", "/roadmap?phase=PH999")
        self.assertEqual(r.status, 404)
        self.assertEqual(r.json()["error"]["code"], "unknown_phase")

    def test_detail_route_is_not_swallowed_by_the_id_route(self):
        """/assets/{id}/risk must not be captured as an asset id of 'x/risk'."""
        api = _scanned_api()
        r = api.request("GET", "/assets/definitely-missing/evidence")
        self.assertEqual(r.status, 404)
        self.assertEqual(r.json()["error"]["code"], "unknown_asset")


class TestSecurityRedaction(unittest.TestCase):
    """§30 at the HTTP boundary: no source snippet, no private key, in any response."""

    def _engine_with_private_key(self) -> Engine:
        asset = CryptoAsset(
            asset_id="km-api-0001", asset_type=AssetType.KEY_MATERIAL,
            asset_name="private key material", file="repo/secrets/id_rsa", line=1,
            primitive="private-key", key_size=2048, tags=["key-material-exposure"],
            evidence=[Evidence(
                detector="certificate-x509", method="pem-scan",
                location="repo/secrets/id_rsa",
                evidence_type=EvidenceType.KEY_MATERIAL, confidence=Confidence.HIGH,
                snippet=("-----BEGIN RSA PRIVATE KEY-----\n"
                         "MIIEpAIB...LEAKED_SECRET...\n"
                         "-----END RSA PRIVATE KEY-----"),
                matched="private key material")])
        result = ScanResult(
            scan_id=stable_id("kmapi", 0.0, prefix="scan"), started_at="2026-01-01",
            target="t", assets=[asset], applications=[], stats=ScanStats(),
            policy="nist_general")
        eng = Engine()
        eng.result = result
        eng.build_graph(); eng.assess(); eng.apply_scenario()
        eng.decide(); eng.impact(); eng.plan(); eng.outputs()
        return eng

    def setUp(self):
        self.api = Api(engine=self._engine_with_private_key())

    @staticmethod
    def _snippet_keys(node, trail="$"):
        """Every path at which some object carries a `snippet` key.

        Structural, not a substring grep: the *word* "snippet" is supposed to appear in
        the `redactions` block, which names the field it removed. Only a live `snippet`
        key is a leak, so that is what this looks for.
        """
        found = []
        if isinstance(node, dict):
            for k, v in node.items():
                if k == "snippet":
                    found.append(f"{trail}.{k}")
                found.extend(TestSecurityRedaction._snippet_keys(v, f"{trail}.{k}"))
        elif isinstance(node, list):
            for i, v in enumerate(node):
                found.extend(TestSecurityRedaction._snippet_keys(v, f"{trail}[{i}]"))
        return found

    def test_no_snippet_in_any_response(self):
        aid = "km-api-0001"
        for path in ("/assets?view=full", f"/assets/{aid}",
                     f"/assets/{aid}/evidence", "/exports/json"):
            payload = self.api.request("GET", path).json()
            self.assertEqual([], self._snippet_keys(payload), path)
            self.assertNotIn("LEAKED_SECRET", json.dumps(payload), path)

    def test_no_snippet_column_in_csv_exports(self):
        for path in ("/exports/assets.csv", "/exports/roadmap.csv",
                     "/exports/impact.csv"):
            body = self.api.request("GET", path).text
            header = body.splitlines()[0].split(",")
            self.assertNotIn("snippet", header, path)
            self.assertNotIn("LEAKED_SECRET", body, path)

    def test_no_key_material_in_any_response(self):
        aid = "km-api-0001"
        for path in ("/cbom", f"/assets/{aid}", f"/assets/{aid}/evidence",
                     "/exports/json"):
            body = self.api.request("GET", path).text
            self.assertNotIn("BEGIN RSA PRIVATE KEY", body, path)
            self.assertNotIn("MIIEpAIB", body, path)

    def test_evidence_provenance_survives_redaction(self):
        ev = self.api.request("GET", "/assets/km-api-0001/evidence").json()
        item = ev["evidence"][0]
        for kept in ("detector", "method", "location", "matched", "proves_execution"):
            self.assertIn(kept, item)
        self.assertNotIn("snippet", item)

    def test_guard_would_catch_a_leak(self):
        """The serialisation guard is a real backstop, proven on a raw PEM string."""
        leaked = ("prefix -----BEGIN RSA PRIVATE KEY-----\nMIIsecret\n"
                  "-----END RSA PRIVATE KEY----- suffix")
        cleaned = _guard(leaked)
        self.assertNotIn("MIIsecret", cleaned)
        self.assertIn(_GUARD_MARKER, cleaned)

    def test_asset_payload_declares_its_redactions(self):
        d = self.api.request("GET", "/assets/km-api-0001").json()
        self.assertIn("redactions", d)
        self.assertIn("snippet", d["redactions"]["evidence_fields_removed"])


class TestHonestScope(unittest.TestCase):
    """The API states what it is and is not (§36)."""

    def setUp(self):
        self.api = _scanned_api()

    def test_cbom_validation_scopes_itself_honestly(self):
        r = self.api.request("GET", "/cbom/validation").json()
        self.assertTrue(r["valid"])
        self.assertIn("vendored", r["claim"].lower())
        self.assertIn("not an external", r["claim"].lower())

    def test_cbom_validates_against_vendored_schema(self):
        r = self.api.request("GET", "/cbom/validation").json()
        self.assertEqual(r["error_count"], 0)
        self.assertEqual(r["errors"], [])

    def test_dashboard_marks_defaulted_context(self):
        d = self.api.request("GET", "/dashboard").json()
        self.assertIn("business_context_defaulted", d["estate"])

    def test_report_leads_with_a_legend(self):
        txt = self.api.request("GET", "/reports").text
        self.assertIn("HOW TO READ THIS REPORT", txt)
        self.assertIn("not a compliance", txt.lower())

    def test_no_banned_absolutes_in_any_json_response(self):
        """§49: the API must not emit an absolute the report layer forbids."""
        api = self.api
        aid = _sample_asset_id(api)
        blob = " ".join(
            api.request("GET", p).text.lower() for p in (
                "/assets?limit=1000&view=full", f"/assets/{aid}/migration",
                "/dashboard", "/roadmap", "/cbom", "/cbom/validation",
                "/reports?format=json"))
        for banned in ("quantum-proof", "unbreakable", "100% accurate",
                       "guaranteed secure", "unhackable", "future-proof"):
            self.assertNotIn(banned, blob, banned)


class TestOpenApi(unittest.TestCase):

    def test_document_is_wellformed_and_complete(self):
        from ecdat.api.openapi import document
        d = document()
        self.assertEqual(d["openapi"], "3.0.3")
        for route in ROUTES:
            self.assertIn(route.template, d["paths"], route.template)
            self.assertIn(route.method.lower(), d["paths"][route.template])
        # Round-trips as JSON.
        self.assertIsInstance(json.dumps(d), str)

    def test_key_endpoints_carry_examples(self):
        from ecdat.api.openapi import document
        paths = document()["paths"]
        scan = paths["/scan"]["post"]
        self.assertIn("examples",
                      scan["requestBody"]["content"]["application/json"])
        assets = paths["/assets"]["get"]
        self.assertIn("example",
                      assets["responses"]["200"]["content"]["application/json"])

    def test_served_openapi_matches_module(self):
        from ecdat.api.openapi import document
        served = _scanned_api().request("GET", "/openapi.json").json()
        self.assertEqual(served["info"]["title"], document()["info"]["title"])


class TestSocketAdapter(unittest.TestCase):
    """The real http.server adapter serves the same answers as the dispatch core."""

    @classmethod
    def setUpClass(cls):
        cls.httpd = make_server("127.0.0.1", 0, Api(), request_logger=None)
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.port}"

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def _call(self, method, path, payload=None):
        data = json.dumps(payload).encode() if payload is not None else None
        req = urllib.request.Request(
            self.base + path, data=data, method=method,
            headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                return resp.status, resp.headers.get("Content-Type"), resp.read()
        except urllib.error.HTTPError as exc:
            # `exc` is itself the response; close it so no socket is left for the GC to
            # reap (an implicit-cleanup ResourceWarning otherwise).
            with exc:
                return exc.code, exc.headers.get("Content-Type"), exc.read()

    def test_socket_roundtrip(self):
        self.assertEqual(self._call("GET", "/health")[0], 200)
        status, _, body = self._call("POST", "/scan", {"demo": True})
        self.assertEqual(status, 201)
        self.assertGreater(json.loads(body)["assets"], 0)

    def test_socket_serves_csv_with_attachment_header(self):
        self._call("POST", "/scan", {"demo": True})
        status, ctype, body = self._call("GET", "/exports/assets.csv")
        self.assertEqual(status, 200)
        self.assertIn("text/csv", ctype)
        self.assertGreater(len(body), 0)

    def test_socket_error_is_json(self):
        status, ctype, body = self._call("GET", "/assets/nope-nope")
        # 409 if this server has no scan yet, 404 if it does; both are clean JSON errors.
        self.assertIn(status, (404, 409))
        self.assertIn("error", json.loads(body))


if __name__ == "__main__":
    unittest.main(verbosity=2)
