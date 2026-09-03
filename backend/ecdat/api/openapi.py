"""A hand-authored OpenAPI 3.0 description of the ECDAT API.

Hand-authored, not generated, for the same reason the JSON-schema validator is
hand-written: it keeps the zero-third-party-dependency property. It is deliberately
partial -- it documents the shape of the key endpoints and carries worked request and
response examples, rather than exhaustively typing every field of every projection. The
canonical field set is defined by `ecdat.models`, and duplicating it here in full would
create a second description that could drift from it.

`document()` builds the spec from the live `ROUTES` table so the path list cannot fall
out of sync with what the service actually serves; the descriptions and examples are the
curated part.
"""

from __future__ import annotations

from typing import Any

from .service import API_VERSION, EXPORTS, ROUTES

_DESCRIPTION = (
    "HTTP contract over the ECDAT analytical backend. Every endpoint is a projection of "
    "the canonical Cryptographic Asset Model produced by the pipeline "
    "(Discovery -> Evidence -> Canonical Asset -> Graph -> Classical + Quantum "
    "Assessment -> Business Context / Mosca -> Migration Decision -> Migration Impact -> "
    "Roadmap -> Outputs). No endpoint computes a cryptographic fact of its own. "
    "Evidence source snippets and private-key material are never served."
)

#: Curated per-path documentation: parameters and worked examples for the endpoints a
#: UI integrator actually needs to understand. Paths not listed here still appear in the
#: spec (built from ROUTES) with their route summary.
_DOCS: dict[tuple[str, str], dict[str, Any]] = {
    ("POST", "/scan"): {
        "description": (
            "Runs the full frozen pipeline and makes the result the current scan. "
            "Synchronous. Pass `demo: true` for the bundled demo estate, or a list of "
            "directory `targets` to scan real trees. An optional `crqc_year` overrides "
            "the Mosca planning horizon (default 2035, a policy horizon and not a "
            "prediction)."),
        "requestBody": {
            "demo_scan": {"demo": True, "policy": "nist_general"},
            "target_scan": {
                "targets": ["/srv/repos/payments", "/srv/certs"],
                "estate": "/srv/estate.json",
                "policy": "nsa_cnsa2",
                "crqc_year": 2030,
            },
        },
        "response": {
            "scan_id": "scan-a1b2c3d4",
            "target": "repositories, certificates, binaries",
            "policy": "nist_general",
            "demo": True,
            "assets": 170,
            "applications": 12,
            "cbom": {"components": 182, "schema_valid": True,
                     "validation_scope": "Conformance to the vendored schema file. This "
                     "is not a CycloneDX certification and not a statement about "
                     "third-party tool acceptance."},
        },
        "errors": ["invalid_scan_target", "invalid_policy", "malformed_request",
                   "scan_in_progress"],
    },
    ("GET", "/assets"): {
        "description": (
            "The canonical inventory, filterable and paginated. Filters are equality on "
            "canonical fields (`decision`, `quantum_class`, `application`, ...); the "
            "response always carries `total`, `matched` and `truncated` so a page is "
            "never mistaken for the whole estate. `view=full` returns complete "
            "snippet-free asset records instead of the summary row."),
        "parameters": {
            "limit": "1..1000, default 100", "offset": "default 0",
            "view": "summary | full", "sort": "priority | risk | name",
            "q": "substring over name/algorithm/file",
            "decision": "RETAIN | HARDEN | UPGRADE | HYBRID | PQC-ONLY",
            "quantum_class": "e.g. shor_broken, grover_reduced, classically_broken",
            "application": "filter by application id",
        },
        "response": {
            "total": 170, "matched": 41, "count": 41, "limit": 100, "offset": 0,
            "truncated": False,
            "assets": [{
                "asset_id": "asset-7f3a20b1",
                "asset_name": "RSA-2048 (TLS server key)",
                "asset_type": "certificate",
                "quantum_class": "shor_broken",
                "quantum_exposure": "high",
                "classical_risk": "medium",
                "migration_decision": "HYBRID",
                "recommended_strategy": "ECDHE-MLKEM hybrid key agreement (RFC 10024)",
                "priority_band": "P1",
                "confidence": "high",
            }],
        },
        "errors": ["scan_not_initialized", "invalid_parameter"],
    },
    ("GET", "/assets/{asset_id}"): {
        "description": "One canonical asset as JSON, with evidence snippets removed.",
        "response": {"asset": {"asset_id": "asset-7f3a20b1",
                               "asset_name": "RSA-2048 (TLS server key)",
                               "migration_decision": "HYBRID"},
                     "redactions": {"evidence_fields_removed": ["snippet"]}},
        "errors": ["unknown_asset", "scan_not_initialized"],
    },
    ("GET", "/assets/{asset_id}/evidence"): {
        "description": (
            "Evidence provenance and confidence. Snippets are removed; detector, method, "
            "matched token and location remain so a finding stays reproducible. "
            "`proves_execution` separates reachability from mere presence."),
        "response": {
            "asset_id": "asset-7f3a20b1", "confidence": "high",
            "strongest_evidence_type": "certificate", "count": 1,
            "evidence": [{"detector": "certificate-x509", "method": "x509-parse",
                          "location": "certs/server.pem", "evidence_type": "certificate",
                          "confidence": "high", "matched": "sha256WithRSAEncryption"}],
        },
        "errors": ["unknown_asset", "scan_not_initialized"],
    },
    ("GET", "/assets/{asset_id}/graph"): {
        "description": (
            "The asset's graph neighbourhood plus its dependency centrality. Centrality "
            "counts coupled units of change (library/protocol/certificate); assets that "
            "only share an algorithm are reported separately as algorithm siblings."),
        "parameters": {"depth": "1..6, default 3"},
        "response": {"asset_id": "asset-7f3a20b1", "depth": 3,
                     "dependency_centrality": 4,
                     "graph": {"nodes": [], "edges": [],
                               "counts": {"nodes": 0, "edges": 0}}},
        "errors": ["unknown_asset", "scan_not_initialized"],
    },
    ("GET", "/assets/{asset_id}/risk"): {
        "description": (
            "Dual-axis risk. The classical axis (attackable now) and the quantum axis "
            "(harvest-now-decrypt-later) are computed independently and reported as two "
            "objects. Bands are ECDAT-derived decision support, not a compliance pass."),
        "response": {
            "asset_id": "asset-7f3a20b1",
            "classical_axis": {"classical_risk": "medium",
                               "classical_security_status": "acceptable-today"},
            "quantum_axis": {"quantum_exposure": "high", "quantum_class": "shor_broken",
                             "quantum_vulnerable": True},
            "mosca_urgency": "plan-now", "priority_band": "P1", "confidence": "high",
        },
        "errors": ["unknown_asset", "scan_not_initialized"],
    },
    ("GET", "/assets/{asset_id}/migration"): {
        "description": (
            "The two-level migration view. `migration_decision` is one of the five "
            "frozen outcomes; `recommended_strategy` is the specific standards-grounded "
            "action beneath it. The two are never collapsed into one field."),
        "response": {
            "asset_id": "asset-7f3a20b1", "migration_decision": "HYBRID",
            "recommended_strategy": "ECDHE-MLKEM hybrid key agreement (RFC 10024)",
            "recommended_pqc": "ML-KEM-768", "recommended_hybrid": "X25519MLKEM768",
            "standards": ["RFC 10024", "FIPS 203"], "crypto_agility": "medium",
            "interoperability": "negotiated",
        },
        "errors": ["unknown_asset", "scan_not_initialized"],
    },
    ("GET", "/assets/{asset_id}/impact"): {
        "description": (
            "Graph-derived migration impact: which applications, services and coupled "
            "assets change when this asset changes, what gates it, and what it gates. "
            "Every list is a graph traversal, not a manually maintained impact list."),
        "response": {
            "asset_id": "asset-7f3a20b1", "migration_decision": "HYBRID",
            "impact": {"applications": ["app-payments"], "dependent_assets": ["asset-.."],
                       "coordinated_effort_months": 6, "unblocks": [], "blockers": []},
            "headline": "1 application(s), 2 service(s), 3 coupled asset(s); 6 month(s) "
                        "coordinated",
        },
        "errors": ["unknown_asset", "scan_not_initialized"],
    },
    ("GET", "/roadmap"): {
        "description": (
            "The phased, prioritized migration roadmap. Optional `phase` and `band` "
            "filters. `items_truncated` reports how many items are summarised rather "
            "than listed inline for large estates."),
        "parameters": {"phase": "phase id, e.g. PH2", "band": "P0 | P1 | P2 | P3"},
        "response": {"totals": {"scheduled": 96, "no_action_required": 74,
                                "gating_assets": 5},
                     "phases": [{"id": "PH2", "name": "Fix now",
                                 "asset_count": 12, "items": []}]},
        "errors": ["scan_not_initialized", "unknown_phase"],
    },
    ("GET", "/dashboard"): {
        "description": "The estate roll-up a screen renders: dual-axis counts, decision "
                       "tallies, urgency, confidence and headlines. Counts only.",
        "response": {"estate": {"assets": 170, "applications": 12,
                                "business_context_defaulted": 0},
                     "classical_axis": {"medium": 40, "low": 130},
                     "quantum_axis": {"high": 60, "info": 110},
                     "migration_decisions": {"RETAIN": 74, "HYBRID": 60, "UPGRADE": 20,
                                             "HARDEN": 10, "PQC-ONLY": 6}},
        "errors": ["scan_not_initialized"],
    },
    ("GET", "/cbom"): {
        "description": (
            "The CycloneDX 1.6 CBOM for the current scan. `?summary=true` returns counts "
            "and the validation result instead of the full document; `?download=true` "
            "sets a CycloneDX content type and an attachment filename."),
        "parameters": {"summary": "true|false", "download": "true|false"},
        "response": {"bomFormat": "CycloneDX", "specVersion": "1.6",
                     "serialNumber": "urn:uuid:...", "components": ["..."]},
        "errors": ["scan_not_initialized"],
    },
    ("GET", "/cbom/validation"): {
        "description": (
            "The schema validation result, with its scope stated explicitly: conformance "
            "to the vendored CycloneDX 1.6 schema subset shipped with ECDAT. Not an "
            "external CycloneDX certification."),
        "response": {"valid": True, "errors": [], "error_count": 0,
                     "schema": "CycloneDX 1.6 (ECMA-424)",
                     "claim": "Validated against the vendored CycloneDX 1.6 schema "
                              "subset shipped with ECDAT. This is not an external "
                              "CycloneDX certification..."},
        "errors": ["scan_not_initialized"],
    },
    ("GET", "/reports"): {
        "description": "The plain-text operator report (`format=text`, default) or a "
                       "JSON envelope carrying both the dashboard and the report "
                       "(`format=json`).",
        "parameters": {"format": "text | json"},
        "errors": ["scan_not_initialized", "invalid_parameter"],
    },
    ("GET", "/exports/{name}"): {
        "description": ("Bulk exports. `name` is one of: "
                        + ", ".join(sorted(EXPORTS)) + ". An unknown name is a "
                        "malformed export request (400), not a missing page."),
        "response": "Binary/text download with a Content-Disposition attachment header.",
        "errors": ["scan_not_initialized", "malformed_export_request"],
    },
}

#: The error vocabulary, documented once. Every handler draws its `code` from here.
_ERRORS: dict[str, dict[str, Any]] = {
    "scan_not_initialized": {"status": 409,
                             "when": "No scan has been run yet. POST /scan first."},
    "unknown_asset": {"status": 404, "when": "The asset id is not in the current scan."},
    "unknown_route": {"status": 404, "when": "No route matches the path."},
    "unknown_phase": {"status": 404, "when": "No roadmap phase with that id."},
    "method_not_allowed": {"status": 405,
                           "when": "The path exists but not for that HTTP method."},
    "invalid_scan_target": {"status": 400,
                            "when": "A scan target is missing, not a directory, or the "
                            "targets list is empty."},
    "target_not_allowed": {"status": 403,
                           "when": "A scan target is outside the configured roots."},
    "invalid_policy": {"status": 400, "when": "The requested policy id is unknown."},
    "malformed_request": {"status": 400,
                          "when": "The request body is not valid JSON or not an object."},
    "malformed_export_request": {"status": 400,
                                 "when": "The export name is not one of the known "
                                 "exports."},
    "invalid_parameter": {"status": 400,
                          "when": "A query parameter is unknown or out of range."},
    "scan_in_progress": {"status": 409,
                         "when": "A second scan was requested while one was running."},
    "body_too_large": {"status": 413, "when": "The request body exceeds 1 MiB."},
    "internal_error": {"status": 500, "when": "An unexpected server-side failure."},
}


def _error_schema_ref() -> dict[str, Any]:
    return {"$ref": "#/components/schemas/Error"}


def _operation(route) -> dict[str, Any]:
    doc = _DOCS.get((route.method, route.template), {})
    op: dict[str, Any] = {
        "summary": route.summary,
        "operationId": _operation_id(route),
        "tags": [_tag(route.template)],
    }
    if "description" in doc:
        op["description"] = doc["description"]

    params = []
    for name in _path_params(route.template):
        params.append({"name": name, "in": "path", "required": True,
                       "schema": {"type": "string"},
                       "description": f"The {name}."})
    for name, desc in (doc.get("parameters") or {}).items():
        params.append({"name": name, "in": "query", "required": False,
                       "schema": {"type": "string"}, "description": desc})
    if params:
        op["parameters"] = params

    if route.method == "POST" and "requestBody" in doc:
        examples = {k: {"value": v} for k, v in doc["requestBody"].items()}
        op["requestBody"] = {
            "required": False,
            "content": {"application/json": {"examples": examples}},
        }

    ok_code = "201" if route.method == "POST" else "200"
    ok: dict[str, Any] = {"description": "Success."}
    if "response" in doc:
        ok["content"] = {"application/json": {"example": doc["response"]}}
    responses: dict[str, Any] = {ok_code: ok}
    for code in doc.get("errors", []):
        status = str(_ERRORS.get(code, {}).get("status", 400))
        responses.setdefault(status, {
            "description": _ERRORS.get(code, {}).get("when", "Error."),
            "content": {"application/json": {"schema": _error_schema_ref()}},
        })
    responses.setdefault("500", {
        "description": "Unexpected server-side failure.",
        "content": {"application/json": {"schema": _error_schema_ref()}}})
    op["responses"] = responses
    return op


def _operation_id(route) -> str:
    slug = route.template.strip("/").replace("/", "_").replace("{", "").replace("}", "")
    return f"{route.method.lower()}_{slug or 'root'}"


def _path_params(template: str) -> list[str]:
    import re
    return re.findall(r"\{(\w+)\}", template)


def _tag(template: str) -> str:
    if template.startswith("/assets"):
        return "assets"
    if template.startswith("/cbom"):
        return "cbom"
    if template.startswith("/exports"):
        return "exports"
    if template in ("/roadmap", "/dashboard", "/reports"):
        return "reporting"
    if template in ("/scan",):
        return "scan"
    return "meta"


def document() -> dict[str, Any]:
    """The full OpenAPI 3.0 document, assembled from the live route table."""
    paths: dict[str, Any] = {}
    for route in ROUTES:
        oas_path = route.template
        paths.setdefault(oas_path, {})[route.method.lower()] = _operation(route)

    return {
        "openapi": "3.0.3",
        "info": {
            "title": "ECDAT API",
            "version": API_VERSION,
            "description": _DESCRIPTION,
            "x-standards": ["FIPS 203", "FIPS 204", "FIPS 205", "NIST IR 8547 (IPD)",
                            "RFC 10024", "CycloneDX 1.6 / ECMA-424"],
            "x-honesty": [
                "Migration decisions and risk bands are ECDAT-derived decision support, "
                "not a compliance verdict.",
                "The CRQC horizon is a policy-planning year, not a prediction.",
                "CBOM validation is against a vendored schema subset, not an external "
                "certification.",
                "Business context is operator-declared; defaulted context is marked.",
            ],
        },
        "servers": [{"url": "/", "description": "This ECDAT instance."}],
        "tags": [
            {"name": "scan", "description": "Run the pipeline."},
            {"name": "assets", "description": "The canonical inventory and per-asset "
             "views: evidence, graph, risk, migration, impact."},
            {"name": "reporting", "description": "Roadmap, dashboard and report."},
            {"name": "cbom", "description": "CycloneDX 1.6 CBOM and its validation."},
            {"name": "exports", "description": "Bulk JSON and CSV downloads."},
            {"name": "meta", "description": "Index, health and this document."},
        ],
        "paths": paths,
        "components": {
            "schemas": {
                "Error": {
                    "type": "object",
                    "properties": {
                        "error": {
                            "type": "object",
                            "properties": {
                                "code": {"type": "string",
                                         "enum": sorted(_ERRORS)},
                                "message": {"type": "string"},
                                "status": {"type": "integer"},
                                "detail": {"type": "object", "nullable": True},
                            },
                            "required": ["code", "message", "status"],
                        },
                    },
                    "required": ["error"],
                },
            },
        },
        "x-errors": _ERRORS,
    }
