"""Routing and handlers: the API surface, with no socket anywhere in it.

A request here is a plain `(method, path, query, body)` tuple and a response is a
`Response` object. That makes every route testable without binding a port, and it means
the transport is a detail -- `ecdat.api.server` is one adapter over `Api.handle`, and an
ASGI/FastAPI adapter would be another, calling exactly the same function.

Three rules hold across every handler and are the reason this file is thin:

  1. NO SECOND SOURCE OF TRUTH. A handler shapes an answer the pipeline already
     computed. It never scores risk, never picks a migration strategy, never walks the
     graph itself. Everything goes through `Engine` accessors, so `/assets/{id}/risk` and
     the CSV export cannot disagree about the same asset.
  2. NO SOURCE CODE, NO KEY MATERIAL. Asset payloads go through `export.asset_json`,
     which drops `Evidence.snippet`. `_guard` is the belt-and-braces check at the
     serialisation boundary: if PEM key material ever reached a response body it would be
     replaced by a marker rather than served (§30).
  3. HONEST SCOPE. `/cbom/validation` reports conformance to the *vendored* schema file
     and says so; nothing here claims external CycloneDX certification.

Scan lifecycle: one current scan per process. `POST /scan` builds a *fresh* `Engine` and
swaps it in only once the pipeline has finished, so a reader mid-scan sees the previous
complete inventory rather than a half-built one. Reads take no lock; a second concurrent
scan is rejected with 409 rather than queued.
"""

from __future__ import annotations

import json
import os
import re
import threading
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Callable

from .. import export as export_mod
from ..analyze import mosca as mosca_mod
from ..engine import Engine, Estate, ScanRequest, demo_request
from ..knowledge import pqc

API_VERSION = "1.0.0"

#: The maximum number of assets a single `/assets` page will inline. A list endpoint that
#: silently caps is a list endpoint that overstates its coverage, so the response always
#: carries `total`/`count`/`truncated` alongside the rows.
DEFAULT_PAGE = 100
MAX_PAGE = 1000
MAX_BODY_BYTES = 1 << 20            # 1 MiB; a scan request is a few hundred bytes

#: Serialisation-boundary guard. A PEM private key must never appear in a response body.
#: Two patterns, in order, because a leaked key can arrive either whole or truncated (an
#: evidence snippet is clipped mid-body and so has no END armour). A single non-greedy
#: pattern with an optional END would match the header alone and leave the key bytes.
_PEM_BLOCK_RX = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?"
    r"-----END [A-Z0-9 ]*PRIVATE KEY-----")
_PEM_HEAD_RX = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[A-Za-z0-9+/=\s\\.-]*")
_GUARD_MARKER = "[REDACTED: private key material -- ECDAT never emits key bytes]"


def _v(x: Any) -> Any:
    return x.value if hasattr(x, "value") else x


# ======================================================================================
# Errors
# ======================================================================================
class ApiError(Exception):
    """A deliberate, reportable failure. Anything else becomes a 500."""

    def __init__(self, status: int, code: str, message: str,
                 detail: Any = None) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message
        self.detail = detail

    def body(self) -> dict[str, Any]:
        d: dict[str, Any] = {"error": {"code": self.code, "message": self.message,
                                       "status": self.status}}
        if self.detail is not None:
            d["error"]["detail"] = self.detail
        return d


def _unknown_asset(asset_id: str) -> ApiError:
    return ApiError(404, "unknown_asset",
                    f"No asset with id '{asset_id}' in the current scan.",
                    {"hint": "GET /assets lists the ids in the current inventory."})


def _no_scan() -> ApiError:
    return ApiError(409, "scan_not_initialized",
                    "No scan has been run in this process yet.",
                    {"hint": "POST /scan first, e.g. {\"demo\": true}."})


# ======================================================================================
# Response
# ======================================================================================
@dataclass
class Response:
    status: int = 200
    body: bytes = b""
    content_type: str = "application/json"
    headers: dict[str, str] = field(default_factory=dict)

    @property
    def text(self) -> str:
        return self.body.decode("utf-8")

    def json(self) -> Any:
        return json.loads(self.body.decode("utf-8"))


def _guard(text: str) -> str:
    """Replace any PEM private-key block that somehow reached a response body.

    This should never fire: snippets are dropped by `export.asset_json` and the CBOM
    generator never emits `relatedCryptoMaterialProperties.value`. It exists because the
    cost of being wrong once is leaking a key, and the cost of the check is a regex scan.

    Whole blocks go first, then any surviving BEGIN header takes its trailing base64 body
    with it -- a clipped snippet has no END armour, and redacting the header alone would
    leave exactly the bytes that matter.
    """
    if "PRIVATE KEY-----" not in text:
        return text
    text = _PEM_BLOCK_RX.sub(_GUARD_MARKER, text)
    return _PEM_HEAD_RX.sub(_GUARD_MARKER, text)


def json_response(payload: Any, status: int = 200, indent: int | None = 2,
                  headers: dict[str, str] | None = None) -> Response:
    text = _guard(json.dumps(payload, indent=indent, default=str))
    return Response(status=status, body=text.encode("utf-8"),
                    content_type="application/json; charset=utf-8",
                    headers=dict(headers or {}))


def text_response(payload: str, status: int = 200,
                  content_type: str = "text/plain; charset=utf-8",
                  headers: dict[str, str] | None = None) -> Response:
    return Response(status=status, body=_guard(payload).encode("utf-8"),
                    content_type=content_type, headers=dict(headers or {}))


def csv_response(payload: str, filename: str) -> Response:
    return text_response(
        payload, content_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'})


# ======================================================================================
# Query helpers
# ======================================================================================
def _one(query: dict[str, list[str]], name: str, default: str | None = None
         ) -> str | None:
    values = query.get(name)
    return values[0] if values else default


def _int(query: dict[str, list[str]], name: str, default: int,
         low: int, high: int) -> int:
    raw = _one(query, name)
    if raw is None or raw == "":
        return default
    try:
        n = int(raw)
    except ValueError:
        raise ApiError(400, "invalid_parameter",
                       f"Query parameter '{name}' must be an integer.",
                       {"received": raw})
    if not low <= n <= high:
        raise ApiError(400, "invalid_parameter",
                       f"Query parameter '{name}' must be between {low} and {high}.",
                       {"received": n})
    return n


def _bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("1", "true", "yes", "on")


# ======================================================================================
# Asset projections
# ======================================================================================
#: The `/assets` list row. Explicit rather than reflective for the same reason the CSV
#: column list is: a new canonical field must not silently reshape a client's contract.
#: It carries BOTH decision levels, because collapsing them is the one thing the frozen
#: model forbids.
SUMMARY_FIELDS: tuple[str, ...] = (
    "asset_id", "asset_name", "asset_type", "application", "owner", "business_unit",
    "file", "line", "algorithm_label", "algorithm_family", "primitive", "key_size",
    "curve", "cryptographic_role", "protocol", "protocol_version", "library",
    "classical_risk", "classical_security_status", "quantum_exposure", "quantum_class",
    "quantum_vulnerable", "risk_score", "mosca_urgency", "priority_band",
    "migration_priority", "migration_decision", "recommended_strategy",
    "recommended_pqc", "recommended_hybrid", "migration_effort", "migration_months",
    "crypto_agility", "interoperability", "dependency_centrality", "confidence",
    "confidence_score", "evidence_type", "context_source", "triage_state",
)


def summary_row(asset: Any) -> dict[str, Any]:
    row = {name: _v(getattr(asset, name, None)) for name in SUMMARY_FIELDS}
    row["evidence_count"] = len(asset.evidence or [])
    row["detectors"] = list(asset.detectors or [])
    return row


def _matches(asset: Any, filters: dict[str, str]) -> bool:
    """Filtering is field equality on canonical values -- never a re-derivation."""
    for name, wanted in filters.items():
        actual = _v(getattr(asset, name, None))
        if str(actual).lower() != wanted.lower():
            return False
    return True


#: query parameter -> canonical field. Only canonical fields are filterable, so a filter
#: can never select on something the inventory does not actually record.
FILTERABLE = {
    "application": "application",
    "asset_type": "asset_type",
    "decision": "migration_decision",
    "strategy": "recommended_strategy",
    "classical_risk": "classical_risk",
    "quantum_exposure": "quantum_exposure",
    "quantum_class": "quantum_class",
    "urgency": "mosca_urgency",
    "band": "priority_band",
    "confidence": "confidence",
    "agility": "crypto_agility",
    "interoperability": "interoperability",
    "owner": "owner",
    "library": "library",
    "context_source": "context_source",
}


# ======================================================================================
# The API
# ======================================================================================
class Api:
    """Holds the current scan and answers requests against it.

    `allowed_roots`, when set, confines `POST /scan` targets to those directories. It is
    off by default because the tool is normally driven by the operator who owns the
    machine; set it whenever the socket is reachable by anyone else.
    """

    def __init__(self, engine: Engine | None = None,
                 allowed_roots: list[str] | None = None) -> None:
        self.engine = engine
        self.allowed_roots = [os.path.abspath(r) for r in (allowed_roots or [])]
        self._scan_lock = threading.Lock()
        self.last_scan: dict[str, Any] | None = None

    # ---------------------------------------------------------------------------------
    def require_engine(self) -> Engine:
        engine = self.engine
        if engine is None or engine.result is None:
            raise _no_scan()
        return engine

    def require_asset(self, asset_id: str):
        engine = self.require_engine()
        asset = engine.asset(asset_id)
        if asset is None:
            raise _unknown_asset(asset_id)
        return engine, asset

    # ---------------------------------------------------------------------------------
    # Dispatch
    # ---------------------------------------------------------------------------------
    def handle(self, method: str, path: str, query: dict[str, list[str]] | None = None,
               body: bytes | str | None = None) -> Response:
        """The socket-free entry point. Never raises for an expected failure."""
        method = (method or "GET").upper()
        path = self._normalise(path)
        query = query or {}
        try:
            handler = self._match(method, path)
            return handler(self, path, query, body)
        except ApiError as exc:
            return json_response(exc.body(), status=exc.status)
        except Exception as exc:                       # noqa: BLE001 -- boundary
            # The message is included because this is an operator-run local tool and a
            # silent 500 wastes their time; it is not exposed to an untrusted network.
            return json_response(
                {"error": {"code": "internal_error", "status": 500,
                           "message": f"{type(exc).__name__}: {exc}"}}, status=500)

    def request(self, method: str, target: str, body: Any = None) -> Response:
        """Convenience for tests and scripts: `api.request('GET', '/assets?limit=5')`."""
        parsed = urllib.parse.urlsplit(target)
        query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        if body is not None and not isinstance(body, (bytes, str)):
            body = json.dumps(body)
        return self.handle(method, parsed.path, query, body)

    @staticmethod
    def _normalise(path: str) -> str:
        path = urllib.parse.unquote(path or "/")
        if len(path) > 1 and path.endswith("/"):
            path = path.rstrip("/") or "/"
        return path

    def _match(self, method: str, path: str) -> Callable:
        allowed: set[str] = set()
        for route in ROUTES:
            m = route.pattern.match(path)
            if not m:
                continue
            allowed.add(route.method)
            if route.method == method:
                groups = m.groupdict()
                if groups:
                    return lambda api, p, q, b, _h=route.handler, _g=groups: _h(
                        api, q, b, **_g)
                return lambda api, p, q, b, _h=route.handler: _h(api, q, b)
        if allowed:
            raise ApiError(405, "method_not_allowed",
                           f"{method} is not supported on {path}.",
                           {"allowed": sorted(allowed)})
        raise ApiError(404, "unknown_route", f"No route for {path}.",
                       {"hint": "GET / lists every available route."})


# ======================================================================================
# Handlers -- each shapes canonical data, none computes it
# ======================================================================================
def h_index(api: Api, query, body) -> Response:
    return json_response({
        "service": "ECDAT API",
        "api_version": API_VERSION,
        "scan_loaded": api.engine is not None and api.engine.result is not None,
        "routes": [{"method": r.method, "path": r.template, "summary": r.summary}
                   for r in ROUTES],
        "notes": [
            "Every endpoint is a projection of the canonical Cryptographic Asset Model. "
            "No endpoint computes a cryptographic fact of its own.",
            "Evidence snippets and private-key material are never served (§30).",
        ],
    })


def h_health(api: Api, query, body) -> Response:
    engine = api.engine
    return json_response({
        "status": "ok",
        "api_version": API_VERSION,
        "scan_loaded": engine is not None and engine.result is not None,
        "scan_id": engine.result.scan_id if engine and engine.result else None,
        "assets": len(engine.assets()) if engine else 0,
    })


def h_openapi(api: Api, query, body) -> Response:
    from .openapi import document
    return json_response(document())


# --------------------------------------------------------------------------------------
def _parse_scan_body(body: bytes | str | None) -> dict[str, Any]:
    if body is None or body == b"" or body == "":
        return {}
    if isinstance(body, bytes):
        if len(body) > MAX_BODY_BYTES:
            raise ApiError(413, "body_too_large",
                           f"Request body exceeds {MAX_BODY_BYTES} bytes.")
        try:
            body = body.decode("utf-8")
        except UnicodeDecodeError:
            raise ApiError(400, "malformed_request",
                           "Request body is not valid UTF-8.")
    try:
        data = json.loads(body)
    except json.JSONDecodeError as exc:
        raise ApiError(400, "malformed_request",
                       f"Request body is not valid JSON: {exc.msg}",
                       {"line": exc.lineno, "column": exc.colno})
    if not isinstance(data, dict):
        raise ApiError(400, "malformed_request",
                       "Request body must be a JSON object.",
                       {"received_type": type(data).__name__})
    return data


def _validate_targets(api: Api, targets: Any) -> list[str]:
    if not isinstance(targets, list) or not targets:
        raise ApiError(400, "invalid_scan_target",
                       "'targets' must be a non-empty list of directory paths.",
                       {"received": targets})
    resolved: list[str] = []
    for t in targets:
        if not isinstance(t, str) or not t.strip():
            raise ApiError(400, "invalid_scan_target",
                           "Each target must be a non-empty string path.",
                           {"received": t})
        full = os.path.abspath(os.path.expanduser(t))
        if not os.path.exists(full):
            raise ApiError(400, "invalid_scan_target",
                           f"Scan target does not exist: {t}", {"resolved": full})
        if not os.path.isdir(full):
            raise ApiError(400, "invalid_scan_target",
                           f"Scan target is not a directory: {t}", {"resolved": full})
        if api.allowed_roots and not any(
                full == root or full.startswith(root + os.sep)
                for root in api.allowed_roots):
            raise ApiError(403, "target_not_allowed",
                           f"Scan target is outside the configured roots: {t}",
                           {"allowed_roots": api.allowed_roots})
        resolved.append(full)
    return resolved


def h_scan(api: Api, query, body) -> Response:
    """Run the full frozen pipeline and make the result the current scan.

    Synchronous by design: the demo estate completes in a couple of seconds and a
    background-job API would be a second lifecycle to keep honest. A concurrent second
    scan is refused rather than queued.
    """
    data = _parse_scan_body(body)

    policy = data.get("policy", pqc.DEFAULT_POLICY)
    if policy not in pqc.POLICIES:
        raise ApiError(400, "invalid_policy",
                       f"Unknown policy '{policy}'.",
                       {"available": sorted(pqc.POLICIES)})

    demo = _bool(data.get("demo", False))
    if demo:
        request = demo_request(policy=policy)
    else:
        targets = _validate_targets(api, data.get("targets"))
        estate = None
        estate_path = data.get("estate")
        if estate_path is not None:
            if not isinstance(estate_path, str) or not os.path.isfile(estate_path):
                raise ApiError(400, "invalid_scan_target",
                               "'estate' must be a path to an estate manifest JSON file.",
                               {"received": estate_path})
            try:
                estate = Estate.from_json(estate_path)
            except Exception as exc:                   # noqa: BLE001
                raise ApiError(400, "invalid_estate",
                               f"Estate manifest could not be loaded: {exc}")
        request = ScanRequest(
            targets=targets, estate=estate, policy=policy,
            label=str(data.get("label", "api-scan")),
            verify_certificates=_bool(data.get("verify_certificates", True)))

    scenario = None
    if "crqc_year" in data or "safety_margin_years" in data:
        year = data.get("crqc_year", mosca_mod.DEFAULT_CRQC_YEAR)
        if not isinstance(year, int) or isinstance(year, bool) or not 2025 <= year <= 2100:
            raise ApiError(400, "invalid_parameter",
                           "'crqc_year' must be an integer between 2025 and 2100.",
                           {"received": year})
        margin = data.get("safety_margin_years", 1.0)
        if not isinstance(margin, (int, float)) or isinstance(margin, bool):
            raise ApiError(400, "invalid_parameter",
                           "'safety_margin_years' must be a number.",
                           {"received": margin})
        scenario = mosca_mod.Scenario(crqc_year=year,
                                      safety_margin_years=float(margin),
                                      label=str(data.get("scenario_label", "api")))

    if not api._scan_lock.acquire(blocking=False):
        raise ApiError(409, "scan_in_progress",
                       "A scan is already running in this process.")
    try:
        engine = Engine()
        result = engine.run(request, scenario=scenario)
        api.engine = engine                            # atomic swap, after completion
    finally:
        api._scan_lock.release()

    validation = engine.cbom_validation()
    summary = {
        "scan_id": result.scan_id,
        "started_at": result.started_at,
        "target": result.target,
        "policy": result.policy,
        "demo": bool(request.estate and request.estate.demo),
        "assets": len(result.assets),
        "applications": len(result.applications),
        "stats": result.stats.to_dict(),
        "graph": engine.graph.stats() if engine.graph else None,
        "roadmap_totals": (engine.roadmap or {}).get("totals"),
        "cbom": {
            "components": len(engine.cbom_document().get("components", [])),
            "schema_valid": validation["valid"],
            "validation_scope": validation["scope"],
        },
        "scenario": engine.scenario.to_dict() if engine.scenario else None,
        "progress": engine.progress.events[-1] if engine.progress.events else None,
        "notes": [
            "Business context is operator-declared; assets whose context_source is "
            "'default' were scored on ECDAT defaults, not discovered facts.",
        ],
    }
    api.last_scan = summary
    return json_response(summary, status=201)


# --------------------------------------------------------------------------------------
def h_assets(api: Api, query, body) -> Response:
    engine = api.require_engine()
    assets = engine.assets()

    filters = {}
    for param, field_name in FILTERABLE.items():
        value = _one(query, param)
        if value:
            filters[field_name] = value
    unknown = [k for k in query
               if k not in FILTERABLE and k not in ("limit", "offset", "view", "q",
                                                    "sort", "indent")]
    if unknown:
        raise ApiError(400, "invalid_parameter",
                       f"Unknown query parameter(s): {', '.join(sorted(unknown))}.",
                       {"filterable": sorted(FILTERABLE)})

    selected = [a for a in assets if _matches(a, filters)] if filters else list(assets)

    needle = (_one(query, "q") or "").strip().lower()
    if needle:
        selected = [a for a in selected
                    if needle in (a.asset_name or "").lower()
                    or needle in (a.algorithm_label or "").lower()
                    or needle in (a.file or "").lower()]

    sort = _one(query, "sort", "priority")
    if sort == "priority":
        selected.sort(key=lambda a: (-(a.migration_priority or 0), a.asset_name or ""))
    elif sort == "risk":
        selected.sort(key=lambda a: (-(a.risk_score or 0.0), a.asset_name or ""))
    elif sort == "name":
        selected.sort(key=lambda a: (a.asset_name or ""))
    else:
        raise ApiError(400, "invalid_parameter",
                       f"Unknown sort '{sort}'.",
                       {"available": ["priority", "risk", "name"]})

    limit = _int(query, "limit", DEFAULT_PAGE, 1, MAX_PAGE)
    offset = _int(query, "offset", 0, 0, 10_000_000)
    page = selected[offset:offset + limit]

    view = _one(query, "view", "summary")
    if view == "summary":
        rows = [summary_row(a) for a in page]
    elif view == "full":
        rows = [engine.asset_view(a.asset_id) for a in page]
    else:
        raise ApiError(400, "invalid_parameter",
                       f"Unknown view '{view}'.",
                       {"available": ["summary", "full"]})

    return json_response({
        "scan_id": engine.result.scan_id,
        "total": len(assets),
        "matched": len(selected),
        "count": len(rows),
        "limit": limit,
        "offset": offset,
        "truncated": offset + len(rows) < len(selected),
        "filters": filters or None,
        "view": view,
        "assets": rows,
        "note": ("`matched` is the filtered count and `total` the full inventory; a "
                 "page is never presented as the whole estate."),
    })


def h_asset(api: Api, query, body, asset_id: str) -> Response:
    engine, _ = api.require_asset(asset_id)
    return json_response({
        "asset": engine.asset_view(asset_id),
        "redactions": export_mod.redactions(),
    })


def h_asset_evidence(api: Api, query, body, asset_id: str) -> Response:
    """Provenance and confidence, with the scanned source line removed (§30)."""
    engine, asset = api.require_asset(asset_id)
    items = engine.asset_evidence(asset_id) or []
    return json_response({
        "asset_id": asset_id,
        "asset_name": asset.asset_name,
        "confidence": _v(asset.confidence),
        "confidence_score": asset.confidence_score,
        "strongest_evidence_type": _v(asset.evidence_type),
        "detectors": list(asset.detectors or []),
        "count": len(items),
        "evidence": items,
        "redactions": export_mod.redactions(),
        "note": ("`proves_execution` distinguishes evidence that shows the algorithm is "
                 "reachable from evidence that only shows it is present. Presence of a "
                 "library is not proof that a vulnerable code path executes."),
    })


def h_asset_graph(api: Api, query, body, asset_id: str) -> Response:
    engine, asset = api.require_asset(asset_id)
    depth = _int(query, "depth", 3, 1, 6)
    sub = engine.asset_graph(asset_id, depth=depth) or {}
    return json_response({
        "asset_id": asset_id,
        "asset_name": asset.asset_name,
        "depth": depth,
        "dependency_centrality": asset.dependency_centrality,
        "dependency_centrality_score": asset.dependency_centrality_score,
        "affected_summary": asset.affected_summary or None,
        "graph": sub,
        "note": ("Dependency centrality counts coupled units of change (library, "
                 "protocol, certificate). Assets that merely share an algorithm are "
                 "reported separately as algorithm siblings, not as coupling."),
    })


def h_asset_risk(api: Api, query, body, asset_id: str) -> Response:
    engine, _ = api.require_asset(asset_id)
    payload = engine.asset_risk(asset_id) or {}
    payload["scenario"] = engine.scenario.to_dict() if engine.scenario else None
    payload["policy"] = engine.policy
    payload["note"] = ("The classical and quantum axes are computed independently and "
                       "reported separately. Bands are ECDAT-derived decision support, "
                       "not a compliance status.")
    return json_response(payload)


def h_asset_migration(api: Api, query, body, asset_id: str) -> Response:
    engine, _ = api.require_asset(asset_id)
    payload = engine.asset_migration(asset_id) or {}
    payload["decision_definitions"] = _decision_definitions(engine)
    payload["note"] = ("Two levels, never collapsed: `migration_decision` is one of the "
                       "five frozen outcomes; `recommended_strategy` is the specific "
                       "standards-grounded action beneath it.")
    return json_response(payload)


def _decision_definitions(engine: Engine) -> dict[str, Any]:
    from ..analyze import decide as decide_mod
    return decide_mod.DECISION_DEFINITION


def h_asset_impact(api: Api, query, body, asset_id: str) -> Response:
    engine, asset = api.require_asset(asset_id)
    impact = engine.asset_impact(asset_id)
    return json_response({
        "asset_id": asset_id,
        "asset_name": asset.asset_name,
        "migration_decision": _v(asset.migration_decision),
        "impact": impact.to_dict() if impact is not None else None,
        "headline": impact.headline() if impact is not None else None,
        "derivation": ("Graph-derived: every list is the result of a traversal of the "
                       "crypto asset graph, not a manually maintained impact list."),
    })


# --------------------------------------------------------------------------------------
def h_roadmap(api: Api, query, body) -> Response:
    engine = api.require_engine()
    roadmap = engine.roadmap or engine.plan()
    phase = _one(query, "phase")
    band = _one(query, "band")

    phases = roadmap.get("phases", [])
    if phase:
        phases = [p for p in phases if str(p.get("id")).lower() == phase.lower()]
        if not phases:
            raise ApiError(404, "unknown_phase", f"No roadmap phase '{phase}'.",
                           {"available": [p.get("id")
                                          for p in roadmap.get("phases", [])]})
    if band:
        phases = [dict(p, items=[i for i in p.get("items", [])
                                 if str(i.get("band", "")).lower() == band.lower()])
                  for p in phases]

    truncated = export_mod.truncated_items(roadmap)
    return json_response({
        "scan_id": engine.result.scan_id,
        "totals": roadmap.get("totals"),
        "bands": roadmap.get("bands"),
        "phases": phases,
        "enablement_waves": roadmap.get("enablement_waves"),
        "applications": roadmap.get("applications"),
        "method": roadmap.get("method"),
        "items_truncated": truncated,
        "note": (f"{truncated} item(s) are summarised rather than listed inline; the "
                 "per-phase `asset_count` is the authoritative total."
                 if truncated else
                 "Every scheduled asset is listed inline; nothing is summarised away."),
    })


def h_dashboard(api: Api, query, body) -> Response:
    engine = api.require_engine()
    payload = engine.dashboard()
    payload["scenario"] = engine.scenario.to_dict() if engine.scenario else None
    return json_response(payload)


def h_cbom(api: Api, query, body) -> Response:
    from ..cbom import generate as cbom_gen
    engine = api.require_engine()
    doc = engine.cbom_document()
    if _bool(_one(query, "download", "false")):
        return Response(
            status=200,
            body=_guard(export_mod.cbom_json(doc)).encode("utf-8"),
            content_type="application/vnd.cyclonedx+json; version=1.6",
            headers={"Content-Disposition":
                     f'attachment; filename="{engine.result.scan_id}-cbom.json"'})
    summary = _bool(_one(query, "summary", "false"))
    if summary:
        return json_response({"counts": cbom_gen.counts(doc),
                              "validation": engine.cbom_validation(),
                              "serialNumber": doc.get("serialNumber"),
                              "specVersion": doc.get("specVersion")})
    return json_response(doc)


def h_cbom_validation(api: Api, query, body) -> Response:
    """Validation scope is stated in the payload, not implied by a green tick."""
    from ..cbom import generate as cbom_gen
    engine = api.require_engine()
    report = engine.cbom_validation()
    report["counts"] = cbom_gen.counts(engine.cbom_document())
    report["claim"] = ("Validated against the vendored CycloneDX 1.6 schema subset "
                       "shipped with ECDAT. This is not an external CycloneDX "
                       "certification and not a statement that any third-party tool "
                       "will accept the document.")
    return json_response(report)


def h_reports(api: Api, query, body) -> Response:
    engine = api.require_engine()
    fmt = _one(query, "format", "text")
    if fmt == "text":
        return text_response(engine.text_report())
    if fmt == "json":
        return json_response({
            "scan_id": engine.result.scan_id,
            "format": "json",
            "dashboard": engine.dashboard(),
            "text_report": engine.text_report(),
        })
    raise ApiError(400, "invalid_parameter", f"Unknown report format '{fmt}'.",
                   {"available": ["text", "json"]})


#: The export catalogue. A request for anything not in here is a malformed export
#: request (400), not a missing page (404) -- the distinction matters to a client.
EXPORTS: dict[str, str] = {
    "json": "Full result: inventory, roadmap, impact and summaries (snippet-free).",
    "assets.csv": "One row per canonical asset, 67 columns.",
    "roadmap.csv": "The plan in execution order, one row per scheduled item.",
    "impact.csv": "One row per asset: reach, coupling, effort and blockers.",
}


def h_export(api: Api, query, body, name: str) -> Response:
    engine = api.require_engine()
    if name not in EXPORTS:
        raise ApiError(400, "malformed_export_request",
                       f"Unknown export '{name}'.",
                       {"available": sorted(EXPORTS),
                        "descriptions": EXPORTS})
    if name == "json":
        indent = _int(query, "indent", 2, 0, 8)
        payload = engine.export_json()
        if indent != 2:
            payload = json.dumps(json.loads(payload), indent=indent or None,
                                 default=str)
        return Response(status=200, body=_guard(payload).encode("utf-8"),
                        content_type="application/json; charset=utf-8",
                        headers={"Content-Disposition":
                                 f'attachment; filename="{engine.result.scan_id}.json"'})
    table = name[:-len(".csv")]
    try:
        payload = engine.export_csv(table)
    except ValueError as exc:
        raise ApiError(400, "malformed_export_request", str(exc))
    return csv_response(payload, f"{engine.result.scan_id}-{table}.csv")


# ======================================================================================
# Route table
# ======================================================================================
@dataclass(frozen=True)
class Route:
    method: str
    template: str
    pattern: re.Pattern
    handler: Callable
    summary: str


def _route(method: str, template: str, handler: Callable, summary: str) -> Route:
    # `[^/]+` for a path parameter so a detail route can never swallow a sub-route, and
    # both ends are anchored so ordering in the table is irrelevant.
    pattern = re.sub(r"\{(\w+)\}", r"(?P<\1>[^/]+)", template)
    return Route(method, template, re.compile("^" + pattern + "$"), handler, summary)


ROUTES: tuple[Route, ...] = (
    _route("GET", "/", h_index, "Route index and service metadata."),
    _route("GET", "/health", h_health, "Liveness and whether a scan is loaded."),
    _route("GET", "/openapi.json", h_openapi, "OpenAPI 3.0 description of this API."),

    _route("POST", "/scan", h_scan, "Run the full pipeline; becomes the current scan."),

    _route("GET", "/assets", h_assets, "Filterable, paginated canonical inventory."),
    _route("GET", "/assets/{asset_id}", h_asset, "One canonical asset, snippet-free."),
    _route("GET", "/assets/{asset_id}/evidence", h_asset_evidence,
           "Evidence provenance and confidence for one asset."),
    _route("GET", "/assets/{asset_id}/graph", h_asset_graph,
           "The asset's graph neighbourhood and coupling."),
    _route("GET", "/assets/{asset_id}/risk", h_asset_risk,
           "Dual-axis risk: classical and quantum, reported separately."),
    _route("GET", "/assets/{asset_id}/migration", h_asset_migration,
           "Migration decision and the specific strategy beneath it."),
    _route("GET", "/assets/{asset_id}/impact", h_asset_impact,
           "Graph-derived migration impact for one asset."),

    _route("GET", "/roadmap", h_roadmap, "Phased, prioritized migration roadmap."),
    _route("GET", "/dashboard", h_dashboard, "Estate roll-up for a UI."),
    _route("GET", "/cbom", h_cbom, "CycloneDX 1.6 CBOM for the current scan."),
    _route("GET", "/cbom/validation", h_cbom_validation,
           "Schema validation result and its honest scope."),
    _route("GET", "/reports", h_reports, "Plain-text operator report."),
    _route("GET", "/exports/{name}", h_export,
           "json | assets.csv | roadmap.csv | impact.csv"),
)
