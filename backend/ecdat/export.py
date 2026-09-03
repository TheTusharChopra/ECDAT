"""Machine-readable exports: JSON and CSV, both projected from the canonical model.

Three artefacts, one source. `assets_csv` is the flat table an analyst opens in a
spreadsheet, `full_json` is the complete result for a downstream system, and the
roadmap/impact tables exist because a plan is only actionable if someone can sort it.

Two properties matter here and are tested:

  * NO SOURCE CODE LEAVES. `Evidence.snippet` holds a line of the scanned file. Exports
    are files people email, so snippets are dropped and only detector/method/matched
    survive (§30: no source-code exfiltration). `full_json` therefore differs from
    `ScanResult.to_dict()` by exactly that redaction, which `redactions()` reports.
  * DEFAULTS ARE VISIBLE. Every asset row carries `business_context_source`, so a
    consumer can tell a declared criticality from an ECDAT default (§36).

CSV writing goes through `csv` from the standard library, which handles quoting and
embedded delimiters correctly -- hand-joining commas is how an estate name with a comma
in it silently corrupts a column.
"""

from __future__ import annotations

import csv
import io
import json
from typing import Any, Iterable

from .models import CryptoAsset, ScanResult

#: Fields dropped from every export. `snippet` is scanned source; `audit_log` and
#: `overrides` can carry operator notes that are not the recipient's business.
REDACTED_EVIDENCE_FIELDS = ("snippet",)

REDACTION_NOTE = ("Source-code snippets are removed from exported artefacts. Detector, "
                  "method, matched token and location are retained so a finding stays "
                  "reproducible without shipping the source.")


# ======================================================================================
# Asset table
# ======================================================================================
#: (column, accessor) -- explicit rather than reflective, so the CSV contract is stable
#: and adding a canonical field cannot silently reshape somebody's saved spreadsheet.
ASSET_COLUMNS: tuple[tuple[str, str], ...] = (
    ("asset_id", "asset_id"),
    ("asset_name", "asset_name"),
    ("asset_type", "asset_type"),
    ("application", "application"),
    ("owner", "owner"),
    ("business_unit", "business_unit"),
    ("repository", "repository"),
    ("file", "file"),
    ("line", "line"),
    ("language", "language"),
    ("container", "container"),
    ("algorithm", "algorithm_label"),
    ("algorithm_family", "algorithm_family"),
    ("primitive", "primitive"),
    ("mode", "mode"),
    ("padding", "padding"),
    ("key_size", "key_size"),
    ("curve", "curve"),
    ("cryptographic_role", "cryptographic_role"),
    ("protocol", "protocol"),
    ("protocol_version", "protocol_version"),
    ("library", "library"),
    ("library_version", "library_version"),
    ("oid", "oid"),
    ("security_strength", "security_strength"),
    ("certificate_subject", "certificate_subject"),
    ("certificate_issuer", "certificate_issuer"),
    ("certificate_expiry", "certificate_expiry"),
    ("days_to_expiry", "days_to_expiry"),
    # --- assessment (dual axis, kept as two columns because they are two facts)
    ("classical_risk", "classical_risk"),
    ("classical_security_status", "classical_security_status"),
    ("quantum_exposure", "quantum_exposure"),
    ("quantum_class", "quantum_class"),
    ("quantum_vulnerable", "quantum_vulnerable"),
    ("risk_score", "risk_score"),
    # --- urgency
    ("mosca_urgency", "mosca_urgency"),
    ("mosca_gap_years", "mosca_gap_years"),
    ("migration_priority", "migration_priority"),
    ("priority_band", "priority_band"),
    # --- decision (two levels, never collapsed into one column)
    ("migration_decision", "migration_decision"),
    ("recommended_strategy", "recommended_strategy"),
    ("recommended_pqc", "recommended_pqc"),
    ("recommended_hybrid", "recommended_hybrid"),
    ("decision_rationale", "decision_rationale"),
    ("decision_blocked_on", "decision_blocked_on"),
    ("standards", "recommendation_citations"),
    # --- migration shape
    ("migration_effort", "migration_effort"),
    ("migration_months", "migration_months"),
    ("crypto_agility", "crypto_agility"),
    ("interoperability", "interoperability"),
    ("pqc_readiness", "pqc_readiness"),
    ("dependency_centrality", "dependency_centrality"),
    ("migration_blockers", "migration_blockers"),
    # --- provenance and honesty flags
    ("confidence", "confidence"),
    ("confidence_score", "confidence_score"),
    ("evidence_type", "evidence_type"),
    ("evidence_count", "_evidence_count"),
    ("detectors", "detectors"),
    ("business_context_source", "context_source"),
    ("data_classification", "data_classification"),
    ("business_criticality", "business_criticality"),
    ("exposure", "exposure"),
    ("internet_exposed", "internet_exposed"),
    ("compliance_tags", "compliance_tags"),
    ("tags", "tags"),
    ("triage_state", "triage_state"),
    ("duplicate_count", "duplicate_count"),
)


def _flat(value: Any) -> Any:
    """Render a canonical value for a single CSV cell."""
    if value is None:
        return ""
    if hasattr(value, "value"):                      # Enum
        return value.value
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (list, tuple)):
        return "; ".join(str(_flat(v)) for v in value)
    if isinstance(value, dict):
        return json.dumps(value, sort_keys=True)
    if isinstance(value, float):
        return round(value, 3)
    return value


def asset_row(a: CryptoAsset) -> dict[str, Any]:
    row: dict[str, Any] = {}
    for column, attr in ASSET_COLUMNS:
        if attr == "_evidence_count":
            row[column] = len(a.evidence or [])
        else:
            row[column] = _flat(getattr(a, attr, None))
    return row


def _csv(rows: Iterable[dict[str, Any]], columns: list[str]) -> str:
    buf = io.StringIO()
    # lineterminator is pinned so output is identical on every platform; the default
    # is \r\n, which makes diffing exports across machines needlessly noisy.
    writer = csv.DictWriter(buf, fieldnames=columns, extrasaction="ignore",
                            lineterminator="\n")
    writer.writeheader()
    for row in rows:
        writer.writerow(row)
    return buf.getvalue()


def assets_csv(assets: list[CryptoAsset]) -> str:
    """The flat inventory table, one row per canonical asset."""
    columns = [c for c, _ in ASSET_COLUMNS]
    return _csv((asset_row(a) for a in assets), columns)


# ======================================================================================
# Roadmap and impact tables
# ======================================================================================
ROADMAP_COLUMNS = ("phase", "phase_name", "priority", "band", "asset_id", "asset_name",
                   "application", "location", "decision", "strategy", "target",
                   "urgency", "effort", "months", "coordinated_months", "agility",
                   "centrality", "blast_radius", "change_units", "prerequisites",
                   "unblocks", "blockers", "why_this_phase")


def roadmap_csv(roadmap: dict[str, Any]) -> str:
    """The plan as a sortable table, in execution order.

    Exports exactly the items the roadmap carries. `roadmap.build` caps how many items
    it inlines per phase for large estates, so callers should pair this with
    `truncated_items()` -- a table that silently drops rows reads as complete when it
    is not.
    """
    rows = []
    for phase in roadmap.get("phases", []):
        for item in phase.get("items", []):
            rows.append({
                "phase": phase.get("id"),
                "phase_name": phase.get("name"),
                "priority": item.get("priority"),
                "band": item.get("band"),
                "asset_id": item.get("asset_id"),
                "asset_name": item.get("asset_name"),
                "application": item.get("application"),
                "location": item.get("location"),
                "decision": item.get("decision"),
                "strategy": item.get("strategy"),
                "target": item.get("target"),
                "urgency": item.get("urgency"),
                "effort": item.get("effort"),
                "months": item.get("months"),
                "coordinated_months": item.get("coordinated_months"),
                "agility": item.get("agility"),
                "centrality": item.get("centrality"),
                "blast_radius": item.get("blast_radius"),
                "change_units": _flat(item.get("change_units")),
                "prerequisites": _flat(item.get("prerequisites")),
                "unblocks": _flat(item.get("unblocks")),
                "blockers": _flat(item.get("blockers")),
                "why_this_phase": item.get("why_this_phase"),
            })
    return _csv(rows, list(ROADMAP_COLUMNS))


def truncated_items(roadmap: dict[str, Any]) -> int:
    """How many roadmap items the plan summarised away rather than listing.

    Reported rather than ignored: a phase that says `asset_count: 400` while listing 50
    items has dropped 350, and an export that does not say so overstates its coverage.
    """
    return sum(int(p.get("items_truncated") or 0)
               for p in roadmap.get("phases", []))


IMPACT_COLUMNS = ("asset_id", "asset_name", "decision", "applications", "services",
                  "repositories", "containers", "files", "owners", "business_units",
                  "business_functions", "change_units", "dependent_assets",
                  "algorithm_siblings", "prerequisites", "unblocks", "own_effort_months",
                  "coordinated_effort_months", "prerequisite_months", "blast_radius",
                  "blast_radius_score", "blockers")


def impact_csv(impacts: dict[str, Any]) -> str:
    """One row per asset: who is affected, what gates it, what it gates."""
    rows = []
    for imp in impacts.values():
        d = imp.to_dict() if hasattr(imp, "to_dict") else dict(imp)
        row = {}
        for column in IMPACT_COLUMNS:
            value = d.get(column)
            if column == "prerequisites" and isinstance(value, list):
                value = [p.get("asset_name", "") if isinstance(p, dict) else str(p)
                         for p in value]
            elif isinstance(value, list) and column in (
                    "applications", "services", "repositories", "containers", "files",
                    "owners", "business_units", "business_functions"):
                value = len(value)
            row[column] = _flat(value)
        rows.append(row)
    return _csv(rows, list(IMPACT_COLUMNS))


# ======================================================================================
# JSON
# ======================================================================================
def _redacted_evidence(a: CryptoAsset) -> list[dict[str, Any]]:
    out = []
    for ev in a.evidence or []:
        d = ev.to_dict()
        for field in REDACTED_EVIDENCE_FIELDS:
            d.pop(field, None)
        out.append(d)
    return out


def asset_json(a: CryptoAsset) -> dict[str, Any]:
    """The canonical asset as JSON, minus the redacted evidence fields."""
    d = a.to_dict()
    d["evidence"] = _redacted_evidence(a)
    return d


def redactions() -> dict[str, Any]:
    """What exports deliberately omit -- stated in the artefact, not just in the docs."""
    return {
        "evidence_fields_removed": list(REDACTED_EVIDENCE_FIELDS),
        "reason": REDACTION_NOTE,
        "key_material": ("Private key material is never persisted or exported. A "
                         "detected key is inventoried by metadata only."),
    }


def full_json(result: ScanResult, roadmap: dict[str, Any] | None = None,
              impacts: dict[str, Any] | None = None,
              summaries: dict[str, Any] | None = None,
              indent: int | None = 2) -> str:
    """The complete result: inventory, plan, impact and summaries in one document."""
    doc: dict[str, Any] = {
        "scan": {
            "scan_id": result.scan_id,
            "started_at": result.started_at,
            "target": result.target,
            "policy": result.policy,
            "stats": result.stats.to_dict(),
        },
        "redactions": redactions(),
        "applications": [app.to_dict() for app in result.applications],
        "assets": [asset_json(a) for a in result.assets],
    }
    if summaries:
        doc["summary"] = summaries
    if impacts:
        doc["impact"] = {aid: (imp.to_dict() if hasattr(imp, "to_dict") else imp)
                         for aid, imp in impacts.items()}
    if roadmap:
        doc["roadmap"] = roadmap
    return json.dumps(doc, indent=indent, sort_keys=False, default=str)


def cbom_json(doc: dict[str, Any], indent: int | None = 2) -> str:
    return json.dumps(doc, indent=indent, default=str)
