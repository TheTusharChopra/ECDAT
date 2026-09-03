"""Human-readable outputs: an estate dashboard aggregate and a plain-text report.

Both are projections. `dashboard()` rolls the canonical assets up into the counts a
screen or an API renders; `text_report()` turns that roll-up into something an operator
can read without a UI. Neither computes a cryptographic fact -- every number is a tally
of fields the pipeline already set, and every recommendation is quoted from the asset's
own `recommended_strategy`.

The report leads with a legend, on purpose. The contract (§36/§49) forbids presenting a
recommendation as a compliance verdict or a defaulted value as a discovered one, so the
first thing the reader sees is what the document is and is not: ECDAT-derived guidance,
not a certification; business context that is operator-declared, with defaults marked.

`_UNCERTAINTY_LEXICON` and the phrasing here avoid the banned absolutes ("quantum-proof",
"100% accurate", "unbreakable"). A test in the phase-10 suite greps the rendered report
for them.
"""

from __future__ import annotations

import collections
from typing import Any

from .analyze import decide as decide_mod
from .models import CryptoAsset, ScanResult

# ======================================================================================
# Constants
# ======================================================================================
BANNER = "ECDAT -- Enterprise Cryptographic Discovery & Analysis"

LEGEND = (
    "ECDAT reports what it discovered and derives recommendations from it. Read this "
    "document as decision support, not as a certification:",
    "  * Migration decisions and risk bands are ECDAT-derived. They are not an "
    "assertion of standards conformance or a compliance pass/fail.",
    "  * Business context (owner, criticality, data lifetime) is operator-declared. "
    "Assets whose context is a fallback are marked DEFAULT.",
    "  * The CRQC year is a policy-planning horizon, not a prediction that a quantum "
    "computer will exist in that year.",
    "  * A finding is only as strong as its evidence. Presence of a library is not "
    "proof that a vulnerable code path executes.",
)

#: Words the report uses instead of absolutes. Never "quantum-proof"/"unbreakable".
_SAFE = {
    "pq_secure": "post-quantum (NIST-standardized parameters)",
    "at_risk": "exposed under the quantum threat model",
}


def _v(x: Any) -> Any:
    return x.value if hasattr(x, "value") else x


def _pct(n: int, total: int) -> str:
    return f"{(100 * n / total):.0f}%" if total else "0%"


# ======================================================================================
# Dashboard aggregate
# ======================================================================================
def _tally(assets: list[CryptoAsset], attr: str) -> dict[str, int]:
    c: collections.Counter = collections.Counter()
    for a in assets:
        c[str(_v(getattr(a, attr)))] += 1
    c.pop("None", None)
    return dict(c)


def dashboard(result: ScanResult, roadmap: dict[str, Any] | None = None,
              impact_summary: dict[str, Any] | None = None) -> dict[str, Any]:
    """The estate roll-up: every headline number a screen or `/dashboard` needs.

    Derived entirely from canonical fields and the already-built roadmap/impact
    summaries. This function introduces no new judgement -- it counts.
    """
    assets = result.assets
    total = len(assets)
    decisions = _tally(assets, "migration_decision")
    defaulted = sum(1 for a in assets if a.context_source == "default")

    return {
        "estate": {
            "target": result.target,
            "scan_id": result.scan_id,
            "scanned_at": result.started_at,
            "policy": result.policy,
            "assets": total,
            "applications": len(result.applications),
            "business_context_defaulted": defaulted,
            "business_context_note": (
                f"{defaulted} asset(s) scored on default business context; the rest are "
                "operator-declared." if defaulted else
                "All assets carry operator-declared business context."),
        },
        # Two axes, reported separately because they are computed separately.
        "classical_axis": _tally(assets, "classical_risk"),
        "quantum_axis": _tally(assets, "quantum_exposure"),
        "quantum_taxonomy": _tally(assets, "quantum_class"),
        "migration_decisions": decisions,
        "decision_definitions": decide_mod.summarize(assets).get("definitions", {}),
        "urgency": _tally(assets, "mosca_urgency"),
        "priority_bands": _tally(assets, "priority_band"),
        "crypto_agility": _tally(assets, "crypto_agility"),
        "interoperability": _tally(assets, "interoperability"),
        "confidence": _tally(assets, "confidence"),
        "asset_types": _tally(assets, "asset_type"),
        "headlines": _headlines(assets, decisions, total, roadmap),
        "roadmap_totals": (roadmap or {}).get("totals"),
        "gating_assets": (impact_summary or {}).get("gating_assets", [])[:10],
        "notes": [
            "All figures are counts of canonical asset fields; no number here is a "
            "second source of cryptographic truth.",
            "Risk bands and decisions are ECDAT-derived recommendations, not a "
            "compliance status.",
        ],
    }


def _headlines(assets: list[CryptoAsset], decisions: dict[str, int], total: int,
               roadmap: dict[str, Any] | None) -> dict[str, Any]:
    quantum_vulnerable = sum(1 for a in assets if a.quantum_vulnerable)
    classically_broken = sum(1 for a in assets
                             if a.quantum_class == "classically_broken")
    retain = decisions.get("RETAIN", 0)
    return {
        "total_assets": total,
        "need_no_change": retain,
        "need_change": total - retain,
        "quantum_vulnerable": quantum_vulnerable,
        "quantum_vulnerable_pct": _pct(quantum_vulnerable, total),
        "classically_broken_today": classically_broken,
        "scheduled": (roadmap or {}).get("totals", {}).get("scheduled"),
        "gating_assets": (roadmap or {}).get("totals", {}).get("gating_assets"),
    }


# ======================================================================================
# Plain-text report
# ======================================================================================
def _bar(label: str, count: int, total: int, width: int = 24) -> str:
    filled = int(round(width * count / total)) if total else 0
    return f"  {label:<26} {count:>4}  {'#' * filled}{'.' * (width - filled)}  " \
           f"{_pct(count, total)}"


def _section(title: str) -> str:
    return f"\n{title}\n{'-' * len(title)}"


def _ordered(tally: dict[str, int], order: list[str]) -> list[tuple[str, int]]:
    """Order known keys first, then any extras by descending count."""
    seen = set()
    out = []
    for k in order:
        if k in tally:
            out.append((k, tally[k]))
            seen.add(k)
    for k, v in sorted(tally.items(), key=lambda kv: -kv[1]):
        if k not in seen:
            out.append((k, v))
    return out


def text_report(result: ScanResult, roadmap: dict[str, Any] | None = None,
                impact_summary: dict[str, Any] | None = None,
                scenario: Any = None) -> str:
    """A self-contained plain-text report an operator can read end to end."""
    d = dashboard(result, roadmap, impact_summary)
    total = d["estate"]["assets"]
    lines: list[str] = []

    # --- header + legend
    lines.append("=" * 78)
    lines.append(BANNER)
    lines.append("=" * 78)
    lines.append(f"Estate      : {d['estate']['target']}")
    lines.append(f"Scan        : {d['estate']['scan_id']}  ({d['estate']['scanned_at']})")
    lines.append(f"Policy      : {d['estate']['policy']}")
    lines.append(f"Assets      : {total} across {d['estate']['applications']} "
                 "application(s)")
    if scenario is not None:
        cy = getattr(scenario, "crqc_year", None)
        if cy:
            lines.append(f"CRQC horizon: {cy} (policy-planning horizon, not a "
                         "prediction)")
    lines.append("")
    lines.append("HOW TO READ THIS REPORT")
    lines.extend(LEGEND)

    # --- executive headline
    h = d["headlines"]
    lines.append(_section("At a glance"))
    lines.append(f"  {h['need_change']} of {total} assets need a cryptographic change; "
                 f"{h['need_no_change']} are fit as-is.")
    lines.append(f"  {h['quantum_vulnerable']} ({h['quantum_vulnerable_pct']}) are "
                 "exposed under the quantum threat model.")
    lines.append(f"  {h['classically_broken_today']} rely on a mechanism that is "
                 "already broken by classical attacks today.")
    if d["estate"]["business_context_defaulted"]:
        lines.append(f"  NOTE: {d['estate']['business_context_defaulted']} asset(s) "
                     "scored on DEFAULT business context (see legend).")

    # --- dual axis
    lines.append(_section("Risk -- classical axis (attackable now)"))
    for k, n in _ordered(d["classical_axis"], ["critical", "high", "medium", "low",
                                               "info"]):
        lines.append(_bar(k, n, total))
    lines.append(_section("Risk -- quantum axis (harvest-now, decrypt-later)"))
    for k, n in _ordered(d["quantum_axis"], ["critical", "high", "medium", "low",
                                             "info"]):
        lines.append(_bar(k, n, total))

    # --- decisions (two-level model)
    lines.append(_section("Migration decisions (five outcomes)"))
    for k, n in _ordered(d["migration_decisions"],
                         ["RETAIN", "HARDEN", "UPGRADE", "HYBRID", "PQC-ONLY"]):
        lines.append(_bar(k, n, total))
    lines.append("  Each decision carries a specific standards-grounded strategy per "
                 "asset; see the roadmap.")

    # --- urgency
    lines.append(_section("Migration urgency (Mosca x+y>z)"))
    for k, n in _ordered(d["urgency"], ["already-late", "critical", "plan-now",
                                        "monitor", "not-applicable"]):
        lines.append(_bar(k, n, total))

    # --- roadmap
    if roadmap:
        lines.append(_section("Prioritized roadmap"))
        t = roadmap.get("totals", {})
        lines.append(f"  {t.get('scheduled', 0)} scheduled, "
                     f"{t.get('no_action_required', 0)} need no change, "
                     f"{t.get('gating_assets', 0)} gating asset(s).")
        for phase in roadmap.get("phases", []):
            if not phase.get("asset_count"):
                continue
            lines.append(f"  [{phase['id']}] {phase['name']}: "
                         f"{phase['asset_count']} asset(s) -- {phase.get('objective', '')}")
        waves = roadmap.get("enablement_waves", [])
        if waves:
            lines.append("")
            lines.append("  One change clears many (gating assets):")
            for w in waves[:5]:
                lines.append(f"    - {w['gating_asset_name']}: unblocks "
                             f"{w['dependent_assets']} asset(s) "
                             f"[{w.get('strategy', '')}]")
        elif roadmap.get("method", {}).get("sequencing_source", "").startswith(
                "UNAVAILABLE"):
            lines.append("  Sequencing omitted: no dependency graph was supplied "
                         "(shown rather than guessed).")

    # --- provenance
    lines.append(_section("Evidence & confidence"))
    for k, n in _ordered(d["confidence"], ["high", "medium", "low"]):
        lines.append(_bar(k, n, total))
    lines.append("  Confidence reflects evidence strength, not severity. A high-severity "
                 "finding can hold low confidence and vice versa.")

    # --- footer
    lines.append(_section("Scope of this report"))
    for note in d["notes"]:
        lines.append(f"  * {note}")
    lines.append("  * This is not a compliance certification and not a claim of "
                 "air-gapped or government-grade assurance.")
    lines.append("=" * 78)
    return "\n".join(lines)
