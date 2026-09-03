"""Scan orchestration: the single entry point that runs the frozen pipeline.

    DISCOVERY -> EVIDENCE -> CANONICAL ASSET -> GRAPH -> ASSESSMENT
    -> BUSINESS CONTEXT -> MOSCA -> DECISION -> IMPACT -> ROADMAP -> OUTPUTS

Every stage enriches the same `CryptoAsset` objects in place. Nothing here builds a
parallel representation of a cryptographic fact, which is what keeps the canonical
model the single source of truth.

Stages are individually skippable so a caller can re-run only what a changed
scenario affects -- moving the CRQC horizon re-runs Mosca onward, but does not
re-scan the filesystem. That is what makes the exposure simulator instant.
"""

from __future__ import annotations

import json
import os
import pathlib
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .knowledge import pqc
from .models import (
    Application,
    Criticality,
    CryptoAsset,
    DataClassification,
    Exposure,
    ScanResult,
    ScanStats,
    stable_id,
)
from .normalize import Normalizer
from .scan.source import SourceScanConfig, SourceScanner


def _v(x):
    """Enum -> its value; everything else unchanged. Used by the read-only views."""
    return x.value if hasattr(x, "value") else x


# ======================================================================================
# Estate manifest (operator-declared business context)
# ======================================================================================
@dataclass
class Estate:
    """Business context for a scan. Explicitly operator-supplied, never discovered."""

    estate_id: str
    name: str
    applications: list[Application] = field(default_factory=list)
    repo_to_app: dict[str, str] = field(default_factory=dict)
    certificate_bindings: dict[str, str] = field(default_factory=dict)
    binary_bindings: dict[str, str] = field(default_factory=dict)
    demo: bool = False
    notice: str = ""
    context_source: str = "operator-declared"

    @classmethod
    def from_json(cls, path: str | pathlib.Path, repo_root: str = "") -> "Estate":
        data = json.loads(pathlib.Path(path).read_text())
        apps: list[Application] = []
        repo_to_app: dict[str, str] = {}
        for a in data.get("applications", []):
            app = Application(
                app_id=a["app_id"], name=a["name"],
                owner=a.get("owner", "unassigned"),
                business_unit=a.get("business_unit", "unassigned"),
                environment=a.get("environment", "production"),
                criticality=Criticality(a.get("criticality", "important")),
                exposure=Exposure(a.get("exposure", "internal")),
                data_classification=DataClassification(
                    a.get("data_classification", "internal")),
                data_lifetime_years=int(a.get("data_lifetime_years", 3)),
                description=a.get("description", ""),
                repositories=list(a.get("repositories", [])),
                containers=list(a.get("containers", [])),
                regulatory=list(a.get("regulatory", [])),
                services=list(a.get("services", [])),
                business_function=a.get("business_function", ""),
                context_source=data.get("context_source", "operator-declared"),
            )
            apps.append(app)
            for repo in app.repositories:
                prefix = os.path.join(repo_root, repo) if repo_root else repo
                repo_to_app[prefix] = app.app_id
        return cls(
            estate_id=data.get("estate_id", "estate"),
            name=data.get("name", "Estate"),
            applications=apps,
            repo_to_app=repo_to_app,
            certificate_bindings=dict(data.get("certificate_bindings", {})),
            binary_bindings=dict(data.get("binary_bindings", {})),
            demo=bool(data.get("demo", False)),
            notice=data.get("notice", ""),
            context_source=data.get("context_source", "operator-declared"),
        )

    def app(self, app_id: str | None) -> Application | None:
        for a in self.applications:
            if a.app_id == app_id:
                return a
        return None


# ======================================================================================
# Scan configuration
# ======================================================================================
@dataclass
class ScanRequest:
    targets: list[str] = field(default_factory=list)   # directories to walk
    estate: Estate | None = None
    policy: str = pqc.DEFAULT_POLICY
    label: str = "scan"
    scan_config: SourceScanConfig = field(default_factory=SourceScanConfig)
    verify_certificates: bool = True


@dataclass
class Progress:
    """Discovery progress, surfaced to the UI so a scan is legible while running."""

    stage: str = "idle"
    detail: str = ""
    percent: int = 0
    events: list[dict] = field(default_factory=list)

    def emit(self, stage: str, detail: str, percent: int) -> None:
        self.stage, self.detail, self.percent = stage, detail, percent
        self.events.append({
            "stage": stage, "detail": detail, "percent": percent,
            "at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        })


# ======================================================================================
# Engine
# ======================================================================================
class Engine:
    """Runs the pipeline. Holds the resulting assets for downstream queries."""

    def __init__(self) -> None:
        self.result: ScanResult | None = None
        self.estate: Estate | None = None
        self.progress = Progress()
        self.graph = None            # populated in Phase 4
        self.impacts: dict = {}      # asset_id -> MigrationImpact, populated in Phase 8
        self.roadmap: dict | None = None
        self.policy: str = pqc.DEFAULT_POLICY
        self.scenario = None         # mosca.Scenario, set in Phase 6
        self.cbom: dict | None = None    # CycloneDX 1.6 document, built in Phase 10
        self.impact_summary: dict | None = None

    # ---------------------------------------------------------------------------------
    def discover(self, request: ScanRequest) -> ScanResult:
        """Stage 1-3: discovery -> evidence -> canonical assets."""
        started = time.time()
        self.estate = request.estate
        self.policy = request.policy
        stats = ScanStats()
        detections = []

        cfg = request.scan_config
        cfg.verify_certificates = request.verify_certificates
        scanner = SourceScanner(cfg)

        total = max(1, len(request.targets))
        for i, target in enumerate(request.targets):
            if not os.path.isdir(target):
                stats.errors.append(f"target not found or not a directory: {target}")
                continue
            self.progress.emit(
                "discovery", f"scanning {os.path.basename(target.rstrip('/'))}",
                int(5 + 55 * i / total))
            found, stats = scanner.scan_tree(target, stats)
            # Re-key file paths so they are estate-relative, not machine-absolute.
            base = os.path.basename(target.rstrip("/"))
            for d in found:
                if d.file and not d.file.startswith(base):
                    d.file = f"{base}/{d.file}" if base not in ("repositories",) else d.file
            detections.extend(found)

        self.progress.emit("normalisation",
                           f"correlating {len(detections)} detections", 65)
        normalizer = Normalizer(
            applications=request.estate.applications if request.estate else [],
            repo_to_app=request.estate.repo_to_app if request.estate else {},
            source=request.estate.estate_id if request.estate else request.label,
        )
        assets = normalizer.normalize(detections)
        self._bind_unmapped(assets, request.estate)
        stats.deduplicated = len(detections) - len(assets)
        # Repositories = trees that actually resolved to a declared repository.
        # Certificate and binary stores are scan targets, not repositories, and
        # counting them would overstate coverage.
        stats.repositories = len({a.repository for a in assets if a.repository})

        self.result = ScanResult(
            scan_id=stable_id(request.label, started, prefix="scan"),
            started_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            target=", ".join(request.targets),
            assets=assets,
            applications=request.estate.applications if request.estate else [],
            stats=stats,
            policy=request.policy,
        )
        stats.duration_ms = int((time.time() - started) * 1000)
        self.progress.emit("normalisation",
                           f"{len(assets)} canonical assets from {len(detections)} detections", 70)
        return self.result

    # ---------------------------------------------------------------------------------
    @staticmethod
    def _count_repositories(targets: list[str]) -> int:
        n = 0
        for t in targets:
            if not os.path.isdir(t):
                continue
            entries = [e for e in os.listdir(t)
                       if os.path.isdir(os.path.join(t, e)) and not e.startswith(".")]
            n += len(entries) if entries else 1
        return n

    def _bind_unmapped(self, assets: list[CryptoAsset], estate: Estate | None) -> None:
        """Attach certificates and binaries to applications via the estate manifest.

        Those artefacts live outside repository trees, so path-prefix matching cannot
        place them. The bindings are operator-declared, and any asset that still has
        no application keeps `context_source='default'` so the UI can mark it as
        lacking business context rather than silently scoring it with defaults.
        """
        if estate is None:
            return
        for a in assets:
            if a.application:
                app = estate.app(a.application)
                if app:
                    a.owner = app.owner
                    a.business_unit = app.business_unit
                    a.compliance_tags = list(app.regulatory)
                    a.context_source = app.context_source
                continue
            basename = os.path.basename(a.file or "")
            app_id = (estate.certificate_bindings.get(basename)
                      or estate.binary_bindings.get(basename))
            if not app_id:
                continue
            app = estate.app(app_id)
            if app is None:
                continue
            a.application = app.app_id
            a.owner = app.owner
            a.business_unit = app.business_unit
            a.usage = app.description or app.name
            a.data_classification = app.data_classification
            a.data_lifetime_years = app.data_lifetime_years
            a.business_criticality = app.criticality
            a.exposure = app.exposure
            a.internet_exposed = app.exposure.value in (
                "external-facing", "internet-facing-critical")
            a.compliance_tags = list(app.regulatory)
            a.context_source = app.context_source

    # ---------------------------------------------------------------------------------
    def build_graph(self) -> "object":
        """Stage 4: crypto asset graph + dependency centrality."""
        from . import graph as graph_mod

        assets = self.assets()
        apps = self.result.applications if self.result else []
        self.progress.emit("graph", f"linking {len(assets)} assets", 74)
        self.graph = graph_mod.build(assets, apps)
        graph_mod.compute_centrality(self.graph, assets)
        self.progress.emit(
            "graph",
            f"{self.graph.stats()['nodes']} nodes, {self.graph.stats()['edges']} edges", 78)
        return self.graph

    # ---------------------------------------------------------------------------------
    def assess(self) -> None:
        """Stage 5-6: dual-axis risk, then crypto agility and interoperability.

        Agility runs after risk because it reads `pqc_readiness`, which discovery
        supplies, and is read in turn by the decision engine in stage 7.
        """
        from .analyze import agility as agility_mod
        from .analyze import risk as risk_mod

        assets = self.assets()
        self.progress.emit("assessment", f"scoring {len(assets)} assets", 82)
        for a in assets:
            risk_mod.apply(a, self.policy)
            agility_mod.apply(a)
        self.progress.emit("assessment",
                           "classical/quantum axes, agility and interoperability set", 86)

    # ---------------------------------------------------------------------------------
    def apply_scenario(self, scenario=None) -> None:
        """Stage 6b: Mosca urgency under an explicit, operator-supplied scenario.

        Separated from `assess()` so the exposure simulator can re-run only this
        stage when the CRQC horizon moves -- no re-scan, no re-scoring of the
        algorithm axes, which is what makes the slider instant.
        """
        from .analyze import mosca as mosca_mod

        if scenario is None:
            scenario = mosca_mod.Scenario()
        self.scenario = scenario
        assets = self.assets()
        self.progress.emit("mosca",
                           f"evaluating x+y>z at CRQC {scenario.crqc_year}", 88)
        for a in assets:
            mosca_mod.apply(a, scenario)
            a.migration_priority, a.priority_band = mosca_mod.priority(a)
        self.progress.emit("mosca", "migration urgency and priority bands set", 90)

    # ---------------------------------------------------------------------------------
    def decide(self) -> dict:
        """Stage 7: five-outcome migration decision + specific strategy."""
        from .analyze import decide as decide_mod

        assets = self.assets()
        self.progress.emit("decision", f"deciding {len(assets)} assets", 92)
        for a in assets:
            decide_mod.apply(a, self.policy)
        summary = decide_mod.summarize(assets)
        self.progress.emit(
            "decision",
            " / ".join(f"{k}={v}" for k, v in summary["decisions"].items() if v), 94)
        return summary

    # ---------------------------------------------------------------------------------
    def impact(self) -> dict:
        """Stage 8: migration impact, derived by traversing the graph.

        Runs after `decide()` because prerequisite detection reads the decision on the
        *upstream* asset -- a provider is only a blocker if it is itself changing. Runs
        before the roadmap because sequencing is what the roadmap consumes.
        """
        from .analyze import impact as impact_mod

        assets = self.assets()
        if self.graph is None:
            self.build_graph()
        self.progress.emit("impact", f"tracing impact for {len(assets)} assets", 95)
        self.impacts = impact_mod.build(self.graph, assets)
        summary = impact_mod.summarize(self.impacts, assets)
        self.impact_summary = summary
        gating = len([i for i in self.impacts.values() if i.unblocks])
        self.progress.emit(
            "impact",
            f"{summary['change_unit_count']} shared units of change, "
            f"{gating} gating asset(s)", 97)
        return summary

    # ---------------------------------------------------------------------------------
    def plan(self) -> dict:
        """Stage 9: prioritized roadmap, projected from the canonical inventory.

        Runs last in the analysis chain because it consumes the output of every stage
        before it -- decision, impact, centrality, agility, Mosca and business context.
        It adds no cryptographic fact of its own.
        """
        from .analyze import roadmap as roadmap_mod

        assets = self.assets()
        if not self.impacts:
            self.impact()
        self.progress.emit("roadmap", f"sequencing {len(assets)} assets", 98)
        apps = self.result.applications if self.result else []
        self.roadmap = roadmap_mod.build(assets, apps, graph=self.graph,
                                        impacts=self.impacts)
        t = self.roadmap["totals"]
        self.progress.emit(
            "roadmap",
            f"{t['scheduled']} scheduled, {t['no_action_required']} need no change, "
            f"{t['gating_assets']} gating", 99)
        return self.roadmap

    # ---------------------------------------------------------------------------------
    def outputs(self, estate_name: str = "") -> dict:
        """Stage 10: shareable artefacts, every one projected from the canonical model.

        Builds the CycloneDX 1.6 CBOM and validates it against the vendored schema. The
        JSON/CSV exports and the human-readable report are produced on demand by the
        `ecdat.export` and `ecdat.reports` modules from the same result, so nothing is
        cached here that could drift from the inventory. This stage adds no cryptographic
        fact -- it serialises the ones already on the assets.
        """
        from .cbom import generate as cbom_gen
        from .cbom import validate as cbom_val

        if self.result is None:
            raise RuntimeError("outputs() requires a completed discovery stage")
        demo = bool(self.estate and self.estate.demo)
        notice = self.estate.notice if self.estate else ""
        name = estate_name or (self.estate.name if self.estate else "") \
            or self.result.target
        self.progress.emit("outputs", f"generating CBOM for {len(self.assets())} assets",
                           99)
        self.cbom = cbom_gen.build(self.result, estate_name=name, demo=demo,
                                   notice=notice)
        report = cbom_val.report(self.cbom)
        counts = cbom_gen.counts(self.cbom)
        self.progress.emit(
            "outputs",
            f"CBOM: {counts['cryptographic_assets']} cryptographic-asset component(s), "
            f"schema-valid={report['valid']}", 100)
        return {"cbom_counts": counts, "validation": report}

    # ---------------------------------------------------------------------------------
    def run(self, request: ScanRequest, scenario=None) -> ScanResult:
        """The full frozen pipeline, in order."""
        self.discover(request)
        self.build_graph()
        self.assess()
        self.apply_scenario(scenario)
        self.decide()
        self.impact()
        self.plan()
        self.outputs()
        self.progress.emit("complete", "pipeline finished", 100)
        return self.result

    # ---------------------------------------------------------------------------------
    # Output accessors. Each builds from the current canonical result, so an artefact
    # can never be served from a stale cache that disagrees with the inventory.
    # ---------------------------------------------------------------------------------
    def cbom_document(self) -> dict:
        if self.cbom is None:
            self.outputs()
        return self.cbom or {}

    def cbom_validation(self) -> dict:
        from .cbom import validate as cbom_val
        return cbom_val.report(self.cbom_document())

    def dashboard(self) -> dict:
        from . import reports as reports_mod
        if self.result is None:
            return {}
        return reports_mod.dashboard(self.result, self.roadmap, self.impact_summary)

    def text_report(self) -> str:
        from . import reports as reports_mod
        if self.result is None:
            return ""
        return reports_mod.text_report(self.result, self.roadmap, self.impact_summary,
                                       self.scenario)

    def export_json(self) -> str:
        from . import export as export_mod
        if self.result is None:
            return "{}"
        return export_mod.full_json(self.result, roadmap=self.roadmap,
                                    impacts=self.impacts,
                                    summaries={"dashboard": self.dashboard()})

    def export_csv(self, table: str = "assets") -> str:
        """`assets` | `roadmap` | `impact` as CSV."""
        from . import export as export_mod
        if self.result is None:
            return ""
        if table == "roadmap":
            return export_mod.roadmap_csv(self.roadmap or {})
        if table == "impact":
            return export_mod.impact_csv(self.impacts)
        if table != "assets":
            raise ValueError(f"unknown table '{table}'; "
                             "expected assets, roadmap or impact")
        return export_mod.assets_csv(self.assets())

    # ---------------------------------------------------------------------------------
    def asset_impact(self, asset_id: str):
        """Impact for one asset, computed on demand if the stage has not run."""
        if not self.impacts:
            self.impact()
        return self.impacts.get(asset_id)

    # ---------------------------------------------------------------------------------
    # Per-asset read-only views. Each is a projection of canonical fields already on the
    # asset -- no recomputation of a cryptographic fact -- so the API stays HTTP glue and
    # the decision/risk/graph logic lives in exactly one place. All return None when the
    # asset id is unknown, which the API turns into a 404.
    # ---------------------------------------------------------------------------------
    def asset_view(self, asset_id: str) -> dict | None:
        """The full canonical asset as JSON, snippet-free (reuses the export redaction)."""
        from . import export as export_mod
        a = self.asset(asset_id)
        return export_mod.asset_json(a) if a else None

    def asset_evidence(self, asset_id: str) -> list[dict] | None:
        """Evidence provenance and confidence for one asset, with snippets removed.

        `proves_execution` is carried alongside because the distinction between "this
        algorithm is reachable" and "this library is present" is the difference between a
        finding and a guess, and a consumer that cannot see it will conflate them.
        """
        from . import export as export_mod
        a = self.asset(asset_id)
        if a is None:
            return None
        out = []
        for ev, d in zip(a.evidence or [], export_mod._redacted_evidence(a)):
            d["proves_execution"] = ev.proves_execution
            out.append(d)
        return out

    def asset_risk(self, asset_id: str) -> dict | None:
        """The dual-axis risk view: classical and quantum reported separately, plus the
        Mosca urgency and confidence already set on the asset. Nothing is re-derived."""
        a = self.asset(asset_id)
        if a is None:
            return None
        return {
            "asset_id": a.asset_id,
            "asset_name": a.asset_name,
            "classical_axis": {
                "classical_risk": _v(a.classical_risk),
                "classical_security_status": a.classical_security_status,
            },
            "quantum_axis": {
                "quantum_exposure": _v(a.quantum_exposure),
                "quantum_class": a.quantum_class,
                "quantum_vulnerable": a.quantum_vulnerable,
            },
            "risk_score": a.risk_score,
            "risk_factors": a.risk_factors,
            "risk_explanation": a.risk_explanation,
            "mosca_urgency": a.mosca_urgency,
            "mosca_gap_years": a.mosca_gap_years,
            "migration_priority": a.migration_priority,
            "priority_band": a.priority_band,
            "confidence": _v(a.confidence),
            "confidence_score": a.confidence_score,
        }

    def asset_migration(self, asset_id: str) -> dict | None:
        """The two-level migration view: the coarse `migration_decision` and the specific
        `recommended_strategy` beneath it, never collapsed into one."""
        a = self.asset(asset_id)
        if a is None:
            return None
        return {
            "asset_id": a.asset_id,
            "asset_name": a.asset_name,
            "migration_decision": _v(a.migration_decision),
            "recommended_strategy": a.recommended_strategy,
            "recommended_pqc": a.recommended_pqc,
            "recommended_hybrid": a.recommended_hybrid,
            "decision_rationale": a.decision_rationale,
            "decision_blocked_on": a.decision_blocked_on,
            "standards": list(a.recommendation_citations or []),
            "migration_effort": _v(a.migration_effort),
            "migration_months": a.migration_months,
            "crypto_agility": _v(a.crypto_agility),
            "interoperability": _v(a.interoperability),
            "pqc_readiness": a.pqc_readiness,
            "migration_blockers": list(a.migration_blockers or []),
        }

    def asset_graph(self, asset_id: str, depth: int = 3) -> dict | None:
        """The asset's graph neighbourhood, delegated to the one graph implementation.

        Returns None only when the asset id is unknown; a known asset that happens to
        have no graph node yields the empty-neighbourhood structure `subgraph_for_asset`
        already defines, which is a valid answer rather than an error.
        """
        from . import graph as graph_mod
        if self.asset(asset_id) is None:
            return None
        if self.graph is None:
            self.build_graph()
        return graph_mod.subgraph_for_asset(self.graph, asset_id, depth=depth)

    # ---------------------------------------------------------------------------------
    def assets(self) -> list[CryptoAsset]:
        return self.result.assets if self.result else []

    def asset(self, asset_id: str) -> CryptoAsset | None:
        for a in self.assets():
            if a.asset_id == asset_id:
                return a
        return None


# ======================================================================================
# Convenience: the demo estate
# ======================================================================================
def demo_paths() -> dict[str, str]:
    here = pathlib.Path(__file__).resolve().parents[2]
    demo = here / "datasets" / "demo"
    return {
        "root": str(demo),
        "estate": str(demo / "estate.json"),
        "repositories": str(demo / "repositories"),
        "certificates": str(demo / "certificates"),
        "binaries": str(demo / "binaries"),
        "containers": str(demo / "containers"),
    }


def demo_request(policy: str = pqc.DEFAULT_POLICY) -> ScanRequest:
    p = demo_paths()
    estate = Estate.from_json(p["estate"])
    targets = [p["repositories"], p["certificates"], p["binaries"]]
    if os.path.isdir(p["containers"]) and os.listdir(p["containers"]):
        targets.append(p["containers"])
    return ScanRequest(targets=targets, estate=estate, policy=policy,
                       label="demo-enterprise")
