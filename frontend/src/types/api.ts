/**
 * ECDAT API types.
 *
 * These mirror the Phase 11 API contract exactly, as observed from the live
 * backend (`GET /openapi.json` and the response shapes it documents). They are
 * a transcription of the canonical asset model -- not a second definition of
 * it. When the backend contract changes, this file follows; it never leads.
 *
 * Nothing here is computed. The frontend renders API results and does not
 * derive risk, exposure, Mosca urgency, decisions, centrality, impact or
 * roadmap placement (§37).
 */

// ---------------------------------------------------------------------------
// Canonical enums. String unions rather than TS enums so they compare directly
// against the raw JSON the API returns.
// ---------------------------------------------------------------------------

/** Classical risk band. Independent of `QuantumExposure`. */
export type RiskBand = "critical" | "high" | "medium" | "low" | "info";

/** Quantum exposure band. Independent of `RiskBand` -- never merge the two. */
export type QuantumExposure = "critical" | "high" | "medium" | "low" | "info";

/** The five frozen migration decisions. There is no sixth. */
export type MigrationDecision =
  | "RETAIN"
  | "HARDEN"
  | "UPGRADE"
  | "HYBRID"
  | "PQC-ONLY";

export const MIGRATION_DECISIONS: readonly MigrationDecision[] = [
  "RETAIN",
  "HARDEN",
  "UPGRADE",
  "HYBRID",
  "PQC-ONLY",
] as const;

export type PriorityBand = "P0" | "P1" | "P2" | "P3";

export const PRIORITY_BANDS: readonly PriorityBand[] = [
  "P0",
  "P1",
  "P2",
  "P3",
] as const;

export type MoscaUrgency =
  | "already-late"
  | "critical"
  | "plan-now"
  | "monitor"
  | "not-applicable";

export type ConfidenceLevel = "high" | "medium" | "low";
export type AgilityLevel = "high" | "medium" | "low";
export type Interoperability = "open" | "negotiated" | "constrained";
export type EffortLevel = "low" | "medium" | "high" | "very-high";

export type AssetType =
  | "source-finding"
  | "certificate"
  | "dependency"
  | "binary-artifact"
  | "container-package"
  | "protocol-config"
  | "key-material";

/**
 * Where a field's value came from. Rendering this honestly is a hard product
 * requirement (§15): a default must never be presented as a discovered fact.
 */
export type ContextSource =
  | "operator-declared"
  | "inferred"
  | "default"
  | "unknown";

// ---------------------------------------------------------------------------
// Assets
// ---------------------------------------------------------------------------

/** One row of `GET /assets` (view=summary). 40 canonical fields + 2 derived. */
export interface AssetSummary {
  asset_id: string;
  asset_name: string;
  asset_type: AssetType | string;
  application: string | null;
  owner: string | null;
  business_unit: string | null;
  file: string | null;
  line: number | null;
  algorithm_label: string | null;
  algorithm_family: string | null;
  primitive: string | null;
  key_size: number | null;
  curve: string | null;
  cryptographic_role: string | null;
  protocol: string | null;
  protocol_version: string | null;
  library: string | null;
  classical_risk: RiskBand;
  classical_security_status: string | null;
  quantum_exposure: QuantumExposure;
  quantum_class: string | null;
  quantum_vulnerable: boolean;
  risk_score: number;
  mosca_urgency: MoscaUrgency | string;
  priority_band: PriorityBand;
  migration_priority: number;
  /** Coarse level: one of the five frozen decisions. */
  migration_decision: MigrationDecision;
  /** Specific standards-grounded action beneath the decision. Never merged. */
  recommended_strategy: string | null;
  recommended_pqc: string | null;
  recommended_hybrid: string | null;
  migration_effort: EffortLevel | string | null;
  migration_months: number | null;
  crypto_agility: AgilityLevel | null;
  interoperability: Interoperability | null;
  dependency_centrality: number | null;
  confidence: ConfidenceLevel;
  confidence_score: number;
  evidence_type: string | null;
  context_source: ContextSource | string | null;
  triage_state: string | null;
  evidence_count: number;
  detectors: string[];
}

/** Mosca's inequality, as evaluated by the backend for one asset. */
export interface MoscaDetail {
  applicable: boolean;
  urgency: MoscaUrgency | string;
  /** x: how long the protected data must stay confidential. */
  x_data_lifetime_years: number | null;
  /** y: how long the migration is estimated to take. */
  y_migration_years: number | null;
  /** z: years remaining to the configured threat horizon. Not a prediction. */
  z_years_to_crqc: number | null;
  gap_years: number | null;
  latest_start_year: number | null;
  years_until_latest_start: number | null;
  inequality: string;
  explanation: string;
  scenario: Scenario;
}

/** Change-impact coupling reachable from this asset through the graph. */
export interface AffectedSummary {
  applications: string[];
  services: string[];
  business_units: string[];
  shared_resources: string[];
  sibling_assets: number;
  /** Same algorithm but NOT coupled to this change: a separate scope. */
  algorithm_siblings: number;
  explanation: string;
}

/** The inputs the decision engine read. Shown so a decision can be audited. */
export interface DecisionInputs {
  role: string | null;
  algorithm: string | null;
  classical_risk: RiskBand;
  quantum_exposure: QuantumExposure;
  data_lifetime_years: number | null;
  data_classification: string | null;
  business_criticality: string | null;
  exposure: string | null;
  dependency_centrality: number | null;
  crypto_agility: AgilityLevel | null;
  interoperability: Interoperability | null;
  migration_effort: EffortLevel | string | null;
  mosca_urgency: MoscaUrgency | string;
  pqc_readiness: string | null;
  policy: string;
  context_source: ContextSource | string | null;
}

export interface RemediationEvent {
  from: string;
  to: string;
  actor: string;
  note: string | null;
  direction: string;
  at: string;
}

/**
 * The full canonical asset, as returned by `GET /assets/{id}` (`asset` key) and
 * by `GET /assets?view=full`.
 *
 * Every analytical field below is a backend verdict. The frontend reads them;
 * it never recomputes one (§37).
 */
export interface CryptoAsset {
  // --- identity -----------------------------------------------------------
  asset_id: string;
  asset_type: AssetType | string;
  asset_name: string;
  application: string | null;
  repository: string | null;
  file: string | null;
  line: number | null;
  language: string | null;
  container: string | null;

  // --- cryptographic identity --------------------------------------------
  algorithm: string | null;
  algorithm_label: string | null;
  algorithm_family: string | null;
  primitive: string | null;
  mode: string | null;
  padding: string | null;
  key_size: number | null;
  /** NORM-001: spellings are not yet normalised backend-side. Display as-is. */
  curve: string | null;
  security_strength: number | null;
  quantum_strength: number | null;
  cryptographic_role: string | null;
  crypto_functions: string[];
  protocol: string | null;
  protocol_version: string | null;
  library: string | null;
  library_version: string | null;
  package: string | null;
  oid: string | null;

  // --- certificate -------------------------------------------------------
  certificate_subject: string | null;
  certificate_issuer: string | null;
  certificate_serial: string | null;
  certificate_not_before: string | null;
  certificate_expiry: string | null;
  certificate_self_signed: boolean | null;
  certificate_san: string[];
  certificate_sig_algorithm: string | null;
  days_to_expiry: number | null;

  // --- business context --------------------------------------------------
  usage: string | null;
  owner: string | null;
  business_unit: string | null;
  data_classification: string | null;
  data_lifetime_years: number | null;
  business_criticality: string | null;
  internet_exposed: boolean | null;
  exposure: string | null;
  /** Whether the context above was declared, inferred or defaulted (§15). */
  context_source: ContextSource | string | null;

  // --- risk: two independent axes ----------------------------------------
  quantum_vulnerable: boolean;
  quantum_class: string | null;
  classical_security_status: string | null;
  classical_risk: RiskBand;
  quantum_exposure: QuantumExposure;
  quantum_risk: QuantumExposure;
  risk_score: number;
  risk_factors: RiskFactors;
  risk_explanation: string[];

  // --- Mosca -------------------------------------------------------------
  mosca_urgency: MoscaUrgency | string;
  mosca_gap_years: number | null;
  mosca_detail: MoscaDetail;

  // --- recommendation ----------------------------------------------------
  recommended_action: string | null;
  recommended_pqc: string | null;
  recommended_hybrid: string | null;
  recommendation_rationale: string | null;
  recommendation_citations: string[];
  migration_steps: string[];
  pqc_readiness: string | null;
  pqc_readiness_note: string | null;

  // --- migration decision: the two levels, never collapsed ---------------
  migration_priority: number;
  priority_band: PriorityBand;
  migration_decision: MigrationDecision;
  recommended_strategy: string | null;
  decision_rationale: string | null;
  decision_inputs: DecisionInputs;
  decision_blocked_on: string | null;
  migration_effort: EffortLevel | string | null;
  migration_months: number | null;

  // --- coupling ----------------------------------------------------------
  dependency_centrality: number | null;
  dependency_centrality_score: number | null;
  affected_assets: string[];
  affected_summary: AffectedSummary;

  // --- agility / interoperability ----------------------------------------
  crypto_agility: AgilityLevel | null;
  crypto_agility_signals: string[];
  interoperability: Interoperability | null;
  interoperability_reason: string | null;
  migration_blockers: string[];

  /** Potential compliance relevance. Not a compliance status. */
  compliance_tags: string[];

  // --- evidence and provenance -------------------------------------------
  confidence: ConfidenceLevel;
  confidence_score: number;
  evidence_type: string | null;
  source: string | null;
  provenance: string | null;
  /** Inline evidence. Never carries `snippet`: the backend removes it. */
  evidence: EvidenceRecord[];
  detectors: string[];
  duplicate_count: number | null;

  // --- workflow ----------------------------------------------------------
  remediation_status: string | null;
  remediation_history: RemediationEvent[];
  triage_state: string | null;
  triage_notes: string | null;
  overrides: Record<string, unknown>;
  audit_log: unknown[];
  tags: string[];
}

/** What the API deliberately omits. Rendered in the UI, never hidden. */
export interface Redactions {
  evidence_fields_removed: string[];
  reason: string;
  key_material: string;
}

export interface AssetDetailResponse {
  asset: CryptoAsset;
  redactions: Redactions;
}

export interface AssetListResponse {
  scan_id: string;
  total: number;
  matched: number;
  count: number;
  limit: number;
  offset: number;
  truncated: boolean;
  /** Echo of the filters the backend actually applied. `null` when none were. */
  filters: Record<string, string> | null;
  view: string;
  assets: AssetSummary[];
  note?: string;
}

/**
 * The same envelope under `view=full`, where each entry is the complete
 * canonical asset rather than the 42-field summary projection.
 *
 * Kept as a separate type rather than a union so a caller cannot accidentally
 * read a full-only field (business criticality, certificate validity, data
 * lifetime) off a summary response and silently get `undefined`. The full view
 * is roughly ten times the payload, so asking for it is a deliberate act.
 */
export interface AssetListFullResponse extends Omit<AssetListResponse, "assets"> {
  assets: CryptoAsset[];
}

// ---------------------------------------------------------------------------
// Evidence -- why ECDAT believes an asset exists. Never carries `snippet`.
// ---------------------------------------------------------------------------

export interface EvidenceRecord {
  detector: string;
  method: string;
  location: string;
  evidence_type: string;
  confidence: ConfidenceLevel;
  matched: string | null;
  reasoning: string | null;
  /**
   * Distinguishes "this algorithm is reachable" from "this library is
   * present" -- the difference between a finding and a guess. Present on
   * `GET /assets/{id}/evidence`; absent from the asset's inline evidence.
   */
  proves_execution?: boolean;
}

export interface EvidenceResponse {
  asset_id: string;
  asset_name: string;
  confidence: ConfidenceLevel;
  confidence_score: number;
  strongest_evidence_type: string | null;
  detectors: string[];
  count: number;
  evidence: EvidenceRecord[];
  redactions: Redactions;
  note?: string;
}

// ---------------------------------------------------------------------------
// Risk -- two independent axes, reported separately.
// ---------------------------------------------------------------------------

export interface RiskFactor {
  name: string;
  raw: number;
  weight: number;
  contribution: number;
  explanation: string;
}

/**
 * One axis's verdict. `band` and `reason` are always present; the remaining
 * fields are the evidence that axis happened to use, so each is optional --
 * a classical verdict carries strength bits, a quantum verdict carries the
 * harvest-now-decrypt-later finding, and neither borrows the other's.
 */
export interface AxisVerdict {
  band: string;
  reason: string;
  trigger: string;
  classical_status?: string;
  strength_bits?: number | null;
  policy_floor?: number | null;
  below_policy_floor?: boolean;
  quantum_strength_bits?: number | null;
  harvest_now_decrypt_later?: boolean;
  data_lifetime_years?: number | null;
}

export interface RiskFactors {
  score: number;
  band: string;
  quantum_band: string;
  classical_status: string;
  quantum_vulnerable: boolean;
  quantum_class: string;
  weights_are_engineering_judgement: boolean;
  factors: RiskFactor[];
  explanation: string[];
  classical_risk: AxisVerdict;
  quantum_exposure: AxisVerdict;
  axes_are_independent: string;
  policy: string;
}
/** The CRQC scenario. `crqc_year` is a policy deadline, not a prediction. */
export interface Scenario {
  crqc_year: number;
  data_lifetime_years: number | null;
  migration_months: number | null;
  safety_margin_years: number;
  label: string;
  crqc_rationale: string;
}

export interface RiskView {
  asset_id: string;
  asset_name: string;
  classical_axis: {
    classical_risk: RiskBand;
    classical_security_status: string | null;
  };
  quantum_axis: {
    quantum_exposure: QuantumExposure;
    quantum_class: string | null;
    quantum_vulnerable: boolean;
  };
  risk_score: number;
  risk_factors: RiskFactors;
  risk_explanation: string[];
  mosca_urgency: MoscaUrgency | string;
  mosca_gap_years: number;
  migration_priority: number;
  priority_band: PriorityBand;
  confidence: ConfidenceLevel;
  confidence_score: number;
  scenario: Scenario;
  policy: string;
  note?: string;
}

// ---------------------------------------------------------------------------
// Migration -- two levels, never collapsed.
// ---------------------------------------------------------------------------

export interface MigrationView {
  asset_id: string;
  asset_name: string;
  migration_decision: MigrationDecision;
  recommended_strategy: string | null;
  recommended_pqc: string | null;
  recommended_hybrid: string | null;
  decision_rationale: string | null;
  decision_blocked_on: string | null;
  standards: string[];
  migration_effort: EffortLevel | string | null;
  migration_months: number | null;
  crypto_agility: AgilityLevel | null;
  interoperability: Interoperability | null;
  pqc_readiness: string | null;
  migration_blockers: string[];
  decision_definitions: Record<MigrationDecision, string>;
  note?: string;
}

// ---------------------------------------------------------------------------
// Impact -- graph-derived blast radius.
// ---------------------------------------------------------------------------

/**
 * One thing that has to happen before this asset can be migrated.
 *
 * `kind` is how the dependency was found -- `provider` (a library or component
 * this asset is built on), `pki` (an issuing certificate) or `protocol` (a peer
 * that has to negotiate the change) -- and `reason` is the backend's own
 * sentence for why. Both come straight from the graph traversal.
 */
export interface ImpactPrerequisite {
  asset_id: string;
  asset_name: string;
  kind: string;
  reason: string;
}

export interface MigrationImpact {
  asset_id: string;
  asset_name: string;
  decision: MigrationDecision;
  applications: string[];
  services: string[];
  repositories: string[];
  containers: string[];
  files: string[];
  owners: string[];
  business_units: string[];
  business_functions: string[];
  libraries: string[];
  protocols: string[];
  certificates: string[];
  change_units: string[];
  dependent_assets: string[];
  algorithm_siblings: string[];
  /** Work that must land first. Objects, not ids: each carries its own reason. */
  prerequisites: ImpactPrerequisite[];
  /** Asset ids that cannot start until this one is done. */
  unblocks: string[];
  own_effort: EffortLevel | string;
  own_effort_months: number;
  coordinated_effort_months: number;
  prerequisite_months: number;
  effort_rule: string;
  effort_drivers: string[];
  blockers: string[];
  blast_radius: number;
  blast_radius_score: number;
  explanation: string;
  traversal: {
    asset_node: string;
    resource_nodes: string[];
    reach_nodes: number;
    coupled_assets: number;
    method: string;
  };
}

export interface ImpactResponse {
  asset_id: string;
  asset_name: string;
  migration_decision: MigrationDecision;
  impact: MigrationImpact;
  headline: string;
  derivation: string;
}

// ---------------------------------------------------------------------------
// Graph
// ---------------------------------------------------------------------------

export type GraphNodeType =
  | "application"
  | "service"
  | "repository"
  | "library"
  | "algorithm"
  | "protocol"
  | "certificate"
  | "crypto-asset"
  | "data"
  | "business-function"
  | "container";

export interface GraphNode {
  id: string;
  type: GraphNodeType | string;
  label: string;
  owner?: string | null;
  business_unit?: string | null;
  environment?: string | null;
  criticality?: string | null;
  exposure?: string | null;
  data_classification?: string | null;
  data_lifetime_years?: number | null;
  context_source?: string | null;
  [key: string]: unknown;
}

export interface GraphEdge {
  source: string;
  target: string;
  type: string;
}

export interface AssetGraphResponse {
  asset_id: string;
  asset_name: string;
  depth: number;
  dependency_centrality: number;
  dependency_centrality_score: number;
  affected_summary: AffectedSummary;
  graph: {
    nodes: GraphNode[];
    edges: GraphEdge[];
    counts: { nodes: number; edges: number };
    focus: string;
  };
  note?: string;
}

// ---------------------------------------------------------------------------
// Dashboard
// ---------------------------------------------------------------------------

/** A distribution: band/label -> count. Keys vary, so it stays a record. */
export type Distribution = Record<string, number>;

export interface GatingAsset {
  asset_id: string;
  asset_name: string;
  decision: MigrationDecision;
  unblocks: number;
  applications: string[];
  rationale: string;
}

export interface DashboardSummary {
  estate: {
    target: string;
    scan_id: string;
    scanned_at: string;
    policy: string;
    assets: number;
    applications: number;
    business_context_defaulted: number;
    business_context_note: string;
  };
  classical_axis: Distribution;
  quantum_axis: Distribution;
  quantum_taxonomy: Distribution;
  migration_decisions: Distribution;
  decision_definitions: Record<MigrationDecision, string>;
  urgency: Distribution;
  priority_bands: Distribution;
  crypto_agility: Distribution;
  interoperability: Distribution;
  confidence: Distribution;
  asset_types: Distribution;
  headlines: {
    total_assets: number;
    need_no_change: number;
    need_change: number;
    quantum_vulnerable: number;
    quantum_vulnerable_pct: string;
    classically_broken_today: number;
    scheduled: number;
    gating_assets: number;
  };
  roadmap_totals: RoadmapTotals;
  gating_assets: GatingAsset[];
  notes: string[];
  scenario: Scenario;
}

// ---------------------------------------------------------------------------
// Roadmap
// ---------------------------------------------------------------------------

export interface RoadmapTotals {
  assets: number;
  in_scope: number;
  scheduled: number;
  no_action_required: number;
  quantum_vulnerable: number;
  classically_broken: number;
  gating_assets: number;
  p0: number;
  p1: number;
  p2: number;
  p3: number;
}

export interface RoadmapItem {
  asset_id: string;
  asset_name: string;
  application: string | null;
  location: string | null;
  priority: number;
  band: PriorityBand;
  urgency: MoscaUrgency | string;
  decision: MigrationDecision;
  strategy: string | null;
  target: string | null;
  effort: EffortLevel | string;
  months: number;
  coordinated_months: number;
  agility: AgilityLevel | null;
  centrality: number;
  blast_radius: number;
  prerequisites: string[];
  unblocks: number;
  blockers: string[];
  change_units: string[];
  phase: string;
  why_this_phase: string;
}

export interface RoadmapBand {
  band: PriorityBand;
  assets: number;
  decisions: Distribution;
  phases: Distribution;
  applications: string[];
  longest_coordinated_months: number;
  top_items: RoadmapItem[];
}

export interface RoadmapPhase {
  id: string;
  name: string;
  objective: string;
  duration: string;
  asset_count: number;
  applications: string[];
  bands: Distribution;
  decisions: Distribution;
  longest_coordinated_months: number;
  deliverables: string[];
  exit_criteria: string[];
  items: RoadmapItem[];
  items_truncated: number;
}

export interface EnablementWave {
  gating_asset: string;
  gating_asset_name: string;
  phase: string;
  decision: MigrationDecision;
  strategy: string | null;
  change_units: string[];
  dependent_assets: number;
  applications: string[];
  months: number;
  rationale: string;
}

export interface RoadmapApplication {
  application: string;
  name: string;
  owner: string | null;
  business_unit: string | null;
  assets: number;
  quantum_vulnerable: number;
  retain: number;
  p0: number;
  p1: number;
  max_priority: number;
  worst_urgency: MoscaUrgency | string;
  effort_months: number;
  decisions: Distribution;
}

export interface RoadmapResponse {
  scan_id: string;
  totals: RoadmapTotals;
  bands: Record<PriorityBand, RoadmapBand>;
  phases: RoadmapPhase[];
  enablement_waves: EnablementWave[];
  applications: RoadmapApplication[];
  method: {
    placement: string;
    precedence: string[];
    sequencing_source: string;
    prerequisites_hoisted: number;
    hoist_rule: string;
    bands_vs_phases: string;
    effort_note: string;
    retain_note: string;
  };
  items_truncated: number;
  note?: string;
}

// ---------------------------------------------------------------------------
// CBOM
// ---------------------------------------------------------------------------

export interface CbomCounts {
  components: number;
  cryptographic_assets: number;
  libraries: number;
  applications: number;
  dependencies: number;
  with_evidence: number;
  algorithm: number;
  certificate: number;
  protocol: number;
  related_crypto_material: number;
}

/**
 * Validation is against the vendored schema file only. `scope` and `claim`
 * carry the backend's own honest wording and must be surfaced verbatim --
 * this is never described as a certification (§21).
 */
export interface CbomValidation {
  valid: boolean;
  errors: string[];
  error_count: number;
  schema: string;
  schema_file: string;
  validator: string;
  scope: string;
  counts: CbomCounts;
  claim: string;
}

export interface CycloneDxDocument {
  bomFormat: string;
  specVersion: string;
  serialNumber: string;
  version: number;
  metadata: Record<string, unknown>;
  components: unknown[];
  dependencies: unknown[];
  [key: string]: unknown;
}

// ---------------------------------------------------------------------------
// Scan
// ---------------------------------------------------------------------------

/**
 * Coverage counters, exactly as `ScanStats` in `ecdat/models.py` declares them.
 *
 * Field names are the backend's. `skipped_files` and `errors` are spelled the
 * way the dataclass spells them rather than the way a screen might prefer to
 * read, so a mismatch is a compile error instead of a silently empty cell.
 *
 * These counters exist only on the `POST /scan` response. No GET route returns
 * them, so a screen that did not run the scan itself cannot show them and must
 * say so rather than substitute anything.
 */
export interface ScanStats {
  repositories: number;
  files_seen: number;
  files_analyzed: number;
  bytes_analyzed: number;
  certificates: number;
  containers: number;
  binaries: number;
  dependencies: number;
  manifests: number;
  configs: number;
  raw_detections: number;
  deduplicated: number;
  skipped_files: number;
  errors: string[];
  duration_ms: number;
  detector_counts?: Distribution;
  language_counts?: Distribution;
  [key: string]: unknown;
}

/** Graph size after the scan, from `graph.stats()`. */
export interface ScanGraphStats {
  nodes: number;
  edges: number;
  nodes_by_type: Distribution;
  edges_by_type: Distribution;
}

/**
 * CBOM counters on the scan response.
 *
 * Narrower than `CbomCounts` from `/cbom/validation`, and deliberately carries
 * `validation_scope` so the wording that bounds the claim travels with the
 * number it bounds (§16: this is not a certification).
 */
export interface ScanCbomSummary {
  components: number;
  schema_valid: boolean;
  validation_scope: string;
}

/**
 * The last progress event the engine emitted.
 *
 * The pipeline is synchronous and this arrives with the finished response, so
 * it is always the terminal event. It is a record of what completed, never a
 * live percentage -- there is no streaming endpoint to read one from.
 */
export interface ScanProgressEvent {
  stage: string;
  detail: string;
  percent: number;
  at?: string;
}

export interface ScanResult {
  scan_id: string;
  started_at: string;
  target: string;
  policy: string;
  demo: boolean;
  assets: number;
  applications: number;
  stats: ScanStats;
  graph: ScanGraphStats;
  roadmap_totals: RoadmapTotals;
  cbom: ScanCbomSummary;
  scenario: Scenario;
  progress: ScanProgressEvent;
  notes: string[];
  [key: string]: unknown;
}

export interface ScanRequest {
  demo?: boolean;
  targets?: string[];
  policy?: string;
  crqc_year?: number;
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

export interface ApiErrorBody {
  error: {
    code: string;
    status: number;
    message: string;
    detail?: unknown;
  };
}

export interface HealthResponse {
  status: string;
  api_version: string;
  scan_loaded: boolean;
  scan_id: string | null;
  assets: number;
}
