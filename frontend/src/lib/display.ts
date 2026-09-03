/**
 * Display helpers: labels, colour tokens and number formatting.
 *
 * Presentation only. Nothing here derives a band, a score, a decision or an
 * urgency -- those arrive from the API already decided (§37). A mapping from
 * `"already-late"` to `"Already late"` is typography, not analysis.
 */

import type {
  AgilityLevel,
  ConfidenceLevel,
  Distribution,
  MigrationDecision,
  PriorityBand,
  QuantumExposure,
  RiskBand,
} from "@/types/api";

// ---------------------------------------------------------------------------
// Colour tokens
// ---------------------------------------------------------------------------

/**
 * Colour for a classical risk band, as a CSS variable reference.
 *
 * Returned as `var(--risk-*)` rather than a literal so charts, badges and the
 * graph all resolve to the same token and both themes work without a second
 * palette. Recharts renders real SVG in the document, so CSS variables resolve
 * normally in `fill` and `stroke`.
 */
export function riskColor(band: string): string {
  return `var(--risk-${normalizeBandKey(band)})`;
}

/** Colour for a quantum exposure band. Deliberately a different family. */
export function quantumColor(band: string): string {
  return `var(--quantum-${normalizeBandKey(band)})`;
}

function normalizeBandKey(band: string): string {
  const key = band?.toLowerCase?.() ?? "";
  return ["critical", "high", "medium", "low", "info"].includes(key) ? key : "info";
}

/** Ordered band keys, worst first. Used to keep chart legends stable. */
export const RISK_ORDER: readonly RiskBand[] = [
  "critical",
  "high",
  "medium",
  "low",
  "info",
];

export const QUANTUM_ORDER: readonly QuantumExposure[] = [
  "critical",
  "high",
  "medium",
  "low",
  "info",
];

/**
 * Business-context vocabularies, worst first.
 *
 * These are transcribed from the backend's own enums in `ecdat/models.py`
 * (`Criticality.score`, `Exposure.score`, `DataClassification.score`) so a
 * chart axis reads in the same order the engine ranks them. They are display
 * orderings of a backend vocabulary, not a scoring model of their own -- the
 * frontend never turns them into a number.
 */
export const CRITICALITY_ORDER: readonly string[] = [
  "mission-critical",
  "high",
  "important",
  "low",
  "non-critical",
];

export const EXPOSURE_ORDER: readonly string[] = [
  "internet-facing-critical",
  "external-facing",
  "controlled",
  "internal",
  "isolated",
];

export const DATA_CLASSIFICATION_ORDER: readonly string[] = [
  "mission-critical",
  "sensitive",
  "confidential",
  "internal",
  "public",
];

export const CRITICALITY_LABEL: Record<string, string> = {
  "mission-critical": "Mission-critical",
  high: "High",
  important: "Important",
  low: "Low",
  "non-critical": "Non-critical",
};

export const EXPOSURE_LABEL: Record<string, string> = {
  "internet-facing-critical": "Internet-facing (critical)",
  "external-facing": "External-facing",
  controlled: "Controlled",
  internal: "Internal",
  isolated: "Isolated",
};

/**
 * Decision colours. Chosen so the reading is "how much work is this", not "how
 * scared should I be": RETAIN is calm, PQC-ONLY is the strongest violet
 * because it is the furthest-travelled quantum outcome, and HARDEN sits in the
 * classical-warning family because it is a classical-weakness fix.
 */
export const DECISION_COLOR: Record<MigrationDecision, string> = {
  RETAIN: "var(--success)",
  HARDEN: "var(--risk-medium)",
  UPGRADE: "var(--info)",
  HYBRID: "var(--quantum-medium)",
  "PQC-ONLY": "var(--quantum-critical)",
};

export const PRIORITY_COLOR: Record<PriorityBand, string> = {
  P0: "var(--risk-critical)",
  P1: "var(--risk-high)",
  P2: "var(--risk-medium)",
  P3: "var(--risk-info)",
};

export const CONFIDENCE_COLOR: Record<ConfidenceLevel, string> = {
  high: "var(--success)",
  medium: "var(--warning)",
  low: "var(--risk-info)",
};

export const AGILITY_COLOR: Record<AgilityLevel, string> = {
  high: "var(--success)",
  medium: "var(--warning)",
  low: "var(--risk-high)",
};

/** Neutral categorical ramp for distributions with no risk semantics. */
export const CATEGORICAL_COLORS = [
  "var(--chart-1)",
  "var(--chart-2)",
  "var(--chart-3)",
  "var(--chart-4)",
  "var(--chart-5)",
  "var(--quantum-medium)",
  "var(--risk-medium)",
  "var(--info)",
] as const;

export function categoricalColor(index: number): string {
  return CATEGORICAL_COLORS[index % CATEGORICAL_COLORS.length];
}

// ---------------------------------------------------------------------------
// Labels
// ---------------------------------------------------------------------------

export const URGENCY_LABEL: Record<string, string> = {
  "already-late": "Already late",
  critical: "Critical",
  "plan-now": "Plan now",
  monitor: "Monitor",
  "not-applicable": "Not applicable",
};

export const ASSET_TYPE_LABEL: Record<string, string> = {
  "source-finding": "Source finding",
  certificate: "Certificate",
  dependency: "Dependency",
  "binary-artifact": "Binary artifact",
  "container-package": "Container package",
  "protocol-config": "Protocol config",
  "key-material": "Key material",
};

export const NODE_TYPE_LABEL: Record<string, string> = {
  application: "Application",
  service: "Service",
  repository: "Repository",
  library: "Library",
  algorithm: "Algorithm",
  protocol: "Protocol",
  certificate: "Certificate",
  "crypto-asset": "Crypto asset",
  data: "Data store",
  "business-function": "Business function",
  container: "Container",
};

/**
 * How a business-context field was populated. The wording is deliberately
 * unambiguous: a default is never described as something ECDAT found (§15).
 */
export const CONTEXT_SOURCE_LABEL: Record<string, string> = {
  "operator-declared": "Operator-declared",
  discovered: "Discovered",
  inferred: "Inferred",
  default: "Default (assumed)",
  unknown: "Unknown",
};

export const CONTEXT_SOURCE_HELP: Record<string, string> = {
  "operator-declared":
    "Supplied by an operator in the estate definition. Not discovered by a detector.",
  discovered: "Read directly from the scanned artefact by a detector.",
  inferred: "Derived from surrounding evidence rather than stated outright.",
  default:
    "No value was available, so ECDAT applied a documented default. This is an assumption, not a finding.",
  unknown: "No value and no applicable default.",
};

export const EFFORT_LABEL: Record<string, string> = {
  low: "Low",
  medium: "Medium",
  high: "High",
  "very-high": "Very high",
};

/** Sentence-case an API token such as `shor_broken` or `plan-now`. */
export function humanize(value: string | null | undefined): string {
  if (!value) return "—";
  const spaced = value.replace(/[_-]+/g, " ").trim();
  return spaced.charAt(0).toUpperCase() + spaced.slice(1);
}

export function urgencyLabel(value: string | null | undefined): string {
  if (!value) return "—";
  return URGENCY_LABEL[value] ?? humanize(value);
}

export function assetTypeLabel(value: string | null | undefined): string {
  if (!value) return "—";
  return ASSET_TYPE_LABEL[value] ?? humanize(value);
}

export function nodeTypeLabel(value: string | null | undefined): string {
  if (!value) return "—";
  return NODE_TYPE_LABEL[value] ?? humanize(value);
}

export function contextSourceLabel(value: string | null | undefined): string {
  if (!value) return "Unknown";
  return CONTEXT_SOURCE_LABEL[value] ?? humanize(value);
}

// ---------------------------------------------------------------------------
// Numbers, dates, paths
// ---------------------------------------------------------------------------

const NUMBER_FORMAT = new Intl.NumberFormat("en-US");

export function formatNumber(value: number | null | undefined): string {
  if (value === null || value === undefined || Number.isNaN(value)) return "—";
  return NUMBER_FORMAT.format(value);
}

/** `count / total` as a whole percentage. Returns `0` for an empty total. */
export function percentOf(count: number, total: number): number {
  if (!total) return 0;
  return Math.round((count / total) * 100);
}

export function formatPercent(count: number, total: number): string {
  return `${percentOf(count, total)}%`;
}

export function formatMonths(months: number | null | undefined): string {
  if (months === null || months === undefined) return "—";
  if (months === 0) return "0 months";
  if (months === 1) return "1 month";
  if (months < 12) return `${months} months`;
  const years = months / 12;
  const rounded = Number.isInteger(years) ? years : Math.round(years * 10) / 10;
  return `${months} months (~${rounded} yr)`;
}

export function formatScore(value: number | null | undefined): string {
  if (value === null || value === undefined || Number.isNaN(value)) return "—";
  return Number.isInteger(value) ? String(value) : value.toFixed(1);
}

export function formatDateTime(iso: string | null | undefined): string {
  if (!iso) return "—";
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  return date.toLocaleString("en-GB", {
    day: "2-digit",
    month: "short",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function formatDate(iso: string | null | undefined): string {
  if (!iso) return "—";
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  return date.toLocaleDateString("en-GB", {
    day: "2-digit",
    month: "short",
    year: "numeric",
  });
}

/** Duration in milliseconds, as reported by the scan stats. */
export function formatDuration(ms: number | null | undefined): string {
  if (ms === null || ms === undefined) return "—";
  if (ms < 1000) return `${Math.round(ms)} ms`;
  return `${(ms / 1000).toFixed(1)} s`;
}

export function formatBytes(bytes: number | null | undefined): string {
  if (bytes === null || bytes === undefined) return "—";
  const units = ["B", "KB", "MB", "GB"];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${unit === 0 ? value : value.toFixed(1)} ${units[unit]}`;
}

/** Keep the tail of a long path: the filename matters more than the prefix. */
export function shortenPath(path: string | null | undefined, max = 42): string {
  if (!path) return "—";
  if (path.length <= max) return path;
  return `…${path.slice(-(max - 1))}`;
}

/**
 * A distribution as sorted entries. `order` pins known keys to a stable
 * sequence (so "critical" is always leftmost); anything unlisted follows,
 * sorted by count.
 */
export function distributionEntries(
  distribution: Distribution | undefined,
  order?: readonly string[],
): { key: string; count: number }[] {
  if (!distribution) return [];
  const entries = Object.entries(distribution).map(([key, count]) => ({ key, count }));
  if (!order) return entries.sort((a, b) => b.count - a.count);
  const rank = (key: string) => {
    const index = order.indexOf(key);
    return index === -1 ? order.length : index;
  };
  return entries.sort((a, b) => rank(a.key) - rank(b.key) || b.count - a.count);
}

export function sumDistribution(distribution: Distribution | undefined): number {
  if (!distribution) return 0;
  return Object.values(distribution).reduce((total, n) => total + n, 0);
}
