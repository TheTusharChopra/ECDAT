/**
 * The inventory filter registry.
 *
 * Every filter here declares, as data, whether the API can apply it. That
 * distinction is not cosmetic: a server filter narrows the whole estate and the
 * result counts stay true, while a client filter can only narrow the page that
 * was already fetched. Presenting the second as the first would overstate what
 * the tool did, so the scope travels with the filter and the UI labels it (§4).
 *
 * `GET /assets` accepts exactly fifteen filters (`FILTERABLE` in
 * `ecdat/api/service.py`). Note that several parameter names differ from the
 * canonical field they test -- `decision` tests `migration_decision`, `band`
 * tests `priority_band`, `urgency` tests `mosca_urgency`. The parameter name is
 * what goes in the URL, so it is what `key` holds.
 *
 * Algorithm, role and protocol are NOT server-filterable. They are listed as
 * required inventory dimensions, so they exist here with `scope: "client"` and
 * are marked as page-scoped everywhere they appear.
 */

import type { AssetSummary, DashboardSummary } from "@/types/api";
import {
  ASSET_TYPE_LABEL,
  CONTEXT_SOURCE_LABEL,
  QUANTUM_ORDER,
  RISK_ORDER,
  humanize,
  urgencyLabel,
} from "@/lib/display";

/** Whether the API applies this filter, or only the loaded page can. */
export type FilterScope = "server" | "client";

export interface FilterDef {
  /** URL key. For a server filter this is the literal API query parameter. */
  key: string;
  label: string;
  scope: FilterScope;
  /** The canonical summary field the filter tests. */
  field: keyof AssetSummary;
  /**
   * A `/dashboard` distribution to take options from. Those distributions are
   * backend-computed counts over the whole estate, so their option lists carry
   * real counts. Filters without one take their options from the asset list.
   */
  distribution?: DashboardDistributionKey;
  /** Fixed display order, where the domain has a meaningful one. */
  order?: readonly string[];
  /** Human label for a raw value. */
  format?: (value: string) => string;
  /** Shown in the always-visible filter row rather than the overflow popover. */
  primary?: boolean;
  /** One line explaining what the filter selects on. */
  help?: string;
}

/** Keys of `DashboardSummary` that hold a `Record<string, number>` histogram. */
export type DashboardDistributionKey =
  | "classical_axis"
  | "quantum_axis"
  | "quantum_taxonomy"
  | "migration_decisions"
  | "urgency"
  | "priority_bands"
  | "crypto_agility"
  | "interoperability"
  | "confidence"
  | "asset_types";

const DECISION_ORDER = ["RETAIN", "HARDEN", "UPGRADE", "HYBRID", "PQC-ONLY"] as const;
const BAND_ORDER = ["P0", "P1", "P2", "P3"] as const;
const LEVEL_ORDER = ["high", "medium", "low"] as const;
const URGENCY_ORDER = [
  "already-late",
  "critical",
  "plan-now",
  "monitor",
  "not-applicable",
] as const;

/**
 * The fifteen server filters, then the three page-scoped ones.
 *
 * Order matters: it is the order the controls appear in.
 */
export const FILTERS: readonly FilterDef[] = [
  {
    key: "asset_type",
    label: "Type",
    scope: "server",
    field: "asset_type",
    distribution: "asset_types",
    format: (value) => ASSET_TYPE_LABEL[value] ?? humanize(value),
    primary: true,
    help: "What kind of thing the finding is: source usage, certificate, dependency, binary, container package or protocol configuration.",
  },
  {
    key: "classical_risk",
    label: "Classical risk",
    scope: "server",
    field: "classical_risk",
    distribution: "classical_axis",
    order: RISK_ORDER,
    primary: true,
    help: "The backend's classical-weakness band. Independent of quantum exposure.",
  },
  {
    key: "quantum_exposure",
    label: "Quantum exposure",
    scope: "server",
    field: "quantum_exposure",
    distribution: "quantum_axis",
    order: QUANTUM_ORDER,
    primary: true,
    help: "The backend's quantum-exposure band. Computed by a separate function that does not read classical risk.",
  },
  {
    key: "decision",
    label: "Decision",
    scope: "server",
    field: "migration_decision",
    distribution: "migration_decisions",
    order: DECISION_ORDER,
    primary: true,
    help: "One of the five frozen migration outcomes. The specific action beneath it is the recommended strategy.",
  },
  {
    key: "band",
    label: "Priority",
    scope: "server",
    field: "priority_band",
    distribution: "priority_bands",
    order: BAND_ORDER,
    primary: true,
    help: "Priority band P0-P3, assigned by the backend's prioritisation pass.",
  },
  {
    key: "urgency",
    label: "Mosca urgency",
    scope: "server",
    field: "mosca_urgency",
    distribution: "urgency",
    order: URGENCY_ORDER,
    format: urgencyLabel,
    primary: true,
    help: "Timing verdict from Mosca's inequality against the configured threat horizon.",
  },
  {
    key: "quantum_class",
    label: "Quantum class",
    scope: "server",
    field: "quantum_class",
    distribution: "quantum_taxonomy",
    format: humanize,
    help: "How the algorithm itself stands up to a quantum attack: Shor-broken, Grover-reduced, already classically broken, PQC-standardised, and so on.",
  },
  {
    key: "confidence",
    label: "Confidence",
    scope: "server",
    field: "confidence",
    distribution: "confidence",
    order: LEVEL_ORDER,
    help: "Detection confidence for the finding, derived from its evidence.",
  },
  {
    key: "agility",
    label: "Crypto agility",
    scope: "server",
    field: "crypto_agility",
    distribution: "crypto_agility",
    order: LEVEL_ORDER,
    help: "How replaceable the cryptography is in place, as assessed by the backend.",
  },
  {
    key: "interoperability",
    label: "Interoperability",
    scope: "server",
    field: "interoperability",
    distribution: "interoperability",
    order: ["open", "negotiated", "constrained"],
    format: humanize,
    help: "Whether a change can be made unilaterally, has to be negotiated, or is constrained by a counterparty.",
  },
  {
    key: "application",
    label: "Application",
    scope: "server",
    field: "application",
    help: "The application the asset belongs to, from business context.",
  },
  {
    key: "owner",
    label: "Owner",
    scope: "server",
    field: "owner",
    help: "The declared owning team.",
  },
  {
    key: "library",
    label: "Library",
    scope: "server",
    field: "library",
    help: "The cryptographic library the finding was made through.",
  },
  {
    key: "strategy",
    label: "Strategy",
    scope: "server",
    field: "recommended_strategy",
    format: humanize,
    help: "The specific standards-grounded action recommended beneath the decision.",
  },
  {
    key: "context_source",
    label: "Context source",
    scope: "server",
    field: "context_source",
    format: (value) => CONTEXT_SOURCE_LABEL[value] ?? humanize(value),
    help: "Where the asset's business context came from: declared by an operator, inferred, or an assumed default.",
  },

  // --- page-scoped: the API has no parameter for these ---------------------
  {
    key: "algorithm",
    label: "Algorithm family",
    scope: "client",
    field: "algorithm_family",
    format: humanize,
    help: "Algorithm family. The API has no algorithm filter, so this narrows the loaded page only.",
  },
  {
    key: "role",
    label: "Role",
    scope: "client",
    field: "cryptographic_role",
    format: humanize,
    help: "Canonical cryptographic role. The API has no role filter, so this narrows the loaded page only.",
  },
  {
    key: "protocol",
    label: "Protocol",
    scope: "client",
    field: "protocol",
    help: "Protocol the asset participates in. The API has no protocol filter, so this narrows the loaded page only.",
  },
];

export const SERVER_FILTERS = FILTERS.filter((filter) => filter.scope === "server");
export const CLIENT_FILTERS = FILTERS.filter((filter) => filter.scope === "client");
export const PRIMARY_FILTERS = FILTERS.filter((filter) => filter.primary);
export const OVERFLOW_FILTERS = FILTERS.filter((filter) => !filter.primary);

export const FILTER_BY_KEY: Record<string, FilterDef> = Object.fromEntries(
  FILTERS.map((filter) => [filter.key, filter]),
);

/** The three sorts the API implements, and the column each one orders by. */
export const SERVER_SORTS = {
  name: "asset_name",
  risk: "risk_score",
  priority: "migration_priority",
} as const;

export type ServerSort = keyof typeof SERVER_SORTS;

/** Reverse map: column id -> the API sort that orders the whole estate by it. */
export const SORT_BY_COLUMN: Record<string, ServerSort> = {
  asset_name: "name",
  risk_score: "risk",
  classical_risk: "risk",
  migration_priority: "priority",
  priority_band: "priority",
};

export const PAGE_SIZES = [25, 50, 100, 200] as const;

/** A filter option: the raw value, its label, and a backend count when known. */
export interface FilterOption {
  value: string;
  label: string;
  count?: number;
}

/**
 * Build one filter's option list.
 *
 * Two sources, deliberately kept apart. A `/dashboard` distribution is a
 * backend aggregate over the whole estate, so its counts are quotable. The
 * asset-list fallback is just the distinct values present in the inventory
 * response, offered so the control can be used at all -- no counts are shown
 * for those, because a count assembled in the browser is not a backend figure.
 */
/**
 * A value's display label.
 *
 * Pure by design: it reads the filter definition and the value, never a fetched
 * option list. The trigger, the chip and the menu all label through here, so one
 * value is spelled the same way in all three -- and so the label is identical in
 * the server render and the client's, which a lookup into `filterOptions` is
 * not: on the server that list is still empty.
 */
export function optionLabel(filter: FilterDef, value: string): string {
  return (filter.format ?? humanize)(value);
}

export function filterOptions(
  filter: FilterDef,
  dashboard: DashboardSummary | undefined,
  assets: readonly AssetSummary[] | undefined,
): FilterOption[] {
  const format = (value: string) => optionLabel(filter, value);

  if (filter.distribution && dashboard) {
    const distribution = dashboard[filter.distribution] as Record<string, number>;
    const entries = Object.entries(distribution ?? {});
    const ordered = filter.order
      ? [...entries].sort(
          (a, b) => orderIndex(filter.order!, a[0]) - orderIndex(filter.order!, b[0]),
        )
      : [...entries].sort((a, b) => b[1] - a[1]);
    return ordered.map(([value, count]) => ({ value, label: format(value), count }));
  }

  if (!assets) return [];

  const seen = new Set<string>();
  for (const asset of assets) {
    const raw = asset[filter.field];
    if (raw === null || raw === undefined || raw === "") continue;
    seen.add(String(raw));
  }
  const values = [...seen];
  values.sort(
    filter.order
      ? (a, b) => orderIndex(filter.order!, a) - orderIndex(filter.order!, b)
      : (a, b) => a.localeCompare(b),
  );
  return values.map((value) => ({ value, label: format(value) }));
}

function orderIndex(order: readonly string[], value: string): number {
  const index = order.indexOf(value);
  return index === -1 ? order.length : index;
}
