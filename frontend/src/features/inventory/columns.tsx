/**
 * Inventory column definitions.
 *
 * Every cell is a read of a canonical field the API returned. Nothing here
 * derives a band, a score, a decision or a priority (§1); the badges only choose
 * a colour for a verdict the backend already reached.
 *
 * Two columns -- business criticality and network exposure -- exist only in the
 * full asset projection. They carry `needsFullView` so the screen can decide
 * whether the heavier request is warranted instead of always paying for it.
 */

"use client";

import Link from "next/link";
import {
  columnVisibilityFeature,
  createColumnHelper,
  rowSelectionFeature,
  tableFeatures,
} from "@tanstack/react-table";

import type { AssetSummary, CryptoAsset } from "@/types/api";
import {
  CONTEXT_SOURCE_HELP,
  CRITICALITY_LABEL,
  CRITICALITY_ORDER,
  EXPOSURE_LABEL,
  EXPOSURE_ORDER,
  QUANTUM_ORDER,
  RISK_ORDER,
  assetTypeLabel,
  contextSourceLabel,
  formatScore,
  humanize,
  shortenPath,
} from "@/lib/display";
import {
  ConfidenceBadge,
  DecisionBadge,
  PriorityBadge,
  QuantumBadge,
  RiskBadge,
  UrgencyBadge,
} from "@/components/ecdat/badges";
import { Checkbox } from "@/components/ui/checkbox";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import type { ServerSort } from "./filters";

/**
 * One table row.
 *
 * The summary projection is the baseline. When the screen fetches `view=full`
 * the two extra business-context fields are present; when it does not they are
 * `undefined`, and their cells say so rather than rendering a blank that would
 * read as "no value recorded".
 */
export type InventoryRow = AssetSummary &
  Partial<Pick<CryptoAsset, "business_criticality" | "exposure">>;

/** Flatten a full asset into a row so both projections render identically. */
export function fullAssetToRow(asset: CryptoAsset): InventoryRow {
  return {
    ...asset,
    // `evidence_count` is a summary-only convenience. The full view ships the
    // records themselves, so the count is the length of what came back.
    evidence_count: asset.evidence?.length ?? 0,
  };
}

export interface InventoryColumnMeta {
  /** Header text, also used in the column-visibility menu. */
  label: string;
  /** What the column holds. Shown as header help. */
  help?: string;
  /** The API sort that reorders the whole estate by this column, if one exists. */
  serverSort?: ServerSort;
  /** Direction of that API sort. Fixed, because the API takes no direction. */
  serverSortDirection?: "asc" | "desc";
  /** Offer a page-scoped sort, for columns the API cannot order by. */
  pageSortable?: boolean;
  /** Comparator key for that page-scoped sort. */
  sortValue?: (row: InventoryRow) => string | number | null | undefined;
  /** Present only in the full asset projection. */
  needsFullView?: boolean;
  /**
   * Let the header text wrap onto two lines.
   *
   * For a few columns the header is wider than anything the column holds, so it
   * alone decides the width. Wrapping it buys that width back without shortening
   * the wording -- and "classical risk" and "quantum exposure" are precisely the
   * two names that must not be shortened, because the whole point is that they
   * are separate axes.
   */
  wrapHeader?: boolean;
  /** Width and alignment, applied to the header cell and the body cells alike. */
  className?: string;
}

export const inventoryFeatures = tableFeatures({
  columnVisibilityFeature,
  rowSelectionFeature,
  columnMeta: {} as InventoryColumnMeta,
});

const helper = createColumnHelper<typeof inventoryFeatures, InventoryRow>();

/** Rank a value against a canonical order. Unknown values sort last, nulls after. */
export function bandRank(order: readonly string[], value: string | null | undefined): number {
  if (value === null || value === undefined || value === "") return order.length + 1;
  const index = order.indexOf(value);
  return index === -1 ? order.length : index;
}

const DECISION_RANK = ["RETAIN", "HARDEN", "UPGRADE", "HYBRID", "PQC-ONLY"];
const URGENCY_RANK = ["already-late", "critical", "plan-now", "monitor", "not-applicable"];

/** An absent value. Never blank, so "not recorded" cannot be read as "zero". */
function Dash() {
  return (
    <span className="text-muted-foreground/50" aria-label="not recorded">
      —
    </span>
  );
}

/** A field that lives only in the full projection, which was not requested. */
function NeedsFullView() {
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span className="text-muted-foreground/70 cursor-help border-b border-dotted text-[11px]">
          full view
        </span>
      </TooltipTrigger>
      <TooltipContent className="max-w-64 text-xs leading-relaxed">
        This field exists only in the full asset projection. Showing the column refetches the
        current page with <code className="font-mono">view=full</code>.
      </TooltipContent>
    </Tooltip>
  );
}

function text(value: string | null | undefined, format: (raw: string) => string = (raw) => raw) {
  if (value === null || value === undefined || value === "") return <Dash />;
  const label = format(value);
  // `title` rather than a Radix tooltip: these cells are trimmed to fit the
  // decision columns on screen, so the full value has to stay reachable -- but
  // there are up to two hundred rows on a page, and mounting a tooltip per cell
  // to say what a native attribute already says would be a poor trade.
  return (
    <span className="block truncate" title={label}>
      {label}
    </span>
  );
}

/**
 * An absent business-context value, carrying the backend's own reason for it.
 *
 * `context_source` records where an asset's business context came from. When it
 * says `default`, nothing was declared and nothing was discovered -- and saying
 * so in place of a bare dash is the difference between "not recorded" and a
 * value the tool quietly assumed (§36). The wording is the backend vocabulary's,
 * not this component's.
 */
function ContextDash({ source }: { source: string | null | undefined }) {
  if (!source) return <Dash />;
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span className="text-muted-foreground/50 cursor-help" aria-label="not recorded">
          —
        </span>
      </TooltipTrigger>
      <TooltipContent className="flex max-w-72 flex-col gap-1 text-xs leading-relaxed">
        <span>Not recorded for this asset.</span>
        <span className="text-muted-foreground">
          <code className="font-mono">context_source</code> = {contextSourceLabel(source)}.{" "}
          {CONTEXT_SOURCE_HELP[source] ?? ""}
        </span>
      </TooltipContent>
    </Tooltip>
  );
}

/** A business-context cell: an absence explains itself from the asset's own field. */
function contextText(
  value: string | null | undefined,
  source: string | null | undefined,
  format: (raw: string) => string = (raw) => raw,
) {
  if (value === null || value === undefined || value === "") {
    return <ContextDash source={source} />;
  }
  const label = format(value);
  return (
    <span className="block truncate" title={label}>
      {label}
    </span>
  );
}

export const inventoryColumns = helper.columns([
  helper.display({
    id: "select",
    header: ({ table }) => (
      <Checkbox
        checked={
          table.getIsAllRowsSelected()
            ? true
            : table.getIsSomeRowsSelected()
              ? "indeterminate"
              : false
        }
        onCheckedChange={(value) => table.toggleAllRowsSelected(value === true)}
        aria-label="Select every asset on this page"
        className="translate-y-[1px]"
      />
    ),
    cell: ({ row }) => (
      <Checkbox
        checked={row.getIsSelected()}
        onCheckedChange={(value) => row.toggleSelected(value === true)}
        aria-label={`Select ${row.original.asset_name}`}
        className="translate-y-[1px]"
        // The row navigates to the asset; ticking the box must not.
        onClick={(event) => event.stopPropagation()}
      />
    ),
    enableHiding: false,
    // Frozen to the left edge with the name beside it: nineteen columns cannot
    // fit a laptop, so the table scrolls sideways, and a scrolled row that no
    // longer says which asset it is would be unreadable. `bg-inherit` takes the
    // row's own background so the frozen cells keep the hover and selected
    // states instead of punching an opaque hole through them.
    meta: { label: "Select", className: "bg-inherit sticky left-0 z-10 w-9" },
  }),

  helper.accessor("asset_name", {
    id: "asset_name",
    header: "Asset",
    cell: ({ row }) => {
      const { asset_id, asset_name, file, line } = row.original;
      const location = file ? (line ? `${file}:${line}` : file) : null;
      return (
        <div className="flex min-w-0 flex-col gap-0.5">
          <Link
            href={`/assets/${asset_id}`}
            className="decoration-muted-foreground/40 truncate font-medium underline-offset-2 hover:underline"
            onClick={(event) => event.stopPropagation()}
          >
            {asset_name}
          </Link>
          {location ? (
            <Tooltip>
              <TooltipTrigger asChild>
                <span className="text-muted-foreground truncate font-mono text-[10.5px]">
                  {shortenPath(location, 34)}
                </span>
              </TooltipTrigger>
              <TooltipContent className="font-mono text-[11px]">{location}</TooltipContent>
            </Tooltip>
          ) : null}
        </div>
      );
    },
    meta: {
      label: "Asset",
      help: "Canonical asset name, and the location the finding was made at.",
      serverSort: "name",
      serverSortDirection: "asc",
      // Narrower than the longest path it can hold, on purpose: the path
      // truncates with the full value on hover, and the width it gives back is
      // what brings the decision columns into view without scrolling.
      className:
        "bg-inherit border-border sticky left-9 z-10 min-w-[11rem] max-w-[13rem] border-r",
    },
  }),

  helper.accessor("asset_type", {
    id: "asset_type",
    header: "Type",
    cell: ({ getValue }) => text(getValue(), assetTypeLabel),
    meta: {
      label: "Type",
      help: "What kind of thing the finding is: source usage, certificate, dependency, binary artefact, container package or protocol configuration.",
      pageSortable: true,
      sortValue: (row) => assetTypeLabel(row.asset_type),
      className: "max-w-[10rem]",
    },
  }),

  helper.accessor("algorithm_label", {
    id: "algorithm_label",
    header: "Algorithm",
    cell: ({ row }) => {
      const { algorithm_label, key_size, curve } = row.original;
      if (!algorithm_label) return <Dash />;
      // Shown exactly as the backend recorded it. Curve spellings are not yet
      // normalised upstream (NORM-001) and must not be normalised here.
      const detail = curve ?? (key_size ? `${key_size}-bit` : null);
      return (
        <div className="flex min-w-0 items-baseline gap-1.5">
          <span className="truncate font-mono text-[12px]">{algorithm_label}</span>
          {detail ? (
            <span className="text-muted-foreground shrink-0 text-[10.5px]">{detail}</span>
          ) : null}
        </div>
      );
    },
    meta: {
      label: "Algorithm",
      help: "Algorithm as identified by the detector, with key size or curve where recorded.",
      pageSortable: true,
      sortValue: (row) => row.algorithm_label,
      className: "max-w-[13rem]",
    },
  }),

  helper.accessor("cryptographic_role", {
    id: "cryptographic_role",
    header: "Role",
    cell: ({ getValue }) => text(getValue(), humanize),
    meta: {
      label: "Role",
      help: "The canonical cryptographic role this asset plays.",
      pageSortable: true,
      sortValue: (row) => row.cryptographic_role,
      className: "max-w-[7.5rem]",
    },
  }),

  helper.accessor("classical_risk", {
    id: "classical_risk",
    header: "Classical risk",
    cell: ({ getValue }) => <RiskBadge band={getValue()} size="sm" />,
    meta: {
      label: "Classical risk",
      help: "The backend's classical-weakness band. Independent of quantum exposure.",
      pageSortable: true,
      wrapHeader: true,
      sortValue: (row) => bandRank(RISK_ORDER, row.classical_risk),
      className: "w-[5.25rem]",
    },
  }),

  helper.accessor("quantum_exposure", {
    id: "quantum_exposure",
    header: "Quantum exposure",
    cell: ({ getValue }) => <QuantumBadge band={getValue()} size="sm" />,
    meta: {
      label: "Quantum exposure",
      help: "The backend's quantum-exposure band, computed by a separate function that does not read classical risk.",
      pageSortable: true,
      wrapHeader: true,
      sortValue: (row) => bandRank(QUANTUM_ORDER, row.quantum_exposure),
      className: "w-[5.75rem]",
    },
  }),

  helper.accessor((row) => row.business_criticality ?? null, {
    id: "business_criticality",
    header: "Criticality",
    cell: ({ row }) => {
      const value = row.original.business_criticality;
      if (value === undefined) return <NeedsFullView />;
      return contextText(value, row.original.context_source, (raw) =>
        CRITICALITY_LABEL[raw] ?? humanize(raw),
      );
    },
    meta: {
      label: "Business criticality",
      help: "Declared business criticality of what this asset protects. Full asset projection only.",
      needsFullView: true,
      pageSortable: true,
      sortValue: (row) => bandRank(CRITICALITY_ORDER, row.business_criticality),
      className: "w-[8.5rem]",
    },
  }),

  helper.accessor((row) => row.exposure ?? null, {
    id: "exposure",
    header: "Exposure",
    cell: ({ row }) => {
      const value = row.original.exposure;
      if (value === undefined) return <NeedsFullView />;
      return contextText(value, row.original.context_source, (raw) =>
        EXPOSURE_LABEL[raw] ?? humanize(raw),
      );
    },
    meta: {
      label: "Network exposure",
      help: "Where the asset is reachable from. Full asset projection only.",
      needsFullView: true,
      pageSortable: true,
      sortValue: (row) => bandRank(EXPOSURE_ORDER, row.exposure),
      className: "w-[8.5rem]",
    },
  }),

  helper.accessor("migration_decision", {
    id: "migration_decision",
    header: "Decision",
    cell: ({ getValue }) => <DecisionBadge decision={getValue()} size="sm" />,
    meta: {
      label: "Migration decision",
      help: "One of the five frozen outcomes. The specific action beneath it is the recommended strategy, kept as its own column.",
      pageSortable: true,
      sortValue: (row) => bandRank(DECISION_RANK, row.migration_decision),
      className: "w-[7.75rem]",
    },
  }),

  helper.accessor("recommended_strategy", {
    id: "recommended_strategy",
    header: "Strategy",
    cell: ({ getValue }) => text(getValue(), humanize),
    meta: {
      label: "Recommended strategy",
      help: "The standards-grounded action recommended beneath the decision. Never collapsed into it.",
      pageSortable: true,
      sortValue: (row) => row.recommended_strategy,
      className: "max-w-[8.75rem]",
    },
  }),

  helper.accessor("priority_band", {
    id: "priority_band",
    header: "Priority",
    cell: ({ row }) => (
      <div className="flex items-center gap-1.5">
        <PriorityBadge band={row.original.priority_band} size="sm" />
        <span className="ecdat-numeric text-muted-foreground text-[10.5px]">
          {row.original.migration_priority ?? "—"}
        </span>
      </div>
    ),
    meta: {
      label: "Priority",
      help: "Priority band, with the backend's numeric migration priority beside it.",
      serverSort: "priority",
      serverSortDirection: "desc",
      className: "w-[7.25rem]",
    },
  }),

  helper.accessor("mosca_urgency", {
    id: "mosca_urgency",
    header: "Urgency",
    cell: ({ getValue }) => <UrgencyBadge urgency={getValue()} size="sm" />,
    meta: {
      label: "Mosca urgency",
      help: "Timing verdict from Mosca's inequality against the configured threat horizon.",
      pageSortable: true,
      sortValue: (row) => bandRank(URGENCY_RANK, row.mosca_urgency),
      className: "w-[8.5rem]",
    },
  }),

  helper.accessor("risk_score", {
    id: "risk_score",
    header: "Score",
    cell: ({ getValue }) => <span className="ecdat-numeric">{formatScore(getValue())}</span>,
    meta: {
      label: "Risk score",
      help: "Weighted composite score from the backend risk engine. Its weights are engineering judgement, stated on each asset's risk tab.",
      serverSort: "risk",
      serverSortDirection: "desc",
      className: "w-[5.5rem] text-right",
    },
  }),

  helper.accessor("application", {
    id: "application",
    header: "Application",
    cell: ({ row }) => contextText(row.original.application, row.original.context_source),
    meta: {
      label: "Application",
      help: "The application the asset belongs to, from business context.",
      pageSortable: true,
      sortValue: (row) => row.application,
      className: "max-w-[12rem]",
    },
  }),

  helper.accessor("library", {
    id: "library",
    header: "Library",
    cell: ({ getValue }) => text(getValue()),
    meta: {
      label: "Library",
      help: "The cryptographic library the finding was made through.",
      pageSortable: true,
      sortValue: (row) => row.library,
      className: "max-w-[8.5rem]",
    },
  }),

  helper.accessor("protocol", {
    id: "protocol",
    header: "Protocol",
    cell: ({ row }) => {
      const { protocol, protocol_version } = row.original;
      if (!protocol) return <Dash />;
      const version =
        protocol_version && protocol_version !== "unspecified" ? protocol_version : null;
      return (
        <span className="block truncate">
          {protocol}
          {version ? (
            <span className="text-muted-foreground ml-1 text-[10.5px]">{version}</span>
          ) : null}
        </span>
      );
    },
    meta: {
      label: "Protocol",
      help: "The protocol the asset participates in, with version where one was negotiated.",
      pageSortable: true,
      sortValue: (row) => row.protocol,
      className: "max-w-[9.5rem]",
    },
  }),

  helper.accessor("owner", {
    id: "owner",
    header: "Owner",
    cell: ({ row }) => contextText(row.original.owner, row.original.context_source),
    meta: {
      label: "Owner",
      help: "The declared owning team.",
      pageSortable: true,
      sortValue: (row) => row.owner,
      className: "max-w-[11rem]",
    },
  }),

  helper.accessor("confidence", {
    id: "confidence",
    header: "Confidence",
    cell: ({ row }) => (
      <ConfidenceBadge
        level={row.original.confidence}
        score={row.original.confidence_score}
        size="sm"
      />
    ),
    meta: {
      label: "Confidence",
      help: "Detection confidence and its score, derived from the finding's evidence.",
      pageSortable: true,
      sortValue: (row) => row.confidence_score,
      className: "w-[8.75rem]",
    },
  }),
]);

/**
 * Visibility the table starts with. Anything absent from this map is visible.
 *
 * The two full-projection columns start hidden so a first page load stays on the
 * light summary payload (§4); turning either on is what triggers `view=full`.
 * Urgency and score start hidden because the priority and risk columns beside
 * them already carry that verdict -- they are there for whoever wants the raw
 * figure, not for everyone by default.
 */
export const DEFAULT_COLUMN_VISIBILITY: Record<string, boolean> = {
  business_criticality: false,
  exposure: false,
  mosca_urgency: false,
  risk_score: false,
};

/** Column ids whose values only exist in the full projection. */
export const FULL_VIEW_COLUMNS: readonly string[] = inventoryColumns
  .filter((column) => (column.meta as InventoryColumnMeta | undefined)?.needsFullView)
  .map((column) => String(column.id));
