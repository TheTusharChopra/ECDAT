/**
 * Shared Recharts chrome.
 *
 * Every chart in ECDAT is framed by `ChartFrame`, which guarantees three things
 * the individual charts would otherwise each have to remember:
 *
 *  - a chart never renders as a blank box -- no data produces a stated empty
 *    state instead of an empty axis (§23);
 *  - a chart is never the only way to read its numbers -- the same series is
 *    emitted as a visually-hidden data table, so a screen reader gets the
 *    figures rather than an unlabelled SVG (§35);
 *  - the surrounding type, spacing and tooltip styling come from one place, so
 *    nine charts read as one system.
 *
 * Colours arrive as `var(--risk-*)` / `var(--quantum-*)` strings from
 * `lib/display`. Nothing here decides what a number means.
 */

"use client";

import type { ReactNode } from "react";

import { cn } from "@/lib/utils";
import { formatNumber } from "@/lib/display";

/** One row of a chart's underlying series. */
export interface ChartDatum {
  /** Stable identity, and the value used when the row links to a filter. */
  key: string;
  /** Axis / legend label. */
  name: string;
  value: number;
  color?: string;
  /** Optional second line for the tooltip. */
  note?: string;
}

// ---------------------------------------------------------------------------
// Shared Recharts styling. Spread these rather than restating them per chart.
// ---------------------------------------------------------------------------

const TICK = { fill: "var(--muted-foreground)", fontSize: 11 } as const;

export const axisProps = {
  stroke: "var(--grid)",
  tick: TICK,
  tickLine: false,
  axisLine: false,
} as const;

export const gridProps = {
  stroke: "var(--grid)",
  strokeDasharray: "2 4",
  vertical: false,
} as const;

export const barCursor = { fill: "var(--muted)", opacity: 0.45 } as const;

/**
 * Category-axis tick renderer that truncates long labels instead of letting
 * them widen the plot (§25). The full label stays available in the tooltip and
 * in the accessible table.
 */
export function truncateLabel(value: string, max = 18): string {
  return value.length > max ? `${value.slice(0, max - 1)}…` : value;
}

// ---------------------------------------------------------------------------
// Tooltip
// ---------------------------------------------------------------------------

/**
 * Minimal structural view of what Recharts injects into a custom tooltip.
 * Declared locally so the charts do not depend on Recharts' internal generics.
 */
export interface ChartTooltipPayloadItem {
  name?: string | number;
  value?: number | string;
  color?: string;
  dataKey?: string | number;
  payload?: Record<string, unknown>;
}

export interface ChartTooltipProps {
  active?: boolean;
  label?: string | number;
  payload?: ChartTooltipPayloadItem[];
  /** When set, each row also shows its share of this total. */
  total?: number;
  /** Suppress the heading row (single-series charts label themselves). */
  hideLabel?: boolean;
  /** Word for one unit, e.g. "asset". Pluralised naively with an "s". */
  unit?: string;
}

export function ChartTooltip({
  active,
  label,
  payload,
  total,
  hideLabel = false,
  unit = "asset",
}: ChartTooltipProps) {
  if (!active || !payload?.length) return null;

  return (
    <div className="bg-popover text-popover-foreground min-w-40 rounded-md border p-2.5 text-xs shadow-md">
      {!hideLabel && label !== undefined ? (
        <p className="mb-1.5 font-medium">{String(label)}</p>
      ) : null}
      <div className="space-y-1">
        {payload.map((item, index) => {
          const numeric = typeof item.value === "number" ? item.value : Number(item.value);
          const swatch =
            item.color ??
            (typeof item.payload?.color === "string" ? item.payload.color : undefined);
          const note =
            typeof item.payload?.note === "string" ? item.payload.note : undefined;
          return (
            <div key={`${item.dataKey ?? item.name ?? index}`} className="space-y-0.5">
              <div className="flex items-center gap-2">
                {swatch ? (
                  <span
                    aria-hidden
                    className="size-2 shrink-0 rounded-[2px]"
                    style={{ backgroundColor: swatch }}
                  />
                ) : null}
                <span className="text-muted-foreground flex-1 truncate">
                  {String(item.name ?? "")}
                </span>
                <span className="ecdat-numeric font-medium">
                  {Number.isFinite(numeric) ? formatNumber(numeric) : "—"}
                  {total && total > 0 && Number.isFinite(numeric) ? (
                    <span className="text-muted-foreground font-normal">
                      {" "}
                      ({Math.round((numeric / total) * 100)}%)
                    </span>
                  ) : null}
                </span>
              </div>
              {note ? <p className="text-muted-foreground pl-4">{note}</p> : null}
            </div>
          );
        })}
      </div>
      {unit ? (
        <p className="text-muted-foreground mt-1.5 border-t pt-1.5 text-[10px]">
          Counted in {unit}s. Click to open the matching inventory view.
        </p>
      ) : null}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Frame
// ---------------------------------------------------------------------------

/**
 * Visually-hidden equivalent of the chart. Not a nicety: a bar chart is an
 * unlabelled `<svg>` to assistive technology, so the series is also published
 * as a real table (§35).
 */
function AccessibleSeries({
  caption,
  data,
  valueLabel,
}: {
  caption: string;
  data: ChartDatum[];
  valueLabel: string;
}) {
  return (
    <table className="sr-only">
      <caption>{caption}</caption>
      <thead>
        <tr>
          <th scope="col">Category</th>
          <th scope="col">{valueLabel}</th>
        </tr>
      </thead>
      <tbody>
        {data.map((datum) => (
          <tr key={datum.key}>
            <th scope="row">{datum.name}</th>
            <td>{datum.value}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

/**
 * Wraps a chart with its accessible description, its empty state, and a fixed
 * height (Recharts' responsive container needs a definite one).
 */
export function ChartFrame({
  data,
  height = 220,
  /** One sentence a screen reader hears before the figures. */
  description,
  valueLabel = "Assets",
  emptyLabel = "No data in this scan.",
  children,
  className,
  footer,
}: {
  data: ChartDatum[];
  height?: number;
  description: string;
  valueLabel?: string;
  emptyLabel?: string;
  children: ReactNode;
  className?: string;
  footer?: ReactNode;
}) {
  const total = data.reduce((sum, datum) => sum + datum.value, 0);
  const empty = data.length === 0 || total === 0;

  if (empty) {
    return (
      <div
        className="text-muted-foreground flex flex-col items-center justify-center gap-1 rounded-md border border-dashed text-center text-xs"
        style={{ height }}
      >
        <p className="font-medium">{emptyLabel}</p>
        <p className="max-w-56 text-[11px]">{description}</p>
      </div>
    );
  }

  return (
    <figure className={cn("m-0 min-w-0", className)}>
      <AccessibleSeries caption={description} data={data} valueLabel={valueLabel} />
      <div style={{ height }} className="min-w-0">
        {children}
      </div>
      {footer ? (
        <figcaption className="text-muted-foreground mt-2 text-[11px] leading-relaxed">
          {footer}
        </figcaption>
      ) : null}
    </figure>
  );
}

// ---------------------------------------------------------------------------
// Legend
// ---------------------------------------------------------------------------

/**
 * Legend rendered as real markup rather than Recharts' SVG legend, so entries
 * can be links, wrap properly, and carry counts.
 */
export function ChartLegend({
  data,
  total,
  onSelect,
  className,
  columns = 1,
}: {
  data: ChartDatum[];
  total?: number;
  onSelect?: (datum: ChartDatum) => void;
  className?: string;
  columns?: 1 | 2;
}) {
  const sum = total ?? data.reduce((acc, datum) => acc + datum.value, 0);

  return (
    <ul
      className={cn(
        "grid gap-x-4 gap-y-1.5 text-xs",
        columns === 2 && "sm:grid-cols-2",
        className,
      )}
    >
      {data.map((datum) => {
        const share = sum > 0 ? Math.round((datum.value / sum) * 100) : 0;
        const body = (
          <>
            <span
              aria-hidden
              className="size-2 shrink-0 rounded-[2px]"
              style={{ backgroundColor: datum.color ?? "var(--muted-foreground)" }}
            />
            <span className="min-w-0 flex-1 truncate">{datum.name}</span>
            <span className="ecdat-numeric shrink-0 font-medium">
              {formatNumber(datum.value)}
            </span>
            <span className="text-muted-foreground ecdat-numeric w-9 shrink-0 text-right">
              {share}%
            </span>
          </>
        );

        return (
          <li key={datum.key} className="min-w-0">
            {onSelect ? (
              <button
                type="button"
                onClick={() => onSelect(datum)}
                className="hover:bg-muted/60 focus-visible:ring-ring flex w-full items-center gap-2 rounded px-1.5 py-1 text-left transition-colors focus-visible:ring-2 focus-visible:outline-none"
              >
                {body}
              </button>
            ) : (
              <span className="flex w-full items-center gap-2 px-1.5 py-1">{body}</span>
            )}
          </li>
        );
      })}
    </ul>
  );
}
