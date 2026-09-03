/**
 * Dashboard KPI card (§7).
 *
 * Each card carries an icon, a label, a value, and -- the part that matters --
 * a sentence explaining what the number counts. A bare "52" beside the word
 * "Quantum Exposed" invites the reader to invent a meaning for it; the caption
 * states the backend's own definition instead.
 *
 * Deliberately absent: trend arrows. A single scan produces no time series, so
 * there is no honest trend to draw (§7, §30). The slot is filled with a
 * composition breakdown instead, which the data does support.
 */

"use client";

import type { LucideIcon } from "lucide-react";
import Link from "next/link";

import { cn } from "@/lib/utils";
import { formatNumber } from "@/lib/display";
import { Card, CardContent } from "@/components/ui/card";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";

/** One segment of the small composition bar under a KPI value. */
export interface KpiSegment {
  label: string;
  value: number;
  color: string;
}

export interface KpiCardProps {
  label: string;
  value: number | string;
  /** What the number counts, in the backend's terms. Always shown. */
  caption: string;
  icon: LucideIcon;
  /** Tint for the icon chip and the accent rule. One token, used sparingly. */
  accent?: string;
  /** Secondary figure rendered beside the value, e.g. "31% of estate". */
  detail?: string;
  /** Where clicking the card goes. Omit to render a non-interactive card. */
  href?: string;
  /** Composition breakdown, drawn as a stacked rule beneath the value. */
  segments?: KpiSegment[];
  /** Longer methodology note, surfaced on hover of the value. */
  help?: string;
  /** Give the hero card a wider footprint in the grid. */
  wide?: boolean;
  className?: string;
}

export function KpiCard({
  label,
  value,
  caption,
  icon: Icon,
  accent = "var(--primary)",
  detail,
  href,
  segments,
  help,
  wide = false,
  className,
}: KpiCardProps) {
  const numeric = typeof value === "number" ? formatNumber(value) : value;
  const segmentTotal = segments?.reduce((sum, s) => sum + s.value, 0) ?? 0;

  const valueNode = (
    <div className="flex items-baseline gap-2">
      <span className="ecdat-numeric text-3xl leading-none font-semibold tracking-tight">
        {numeric}
      </span>
      {detail ? (
        <span className="text-muted-foreground truncate text-xs">{detail}</span>
      ) : null}
    </div>
  );

  const body = (
    <CardContent className="flex h-full flex-col gap-3 px-4">
      <div className="flex items-start justify-between gap-2">
        <p className="text-muted-foreground min-w-0 text-xs font-medium tracking-wide uppercase">
          {label}
        </p>
        <span
          aria-hidden
          className="grid size-7 shrink-0 place-items-center rounded-md"
          style={{
            color: accent,
            backgroundColor: `color-mix(in oklab, ${accent} 14%, transparent)`,
          }}
        >
          <Icon className="size-4" />
        </span>
      </div>

      {help ? (
        <Tooltip>
          <TooltipTrigger asChild>
            <div className="w-fit cursor-help">{valueNode}</div>
          </TooltipTrigger>
          <TooltipContent className="max-w-72 text-xs leading-relaxed">
            {help}
          </TooltipContent>
        </Tooltip>
      ) : (
        valueNode
      )}

      {segments && segmentTotal > 0 ? (
        <div
          className="bg-muted flex h-1.5 w-full overflow-hidden rounded-full"
          role="img"
          aria-label={segments
            .map((s) => `${s.label}: ${s.value}`)
            .join(", ")}
        >
          {segments
            .filter((s) => s.value > 0)
            .map((s) => (
              <span
                key={s.label}
                title={`${s.label}: ${formatNumber(s.value)}`}
                style={{
                  width: `${(s.value / segmentTotal) * 100}%`,
                  backgroundColor: s.color,
                }}
              />
            ))}
        </div>
      ) : null}

      <p className="text-muted-foreground mt-auto text-[11px] leading-relaxed">
        {caption}
      </p>
    </CardContent>
  );

  const shell = cn(
    "relative min-w-0 gap-0 overflow-hidden py-4",
    wide && "sm:col-span-2",
    className,
  );

  if (!href) {
    return <Card className={shell}>{body}</Card>;
  }

  return (
    <Card
      className={cn(
        shell,
        "hover:border-ring/60 group transition-[border-color,box-shadow,transform] duration-150 hover:-translate-y-px hover:shadow-md",
        "focus-within:ring-ring focus-within:ring-2",
      )}
    >
      <Link
        href={href}
        className="absolute inset-0 z-10 rounded-[inherit] focus-visible:outline-none"
        aria-label={`${label}: ${numeric}. ${caption}`}
      />
      {body}
    </Card>
  );
}

/**
 * KPI grid. Four columns at desktop with the hero card spanning two, so the
 * seven cards tile exactly rather than leaving a ragged trailing gap.
 */
export function KpiGrid({ children }: { children: React.ReactNode }) {
  return (
    <div className="grid min-w-0 grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4">
      {children}
    </div>
  );
}
