/**
 * Semantic badges.
 *
 * The single place where a backend verdict becomes a visual token. Classical
 * risk and quantum exposure use different colour families *and* different
 * shapes -- a filled dot versus an atom glyph -- so the two axes stay visually
 * separable even in a screenshot, at a glance, on a projector (§4).
 */

import type { ComponentProps, ReactNode } from "react";
import { Atom } from "lucide-react";

import { cn } from "@/lib/utils";
import {
  AGILITY_COLOR,
  CONFIDENCE_COLOR,
  DECISION_COLOR,
  PRIORITY_COLOR,
  contextSourceLabel,
  humanize,
  quantumColor,
  riskColor,
  urgencyLabel,
} from "@/lib/display";
import type {
  AgilityLevel,
  ConfidenceLevel,
  MigrationDecision,
  PriorityBand,
} from "@/types/api";

type ChipSize = "sm" | "md";

interface ChipProps extends Omit<ComponentProps<"span">, "color"> {
  /** A CSS colour or `var(--token)` reference. */
  color: string;
  size?: ChipSize;
  /** Rendered before the label. Omit for the plain dot treatment. */
  glyph?: ReactNode;
  /** Suppress the leading dot (used when a glyph replaces it). */
  noDot?: boolean;
  children: ReactNode;
}

/**
 * Base chip. The tint is derived from the single colour token with `color-mix`
 * so one token drives text, border and background in both themes.
 */
function Chip({
  color,
  size = "md",
  glyph,
  noDot = false,
  className,
  children,
  ...props
}: ChipProps) {
  return (
    <span
      className={cn(
        "inline-flex w-fit shrink-0 items-center gap-1.5 rounded-md border font-medium whitespace-nowrap",
        size === "sm" ? "h-5 px-1.5 text-[11px]" : "h-6 px-2 text-xs",
        className,
      )}
      style={{
        color,
        borderColor: `color-mix(in oklab, ${color} 32%, transparent)`,
        backgroundColor: `color-mix(in oklab, ${color} 12%, transparent)`,
      }}
      {...props}
    >
      {glyph}
      {!noDot && !glyph ? (
        <span
          aria-hidden
          className="size-1.5 shrink-0 rounded-full"
          style={{ backgroundColor: color }}
        />
      ) : null}
      {children}
    </span>
  );
}

/** Classical risk band. Warm scale, filled dot. */
export function RiskBadge({
  band,
  size = "md",
  className,
}: {
  band: string;
  size?: ChipSize;
  className?: string;
}) {
  return (
    <Chip
      color={riskColor(band)}
      size={size}
      className={className}
      title={`Classical risk: ${humanize(band)}`}
    >
      {humanize(band)}
    </Chip>
  );
}

/**
 * Quantum exposure band. Cool violet scale plus an atom glyph -- never the same
 * treatment as classical risk, because the two are never the same claim.
 */
export function QuantumBadge({
  band,
  size = "md",
  className,
}: {
  band: string;
  size?: ChipSize;
  className?: string;
}) {
  return (
    <Chip
      color={quantumColor(band)}
      size={size}
      className={className}
      glyph={<Atom aria-hidden className="size-3 shrink-0" />}
      title={`Quantum exposure: ${humanize(band)}`}
    >
      {humanize(band)}
    </Chip>
  );
}

/** One of the five frozen migration decisions. */
export function DecisionBadge({
  decision,
  size = "md",
  className,
}: {
  decision: MigrationDecision | string;
  size?: ChipSize;
  className?: string;
}) {
  const color = DECISION_COLOR[decision as MigrationDecision] ?? "var(--muted-foreground)";
  return (
    <Chip
      color={color}
      size={size}
      className={cn("font-semibold tracking-tight", className)}
      title={`Migration decision: ${decision}`}
    >
      {decision}
    </Chip>
  );
}

export function PriorityBadge({
  band,
  size = "md",
  className,
}: {
  band: PriorityBand | string;
  size?: ChipSize;
  className?: string;
}) {
  const color = PRIORITY_COLOR[band as PriorityBand] ?? "var(--muted-foreground)";
  return (
    <Chip
      color={color}
      size={size}
      className={cn("font-semibold", className)}
      title={`Priority band: ${band}`}
    >
      {band}
    </Chip>
  );
}

export function ConfidenceBadge({
  level,
  score,
  size = "md",
  className,
}: {
  level: ConfidenceLevel | string;
  score?: number;
  size?: ChipSize;
  className?: string;
}) {
  const color = CONFIDENCE_COLOR[level as ConfidenceLevel] ?? "var(--muted-foreground)";
  return (
    <Chip
      color={color}
      size={size}
      className={className}
      title={
        score === undefined
          ? `Detection confidence: ${level}`
          : `Detection confidence: ${level} (${score})`
      }
    >
      {humanize(level)}
      {score === undefined ? null : (
        <span className="ecdat-numeric opacity-70">{score}</span>
      )}
    </Chip>
  );
}

export function UrgencyBadge({
  urgency,
  size = "md",
  className,
}: {
  urgency: string;
  size?: ChipSize;
  className?: string;
}) {
  // Mosca urgency is a timing verdict, so it borrows the risk (time-pressure)
  // family rather than the quantum-exposure family.
  const color =
    urgency === "already-late"
      ? "var(--risk-critical)"
      : urgency === "critical"
        ? "var(--risk-high)"
        : urgency === "plan-now"
          ? "var(--risk-medium)"
          : urgency === "monitor"
            ? "var(--info)"
            : "var(--muted-foreground)";
  return (
    <Chip color={color} size={size} className={className} title={`Mosca urgency: ${urgency}`}>
      {urgencyLabel(urgency)}
    </Chip>
  );
}

export function AgilityBadge({
  level,
  size = "md",
  className,
}: {
  level: AgilityLevel | string | null;
  size?: ChipSize;
  className?: string;
}) {
  if (!level) return <span className="text-muted-foreground text-xs">—</span>;
  const color = AGILITY_COLOR[level as AgilityLevel] ?? "var(--muted-foreground)";
  return (
    <Chip color={color} size={size} className={className} title={`Crypto agility: ${level}`}>
      {humanize(level)}
    </Chip>
  );
}

/**
 * Where a value came from. Discovered facts and assumed defaults must never
 * look alike (§15), so the default case is rendered as an explicit, muted
 * "assumed" chip rather than being silently indistinguishable from a finding.
 */
export function ProvenanceBadge({
  source,
  size = "sm",
  className,
}: {
  source: string | null | undefined;
  size?: ChipSize;
  className?: string;
}) {
  const key = source ?? "unknown";
  const color =
    key === "operator-declared" || key === "discovered"
      ? "var(--info)"
      : key === "inferred"
        ? "var(--warning)"
        : "var(--muted-foreground)";
  return (
    <Chip
      color={color}
      size={size}
      className={cn("uppercase tracking-wide", className)}
      noDot
    >
      {contextSourceLabel(key)}
    </Chip>
  );
}

/**
 * A neutral outline chip for facts with no risk semantics: algorithm family,
 * library, protocol, role. Kept colourless on purpose -- §4 warns against
 * colouring everything.
 */
export function FactChip({
  children,
  className,
  mono = false,
}: {
  children: ReactNode;
  className?: string;
  mono?: boolean;
}) {
  return (
    <span
      className={cn(
        "bg-muted/60 text-muted-foreground inline-flex h-6 w-fit shrink-0 items-center rounded-md border px-2 text-xs font-medium whitespace-nowrap",
        mono && "font-mono text-[11px]",
        className,
      )}
    >
      {children}
    </span>
  );
}

export { Chip };
