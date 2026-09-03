/**
 * Post-scan snapshot panels, all sourced from `GET /dashboard` (§9–§12).
 *
 * The dashboard endpoint pre-aggregates every distribution shown here. These
 * components re-order and colour them; they never bucket, sum into a new
 * verdict, or fill in a band the API did not return.
 *
 * That last point is load-bearing in two places:
 *
 *  - The two risk axes are rendered from the keys the response actually
 *    contains. The classical axis currently returns five bands and the quantum
 *    axis four; forcing both to the same four or inventing a quantum "high"
 *    would be fabricating a band the engine did not assign (§11).
 *  - The decision snapshot iterates the five frozen decisions, but each count is
 *    read from `migration_decisions`. A decision the scan produced none of shows
 *    zero, not a plausible-looking number (§10).
 */

"use client";

import Link from "next/link";
import {
  Atom,
  CircleCheck,
  Layers,
  ShieldAlert,
  ShieldX,
  Sigma,
  Unlock,
} from "lucide-react";

import type { DashboardSummary, Distribution, MigrationDecision } from "@/types/api";
import { MIGRATION_DECISIONS } from "@/types/api";
import {
  CONFIDENCE_COLOR,
  DECISION_COLOR,
  QUANTUM_ORDER,
  RISK_ORDER,
  distributionEntries,
  formatNumber,
  humanize,
  percentOf,
  quantumColor,
  riskColor,
  sumDistribution,
} from "@/lib/display";
import { cn } from "@/lib/utils";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { MethodNote, Section } from "@/components/ecdat/layout";
import { KpiCard, KpiGrid } from "@/features/dashboard/kpi-card";

// ---------------------------------------------------------------------------
// §9. Security snapshot
// ---------------------------------------------------------------------------

/**
 * The five headline figures the backend publishes.
 *
 * `quantum_vulnerable_pct` is used as the API returned it rather than
 * recomputed, so the page cannot disagree with the endpoint about its own
 * percentage.
 */
export function SecuritySnapshot({ data }: { data: DashboardSummary }) {
  const h = data.headlines;

  return (
    <KpiGrid>
      <KpiCard
        label="Total cryptographic assets"
        value={h.total_assets}
        caption="Canonical assets across the scanned estate, one per real cryptographic thing."
        icon={Layers}
        accent="var(--primary)"
        href="/inventory"
        detail={`${formatNumber(data.estate.applications)} applications`}
        help="Built by the canonical-asset stage after evidence correlation. Several detections can collapse into one asset."
        segments={[
          { label: "Need change", value: h.need_change, color: "var(--risk-high)" },
          { label: "Need no change", value: h.need_no_change, color: "var(--success)" },
        ]}
      />
      <KpiCard
        label="Need change"
        value={h.need_change}
        caption="Assets whose decision is anything other than RETAIN."
        icon={ShieldAlert}
        accent="var(--risk-high)"
        href="/inventory?band=P0"
        detail={`${percentOf(h.need_change, h.total_assets)}% of estate`}
        help="The sum of HARDEN, UPGRADE, HYBRID and PQC-ONLY decisions, as counted by the backend."
      />
      <KpiCard
        label="Need no change"
        value={h.need_no_change}
        caption="Assets the engine decided to RETAIN: already appropriate for the policy."
        icon={CircleCheck}
        accent="var(--success)"
        href="/inventory?decision=RETAIN"
        help="RETAIN is a decision, not an absence of one. These assets were assessed and found acceptable."
      />
      <KpiCard
        label="Quantum vulnerable"
        value={h.quantum_vulnerable}
        caption="Assets a large-scale quantum computer would break or materially weaken."
        icon={Atom}
        accent="var(--quantum-critical)"
        href="/inventory?quantum_vulnerable=true"
        detail={`${h.quantum_vulnerable_pct} of estate`}
        help="Quantum exposure is assessed by its own function from the algorithm's quantum class. It is independent of classical risk — this figure says nothing about today's exploitability."
      />
      <KpiCard
        label="Classically broken today"
        value={h.classically_broken_today}
        caption="Assets exploitable with the computers that exist right now."
        icon={ShieldX}
        accent="var(--risk-critical)"
        href="/inventory?classical_risk=critical"
        help="Derived from present-day cryptanalysis and the active policy floor. These do not need a quantum computer to be a problem."
      />
    </KpiGrid>
  );
}

// ---------------------------------------------------------------------------
// §10. Migration decision snapshot
// ---------------------------------------------------------------------------

/**
 * The five frozen decisions as five cards.
 *
 * The decision vocabulary is fixed at exactly five, so the cards are laid out
 * from that constant — but every number is a lookup into the response, and the
 * definition under each card is the backend's own `decision_definitions` text.
 */
export function DecisionSnapshot({ data }: { data: DashboardSummary }) {
  const counts = data.migration_decisions;
  const total = sumDistribution(counts);

  return (
    <Section
      title="Migration decisions"
      description="Every asset receives exactly one of five decisions."
      help="The decision is the coarse instruction. Beneath it each asset carries a specific standards-grounded strategy, which is a separate field and is never collapsed into the decision."
      contentClassName="space-y-3"
    >
      <div className="grid gap-2 sm:grid-cols-3 lg:grid-cols-5">
        {MIGRATION_DECISIONS.map((decision) => (
          <DecisionCard
            key={decision}
            decision={decision}
            count={counts?.[decision] ?? 0}
            total={total}
            definition={data.decision_definitions?.[decision]}
          />
        ))}
      </div>
      <MethodNote>
        Reported by the analysis backend:{" "}
        <span className="text-foreground">
          &ldquo;Risk bands and decisions are ECDAT-derived recommendations, not a
          compliance status.&rdquo;
        </span>
      </MethodNote>
    </Section>
  );
}

function DecisionCard({
  decision,
  count,
  total,
  definition,
}: {
  decision: MigrationDecision;
  count: number;
  total: number;
  definition: string | undefined;
}) {
  const color = DECISION_COLOR[decision];

  const card = (
    <Link
      href={`/inventory?decision=${decision}`}
      className="bg-card hover:border-primary/40 focus-visible:ring-ring flex min-w-0 flex-col gap-2 rounded-lg border p-3 transition-colors focus-visible:ring-2 focus-visible:outline-none"
    >
      <span className="flex items-center gap-1.5">
        <span
          aria-hidden
          className="size-2 shrink-0 rounded-[2px]"
          style={{ backgroundColor: color }}
        />
        <span className="truncate text-[11px] font-semibold tracking-tight">
          {decision}
        </span>
      </span>
      <span className="flex items-baseline gap-1.5">
        <span
          className={cn(
            "ecdat-numeric text-2xl leading-none font-semibold tracking-tight",
            count === 0 && "text-muted-foreground",
          )}
        >
          {formatNumber(count)}
        </span>
        <span className="text-muted-foreground text-[11px]">
          {total > 0 ? `${percentOf(count, total)}%` : "—"}
        </span>
      </span>
      <span
        aria-hidden
        className="bg-muted h-1 w-full overflow-hidden rounded-full"
      >
        <span
          className="block h-full rounded-full"
          style={{
            width: total > 0 ? `${(count / total) * 100}%` : "0%",
            backgroundColor: color,
          }}
        />
      </span>
    </Link>
  );

  if (!definition) return card;

  return (
    <Tooltip>
      <TooltipTrigger asChild>{card}</TooltipTrigger>
      <TooltipContent className="max-w-80 text-xs leading-relaxed">
        {definition}
      </TooltipContent>
    </Tooltip>
  );
}

// ---------------------------------------------------------------------------
// §11. Risk snapshot -- two axes, never merged
// ---------------------------------------------------------------------------

/**
 * The two risk axes side by side.
 *
 * Built as twins on purpose: same form, different colour family, separate
 * totals. The bands drawn are the ones present in each distribution, so the
 * classical panel shows whatever classical bands the engine assigned and the
 * quantum panel whatever quantum bands it assigned. Neither is padded to match
 * the other.
 */
export function RiskSnapshot({ data }: { data: DashboardSummary }) {
  return (
    <div className="grid min-w-0 gap-4 lg:grid-cols-2">
      <Section
        title="Classical risk"
        description="Exploitable with the computers that exist today."
        help="Assessed from present-day cryptanalysis, key size, mode of operation and the active policy floor."
        contentClassName="space-y-3"
      >
        <AxisBands
          distribution={data.classical_axis}
          order={RISK_ORDER}
          color={riskColor}
          filterKey="classical_risk"
        />
      </Section>

      <Section
        title="Quantum exposure"
        description="Exposure to a future large-scale quantum computer."
        help="Assessed by a separate function from the algorithm's quantum class. It shares no state with classical risk, so an asset can be low on one axis and critical on the other."
        contentClassName="space-y-3"
      >
        <AxisBands
          distribution={data.quantum_axis}
          order={QUANTUM_ORDER}
          color={quantumColor}
          filterKey="quantum_exposure"
        />
      </Section>

      <div className="lg:col-span-2">
        <MethodNote>
          The two axes are never averaged into one score. An asset that is classically
          low can be quantum critical, and collapsing the two would erase precisely the
          finding that matters. Each panel shows only the bands this scan actually
          assigned.
        </MethodNote>
      </div>
    </div>
  );
}

/**
 * One axis as horizontal bars.
 *
 * Horizontal rather than vertical because band names are words, not dates, and
 * because the two panels then read as two lists of the same shape. Widths are
 * proportions of that axis's own total.
 */
function AxisBands({
  distribution,
  order,
  color,
  filterKey,
}: {
  distribution: Distribution | undefined;
  order: readonly string[];
  color: (band: string) => string;
  filterKey: "classical_risk" | "quantum_exposure";
}) {
  // Only the bands the API returned. `distributionEntries` pins known keys to
  // the canonical worst-first order and leaves anything unrecognised after it.
  const entries = distributionEntries(distribution, order).filter(
    (entry) => entry.count > 0,
  );
  const total = sumDistribution(distribution);

  if (entries.length === 0) {
    return (
      <p className="text-muted-foreground text-xs">
        This scan assigned no bands on this axis.
      </p>
    );
  }

  return (
    <div className="min-w-0 space-y-2">
      <ul className="min-w-0 space-y-1.5">
        {entries.map((entry) => (
          <li key={entry.key} className="min-w-0">
            <Link
              href={`/inventory?${filterKey}=${entry.key}`}
              className="hover:bg-muted/50 focus-visible:ring-ring group grid min-w-0 grid-cols-[5.5rem_1fr_auto] items-center gap-2 rounded px-1 py-1 transition-colors focus-visible:ring-2 focus-visible:outline-none"
            >
              <span className="flex min-w-0 items-center gap-1.5">
                <span
                  aria-hidden
                  className="size-2 shrink-0 rounded-[2px]"
                  style={{ backgroundColor: color(entry.key) }}
                />
                <span className="truncate text-xs">{humanize(entry.key)}</span>
              </span>
              <span
                aria-hidden
                className="bg-muted h-2 w-full overflow-hidden rounded-full"
              >
                <span
                  className="block h-full rounded-full transition-opacity group-hover:opacity-85"
                  style={{
                    width: `${(entry.count / total) * 100}%`,
                    backgroundColor: color(entry.key),
                  }}
                />
              </span>
              <span className="flex shrink-0 items-baseline gap-1.5">
                <span className="ecdat-numeric text-xs font-medium">
                  {formatNumber(entry.count)}
                </span>
                <span className="text-muted-foreground ecdat-numeric w-8 text-right text-[11px]">
                  {percentOf(entry.count, total)}%
                </span>
              </span>
            </Link>
          </li>
        ))}
      </ul>
      <p className="text-muted-foreground border-t pt-2 text-[11px]">
        {formatNumber(total)} assets banded on this axis ·{" "}
        {entries.length} band{entries.length === 1 ? "" : "s"} present in this scan
      </p>
    </div>
  );
}

// ---------------------------------------------------------------------------
// §12. Confidence summary
// ---------------------------------------------------------------------------

/**
 * Detection confidence across the estate.
 *
 * Three levels, because that is what `dashboard.confidence` returns. Evidence
 * provenance (direct, contextual, inferred) is a per-asset field and the API
 * publishes no estate-wide aggregate of it, so none is shown here (§12).
 */
export function ConfidenceSummary({ data }: { data: DashboardSummary }) {
  const entries = distributionEntries(data.confidence, ["high", "medium", "low"]);
  const total = sumDistribution(data.confidence);

  return (
    <Section
      title="Detection confidence"
      description="How strongly the evidence supports each finding."
      help="Confidence is computed per asset from its evidence records — how many detectors agreed, and how direct the evidence was. It qualifies the detection, not the risk verdict."
      contentClassName="space-y-3"
    >
      <div className="grid gap-2 sm:grid-cols-3">
        {entries.map((entry) => (
          <Link
            key={entry.key}
            href={`/inventory?confidence=${entry.key}`}
            className="bg-card hover:border-primary/40 focus-visible:ring-ring flex min-w-0 items-center gap-2.5 rounded-lg border p-3 transition-colors focus-visible:ring-2 focus-visible:outline-none"
          >
            <span
              aria-hidden
              className="grid size-8 shrink-0 place-items-center rounded-md"
              style={{
                color:
                  CONFIDENCE_COLOR[entry.key as keyof typeof CONFIDENCE_COLOR] ??
                  "var(--muted-foreground)",
                backgroundColor: `color-mix(in oklab, ${
                  CONFIDENCE_COLOR[entry.key as keyof typeof CONFIDENCE_COLOR] ??
                  "var(--muted-foreground)"
                } 14%, transparent)`,
              }}
            >
              <Sigma className="size-4" />
            </span>
            <span className="min-w-0">
              <span className="flex items-baseline gap-1.5">
                <span className="ecdat-numeric text-xl leading-none font-semibold">
                  {formatNumber(entry.count)}
                </span>
                <span className="text-muted-foreground text-[11px]">
                  {percentOf(entry.count, total)}%
                </span>
              </span>
              <span className="text-muted-foreground block truncate text-[11px]">
                {humanize(entry.key)} confidence
              </span>
            </span>
          </Link>
        ))}
      </div>
      <MethodNote>
        Low confidence marks a finding worth confirming, not a finding to discount. The
        risk and decision fields are computed the same way regardless of confidence; the
        confidence field is what tells an operator where to look first when validating.
      </MethodNote>
    </Section>
  );
}

// ---------------------------------------------------------------------------
// Quantum taxonomy -- the vocabulary behind the quantum axis
// ---------------------------------------------------------------------------

/**
 * Why each asset sits where it does on the quantum axis.
 *
 * Included because the quantum axis on its own invites the question "broken by
 * what?", and the taxonomy is the backend's answer: Shor, Grover, already
 * classically broken, PQC-standardised, hybrid, or unknown.
 */
export function QuantumTaxonomySummary({ data }: { data: DashboardSummary }) {
  const entries = distributionEntries(data.quantum_taxonomy).filter(
    (entry) => entry.count > 0,
  );
  const total = sumDistribution(data.quantum_taxonomy);
  if (entries.length === 0) return null;

  const HELP: Record<string, string> = {
    shor_broken:
      "Shor's algorithm breaks this outright: RSA, finite-field and elliptic-curve public-key cryptography.",
    grover_reduced:
      "Grover's algorithm halves the effective security level. Often still acceptable at a large enough key size.",
    classically_broken:
      "Already broken or deprecated by present-day cryptanalysis. A quantum computer is not required.",
    pqc_standardized:
      "A NIST-standardised post-quantum algorithm (FIPS 203/204/205).",
    pqc_selected: "Selected for standardisation but not yet published as a FIPS standard.",
    hybrid_pqt: "A hybrid post-quantum/traditional construction. Key agreement only.",
    unknown: "The algorithm could not be classified against the quantum taxonomy.",
  };

  return (
    <Section
      title="Quantum taxonomy"
      description="Why each asset lands where it does on the quantum axis."
      help="The classification vocabulary the quantum-exposure function reads. Each asset carries exactly one class."
      contentClassName="space-y-3"
    >
      <ul className="min-w-0 space-y-1.5">
        {entries.map((entry) => (
          <li key={entry.key}>
            <Tooltip>
              <TooltipTrigger asChild>
                <Link
                  href={`/inventory?quantum_class=${entry.key}`}
                  className="hover:bg-muted/50 focus-visible:ring-ring group grid min-w-0 cursor-help grid-cols-[9.5rem_1fr_auto] items-center gap-2 rounded px-1 py-1 transition-colors focus-visible:ring-2 focus-visible:outline-none"
                >
                  <span className="truncate font-mono text-[11px]">{entry.key}</span>
                  <span
                    aria-hidden
                    className="bg-muted h-2 w-full overflow-hidden rounded-full"
                  >
                    <span
                      className="block h-full rounded-full bg-[var(--quantum-medium)] transition-opacity group-hover:opacity-85"
                      style={{ width: `${(entry.count / total) * 100}%` }}
                    />
                  </span>
                  <span className="ecdat-numeric shrink-0 text-xs font-medium">
                    {formatNumber(entry.count)}
                  </span>
                </Link>
              </TooltipTrigger>
              <TooltipContent className="max-w-80 text-xs leading-relaxed">
                {HELP[entry.key] ?? humanize(entry.key)}
              </TooltipContent>
            </Tooltip>
          </li>
        ))}
      </ul>
      <MethodNote>
        ECDAT does not predict when a cryptographically relevant quantum computer will
        exist. The threat horizon it plans against is a policy deadline, stated on the
        dashboard alongside its rationale.
      </MethodNote>
    </Section>
  );
}

/** Small shared icon for the urgency strip below the snapshot. */
export const UrgencyIcon = Unlock;
