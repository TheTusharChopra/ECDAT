/**
 * Dashboard charts sourced entirely from `GET /dashboard` (§8 charts 1, 2, 5, 6, 8).
 *
 * These five read pre-aggregated distributions off the summary endpoint. The
 * frontend re-orders them for legibility and colours them; it does not add,
 * bucket or recompute a single count (§30, §37).
 *
 * The two axis charts are deliberately built as twins -- same size, same form,
 * different colour family -- because the point they have to make is structural:
 * classical risk and quantum exposure are separate verdicts from separate
 * functions, and an estate can be calm on one axis and alight on the other.
 */

"use client";

import { useRouter } from "next/navigation";
import {
  Bar,
  BarChart,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip as RechartsTooltip,
  XAxis,
  YAxis,
  CartesianGrid,
} from "recharts";

import type { DashboardSummary, Distribution, MigrationDecision } from "@/types/api";
import {
  AGILITY_COLOR,
  DECISION_COLOR,
  PRIORITY_COLOR,
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
import { MIGRATION_DECISIONS, PRIORITY_BANDS } from "@/types/api";
import { Section, MethodNote } from "@/components/ecdat/layout";
import {
  ChartFrame,
  ChartLegend,
  ChartTooltip,
  axisProps,
  barCursor,
  gridProps,
  type ChartDatum,
} from "@/components/charts/chart-kit";
import { cn } from "@/lib/utils";

/** Turn a backend distribution into a coloured, ordered chart series. */
function toSeries(
  distribution: Distribution | undefined,
  options: {
    order?: readonly string[];
    color: (key: string) => string;
    label?: (key: string) => string;
    /** Drop zero-count categories (donuts) or keep them (axis charts). */
    dropEmpty?: boolean;
  },
): ChartDatum[] {
  const { order, color, label = humanize, dropEmpty = false } = options;
  return distributionEntries(distribution, order)
    .filter((entry) => (dropEmpty ? entry.count > 0 : true))
    .map((entry) => ({
      key: entry.key,
      name: label(entry.key),
      value: entry.count,
      color: color(entry.key),
    }));
}

// ---------------------------------------------------------------------------
// 1 + 2. The two risk axes, as twin panels
// ---------------------------------------------------------------------------

function AxisBars({
  data,
  total,
  description,
  onSelect,
  height = 172,
}: {
  data: ChartDatum[];
  total: number;
  description: string;
  onSelect: (datum: ChartDatum) => void;
  height?: number;
}) {
  return (
    <ChartFrame data={data} height={height} description={description}>
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data} margin={{ top: 8, right: 4, bottom: 0, left: -18 }}>
          <CartesianGrid {...gridProps} />
          <XAxis dataKey="name" {...axisProps} interval={0} />
          <YAxis {...axisProps} allowDecimals={false} width={38} />
          <RechartsTooltip
            cursor={barCursor}
            content={<ChartTooltip total={total} hideLabel={false} />}
          />
          <Bar dataKey="value" radius={[3, 3, 0, 0]} maxBarSize={54} isAnimationActive={false}>
            {data.map((datum) => (
              <Cell
                key={datum.key}
                fill={datum.color}
                className="cursor-pointer transition-opacity hover:opacity-80"
                onClick={() => onSelect(datum)}
              />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </ChartFrame>
  );
}

export function RiskAxisPanels({ data }: { data: DashboardSummary }) {
  const router = useRouter();

  const classical = toSeries(data.classical_axis, {
    order: RISK_ORDER,
    color: riskColor,
  });
  const quantum = toSeries(data.quantum_axis, {
    order: QUANTUM_ORDER,
    color: quantumColor,
  });

  const classicalTotal = sumDistribution(data.classical_axis);
  const quantumTotal = sumDistribution(data.quantum_axis);

  return (
    <div className="grid min-w-0 gap-4 lg:grid-cols-2">
      <Section
        title="Classical Risk"
        description="Exploitable with the computers that exist today"
        help="Derived from present-day cryptanalysis, key size, mode of operation and the active policy floor. Computed by the classical risk function alone."
      >
        <AxisBars
          data={classical}
          total={classicalTotal}
          description="Assets by classical risk band, from critical to informational."
          onSelect={(datum) => router.push(`/inventory?classical_risk=${datum.key}`)}
        />
        <ChartLegend
          data={classical}
          total={classicalTotal}
          className="mt-3"
          columns={2}
          onSelect={(datum) => router.push(`/inventory?classical_risk=${datum.key}`)}
        />
      </Section>

      <Section
        title="Quantum Exposure"
        description="Exposure to a future large-scale quantum computer"
        help="Derived from the algorithm's quantum class — Shor-broken, Grover-reduced, PQC-standardised and so on. Computed by a separate function that shares no state with classical risk."
      >
        <AxisBars
          data={quantum}
          total={quantumTotal}
          description="Assets by quantum exposure band, from critical to informational."
          onSelect={(datum) => router.push(`/inventory?quantum_exposure=${datum.key}`)}
        />
        <ChartLegend
          data={quantum}
          total={quantumTotal}
          className="mt-3"
          columns={2}
          onSelect={(datum) => router.push(`/inventory?quantum_exposure=${datum.key}`)}
        />
      </Section>

      <div className="lg:col-span-2">
        <MethodNote>
          Reported by the analysis backend:{" "}
          <span className="text-foreground">
            &ldquo;All figures are counts of canonical asset fields; no number here is a
            second source of cryptographic truth.&rdquo;
          </span>{" "}
          The two panels above are never summed into a single score — an asset that is
          classically LOW can be quantum CRITICAL, and averaging the two would erase the
          finding that matters.
        </MethodNote>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// 5. Migration decision distribution
// ---------------------------------------------------------------------------

export function MigrationDecisionChart({ data }: { data: DashboardSummary }) {
  const router = useRouter();

  const series = toSeries(data.migration_decisions, {
    order: MIGRATION_DECISIONS,
    color: (key) => DECISION_COLOR[key as MigrationDecision] ?? "var(--muted-foreground)",
    label: (key) => key,
    dropEmpty: true,
  });
  const total = sumDistribution(data.migration_decisions);

  return (
    <Section
      title="Migration Decisions"
      description="One of exactly five decisions per asset"
      help="RETAIN, HARDEN, UPGRADE, HYBRID or PQC-ONLY. The decision is the coarse instruction; each asset also carries a specific standards-grounded strategy, shown on its detail page."
    >
      <div className="flex min-w-0 flex-col gap-4 sm:flex-row sm:items-center">
        <div className="relative shrink-0 sm:w-52">
          <ChartFrame
            data={series}
            height={188}
            description="Assets by migration decision."
          >
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <RechartsTooltip content={<ChartTooltip total={total} hideLabel />} />
                <Pie
                  data={series}
                  dataKey="value"
                  nameKey="name"
                  innerRadius="58%"
                  outerRadius="86%"
                  paddingAngle={2}
                  strokeWidth={0}
                  isAnimationActive={false}
                >
                  {series.map((datum) => (
                    <Cell
                      key={datum.key}
                      fill={datum.color}
                      className="cursor-pointer transition-opacity hover:opacity-80"
                      onClick={() => router.push(`/inventory?decision=${datum.key}`)}
                    />
                  ))}
                </Pie>
              </PieChart>
            </ResponsiveContainer>
          </ChartFrame>
          <div className="pointer-events-none absolute inset-0 grid place-items-center">
            <div className="text-center">
              <p className="ecdat-numeric text-2xl leading-none font-semibold">
                {formatNumber(total)}
              </p>
              <p className="text-muted-foreground text-[10px] tracking-wide uppercase">
                assets
              </p>
            </div>
          </div>
        </div>

        <div className="min-w-0 flex-1 space-y-2">
          <ChartLegend
            data={series}
            total={total}
            onSelect={(datum) => router.push(`/inventory?decision=${datum.key}`)}
          />
          <p className="text-muted-foreground border-t pt-2 text-[11px] leading-relaxed">
            {data.decision_definitions.RETAIN}
          </p>
        </div>
      </div>
    </Section>
  );
}

// ---------------------------------------------------------------------------
// 6. Migration priority queue
// ---------------------------------------------------------------------------

/**
 * The queue as a single ribbon rather than four bars: priority bands are one
 * ordered pipeline through the same estate, and a ribbon shows the proportions
 * of that pipeline at a glance. Each segment links to its filtered inventory.
 */
export function PriorityQueueChart({ data }: { data: DashboardSummary }) {
  const router = useRouter();

  const series = toSeries(data.priority_bands, {
    order: PRIORITY_BANDS,
    color: (key) => PRIORITY_COLOR[key as keyof typeof PRIORITY_COLOR] ?? "var(--muted)",
    label: (key) => key,
    dropEmpty: true,
  });
  const total = sumDistribution(data.priority_bands);

  const bandCaption: Record<string, string> = {
    P0: "Start now",
    P1: "Next planning cycle",
    P2: "Scheduled",
    P3: "Monitor",
  };

  return (
    <Section
      title="Migration Priority Queue"
      description="The whole estate, ranked into four bands"
      help="Priority is a backend-computed rank combining both risk axes, Mosca urgency, business criticality and graph coupling. Bands cover every asset, including those that need no change."
    >
      <div className="space-y-4">
        <div
          className="bg-muted flex h-9 w-full overflow-hidden rounded-md"
          role="img"
          aria-label={series
            .map((datum) => `${datum.name}: ${datum.value} assets`)
            .join(", ")}
        >
          {series.map((datum) => (
            <button
              key={datum.key}
              type="button"
              onClick={() => router.push(`/inventory?band=${datum.key}`)}
              title={`${datum.name} — ${formatNumber(datum.value)} assets (${percentOf(
                datum.value,
                total,
              )}%)`}
              className="focus-visible:ring-ring relative flex items-center justify-center transition-opacity hover:opacity-85 focus-visible:z-10 focus-visible:ring-2 focus-visible:outline-none"
              style={{
                width: `${(datum.value / total) * 100}%`,
                backgroundColor: datum.color,
              }}
            >
              <span className="ecdat-numeric truncate px-1 text-[11px] font-semibold text-white/95 mix-blend-luminosity">
                {datum.value}
              </span>
            </button>
          ))}
        </div>

        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          {series.map((datum) => (
            <button
              key={datum.key}
              type="button"
              onClick={() => router.push(`/inventory?band=${datum.key}`)}
              className="hover:bg-muted/60 focus-visible:ring-ring min-w-0 rounded-md border p-2 text-left transition-colors focus-visible:ring-2 focus-visible:outline-none"
            >
              <div className="flex items-center gap-1.5">
                <span
                  aria-hidden
                  className="size-2 shrink-0 rounded-[2px]"
                  style={{ backgroundColor: datum.color }}
                />
                <span className="text-xs font-semibold">{datum.name}</span>
              </div>
              <p className="ecdat-numeric mt-1 text-lg leading-none font-semibold">
                {formatNumber(datum.value)}
              </p>
              <p className="text-muted-foreground mt-0.5 text-[11px]">
                {bandCaption[datum.key] ?? "Ranked"}
              </p>
            </button>
          ))}
        </div>

        <p className="text-muted-foreground text-[11px] leading-relaxed">
          {formatNumber(data.headlines.scheduled)} of {formatNumber(total)} assets carry a
          decision other than RETAIN and therefore enter the programme schedule; the
          remaining {formatNumber(data.headlines.need_no_change)} are ranked but require no
          cryptographic change.
        </p>
      </div>
    </Section>
  );
}

// ---------------------------------------------------------------------------
// 8. Crypto agility, paired with interoperability
// ---------------------------------------------------------------------------

function MiniBars({
  data,
  total,
  description,
  onSelect,
}: {
  data: ChartDatum[];
  total: number;
  description: string;
  onSelect: (datum: ChartDatum) => void;
}) {
  return (
    <ChartFrame data={data} height={104} description={description}>
      <ResponsiveContainer width="100%" height="100%">
        <BarChart
          data={data}
          layout="vertical"
          margin={{ top: 0, right: 44, bottom: 0, left: 0 }}
          barCategoryGap={6}
        >
          <XAxis type="number" hide />
          <YAxis
            type="category"
            dataKey="name"
            {...axisProps}
            width={78}
            interval={0}
          />
          <RechartsTooltip cursor={barCursor} content={<ChartTooltip total={total} />} />
          <Bar dataKey="value" radius={[0, 3, 3, 0]} maxBarSize={16} isAnimationActive={false}>
            {data.map((datum) => (
              <Cell
                key={datum.key}
                fill={datum.color}
                className="cursor-pointer transition-opacity hover:opacity-80"
                onClick={() => onSelect(datum)}
              />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </ChartFrame>
  );
}

export function AgilityChart({ data }: { data: DashboardSummary }) {
  const router = useRouter();

  const agility = toSeries(data.crypto_agility, {
    order: ["high", "medium", "low"],
    color: (key) => AGILITY_COLOR[key as keyof typeof AGILITY_COLOR] ?? "var(--muted)",
    dropEmpty: true,
  });
  const interop = toSeries(data.interoperability, {
    order: ["open", "negotiated", "constrained"],
    color: (key) =>
      ({
        open: "var(--success)",
        negotiated: "var(--warning)",
        constrained: "var(--risk-high)",
      })[key] ?? "var(--muted)",
    dropEmpty: true,
  });

  const agilityTotal = sumDistribution(data.crypto_agility);
  const interopTotal = sumDistribution(data.interoperability);

  return (
    <Section
      title="Changeability"
      description="How hard each asset is to change, and who else has to agree"
      help="Crypto agility and interoperability are canonical fields on the asset, not scores. Together they explain why a low-risk asset can still need a long lead time."
    >
      <div className="space-y-4">
        <div>
          <p className="text-muted-foreground mb-1.5 text-[11px] font-medium tracking-wide uppercase">
            Crypto agility
          </p>
          <MiniBars
            data={agility}
            total={agilityTotal}
            description="Assets by crypto agility: high, medium or low."
            onSelect={(datum) => router.push(`/inventory?agility=${datum.key}`)}
          />
        </div>
        <div className="border-t pt-3">
          <p className="text-muted-foreground mb-1.5 text-[11px] font-medium tracking-wide uppercase">
            Interoperability
          </p>
          <MiniBars
            data={interop}
            total={interopTotal}
            description="Assets by interoperability constraint: open, negotiated or constrained."
            onSelect={(datum) => router.push(`/inventory?interoperability=${datum.key}`)}
          />
        </div>
        <p className="text-muted-foreground text-[11px] leading-relaxed">
          CONSTRAINED means the mechanism cannot be changed unilaterally — a peer, a
          certificate authority or a compiled artefact has to move first. That is what
          drives an asset towards a HYBRID decision rather than PQC-ONLY.
        </p>
      </div>
    </Section>
  );
}

// ---------------------------------------------------------------------------
// Quantum taxonomy — the class breakdown behind the quantum axis
// ---------------------------------------------------------------------------

const QUANTUM_CLASS_LABEL: Record<string, string> = {
  shor_broken: "Shor-broken",
  grover_reduced: "Grover-reduced",
  classically_broken: "Classically broken",
  pqc_standardized: "PQC standardised",
  pqc_selected: "PQC selected",
  hybrid_pqt: "PQ/T hybrid",
  unknown: "Unknown",
};

const QUANTUM_CLASS_COLOR: Record<string, string> = {
  shor_broken: "var(--quantum-critical)",
  grover_reduced: "var(--quantum-medium)",
  classically_broken: "var(--risk-critical)",
  pqc_standardized: "var(--success)",
  pqc_selected: "var(--chart-5)",
  hybrid_pqt: "var(--info)",
  unknown: "var(--muted-foreground)",
};

export function QuantumTaxonomyChart({
  data,
  className,
}: {
  data: DashboardSummary;
  className?: string;
}) {
  const router = useRouter();

  const series = toSeries(data.quantum_taxonomy, {
    order: [
      "classically_broken",
      "shor_broken",
      "grover_reduced",
      "unknown",
      "hybrid_pqt",
      "pqc_standardized",
      "pqc_selected",
    ],
    color: (key) => QUANTUM_CLASS_COLOR[key] ?? "var(--muted-foreground)",
    label: (key) => QUANTUM_CLASS_LABEL[key] ?? humanize(key),
    dropEmpty: true,
  });
  const total = sumDistribution(data.quantum_taxonomy);

  return (
    <Section
      title="Algorithm Quantum Class"
      description="Why each asset sits where it does on the quantum axis"
      help="The quantum class is the mechanism-level fact that produces the quantum exposure band: whether Shor breaks it outright, Grover halves its strength, or it is already a standardised post-quantum algorithm."
      className={cn("min-w-0", className)}
    >
      <ChartFrame
        data={series}
        height={216}
        description="Assets by algorithm quantum class."
      >
        <ResponsiveContainer width="100%" height="100%">
          <BarChart
            data={series}
            layout="vertical"
            margin={{ top: 0, right: 40, bottom: 0, left: 0 }}
          >
            <XAxis type="number" hide />
            <YAxis type="category" dataKey="name" {...axisProps} width={126} interval={0} />
            <RechartsTooltip cursor={barCursor} content={<ChartTooltip total={total} />} />
            <Bar dataKey="value" radius={[0, 3, 3, 0]} maxBarSize={18} isAnimationActive={false}>
              {series.map((datum) => (
                <Cell
                  key={datum.key}
                  fill={datum.color}
                  className="cursor-pointer transition-opacity hover:opacity-80"
                  onClick={() => router.push(`/inventory?quantum_class=${datum.key}`)}
                />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </ChartFrame>
      <p className="text-muted-foreground mt-2 text-[11px] leading-relaxed">
        &ldquo;Classically broken&rdquo; assets are a present-day problem and are scheduled
        ahead of the quantum programme; the two are sequenced independently.
      </p>
    </Section>
  );
}
