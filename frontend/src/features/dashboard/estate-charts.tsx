/**
 * Dashboard charts that aggregate the inventory (§8 charts 3, 4, 7, 9).
 *
 * `GET /dashboard` does not carry an algorithm-family breakdown, a two-axis
 * crosstab, certificate posture, or a blast-radius ranking, so these four count
 * over `GET /assets` and `GET /roadmap` instead. What is counted is always a
 * canonical field the backend already decided: `algorithm_family`,
 * `classical_risk`, `quantum_exposure`, `days_to_expiry`, `blast_radius`.
 * Grouping and colouring records is presentation; none of these panels produces
 * a verdict the API did not already return (§30, §37).
 */

"use client";

import { useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { CalendarClock, ShieldOff, TriangleAlert } from "lucide-react";
import {
  Bar,
  BarChart,
  Cell,
  ResponsiveContainer,
  Tooltip as RechartsTooltip,
  XAxis,
  YAxis,
} from "recharts";

import type { AssetSummary, CryptoAsset, MigrationDecision, RoadmapResponse } from "@/types/api";
import {
  CRITICALITY_LABEL,
  CRITICALITY_ORDER,
  DECISION_COLOR,
  QUANTUM_ORDER,
  RISK_ORDER,
  categoricalColor,
  formatNumber,
  humanize,
  quantumColor,
  riskColor,
} from "@/lib/display";
import { useAssetsFull } from "@/lib/queries";
import { cn } from "@/lib/utils";
import { Section, MethodNote } from "@/components/ecdat/layout";
import { ChartSkeleton } from "@/components/ecdat/states";
import { DecisionBadge } from "@/components/ecdat/badges";
import {
  ChartFrame,
  ChartTooltip,
  axisProps,
  barCursor,
  truncateLabel,
  type ChartDatum,
} from "@/components/charts/chart-kit";
import { Button } from "@/components/ui/button";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";

// ---------------------------------------------------------------------------
// 3. Algorithm family distribution
// ---------------------------------------------------------------------------

const FAMILY_TOP_N = 12;

export function AlgorithmFamilyChart({ assets }: { assets: AssetSummary[] }) {
  const router = useRouter();

  const series = useMemo<ChartDatum[]>(() => {
    const counts = new Map<string, number>();
    for (const asset of assets) {
      const key = asset.algorithm_family ?? "__unclassified__";
      counts.set(key, (counts.get(key) ?? 0) + 1);
    }
    const ranked = [...counts.entries()].sort((a, b) => b[1] - a[1]);
    const head = ranked.slice(0, FAMILY_TOP_N);
    const tail = ranked.slice(FAMILY_TOP_N);

    const rows: ChartDatum[] = head.map(([key, value], index) => ({
      key,
      name: key === "__unclassified__" ? "Unclassified" : key,
      value,
      color:
        key === "__unclassified__" ? "var(--muted-foreground)" : categoricalColor(index),
    }));

    if (tail.length > 0) {
      rows.push({
        key: "__other__",
        name: `Other (${tail.length} families)`,
        value: tail.reduce((sum, [, value]) => sum + value, 0),
        color: "var(--muted-foreground)",
        note: tail.map(([key]) => key).join(", "),
      });
    }
    return rows;
  }, [assets]);

  const total = assets.length;
  const unclassified = series.find((row) => row.key === "__unclassified__")?.value ?? 0;

  return (
    <Section
      title="Algorithm Families"
      description="Which cryptographic families the estate actually runs on"
      help="Counted over the canonical `algorithm_family` field. Families are assigned during normalisation, so every variant spelling of an algorithm lands in one family."
    >
      <ChartFrame
        data={series}
        height={260}
        description="Cryptographic assets grouped by algorithm family."
        footer={
          unclassified > 0
            ? `${formatNumber(unclassified)} assets carry no family classification — usually a protocol or configuration finding where the concrete algorithm is negotiated at runtime rather than named in the source.`
            : undefined
        }
      >
        <ResponsiveContainer width="100%" height="100%">
          <BarChart
            data={series}
            layout="vertical"
            margin={{ top: 0, right: 40, bottom: 0, left: 0 }}
          >
            <XAxis type="number" hide />
            <YAxis
              type="category"
              dataKey="name"
              {...axisProps}
              width={118}
              interval={0}
              tickFormatter={(value: string) => truncateLabel(value, 16)}
            />
            <RechartsTooltip cursor={barCursor} content={<ChartTooltip total={total} />} />
            <Bar dataKey="value" radius={[0, 3, 3, 0]} maxBarSize={14} isAnimationActive={false}>
              {series.map((datum) => {
                const selectable = !datum.key.startsWith("__");
                return (
                  <Cell
                    key={datum.key}
                    fill={datum.color}
                    className={cn(
                      "transition-opacity",
                      selectable && "cursor-pointer hover:opacity-80",
                    )}
                    onClick={
                      selectable
                        ? () =>
                            router.push(
                              `/inventory?q=${encodeURIComponent(datum.name)}`,
                            )
                        : undefined
                    }
                  />
                );
              })}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </ChartFrame>
    </Section>
  );
}

// ---------------------------------------------------------------------------
// 4. The two-axis crosstab
// ---------------------------------------------------------------------------

type CrosstabAxis = "classical" | "criticality";

/**
 * The most consequential panel on the dashboard.
 *
 * A single blended "security score" would report this estate as broadly fine.
 * The crosstab shows why that would be wrong: there is a population of assets
 * sitting at LOW classical risk and CRITICAL quantum exposure -- unremarkable
 * today, harvestable now and decryptable later. That population only exists as
 * a visible finding because the two axes are scored separately, and this grid is
 * the shape of that architectural decision.
 *
 * Cell intensity ramps within each column using that column's own quantum
 * colour, so the quantum-critical column reads as a vertical band cutting
 * across every classical row.
 */
export function RiskCrosstabChart({ assets }: { assets: AssetSummary[] }) {
  const [axis, setAxis] = useState<CrosstabAxis>("classical");

  // The business-criticality axis is a full-view-only field, so it is fetched
  // only if the reader actually asks for it (§34).
  const fullQuery = useAssetsFull({ limit: 1000 }, axis === "criticality");

  const rowsOrder = axis === "classical" ? RISK_ORDER : CRITICALITY_ORDER;
  const rowLabel = (key: string) =>
    axis === "classical" ? humanize(key) : (CRITICALITY_LABEL[key] ?? humanize(key));
  const rowColor = (key: string) =>
    axis === "classical" ? riskColor(key) : "var(--muted-foreground)";

  const records: { row: string | null; column: string | null; id: string }[] = useMemo(() => {
    if (axis === "classical") {
      return assets.map((asset) => ({
        row: asset.classical_risk,
        column: asset.quantum_exposure,
        id: asset.asset_id,
      }));
    }
    const full: CryptoAsset[] = fullQuery.data?.assets ?? [];
    return full.map((asset) => ({
      row: asset.business_criticality ?? null,
      column: asset.quantum_exposure ?? null,
      id: asset.asset_id,
    }));
  }, [axis, assets, fullQuery.data]);

  const { grid, columns, rowTotals, columnTotals, maxByColumn, total } = useMemo(() => {
    const counts = new Map<string, number>();
    const rowT = new Map<string, number>();
    const colT = new Map<string, number>();
    const present = new Set<string>();

    for (const record of records) {
      if (!record.row || !record.column) continue;
      counts.set(
        `${record.row}|${record.column}`,
        (counts.get(`${record.row}|${record.column}`) ?? 0) + 1,
      );
      rowT.set(record.row, (rowT.get(record.row) ?? 0) + 1);
      colT.set(record.column, (colT.get(record.column) ?? 0) + 1);
      present.add(record.column);
    }

    const cols = QUANTUM_ORDER.filter((band) => present.has(band));
    const maxCol = new Map<string, number>();
    for (const column of cols) {
      let max = 0;
      for (const row of rowsOrder) max = Math.max(max, counts.get(`${row}|${column}`) ?? 0);
      maxCol.set(column, max);
    }

    return {
      grid: counts,
      columns: cols,
      rowTotals: rowT,
      columnTotals: colT,
      maxByColumn: maxCol,
      total: records.filter((r) => r.row && r.column).length,
    };
  }, [records, rowsOrder]);

  const visibleRows = rowsOrder.filter((row) => (rowTotals.get(row) ?? 0) > 0);

  const axisToggle = (
    <div className="bg-muted flex rounded-md p-0.5">
      {(
        [
          ["classical", "Classical risk"],
          ["criticality", "Business criticality"],
        ] as const
      ).map(([value, label]) => (
        <button
          key={value}
          type="button"
          onClick={() => setAxis(value)}
          aria-pressed={axis === value}
          className={cn(
            "focus-visible:ring-ring rounded-[5px] px-2 py-1 text-[11px] font-medium transition-colors focus-visible:ring-2 focus-visible:outline-none",
            axis === value
              ? "bg-background text-foreground shadow-sm"
              : "text-muted-foreground hover:text-foreground",
          )}
        >
          {label}
        </button>
      ))}
    </div>
  );

  const orthogonal =
    axis === "classical"
      ? (grid.get("low|critical") ?? 0) + (grid.get("info|critical") ?? 0)
      : 0;

  return (
    <Section
      title="Two-Axis Crosstab"
      description={
        axis === "classical"
          ? "Classical risk against quantum exposure"
          : "Business criticality against quantum exposure"
      }
      help="Each cell counts assets holding both verdicts. The two verdicts are produced by separate backend functions that share no state, which is why an asset can sit in a corner that a single blended score could not represent."
      actions={axisToggle}
    >
      {axis === "criticality" && fullQuery.isPending ? (
        <ChartSkeleton height={230} />
      ) : (
        <div className="min-w-0 space-y-3">
          <div className="ecdat-scrollbar -mx-1 overflow-x-auto px-1">
            <table className="w-full min-w-[30rem] border-separate border-spacing-1 text-xs">
              <caption className="sr-only">
                {axis === "classical"
                  ? "Assets by classical risk band and quantum exposure band."
                  : "Assets by business criticality and quantum exposure band."}
              </caption>
              <thead>
                <tr>
                  <th scope="col" className="w-32 text-left font-normal">
                    <span className="text-muted-foreground text-[10px] tracking-wide uppercase">
                      {axis === "classical" ? "Classical ↓" : "Criticality ↓"} / Quantum →
                    </span>
                  </th>
                  {columns.map((column) => (
                    <th key={column} scope="col" className="px-1 pb-1 font-medium">
                      <span className="flex items-center justify-center gap-1.5">
                        <span
                          aria-hidden
                          className="size-2 rounded-[2px]"
                          style={{ backgroundColor: quantumColor(column) }}
                        />
                        <span className="capitalize">{column}</span>
                      </span>
                    </th>
                  ))}
                  <th scope="col" className="text-muted-foreground w-14 pb-1 font-medium">
                    Total
                  </th>
                </tr>
              </thead>
              <tbody>
                {visibleRows.map((row) => (
                  <tr key={row}>
                    <th scope="row" className="py-0 text-left font-medium">
                      <span className="flex items-center gap-1.5">
                        <span
                          aria-hidden
                          className="size-2 shrink-0 rounded-[2px]"
                          style={{ backgroundColor: rowColor(row) }}
                        />
                        <span className="truncate">{rowLabel(row)}</span>
                      </span>
                    </th>
                    {columns.map((column) => {
                      const count = grid.get(`${row}|${column}`) ?? 0;
                      const max = maxByColumn.get(column) ?? 0;
                      const intensity = max > 0 ? count / max : 0;
                      const tint = 8 + Math.round(intensity * 62);
                      // Both dimensions are server-side filters only on the
                      // classical axis; business criticality is not in the
                      // backend's FILTERABLE set, so those cells do not
                      // pretend to be links.
                      const href =
                        axis === "classical" && count > 0
                          ? `/inventory?classical_risk=${row}&quantum_exposure=${column}`
                          : null;

                      const cell = (
                        <span
                          className={cn(
                            "ecdat-numeric grid h-9 w-full place-items-center rounded-md border text-[13px] font-medium tabular-nums transition-all",
                            count === 0 && "text-muted-foreground/50",
                            href && "hover:ring-ring cursor-pointer hover:ring-2",
                          )}
                          style={
                            count > 0
                              ? {
                                  backgroundColor: `color-mix(in oklab, ${quantumColor(
                                    column,
                                  )} ${tint}%, var(--card))`,
                                  borderColor: `color-mix(in oklab, ${quantumColor(
                                    column,
                                  )} ${Math.min(tint + 14, 78)}%, transparent)`,
                                }
                              : { borderStyle: "dashed" }
                          }
                        >
                          {count === 0 ? "·" : count}
                        </span>
                      );

                      return (
                        <td key={column} className="p-0">
                          <Tooltip>
                            <TooltipTrigger asChild>
                              {href ? (
                                <Link
                                  href={href}
                                  className="block focus-visible:outline-none"
                                  aria-label={`${count} assets at ${rowLabel(
                                    row,
                                  )} classical risk and ${column} quantum exposure`}
                                >
                                  {cell}
                                </Link>
                              ) : (
                                cell
                              )}
                            </TooltipTrigger>
                            <TooltipContent className="text-xs">
                              <p className="font-medium">
                                {formatNumber(count)} asset{count === 1 ? "" : "s"}
                              </p>
                              <p className="text-muted-foreground">
                                {rowLabel(row)} ·{" "}
                                <span className="capitalize">{column}</span> quantum exposure
                              </p>
                            </TooltipContent>
                          </Tooltip>
                        </td>
                      );
                    })}
                    <td className="text-muted-foreground ecdat-numeric text-center text-[13px]">
                      {formatNumber(rowTotals.get(row) ?? 0)}
                    </td>
                  </tr>
                ))}
                <tr>
                  <th scope="row" className="text-muted-foreground text-left text-[11px] font-medium">
                    Total
                  </th>
                  {columns.map((column) => (
                    <td
                      key={column}
                      className="text-muted-foreground ecdat-numeric text-center text-[13px]"
                    >
                      {formatNumber(columnTotals.get(column) ?? 0)}
                    </td>
                  ))}
                  <td className="ecdat-numeric text-center text-[13px] font-semibold">
                    {formatNumber(total)}
                  </td>
                </tr>
              </tbody>
            </table>
          </div>

          {axis === "classical" && orthogonal > 0 ? (
            <MethodNote className="border-l-[var(--quantum-critical)]">
              <span className="text-foreground font-medium">
                {formatNumber(orthogonal)} assets sit at LOW or INFO classical risk and
                CRITICAL quantum exposure.
              </span>{" "}
              They are sound against today&rsquo;s attacks and broken by a future one. A
              single blended security score would average them into the middle of the
              estate and lose the finding entirely — which is why ECDAT never computes one.
            </MethodNote>
          ) : null}

          {axis === "criticality" ? (
            <MethodNote>
              Business criticality is operator-declared or defaulted context, not a
              discovered fact. Cells on this axis are not links because business
              criticality is not one of the backend&rsquo;s server-side filters.
            </MethodNote>
          ) : null}
        </div>
      )}
    </Section>
  );
}

// ---------------------------------------------------------------------------
// 7. Certificate posture
// ---------------------------------------------------------------------------

interface ExpiryBucket {
  key: string;
  name: string;
  color: string;
  test: (days: number) => boolean;
}

/**
 * Windows applied to the backend's own `days_to_expiry` value. The thresholds
 * are a presentation grouping -- ECDAT does not publish an "expiring soon"
 * verdict, so the panel states the windows rather than implying the engine
 * chose them.
 */
const EXPIRY_BUCKETS: ExpiryBucket[] = [
  { key: "expired", name: "Expired", color: "var(--risk-critical)", test: (d) => d < 0 },
  { key: "30", name: "≤ 30 days", color: "var(--risk-high)", test: (d) => d >= 0 && d <= 30 },
  { key: "90", name: "31–90 days", color: "var(--risk-medium)", test: (d) => d > 30 && d <= 90 },
  { key: "365", name: "91–365 days", color: "var(--chart-3)", test: (d) => d > 90 && d <= 365 },
  { key: "beyond", name: "Over 1 year", color: "var(--success)", test: (d) => d > 365 },
];

export function CertificatePostureChart() {
  const query = useAssetsFull({ asset_type: "certificate", limit: 1000 });
  // Memoised so the fallback empty array is not a fresh value on every render,
  // which would defeat the memo below it.
  const certificates = useMemo(() => query.data?.assets ?? [], [query.data]);

  const { series, distinct, selfSigned, expired, soonest } = useMemo(() => {
    // Two units are in play and they must not be mixed in one row of figures.
    // A certificate yields several cryptographic assets (its key algorithm and
    // its signature hash are assessed separately), so the summary tiles count
    // distinct certificates -- deduplicated by serial -- while the chart counts
    // assets and says so in its own label and footer.
    const buckets = new Map<string, number>();
    const bySerial = new Map<string, (typeof certificates)[number]>();
    let unkeyed = 0;

    for (const certificate of certificates) {
      const days = certificate.days_to_expiry;
      if (typeof days === "number") {
        const bucket = EXPIRY_BUCKETS.find((candidate) => candidate.test(days));
        if (bucket) buckets.set(bucket.key, (buckets.get(bucket.key) ?? 0) + 1);
      }
      const serial = certificate.certificate_serial;
      if (serial) {
        if (!bySerial.has(serial)) bySerial.set(serial, certificate);
      } else {
        unkeyed += 1;
      }
    }

    let expiredCerts = 0;
    let selfSignedCerts = 0;
    let minDays: number | null = null;
    for (const certificate of bySerial.values()) {
      const days = certificate.days_to_expiry;
      if (typeof days === "number") {
        if (days < 0) expiredCerts += 1;
        if (days >= 0 && (minDays === null || days < minDays)) minDays = days;
      }
      if (certificate.certificate_self_signed) selfSignedCerts += 1;
    }

    return {
      series: EXPIRY_BUCKETS.map((bucket) => ({
        key: bucket.key,
        name: bucket.name,
        value: buckets.get(bucket.key) ?? 0,
        color: bucket.color,
      })).filter((row) => row.value > 0),
      distinct: bySerial.size + unkeyed,
      selfSigned: selfSignedCerts,
      expired: expiredCerts,
      soonest: minDays,
    };
  }, [certificates]);

  if (query.isPending) {
    return (
      <Section title="Certificate Posture" description="Validity windows across the PKI estate">
        <ChartSkeleton height={200} />
      </Section>
    );
  }

  return (
    <Section
      title="Certificate Posture"
      description="Validity windows across the PKI estate"
      help="Grouped from each certificate's `days_to_expiry`, which the backend computes when it parses the certificate. The window boundaries are a presentation choice; ECDAT does not publish an 'expiring soon' verdict."
    >
      <div className="space-y-4">
        <div className="grid grid-cols-3 gap-2">
          <Stat
            icon={CalendarClock}
            label="Certificates"
            value={formatNumber(distinct)}
            note={`${formatNumber(certificates.length)} crypto assets`}
            accent="var(--chart-3)"
          />
          <Stat
            icon={TriangleAlert}
            label="Expired"
            value={formatNumber(expired)}
            note={
              soonest !== null
                ? `certificates · next expiry in ${soonest}d`
                : "certificates · none live"
            }
            accent={expired > 0 ? "var(--risk-critical)" : "var(--muted-foreground)"}
          />
          <Stat
            icon={ShieldOff}
            label="Self-signed"
            value={formatNumber(selfSigned)}
            note="no external chain of trust"
            accent={selfSigned > 0 ? "var(--warning)" : "var(--muted-foreground)"}
          />
        </div>

        <ChartFrame
          data={series}
          height={150}
          valueLabel="Certificate assets"
          description="Certificate assets grouped by time remaining before expiry."
          emptyLabel="No certificates carry an expiry date in this scan."
          footer={`Each certificate yields more than one cryptographic asset — its key algorithm and its signature hash are assessed separately — so ${formatNumber(
            certificates.length,
          )} assets across ${formatNumber(distinct)} certificates.`}
        >
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={series} margin={{ top: 8, right: 4, bottom: 0, left: -22 }}>
              <XAxis dataKey="name" {...axisProps} interval={0} />
              <YAxis {...axisProps} allowDecimals={false} width={34} />
              <RechartsTooltip
                cursor={barCursor}
                content={<ChartTooltip unit="certificate asset" />}
              />
              <Bar dataKey="value" radius={[3, 3, 0, 0]} maxBarSize={44} isAnimationActive={false}>
                {series.map((datum) => (
                  <Cell key={datum.key} fill={datum.color} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </ChartFrame>

        <Button asChild variant="outline" size="sm" className="w-full">
          <Link href="/inventory?asset_type=certificate">Open certificate inventory</Link>
        </Button>
      </div>
    </Section>
  );
}

function Stat({
  icon: Icon,
  label,
  value,
  note,
  accent,
}: {
  icon: typeof CalendarClock;
  label: string;
  value: string;
  note: string;
  accent: string;
}) {
  return (
    <div className="min-w-0 rounded-md border p-2">
      <div className="flex items-center gap-1.5">
        <Icon className="size-3.5 shrink-0" style={{ color: accent }} aria-hidden />
        <span className="text-muted-foreground truncate text-[10px] font-medium tracking-wide uppercase">
          {label}
        </span>
      </div>
      <p className="ecdat-numeric mt-1 text-lg leading-none font-semibold">{value}</p>
      <p className="text-muted-foreground mt-0.5 truncate text-[10px]">{note}</p>
    </div>
  );
}

// ---------------------------------------------------------------------------
// 9. Highest-impact assets
// ---------------------------------------------------------------------------

const IMPACT_TOP_N = 8;

/**
 * Ranks scheduled assets by the blast radius the impact engine computed for
 * them. The ordering is a sort of a backend field, not a scoring model: the
 * number itself is graph-derived on the server (§19, §37).
 */
export function HighestImpactChart({ roadmap }: { roadmap: RoadmapResponse }) {
  const router = useRouter();

  const series = useMemo(() => {
    const seen = new Map<
      string,
      { id: string; name: string; blast: number; decision: MigrationDecision; where: string | null }
    >();
    for (const phase of roadmap.phases) {
      for (const item of phase.items) {
        const existing = seen.get(item.asset_id);
        if (!existing || item.blast_radius > existing.blast) {
          seen.set(item.asset_id, {
            id: item.asset_id,
            name: item.asset_name,
            blast: item.blast_radius,
            decision: item.decision,
            where: item.application,
          });
        }
      }
    }
    return [...seen.values()]
      .sort((a, b) => b.blast - a.blast)
      .slice(0, IMPACT_TOP_N)
      .map((row) => ({
        key: row.id,
        name: row.where ? `${row.name} · ${row.where}` : row.name,
        value: row.blast,
        color: DECISION_COLOR[row.decision] ?? "var(--muted-foreground)",
        note: `${row.decision} · ${row.name}`,
      }));
  }, [roadmap]);

  const scheduled = roadmap.totals.scheduled;

  return (
    <Section
      title="Highest-Impact Assets"
      description="Where a single cryptographic change reaches furthest"
      help="Blast radius is computed by the impact engine from the asset graph: the count of applications, services, repositories, certificates and dependent assets a change to this asset would touch. Bars are coloured by migration decision."
    >
      <ChartFrame
        data={series}
        height={260}
        valueLabel="Blast radius"
        description="Scheduled assets ranked by the blast radius of changing them."
        emptyLabel="No scheduled assets in this scan."
        footer={`Top ${series.length} of ${formatNumber(
          scheduled,
        )} scheduled assets, ranked by graph-derived blast radius. Colour indicates the migration decision.`}
      >
        <ResponsiveContainer width="100%" height="100%">
          <BarChart
            data={series}
            layout="vertical"
            margin={{ top: 0, right: 40, bottom: 0, left: 0 }}
          >
            <XAxis type="number" hide />
            <YAxis
              type="category"
              dataKey="name"
              {...axisProps}
              width={150}
              interval={0}
              tickFormatter={(value: string) => truncateLabel(value, 22)}
            />
            <RechartsTooltip
              cursor={barCursor}
              content={<ChartTooltip unit="downstream element" />}
            />
            <Bar dataKey="value" radius={[0, 3, 3, 0]} maxBarSize={16} isAnimationActive={false}>
              {series.map((datum) => (
                <Cell
                  key={datum.key}
                  fill={datum.color}
                  className="cursor-pointer transition-opacity hover:opacity-80"
                  onClick={() => router.push(`/assets/${datum.key}`)}
                />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </ChartFrame>
    </Section>
  );
}

// ---------------------------------------------------------------------------
// Gating assets -- the sequencing story
// ---------------------------------------------------------------------------

export function GatingAssetsPanel({ roadmap }: { roadmap: RoadmapResponse }) {
  const waves = roadmap.enablement_waves;

  // The backend currently returns the same rationale sentence for every wave,
  // because the reason is a property of the sequencing rule rather than of any
  // one asset. Printing it four times reads as padding, so it is hoisted to a
  // single note -- and only hoisted when the sentences really are identical, so
  // per-wave reasoning still shows through if the engine starts differentiating.
  const rationales = new Set(waves.map((wave) => wave.rationale).filter(Boolean));
  const sharedRationale = rationales.size === 1 ? [...rationales][0] : null;

  return (
    <Section
      title="Enablement Waves"
      description="One change that unblocks many"
      help="Derived from the asset graph. Where a single library, provider or certificate authority gates many downstream assets, the programme sequences that one change first regardless of its own risk score."
    >
      {waves.length === 0 ? (
        <p className="text-muted-foreground text-xs">
          No gating assets in this scan: no single change unblocks a group of others.
        </p>
      ) : (
        <div className="space-y-3">
          <ul className="space-y-2">
            {waves.map((wave) => (
              <li key={wave.gating_asset}>
                <Link
                  href={`/assets/${wave.gating_asset}`}
                  className="hover:border-ring/60 focus-visible:ring-ring group block rounded-md border p-3 transition-colors focus-visible:ring-2 focus-visible:outline-none"
                >
                  <div className="flex min-w-0 items-start justify-between gap-3">
                    <div className="min-w-0">
                      <p className="group-hover:text-primary truncate text-sm font-medium transition-colors">
                        {wave.gating_asset_name}
                      </p>
                      <p className="text-muted-foreground mt-0.5 text-[11px]">
                        {wave.phase} · {wave.applications.length} application
                        {wave.applications.length === 1 ? "" : "s"} · {wave.months} months
                      </p>
                      {wave.strategy ? (
                        <p className="text-muted-foreground/90 mt-1 truncate text-[11px]">
                          {wave.strategy}
                        </p>
                      ) : null}
                    </div>
                    <div className="flex shrink-0 items-center gap-2">
                      <DecisionBadge decision={wave.decision} />
                      <div className="text-right">
                        <p className="ecdat-numeric text-lg leading-none font-semibold">
                          {formatNumber(wave.dependent_assets)}
                        </p>
                        <p className="text-muted-foreground text-[10px]">unblocked</p>
                      </div>
                    </div>
                  </div>
                  {sharedRationale ? null : (
                    <p className="text-muted-foreground mt-2 border-t pt-2 text-[11px] leading-relaxed">
                      {wave.rationale}
                    </p>
                  )}
                </Link>
              </li>
            ))}
          </ul>
          {sharedRationale ? <MethodNote>{sharedRationale}</MethodNote> : null}
        </div>
      )}
    </Section>
  );
}
