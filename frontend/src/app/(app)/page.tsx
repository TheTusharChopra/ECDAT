/**
 * Overview — the estate dashboard.
 *
 * The screen answers one question: what cryptography exists here (§32). Its
 * order of argument is deliberate. The estate strip establishes what was
 * actually scanned and under which policy anchor. The KPI row states the seven
 * counts. Then the two risk axes appear side by side, because the single most
 * important thing a reader has to understand about ECDAT is that it does not
 * have one risk number. The crosstab that follows proves it with the estate's
 * own data. Everything after that -- decisions, priority, families, impact,
 * certificates, sequencing -- is the consequence.
 *
 * Three requests populate the whole page: `/dashboard`, `/assets` and
 * `/roadmap`. Nothing is computed here that the backend did not already decide.
 */

"use client";

import Link from "next/link";
import { CalendarClock, FolderSearch, RefreshCw, ScrollText, ShieldQuestion } from "lucide-react";

import type { DashboardSummary } from "@/types/api";
import { useAssets, useDashboard, useRoadmap } from "@/lib/queries";
import { formatDateTime, formatNumber } from "@/lib/display";
import { MethodNote, PageHeader, PageShell, Section } from "@/components/ecdat/layout";
import { ChartSkeleton, ErrorState, PanelSkeleton } from "@/components/ecdat/states";
import { KpiRow, KpiRowSkeleton } from "@/features/dashboard/kpi-row";
import {
  AgilityChart,
  MigrationDecisionChart,
  PriorityQueueChart,
  QuantumTaxonomyChart,
  RiskAxisPanels,
} from "@/features/dashboard/distribution-charts";
import {
  AlgorithmFamilyChart,
  CertificatePostureChart,
  GatingAssetsPanel,
  HighestImpactChart,
  RiskCrosstabChart,
} from "@/features/dashboard/estate-charts";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";

export default function OverviewPage() {
  const dashboard = useDashboard();
  // The summary projection is enough for every aggregate on this page and is a
  // tenth of the full view's payload (§34).
  const assets = useAssets({ limit: 1000 });
  const roadmap = useRoadmap();

  if (dashboard.isError) {
    return (
      <PageShell>
        <PageHeader title="Overview" question="What cryptography exists across the estate?" />
        <Card>
          <CardContent>
            <ErrorState error={dashboard.error} onRetry={() => dashboard.refetch()} />
          </CardContent>
        </Card>
      </PageShell>
    );
  }

  const data = dashboard.data;

  return (
    <PageShell>
      <PageHeader
        title="Overview"
        question="What cryptography exists across the estate?"
        description="Every figure on this page is a count of canonical asset fields produced by the analysis backend. Risk bands and migration decisions are ECDAT-derived engineering recommendations, not a compliance status."
        actions={
          <Button
            variant="outline"
            size="sm"
            onClick={() => {
              void dashboard.refetch();
              void assets.refetch();
              void roadmap.refetch();
            }}
            disabled={dashboard.isFetching}
          >
            <RefreshCw className={dashboard.isFetching ? "animate-spin" : undefined} />
            Refresh
          </Button>
        }
      />

      {data ? <EstateStrip data={data} /> : <EstateStripSkeleton />}

      {data ? <KpiRow data={data} /> : <KpiRowSkeleton />}

      {/* The dual-axis statement. */}
      {data ? (
        <RiskAxisPanels data={data} />
      ) : (
        <div className="grid gap-4 lg:grid-cols-2">
          <Section title="Classical Risk">
            <ChartSkeleton height={200} />
          </Section>
          <Section title="Quantum Exposure">
            <ChartSkeleton height={200} />
          </Section>
        </div>
      )}

      {/* The proof, in this estate's own numbers. */}
      {assets.isError ? (
        <Section title="Two-Axis Crosstab">
          <ErrorState error={assets.error} onRetry={() => assets.refetch()} compact />
        </Section>
      ) : assets.data ? (
        <RiskCrosstabChart assets={assets.data.assets} />
      ) : (
        <Section title="Two-Axis Crosstab">
          <ChartSkeleton height={230} />
        </Section>
      )}

      <div className="grid min-w-0 gap-4 lg:grid-cols-2">
        {data ? (
          <MigrationDecisionChart data={data} />
        ) : (
          <Section title="Migration Decisions">
            <ChartSkeleton height={190} />
          </Section>
        )}
        {data ? (
          <PriorityQueueChart data={data} />
        ) : (
          <Section title="Migration Priority Queue">
            <PanelSkeleton lines={5} />
          </Section>
        )}
      </div>

      <div className="grid min-w-0 gap-4 lg:grid-cols-2">
        {assets.data ? (
          <AlgorithmFamilyChart assets={assets.data.assets} />
        ) : (
          <Section title="Algorithm Families">
            <ChartSkeleton height={260} />
          </Section>
        )}
        {data ? (
          <QuantumTaxonomyChart data={data} />
        ) : (
          <Section title="Algorithm Quantum Class">
            <ChartSkeleton height={216} />
          </Section>
        )}
      </div>

      <div className="grid min-w-0 gap-4 lg:grid-cols-2">
        {roadmap.isError ? (
          <Section title="Highest-Impact Assets">
            <ErrorState error={roadmap.error} onRetry={() => roadmap.refetch()} compact />
          </Section>
        ) : roadmap.data ? (
          <HighestImpactChart roadmap={roadmap.data} />
        ) : (
          <Section title="Highest-Impact Assets">
            <ChartSkeleton height={260} />
          </Section>
        )}
        <CertificatePostureChart />
      </div>

      <div className="grid min-w-0 gap-4 lg:grid-cols-2">
        {roadmap.data ? (
          <GatingAssetsPanel roadmap={roadmap.data} />
        ) : (
          <Section title="Enablement Waves">
            <PanelSkeleton lines={4} />
          </Section>
        )}
        {data ? (
          <AgilityChart data={data} />
        ) : (
          <Section title="Changeability">
            <ChartSkeleton height={220} />
          </Section>
        )}
      </div>

      {data ? <ScanNotes data={data} /> : null}
    </PageShell>
  );
}

// ---------------------------------------------------------------------------
// Estate strip
// ---------------------------------------------------------------------------

function EstateStripSkeleton() {
  return (
    <Card className="py-3">
      <CardContent className="flex flex-wrap gap-6 px-4">
        {Array.from({ length: 4 }).map((_, index) => (
          <div key={index} className="space-y-1.5">
            <Skeleton className="h-3 w-20" />
            <Skeleton className="h-4 w-32" />
          </div>
        ))}
      </CardContent>
    </Card>
  );
}

/**
 * What was scanned, under which policy, against which threat-horizon anchor.
 *
 * The CRQC year sits here rather than being buried in a risk panel because
 * every urgency verdict downstream depends on it, and because the wording has
 * to travel with the number: it is a policy deadline, not a forecast.
 */
function EstateStrip({ data }: { data: DashboardSummary }) {
  const { estate, scenario } = data;
  const targets = estate.target.split(",").map((part) => part.trim()).filter(Boolean);

  return (
    <Card className="min-w-0 gap-0 py-0">
      <CardContent className="flex min-w-0 flex-col gap-4 px-4 py-3 lg:flex-row lg:items-center lg:gap-8">
        <div className="min-w-0 flex-1">
          <div className="text-muted-foreground flex items-center gap-1.5 text-[10px] font-medium tracking-wide uppercase">
            <FolderSearch className="size-3" aria-hidden />
            Scanned estate
          </div>
          <div className="mt-1 flex flex-wrap items-center gap-1.5">
            {targets.map((target) => (
              <Tooltip key={target}>
                <TooltipTrigger asChild>
                  <code className="bg-muted max-w-56 truncate rounded px-1.5 py-0.5 font-mono text-[11px]">
                    {target.split("/").slice(-2).join("/")}
                  </code>
                </TooltipTrigger>
                <TooltipContent className="font-mono text-[11px]">{target}</TooltipContent>
              </Tooltip>
            ))}
          </div>
        </div>

        <Stat label="Scan" value={estate.scan_id} mono />
        <Stat label="Completed" value={formatDateTime(estate.scanned_at)} />
        <Stat label="Policy" value={estate.policy} mono />

        <div className="min-w-0 shrink-0">
          <div className="text-muted-foreground flex items-center gap-1.5 text-[10px] font-medium tracking-wide uppercase">
            <CalendarClock className="size-3" aria-hidden />
            Threat horizon
          </div>
          <div className="mt-1 flex items-center gap-1.5">
            <span className="ecdat-numeric text-sm font-semibold">{scenario.crqc_year}</span>
            <Tooltip>
              <TooltipTrigger asChild>
                <button
                  type="button"
                  aria-label="About the threat horizon"
                  className="text-muted-foreground hover:text-foreground transition-colors"
                >
                  <ShieldQuestion className="size-3.5" />
                </button>
              </TooltipTrigger>
              <TooltipContent className="max-w-80 text-xs leading-relaxed">
                {scenario.crqc_rationale}
              </TooltipContent>
            </Tooltip>
            <Button asChild variant="ghost" size="sm" className="h-6 px-1.5 text-[11px]">
              <Link href="/settings">Change</Link>
            </Button>
          </div>
        </div>
      </CardContent>

      <div className="text-muted-foreground border-t px-4 py-2 text-[11px] leading-relaxed">
        <span className="text-foreground font-medium">{estate.business_context_note}</span>{" "}
        {estate.business_context_defaulted > 0
          ? `${formatNumber(
              estate.business_context_defaulted,
            )} assets carry defaulted business context, which is an assumption rather than a discovered fact and is labelled as such wherever it is used.`
          : "Business context is operator-declared, so Mosca urgency is not resting on assumed data lifetimes."}
      </div>
    </Card>
  );
}

function Stat({
  label,
  value,
  mono = false,
}: {
  label: string;
  value: string;
  mono?: boolean;
}) {
  return (
    <div className="min-w-0 shrink-0">
      <p className="text-muted-foreground text-[10px] font-medium tracking-wide uppercase">
        {label}
      </p>
      <p className={mono ? "mt-1 font-mono text-[11px]" : "mt-1 text-xs"}>{value}</p>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Backend notes
// ---------------------------------------------------------------------------

/** The backend's own caveats about this scan, quoted rather than paraphrased. */
function ScanNotes({ data }: { data: DashboardSummary }) {
  if (data.notes.length === 0) return null;

  return (
    <Section
      title="How to read these figures"
      description="Reported by the analysis backend for this scan"
    >
      <ul className="space-y-2">
        {data.notes.map((note) => (
          <li key={note} className="flex gap-2">
            <ScrollText className="text-muted-foreground mt-0.5 size-3.5 shrink-0" aria-hidden />
            <MethodNote className="border-l-0 pl-0">{note}</MethodNote>
          </li>
        ))}
      </ul>
    </Section>
  );
}
