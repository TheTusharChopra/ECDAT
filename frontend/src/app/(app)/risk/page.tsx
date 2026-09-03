"use client";

import Link from "next/link";
import {
  Atom,
  CalendarClock,
  Clock,
  RefreshCw,
  ShieldX,
} from "lucide-react";

import { useAssets, useDashboard } from "@/lib/queries";
import { formatNumber } from "@/lib/display";
import { PageHeader, PageShell, Section } from "@/components/ecdat/layout";
import { UrgencyBadge } from "@/components/ecdat/badges";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { RiskCrosstabChart } from "@/features/dashboard/estate-charts";
import { RiskAxisPanels } from "@/features/dashboard/distribution-charts";
import { ErrorState, PanelSkeleton } from "@/components/ecdat/states";

export default function RiskPage() {
  const dashboard = useDashboard();
  const assets = useAssets({ limit: 1000 });

  if (dashboard.isError) {
    return (
      <PageShell>
        <PageHeader
          title="Risk & Mosca Analysis"
          question="How do classical vulnerability and post-quantum exposure diverge across the estate?"
        />
        <ErrorState error={dashboard.error} onRetry={() => dashboard.refetch()} />
      </PageShell>
    );
  }

  const data = dashboard.data;

  return (
    <PageShell>
      <PageHeader
        title="Risk & Mosca Analysis"
        question="How do classical vulnerability and post-quantum exposure diverge across the estate?"
        description="ECDAT rejects blended risk numbers. Classical risk assesses immediate exploitability today; quantum exposure assesses vulnerability to future Shor/Grover attacks. Mosca's Inequality (x + y > z) determines timeline urgency."
        actions={
          <Button
            variant="outline"
            size="sm"
            onClick={() => {
              void dashboard.refetch();
              void assets.refetch();
            }}
            disabled={dashboard.isFetching}
          >
            <RefreshCw className={dashboard.isFetching ? "mr-1.5 size-3.5 animate-spin" : "mr-1.5 size-3.5"} />
            Refresh
          </Button>
        }
      />

      {/* Mosca & Urgency Strip */}
      {data ? (
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          <Card className="p-3">
            <span className="text-[10px] uppercase font-semibold text-muted-foreground flex items-center gap-1">
              <ShieldX className="size-3.5 text-risk-critical" />
              Broken Today (Classical)
            </span>
            <div className="ecdat-numeric mt-1 text-2xl font-bold text-foreground">
              {formatNumber(data.headlines.classically_broken_today)}
            </div>
            <p className="text-[10px] text-muted-foreground">exploitable now on classical hardware</p>
          </Card>

          <Card className="p-3">
            <span className="text-[10px] uppercase font-semibold text-muted-foreground flex items-center gap-1">
              <Atom className="size-3.5 text-quantum-critical" />
              Quantum Vulnerable
            </span>
            <div className="ecdat-numeric mt-1 text-2xl font-bold text-foreground">
              {formatNumber(data.headlines.quantum_vulnerable)}
            </div>
            <p className="text-[10px] text-muted-foreground">{data.headlines.quantum_vulnerable_pct} of entire estate</p>
          </Card>

          <Card className="p-3">
            <span className="text-[10px] uppercase font-semibold text-muted-foreground flex items-center gap-1">
              <CalendarClock className="size-3.5 text-primary" />
              Threat Horizon (z)
            </span>
            <div className="ecdat-numeric mt-1 text-2xl font-bold text-foreground">
              {data.scenario.crqc_year}
            </div>
            <p className="text-[10px] text-muted-foreground">policy planning horizon</p>
          </Card>

          <Card className="p-3">
            <span className="text-[10px] uppercase font-semibold text-muted-foreground flex items-center gap-1">
              <Clock className="size-3.5 text-chart-3" />
              Urgency Distributions
            </span>
            <div className="mt-1 flex flex-wrap gap-1">
              {Object.entries(data.urgency || {}).map(([urgency, count]) => (
                <Link
                  key={urgency}
                  href={`/inventory?urgency=${urgency}`}
                  className="flex items-center gap-1 hover:opacity-80 text-xs"
                >
                  <UrgencyBadge urgency={urgency} size="sm" />
                  <span className="font-mono text-[11px] text-muted-foreground">({count})</span>
                </Link>
              ))}
            </div>
          </Card>
        </div>
      ) : (
        <PanelSkeleton lines={3} />
      )}

      {/* Dual Axis Distribution Panels */}
      {data ? (
        <RiskAxisPanels data={data} />
      ) : (
        <PanelSkeleton lines={6} />
      )}

      {/* The Two-Axis Crosstab Proof */}
      <Section
        title="Two-Axis Risk Crosstab Matrix"
        description="The mathematical proof that classical risk and quantum exposure are orthogonal"
      >
        {assets.isPending ? (
          <PanelSkeleton lines={6} />
        ) : assets.data ? (
          <RiskCrosstabChart assets={assets.data.assets} />
        ) : null}
      </Section>
    </PageShell>
  );
}
