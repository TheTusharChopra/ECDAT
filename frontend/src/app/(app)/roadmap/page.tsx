"use client";

import Link from "next/link";
import {
  Boxes,
  Calendar,
  CheckCircle2,
  Clock,
  Download,
  Flame,
  GitFork,
  Milestone,
  RefreshCw,
  ShieldAlert,
  Zap,
} from "lucide-react";

import { useRoadmap } from "@/lib/queries";
import { exportUrl } from "@/lib/api-client";
import { formatNumber, humanize } from "@/lib/display";
import { PageHeader, PageShell, Section } from "@/components/ecdat/layout";
import { DecisionBadge, PriorityBadge } from "@/components/ecdat/badges";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { ErrorState, PanelSkeleton } from "@/components/ecdat/states";

export default function RoadmapPage() {
  const roadmapQuery = useRoadmap();

  if (roadmapQuery.isError) {
    return (
      <PageShell>
        <PageHeader
          title="Roadmap"
          question="How should cryptographic migrations be sequenced across the estate?"
        />
        <ErrorState error={roadmapQuery.error} onRetry={() => roadmapQuery.refetch()} />
      </PageShell>
    );
  }

  if (roadmapQuery.isPending || !roadmapQuery.data) {
    return (
      <PageShell>
        <PageHeader
          title="Roadmap"
          question="How should cryptographic migrations be sequenced across the estate?"
        />
        <div className="space-y-4">
          <PanelSkeleton lines={3} />
          <PanelSkeleton lines={6} />
        </div>
      </PageShell>
    );
  }

  const data = roadmapQuery.data;
  const totals = data.totals;

  return (
    <PageShell>
      <PageHeader
        title="Roadmap"
        question="How should cryptographic migrations be sequenced across the estate?"
        description="Graph-aware, priority-ordered execution plan. Gating assets and shared cryptographic libraries are hoisted to earlier phases to unblock downstream dependencies without circular blocking."
        actions={
          <div className="flex items-center gap-2">
            <Button asChild variant="outline" size="sm">
              <a href={exportUrl("roadmap.csv")} download>
                <Download className="mr-1.5 size-3.5" />
                Export CSV
              </a>
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => roadmapQuery.refetch()}
              disabled={roadmapQuery.isFetching}
            >
              <RefreshCw className={roadmapQuery.isFetching ? "mr-1.5 size-3.5 animate-spin" : "mr-1.5 size-3.5"} />
              Refresh
            </Button>
          </div>
        }
      />

      {/* Headline Totals Strip */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
        <StatCard
          label="Total Scheduled"
          value={formatNumber(totals.scheduled)}
          detail="assets needing migration"
          icon={Calendar}
          accent="var(--primary)"
        />
        <StatCard
          label="Gating Assets"
          value={formatNumber(totals.gating_assets)}
          detail="unblock many others"
          icon={GitFork}
          accent="var(--chart-3)"
        />
        <StatCard
          label="No Action Required"
          value={formatNumber(totals.no_action_required)}
          detail="retained / already compliant"
          icon={CheckCircle2}
          accent="var(--success)"
        />
        <StatCard
          label="Phase 0 (Blockers)"
          value={formatNumber(totals.p0)}
          detail="immediate remediation"
          icon={Flame}
          accent="var(--risk-critical)"
        />
        <StatCard
          label="Phase 1 (Urgent)"
          value={formatNumber(totals.p1)}
          detail="classically broken"
          icon={ShieldAlert}
          accent="var(--risk-high)"
        />
        <StatCard
          label="Phase 2 & 3"
          value={formatNumber((totals.p2 ?? 0) + (totals.p3 ?? 0))}
          detail="phased PQC transitions"
          icon={Zap}
          accent="var(--quantum-medium)"
        />
      </div>

      {/* Enablement Waves */}
      {data.enablement_waves?.length ? (
        <Section
          title="Enablement Waves"
          description="High-reach changes sequenced first to unblock dependent application teams"
          help="When a core library, crypto provider, or Root CA is upgraded, all downstream consumer applications become unblocked for PQC migration."
        >
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {data.enablement_waves.map((wave, idx) => (
              <Card key={idx} className="flex flex-col justify-between p-4">
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <Badge variant="outline" className="font-mono text-[10px]">
                      Wave {idx + 1} · {wave.phase}
                    </Badge>
                    <DecisionBadge decision={wave.decision} size="sm" />
                  </div>
                  <div>
                    <h3 className="font-semibold text-sm text-foreground">
                      <Link
                        href={`/assets/${wave.gating_asset}`}
                        className="hover:underline hover:text-primary transition-colors"
                      >
                        {wave.gating_asset_name}
                      </Link>
                    </h3>
                    <p className="font-mono text-[11px] text-muted-foreground mt-0.5">
                      {wave.strategy}
                    </p>
                  </div>
                  {wave.rationale ? (
                    <p className="text-xs text-muted-foreground leading-relaxed">
                      {wave.rationale}
                    </p>
                  ) : null}
                </div>

                <div className="mt-4 flex items-center justify-between border-t pt-3 text-xs">
                  <span className="text-muted-foreground">
                    Unblocks <strong className="text-foreground">{wave.dependent_assets}</strong> assets
                  </span>
                  <span className="font-mono text-muted-foreground">
                    ~{wave.months} months
                  </span>
                </div>
              </Card>
            ))}
          </div>
        </Section>
      ) : null}

      {/* Phased Roadmap Execution Plan */}
      <Section
        title="Execution Plan by Phase"
        description="Structured migration phases ordered by priority, dependencies, and risk level"
      >
        <div className="space-y-6">
          {data.phases.map((phase) => (
            <Card key={phase.id || phase.name} className="overflow-hidden">
              <CardHeader className="bg-muted/40 border-b pb-4">
                <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
                  <div>
                    <div className="flex items-center gap-2">
                      <Milestone className="size-4 text-primary" />
                      <CardTitle className="text-base font-bold">
                        {phase.name || phase.id}
                      </CardTitle>
                    </div>
                    {phase.objective ? (
                      <p className="mt-1 text-xs text-muted-foreground">
                        {phase.objective}
                      </p>
                    ) : null}
                  </div>

                  <div className="flex items-center gap-2">
                    {phase.duration ? (
                      <Badge variant="secondary" className="font-mono text-xs">
                        <Clock className="mr-1 size-3" />
                        {phase.duration}
                      </Badge>
                    ) : null}
                    <Badge variant="outline" className="font-mono text-xs">
                      <Boxes className="mr-1 size-3" />
                      {phase.items?.length ?? phase.asset_count ?? 0} Work Items
                    </Badge>
                  </div>
                </div>
              </CardHeader>

              <CardContent className="p-0">
                {phase.items && phase.items.length > 0 ? (
                  <div className="divide-y text-xs">
                    {phase.items.map((item) => (
                      <div
                        key={item.asset_id}
                        className="flex flex-col gap-2 p-3.5 transition-colors hover:bg-muted/30 sm:flex-row sm:items-center sm:justify-between"
                      >
                        <div className="space-y-1 min-w-0 flex-1">
                          <div className="flex flex-wrap items-center gap-2">
                            <Link
                              href={`/assets/${item.asset_id}`}
                              className="font-semibold text-foreground hover:text-primary hover:underline transition-colors"
                            >
                              {item.asset_name}
                            </Link>
                            <DecisionBadge decision={item.decision} size="sm" />
                            <PriorityBadge band={item.band} size="sm" />
                            {item.application ? (
                              <Badge variant="outline" className="text-[10px]">
                                {item.application}
                              </Badge>
                            ) : null}
                          </div>

                          <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-[11px] text-muted-foreground">
                            {item.strategy ? <span>Strategy: {item.strategy}</span> : null}
                            {item.target ? <span className="font-mono">Target: {item.target}</span> : null}
                            {item.location ? <span className="font-mono">{item.location}</span> : null}
                          </div>

                          {item.why_this_phase ? (
                            <p className="text-[11px] text-muted-foreground/90 italic">
                              {item.why_this_phase}
                            </p>
                          ) : null}
                        </div>

                        <div className="flex shrink-0 items-center gap-4 text-right sm:flex-col sm:items-end sm:gap-1">
                          <span className="font-mono text-xs font-medium text-foreground">
                            {item.months} mo (effort: {humanize(String(item.effort))})
                          </span>
                          {item.unblocks > 0 ? (
                            <span className="text-[11px] text-success font-medium">
                              Unblocks {item.unblocks} downstream
                            </span>
                          ) : null}
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="p-4 text-center text-xs text-muted-foreground">
                    No individual items assigned to this phase.
                  </div>
                )}
              </CardContent>
            </Card>
          ))}
        </div>
      </Section>
    </PageShell>
  );
}

function StatCard({
  label,
  value,
  detail,
  icon: Icon,
  accent,
}: {
  label: string;
  value: string;
  detail: string;
  icon: typeof Calendar;
  accent: string;
}) {
  return (
    <div className="rounded-lg border bg-card p-3 shadow-xs">
      <div className="flex items-center gap-1.5">
        <Icon className="size-3.5 shrink-0" style={{ color: accent }} />
        <span className="truncate text-[10px] font-semibold uppercase text-muted-foreground">
          {label}
        </span>
      </div>
      <div className="ecdat-numeric mt-1.5 text-xl font-bold leading-none text-foreground">
        {value}
      </div>
      <p className="mt-1 truncate text-[10px] text-muted-foreground">{detail}</p>
    </div>
  );
}
