"use client";

import Link from "next/link";
import {
  ArrowRight,
  CheckCircle2,
  Filter,
  Flame,
  RefreshCw,
  ShieldAlert,
  Workflow,
} from "lucide-react";

import { useAssets, useDashboard } from "@/lib/queries";
import { formatNumber, humanize, percentOf } from "@/lib/display";
import { PageHeader, PageShell, Section } from "@/components/ecdat/layout";
import { DecisionBadge, PriorityBadge, RiskBadge } from "@/components/ecdat/badges";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { ErrorState, PanelSkeleton } from "@/components/ecdat/states";

export default function RemediationPage() {
  const dashboard = useDashboard();
  const urgentAssets = useAssets({ limit: 50, sort: "priority" });

  if (dashboard.isError) {
    return (
      <PageShell>
        <PageHeader
          title="Remediation Tracker"
          question="Which cryptographic assets require active remediation and in what order?"
        />
        <ErrorState error={dashboard.error} onRetry={() => dashboard.refetch()} />
      </PageShell>
    );
  }

  const data = dashboard.data;

  return (
    <PageShell>
      <PageHeader
        title="Remediation Tracker"
        question="Which cryptographic assets require active remediation and in what order?"
        description="Track the cryptographic remediation lifecycle across the enterprise. Assets are ordered by migration priority score, taking into account classical exploitability, quantum vulnerability, data lifetime, and dependency centrality."
        actions={
          <Button
            variant="outline"
            size="sm"
            onClick={() => {
              void dashboard.refetch();
              void urgentAssets.refetch();
            }}
            disabled={dashboard.isFetching}
          >
            <RefreshCw className={dashboard.isFetching ? "mr-1.5 size-3.5 animate-spin" : "mr-1.5 size-3.5"} />
            Refresh
          </Button>
        }
      />

      {/* Headline Remediation Stats */}
      {data ? (
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          <Card className="p-3">
            <span className="text-[10px] uppercase font-semibold text-muted-foreground flex items-center gap-1">
              <Flame className="size-3.5 text-risk-critical" />
              Action Required
            </span>
            <div className="ecdat-numeric mt-1 text-2xl font-bold text-foreground">
              {formatNumber(data.headlines.need_change)}
            </div>
            <p className="text-[10px] text-muted-foreground">
              {percentOf(data.headlines.need_change, data.headlines.total_assets)}% of total estate
            </p>
          </Card>

          <Card className="p-3">
            <span className="text-[10px] uppercase font-semibold text-muted-foreground flex items-center gap-1">
              <CheckCircle2 className="size-3.5 text-success" />
              No Change Needed
            </span>
            <div className="ecdat-numeric mt-1 text-2xl font-bold text-foreground">
              {formatNumber(data.headlines.need_no_change)}
            </div>
            <p className="text-[10px] text-muted-foreground">retained / already compliant</p>
          </Card>

          <Card className="p-3">
            <span className="text-[10px] uppercase font-semibold text-muted-foreground flex items-center gap-1">
              <ShieldAlert className="size-3.5 text-risk-high" />
              P0 & P1 Critical Items
            </span>
            <div className="ecdat-numeric mt-1 text-2xl font-bold text-foreground">
              {formatNumber((data.priority_bands?.P0 ?? 0) + (data.priority_bands?.P1 ?? 0))}
            </div>
            <p className="text-[10px] text-muted-foreground">top priority queue</p>
          </Card>

          <Card className="p-3">
            <span className="text-[10px] uppercase font-semibold text-muted-foreground flex items-center gap-1">
              <Workflow className="size-3.5 text-primary" />
              Gating Remediations
            </span>
            <div className="ecdat-numeric mt-1 text-2xl font-bold text-foreground">
              {formatNumber(data.headlines.gating_assets)}
            </div>
            <p className="text-[10px] text-muted-foreground">unblock multiple dependents</p>
          </Card>
        </div>
      ) : (
        <PanelSkeleton lines={3} />
      )}

      {/* High Priority Remediation Work Queue */}
      <Section
        title="Top Remediation Work Queue"
        description="Assets ordered by migration priority score for immediate engineering action"
        actions={
          <Button asChild variant="outline" size="sm">
            <Link href="/inventory?band=P0">
              <Filter className="mr-1.5 size-3" />
              View All in Inventory
            </Link>
          </Button>
        }
      >
        {urgentAssets.isPending ? (
          <PanelSkeleton lines={8} />
        ) : urgentAssets.data?.assets ? (
          <Card className="overflow-hidden">
            <div className="divide-y text-xs">
              {urgentAssets.data.assets.slice(0, 15).map((asset) => (
                <div
                  key={asset.asset_id}
                  className="flex flex-col gap-2 p-3.5 transition-colors hover:bg-muted/30 sm:flex-row sm:items-center sm:justify-between"
                >
                  <div className="space-y-1 min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <Link
                        href={`/assets/${asset.asset_id}`}
                        className="font-semibold text-foreground hover:text-primary hover:underline transition-colors"
                      >
                        {asset.asset_name}
                      </Link>
                      <RiskBadge band={asset.classical_risk} size="sm" />
                      <DecisionBadge decision={asset.migration_decision} size="sm" />
                      <PriorityBadge band={asset.priority_band} size="sm" />
                      {asset.application ? (
                        <Badge variant="outline" className="text-[10px]">
                          {asset.application}
                        </Badge>
                      ) : null}
                    </div>

                    <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-[11px] text-muted-foreground">
                      <span className="font-mono">ID: {asset.asset_id}</span>
                      {asset.recommended_strategy ? (
                        <span>Strategy: <strong>{asset.recommended_strategy}</strong></span>
                      ) : null}
                      {asset.file ? (
                        <span className="font-mono">{asset.file}</span>
                      ) : null}
                    </div>
                  </div>

                  <div className="flex shrink-0 items-center gap-3">
                    <div className="text-right">
                      <div className="font-mono text-xs font-semibold text-foreground">
                        Priority Score: {asset.migration_priority}
                      </div>
                      <span className="text-[10px] text-muted-foreground">
                        Effort: {humanize(String(asset.migration_effort ?? "moderate"))}
                      </span>
                    </div>

                    <Button asChild variant="outline" size="sm" className="h-8 text-xs">
                      <Link href={`/assets/${asset.asset_id}`}>
                        Investigate
                        <ArrowRight className="ml-1 size-3" />
                      </Link>
                    </Button>
                  </div>
                </div>
              ))}
            </div>
          </Card>
        ) : null}
      </Section>
    </PageShell>
  );
}
