"use client";

import Link from "next/link";
import {
  ArrowRight,
  RefreshCw,
  Sparkles,
} from "lucide-react";

import { useDashboard } from "@/lib/queries";
import { formatNumber, percentOf } from "@/lib/display";
import { PageHeader, PageShell } from "@/components/ecdat/layout";
import { DecisionBadge } from "@/components/ecdat/badges";
import { Button } from "@/components/ui/button";
import { Card, CardTitle } from "@/components/ui/card";
import {
  AgilityChart,
  MigrationDecisionChart,
  PriorityQueueChart,
} from "@/features/dashboard/distribution-charts";
import { ErrorState, PanelSkeleton } from "@/components/ecdat/states";
import type { MigrationDecision } from "@/types/api";

export default function MigrationPage() {
  const dashboard = useDashboard();

  if (dashboard.isError) {
    return (
      <PageShell>
        <PageHeader
          title="Migration Strategies"
          question="What cryptographic actions does the engine recommend across the estate?"
        />
        <ErrorState error={dashboard.error} onRetry={() => dashboard.refetch()} />
      </PageShell>
    );
  }

  const data = dashboard.data;

  return (
    <PageShell>
      <PageHeader
        title="Migration Strategies"
        question="What cryptographic actions does the engine recommend across the estate?"
        description="Every asset receives one of five frozen executive decisions: RETAIN (no change needed), HARDEN (parameter or lifecycle update), UPGRADE (replace classically broken), HYBRID (post-quantum dual stack), or PQC-ONLY (standalone quantum-safe)."
        actions={
          <Button
            variant="outline"
            size="sm"
            onClick={() => dashboard.refetch()}
            disabled={dashboard.isFetching}
          >
            <RefreshCw className={dashboard.isFetching ? "mr-1.5 size-3.5 animate-spin" : "mr-1.5 size-3.5"} />
            Refresh
          </Button>
        }
      />

      {/* Decision Cards with Definitions */}
      {data ? (
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
          {Object.entries(data.migration_decisions || {}).map(([decision, count]) => {
            const definition = data.decision_definitions?.[decision as keyof typeof data.decision_definitions];
            return (
              <Card key={decision} className="flex flex-col justify-between p-4 transition-colors hover:border-primary/50">
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <DecisionBadge decision={decision as MigrationDecision} />
                    <span className="text-xs text-muted-foreground">
                      {percentOf(count, data.headlines.total_assets)}%
                    </span>
                  </div>
                  <div className="ecdat-numeric text-2xl font-bold text-foreground">
                    {formatNumber(count)}
                  </div>
                  {definition ? (
                    <p className="text-[11px] text-muted-foreground leading-relaxed">
                      {definition}
                    </p>
                  ) : null}
                </div>

                <Button asChild variant="ghost" size="sm" className="mt-3 w-full justify-between text-xs">
                  <Link href={`/inventory?decision=${decision}`}>
                    Filter in Inventory
                    <ArrowRight className="size-3" />
                  </Link>
                </Button>
              </Card>
            );
          })}
        </div>
      ) : (
        <PanelSkeleton lines={3} />
      )}

      {/* Decision Distribution and Priority Queue Charts */}
      <div className="grid min-w-0 gap-4 lg:grid-cols-2">
        {data ? (
          <MigrationDecisionChart data={data} />
        ) : (
          <PanelSkeleton lines={5} />
        )}
        {data ? (
          <PriorityQueueChart data={data} />
        ) : (
          <PanelSkeleton lines={5} />
        )}
      </div>

      {/* Crypto Agility Distribution */}
      <div className="grid min-w-0 gap-4 lg:grid-cols-2">
        {data ? (
          <AgilityChart data={data} />
        ) : (
          <PanelSkeleton lines={5} />
        )}
        <Card className="p-5 flex flex-col justify-center space-y-3">
          <CardTitle className="text-base flex items-center gap-2">
            <Sparkles className="size-4 text-primary" />
            Decision Engine Rules
          </CardTitle>
          <p className="text-xs text-muted-foreground leading-relaxed">
            The decision engine is 100% deterministic and follows a frozen hierarchy:
          </p>
          <ul className="list-disc pl-5 text-xs text-muted-foreground space-y-1.5 leading-relaxed">
            <li><strong>Expired Certificates:</strong> Trigger HARDEN with strategy <code>renew-certificate</code> first, unblocking key upgrades.</li>
            <li><strong>Classically Broken:</strong> MD5, SHA-1, DES, and RC4 trigger UPGRADE for immediate classical substitution.</li>
            <li><strong>Post-Quantum Transition:</strong> Shor-vulnerable public key algorithms choose between HYBRID and PQC-ONLY based on interoperability and peer control.</li>
            <li><strong>Symmetric &amp; Hashes:</strong> AES-256 and SHA-256 trigger RETAIN, eliminating unnecessary engineering churn.</li>
          </ul>
        </Card>
      </div>
    </PageShell>
  );
}
