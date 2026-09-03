"use client";

import { useState } from "react";
import Link from "next/link";
import {
  ArrowRight,
  GitFork,
  Network,
  RefreshCw,
} from "lucide-react";

import { useAssetGraph, useAssets } from "@/lib/queries";
import { PageHeader, PageShell, Section } from "@/components/ecdat/layout";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { ErrorState, PanelSkeleton } from "@/components/ecdat/states";

export default function GraphPage() {
  const assetsQuery = useAssets({ limit: 200 });
  const [selectedAssetId, setSelectedAssetId] = useState<string>("");
  const [depth, setDepth] = useState<number>(3);

  const assets = assetsQuery.data?.assets ?? [];
  const currentAssetId = selectedAssetId || (assets[0]?.asset_id ?? "");

  const graphQuery = useAssetGraph(currentAssetId, depth, Boolean(currentAssetId));

  return (
    <PageShell>
      <PageHeader
        title="Dependency Graph"
        question="How is cryptography interconnected across applications, services, repositories, and certificates?"
        description="ECDAT models the cryptographic estate as a directed dependency graph. Traversals compute blast radius, dependency centrality, and enablement waves."
        actions={
          <Button
            variant="outline"
            size="sm"
            onClick={() => {
              void assetsQuery.refetch();
              void graphQuery.refetch();
            }}
            disabled={graphQuery.isFetching}
          >
            <RefreshCw className={graphQuery.isFetching ? "mr-1.5 size-3.5 animate-spin" : "mr-1.5 size-3.5"} />
            Refresh
          </Button>
        }
      />

      {/* Asset and Depth Controls */}
      <Card className="p-4">
        <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex flex-1 items-center gap-3">
            <span className="text-xs font-semibold text-muted-foreground shrink-0">Focus Asset:</span>
            <Select
              value={currentAssetId}
              onValueChange={setSelectedAssetId}
              disabled={assets.length === 0}
            >
              <SelectTrigger className="w-full sm:max-w-md">
                <SelectValue placeholder="Select an asset..." />
              </SelectTrigger>
              <SelectContent>
                {assets.map((asset) => (
                  <SelectItem key={asset.asset_id} value={asset.asset_id}>
                    {asset.asset_name} ({asset.application ?? "Global"}) · {asset.migration_decision}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          <div className="flex items-center gap-2">
            <span className="text-xs font-semibold text-muted-foreground">Traversal Depth:</span>
            <div className="flex gap-1">
              {[1, 2, 3, 4].map((d) => (
                <Button
                  key={d}
                  variant={depth === d ? "default" : "outline"}
                  size="sm"
                  className="h-8 w-8 p-0 text-xs font-mono"
                  onClick={() => setDepth(d)}
                >
                  {d}
                </Button>
              ))}
            </div>
          </div>
        </div>
      </Card>

      {/* Graph Metrics Strip */}
      {graphQuery.data ? (
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          <Card className="p-3">
            <span className="text-[10px] uppercase font-semibold text-muted-foreground">Nodes in Neighborhood</span>
            <div className="ecdat-numeric mt-1 text-2xl font-bold text-foreground">
              {graphQuery.data.graph.nodes?.length ?? 0}
            </div>
            <p className="text-[10px] text-muted-foreground">within depth {depth}</p>
          </Card>
          <Card className="p-3">
            <span className="text-[10px] uppercase font-semibold text-muted-foreground">Coupling Edges</span>
            <div className="ecdat-numeric mt-1 text-2xl font-bold text-foreground">
              {graphQuery.data.graph.edges?.length ?? 0}
            </div>
            <p className="text-[10px] text-muted-foreground">dependency connections</p>
          </Card>
          <Card className="p-3">
            <span className="text-[10px] uppercase font-semibold text-muted-foreground">Dependency Centrality</span>
            <div className="ecdat-numeric mt-1 text-2xl font-bold text-foreground">
              {graphQuery.data.dependency_centrality_score ?? 0}
            </div>
            <p className="text-[10px] text-muted-foreground">centrality ranking</p>
          </Card>
          <Card className="p-3">
            <span className="text-[10px] uppercase font-semibold text-muted-foreground">Affected Scope</span>
            <div className="ecdat-numeric mt-1 text-2xl font-bold text-foreground">
              {graphQuery.data.affected_summary?.applications?.length ?? 0}
            </div>
            <p className="text-[10px] text-muted-foreground">applications reached</p>
          </Card>
        </div>
      ) : null}

      {/* Graph Node Explorer */}
      <Section
        title={`Neighborhood for ${graphQuery.data?.asset_name ?? "Selected Asset"}`}
        description="All interconnected applications, services, algorithms, certificates, and libraries"
      >
        {graphQuery.isPending ? (
          <PanelSkeleton lines={6} />
        ) : graphQuery.isError ? (
          <ErrorState error={graphQuery.error} onRetry={() => graphQuery.refetch()} />
        ) : graphQuery.data?.graph?.nodes?.length ? (
          <div className="grid gap-4 md:grid-cols-2">
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-base flex items-center gap-2">
                  <Network className="size-4 text-primary" />
                  Connected Nodes ({graphQuery.data.graph.nodes.length})
                </CardTitle>
              </CardHeader>
              <CardContent className="max-h-96 overflow-y-auto divide-y p-0">
                {graphQuery.data.graph.nodes.map((node) => (
                  <div key={node.id} className="flex items-center justify-between p-3 text-xs hover:bg-muted/30">
                    <div className="space-y-0.5">
                      <div className="flex items-center gap-2">
                        <Badge variant="outline" className="text-[10px] font-mono">
                          {node.type}
                        </Badge>
                        <span className="font-semibold text-foreground">{node.label}</span>
                      </div>
                      <p className="font-mono text-[10px] text-muted-foreground">{node.id}</p>
                    </div>

                    {node.type === "crypto-asset" ? (
                      <Button asChild variant="ghost" size="sm" className="h-7 text-xs">
                        <Link href={`/assets/${node.id.replace("crypto-asset:", "")}`}>
                          View
                          <ArrowRight className="ml-1 size-3" />
                        </Link>
                      </Button>
                    ) : null}
                  </div>
                ))}
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-base flex items-center gap-2">
                  <GitFork className="size-4 text-primary" />
                  Coupling Edges ({graphQuery.data.graph.edges.length})
                </CardTitle>
              </CardHeader>
              <CardContent className="max-h-96 overflow-y-auto divide-y p-0 text-xs">
                {graphQuery.data.graph.edges.map((edge, i) => (
                  <div key={i} className="p-3 space-y-1 hover:bg-muted/30">
                    <div className="flex items-center justify-between">
                      <Badge variant="secondary" className="text-[10px] font-mono">
                        {edge.type}
                      </Badge>
                    </div>
                    <div className="flex items-center gap-2 font-mono text-[11px] text-muted-foreground">
                      <span className="truncate max-w-[45%] text-foreground">{edge.source}</span>
                      <span>&rarr;</span>
                      <span className="truncate max-w-[45%] text-foreground">{edge.target}</span>
                    </div>
                  </div>
                ))}
              </CardContent>
            </Card>
          </div>
        ) : (
          <p className="text-xs text-muted-foreground">No graph nodes returned.</p>
        )}
      </Section>
    </PageShell>
  );
}
