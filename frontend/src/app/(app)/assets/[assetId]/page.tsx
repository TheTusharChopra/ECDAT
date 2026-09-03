"use client";

import { use, useState } from "react";
import Link from "next/link";
import {
  ArrowLeft,
  Building2,
  Calendar,
  FileCode,
  FileKey,
  GitFork,
  Network,
  RefreshCw,
  Scale,
  ScrollText,
  ShieldAlert,
  Sparkles,
  Workflow,
} from "lucide-react";

import {
  useAsset,
  useAssetGraph,
  useEvidence,
  useImpact,
  useMigration,
  useRisk,
} from "@/lib/queries";
import {
  formatDateTime,
  humanize,
  shortenPath,
} from "@/lib/display";
import { PageShell } from "@/components/ecdat/layout";
import {
  ConfidenceBadge,
  DecisionBadge,
  PriorityBadge,
  QuantumBadge,
  RiskBadge,
  UrgencyBadge,
} from "@/components/ecdat/badges";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Badge } from "@/components/ui/badge";
import { ErrorState, PanelSkeleton } from "@/components/ecdat/states";

export default function AssetDetailPage({
  params,
}: {
  params: Promise<{ assetId: string }>;
}) {
  const resolvedParams = use(params);
  const assetId = resolvedParams.assetId;

  const [activeTab, setActiveTab] = useState("overview");

  const assetQuery = useAsset(assetId);
  const evidenceQuery = useEvidence(assetId, activeTab === "evidence" || activeTab === "overview");
  const riskQuery = useRisk(assetId, activeTab === "risk" || activeTab === "overview");
  const migrationQuery = useMigration(assetId, activeTab === "migration" || activeTab === "overview");
  const impactQuery = useImpact(assetId, activeTab === "impact" || activeTab === "overview");
  const graphQuery = useAssetGraph(assetId, 3, activeTab === "graph");

  if (assetQuery.isError) {
    return (
      <PageShell>
        <div className="mb-4">
          <Button asChild variant="ghost" size="sm">
            <Link href="/inventory">
              <ArrowLeft className="mr-1.5 size-4" />
              Back to Inventory
            </Link>
          </Button>
        </div>
        <ErrorState error={assetQuery.error} onRetry={() => assetQuery.refetch()} />
      </PageShell>
    );
  }

  if (assetQuery.isPending || !assetQuery.data) {
    return (
      <PageShell>
        <div className="space-y-4">
          <PanelSkeleton lines={3} />
          <PanelSkeleton lines={8} />
        </div>
      </PageShell>
    );
  }

  const asset = assetQuery.data.asset;

  return (
    <PageShell>
      {/* Top Breadcrumb / Back button */}
      <div className="flex items-center justify-between">
        <Button asChild variant="ghost" size="sm" className="-ml-2 text-muted-foreground hover:text-foreground">
          <Link href="/inventory">
            <ArrowLeft className="mr-1.5 size-4" />
            Back to Inventory
          </Link>
        </Button>
        <Button
          variant="outline"
          size="sm"
          onClick={() => {
            void assetQuery.refetch();
            void evidenceQuery.refetch();
            void riskQuery.refetch();
            void migrationQuery.refetch();
            void impactQuery.refetch();
            void graphQuery.refetch();
          }}
          disabled={assetQuery.isFetching}
        >
          <RefreshCw className={assetQuery.isFetching ? "mr-1.5 size-3.5 animate-spin" : "mr-1.5 size-3.5"} />
          Refresh
        </Button>
      </div>

      {/* Asset Header */}
      <div className="rounded-lg border bg-card p-5 shadow-xs">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
          <div className="space-y-1.5">
            <div className="flex flex-wrap items-center gap-2">
              <Badge variant="outline" className="font-mono text-[11px] uppercase">
                {asset.asset_type}
              </Badge>
              <h1 className="text-xl font-bold tracking-tight text-foreground sm:text-2xl">
                {asset.asset_name}
              </h1>
              {asset.algorithm_label && asset.algorithm_label !== asset.asset_name ? (
                <span className="font-mono text-xs text-muted-foreground">
                  ({asset.algorithm_label})
                </span>
              ) : null}
            </div>

            <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-muted-foreground">
              <span className="font-mono">ID: {asset.asset_id}</span>
              {asset.application ? (
                <span className="flex items-center gap-1">
                  <Building2 className="size-3.5" />
                  {asset.application}
                </span>
              ) : null}
              {asset.file ? (
                <span className="flex items-center gap-1 font-mono text-[11px]">
                  <FileCode className="size-3.5" />
                  {shortenPath(asset.file, 45)}
                  {asset.line ? `:${asset.line}` : ""}
                </span>
              ) : null}
            </div>
          </div>

          {/* Verdict Tokens */}
          <div className="flex flex-wrap items-center gap-2">
            <RiskBadge band={asset.classical_risk} />
            <QuantumBadge band={asset.quantum_exposure} />
            <DecisionBadge decision={asset.migration_decision} />
            <PriorityBadge band={asset.priority_band} />
            <ConfidenceBadge level={asset.confidence} score={asset.confidence_score} />
          </div>
        </div>
      </div>

      {/* Main Tabs */}
      <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-4">
        <TabsList className="grid w-full grid-cols-3 sm:grid-cols-6">
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="risk">Risk & Mosca</TabsTrigger>
          <TabsTrigger value="migration">Migration</TabsTrigger>
          <TabsTrigger value="evidence">
            Evidence {evidenceQuery.data?.evidence?.length ? `(${evidenceQuery.data.evidence.length})` : ""}
          </TabsTrigger>
          <TabsTrigger value="impact">Impact</TabsTrigger>
          <TabsTrigger value="graph">Graph</TabsTrigger>
        </TabsList>

        {/* Tab 1: Overview */}
        <TabsContent value="overview" className="space-y-4">
          <div className="grid gap-4 md:grid-cols-2">
            {/* Cryptographic Properties */}
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="flex items-center gap-2 text-base">
                  <FileKey className="size-4 text-primary" />
                  Cryptographic Properties
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-2.5 text-xs">
                <Row label="Algorithm" value={asset.algorithm} mono />
                <Row label="Algorithm Family" value={asset.algorithm_family} />
                <Row label="Cryptographic Role" value={humanize(asset.cryptographic_role ?? "")} />
                <Row label="Primitive" value={asset.primitive} />
                <Row label="Key Size" value={asset.key_size ? `${asset.key_size} bits` : null} mono />
                <Row label="Curve" value={asset.curve} mono />
                <Row label="Security Strength (Classical)" value={asset.security_strength ? `${asset.security_strength} bits` : null} />
                <Row label="Quantum Strength" value={asset.quantum_strength ? `${asset.quantum_strength} bits` : null} />
                <Row label="Cipher Mode / Padding" value={[asset.mode, asset.padding].filter(Boolean).join(" / ") || null} />
                <Row label="Protocol / Version" value={[asset.protocol, asset.protocol_version].filter(Boolean).join(" ") || null} />
                <Row label="Library / Version" value={[asset.library, asset.library_version].filter(Boolean).join(" ") || null} />
                <Row label="OID" value={asset.oid} mono />
              </CardContent>
            </Card>

            {/* Business Context & Governance */}
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="flex items-center gap-2 text-base">
                  <Building2 className="size-4 text-primary" />
                  Business Context & Governance
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-2.5 text-xs">
                <Row label="Application" value={asset.application} />
                <Row label="Repository" value={asset.repository} mono />
                <Row label="Owner" value={asset.owner} />
                <Row label="Business Unit" value={asset.business_unit} />
                <Row label="Business Criticality" value={asset.business_criticality} />
                <Row label="Data Classification" value={asset.data_classification} />
                <Row label="Data Lifetime" value={asset.data_lifetime_years ? `${asset.data_lifetime_years} years` : null} />
                <Row label="Internet Exposed" value={asset.internet_exposed === null ? null : asset.internet_exposed ? "Yes (External)" : "No (Internal)"} />
                <Row label="Context Source" value={humanize(asset.context_source ?? "")} />
                <Row label="Triage State" value={humanize(asset.triage_state ?? "")} />
              </CardContent>
            </Card>
          </div>

          {/* Certificate Specific Details if applicable */}
          {asset.asset_type === "certificate" || asset.certificate_issuer || asset.certificate_expiry ? (
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="flex items-center gap-2 text-base">
                  <Scale className="size-4 text-primary" />
                  X.509 Certificate Profile
                </CardTitle>
              </CardHeader>
              <CardContent className="grid gap-x-8 gap-y-2.5 text-xs sm:grid-cols-2">
                <Row label="Subject" value={asset.certificate_subject} mono />
                <Row label="Issuer" value={asset.certificate_issuer} mono />
                <Row label="Serial Number" value={asset.certificate_serial} mono />
                <Row label="Signature Algorithm" value={asset.certificate_sig_algorithm} mono />
                <Row label="Valid From" value={formatDateTime(asset.certificate_not_before)} />
                <Row label="Expiry Date" value={formatDateTime(asset.certificate_expiry)} />
                <Row
                  label="Days to Expiry"
                  value={
                    typeof asset.days_to_expiry === "number"
                      ? asset.days_to_expiry < 0
                        ? `Expired (${Math.abs(asset.days_to_expiry)} days ago)`
                        : `${asset.days_to_expiry} days remaining`
                      : null
                  }
                />
                <Row label="Self-Signed" value={asset.certificate_self_signed ? "Yes (Untrusted Root)" : "No"} />
              </CardContent>
            </Card>
          ) : null}
        </TabsContent>

        {/* Tab 2: Risk & Mosca */}
        <TabsContent value="risk" className="space-y-4">
          <div className="grid gap-4 md:grid-cols-2">
            {/* Classical vs Quantum Dual-Axis */}
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="flex items-center gap-2 text-base">
                  <ShieldAlert className="size-4 text-risk-critical" />
                  Dual-Axis Security Evaluation
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4 text-xs">
                <div className="grid grid-cols-2 gap-3 rounded-md border p-3">
                  <div>
                    <span className="text-[10px] uppercase font-semibold text-muted-foreground">Classical Risk</span>
                    <div className="mt-1 flex items-center gap-1.5">
                      <RiskBadge band={asset.classical_risk} />
                    </div>
                    <p className="mt-1 text-[11px] text-muted-foreground">
                      Status: {humanize(asset.classical_security_status ?? "unclassified")}
                    </p>
                  </div>
                  <div>
                    <span className="text-[10px] uppercase font-semibold text-muted-foreground">Quantum Exposure</span>
                    <div className="mt-1 flex items-center gap-1.5">
                      <QuantumBadge band={asset.quantum_exposure} />
                    </div>
                    <p className="mt-1 text-[11px] text-muted-foreground">
                      Class: {humanize(asset.quantum_class ?? "unclassified")}
                    </p>
                  </div>
                </div>

                <Row label="Overall Risk Score" value={String(asset.risk_score)} />
                <Row label="Priority Band" value={asset.priority_band} />
                <Row label="Migration Priority Number" value={String(asset.migration_priority)} />
                <Row label="Mosca Urgency Verdict" value={humanize(asset.mosca_urgency)} />
              </CardContent>
            </Card>

            {/* Mosca Inequality Details */}
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="flex items-center gap-2 text-base">
                  <Calendar className="size-4 text-primary" />
                  Mosca Urgency Formula (x + y &gt; z)
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-3 text-xs">
                <div className="rounded-md bg-muted/40 p-3 font-mono text-[11px] space-y-1">
                  <div>x (Data Lifetime): {asset.data_lifetime_years ?? 0} yrs</div>
                  <div>y (Migration Effort): {((asset.migration_months ?? 12) / 12).toFixed(1)} yrs ({asset.migration_months ?? 12} mo)</div>
                  <div>z (Threat Horizon): 2035 policy anchor</div>
                  <div className="border-t pt-1 font-semibold text-foreground">
                    Status: <UrgencyBadge urgency={asset.mosca_urgency} />
                  </div>
                </div>
                <p className="text-[11px] text-muted-foreground leading-relaxed">
                  Mosca&rsquo;s theorem dictates that if the time required for data secrecy plus migration time exceeds the arrival of a Cryptographically Relevant Quantum Computer (CRQC), the system is already at risk of harvest-now-decrypt-later attacks.
                </p>
              </CardContent>
            </Card>
          </div>

          {/* Risk Factors Breakdown from GET /assets/{id}/risk */}
          {riskQuery.data?.risk_factors?.factors?.length ? (
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-base">Scoring Factors & Explanations</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="divide-y text-xs">
                  {riskQuery.data.risk_factors.factors.map((f, i) => (
                    <div key={i} className="py-2.5 space-y-1">
                      <div className="flex items-center justify-between">
                        <span className="font-semibold text-foreground">{humanize(f.name)}</span>
                        <span className="font-mono text-muted-foreground">
                          Weight: {f.weight} · Contrib: {f.contribution}
                        </span>
                      </div>
                      <p className="text-muted-foreground">{f.explanation}</p>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          ) : null}
        </TabsContent>

        {/* Tab 3: Migration */}
        <TabsContent value="migration" className="space-y-4">
          <div className="grid gap-4 md:grid-cols-2">
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="flex items-center gap-2 text-base">
                  <Workflow className="size-4 text-primary" />
                  Recommended Strategy
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-3 text-xs">
                <div className="flex items-center gap-2">
                  <DecisionBadge decision={asset.migration_decision} />
                  <span className="font-mono font-medium text-foreground">
                    {asset.recommended_strategy}
                  </span>
                </div>
                <Row label="Recommended PQC Algorithm" value={asset.recommended_pqc} mono />
                <Row label="Recommended Hybrid Algorithm" value={asset.recommended_hybrid} mono />
                <Row label="Estimated Effort" value={humanize(asset.migration_effort ?? "")} />
                <Row label="Estimated Timeline" value={asset.migration_months ? `${asset.migration_months} months` : null} />
                <Row label="Crypto Agility" value={humanize(asset.crypto_agility ?? "")} />
                <Row label="Interoperability Constraint" value={humanize(asset.interoperability ?? "")} />
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="flex items-center gap-2 text-base">
                  <ScrollText className="size-4 text-primary" />
                  Decision Rationale & Blockers
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-3 text-xs">
                {migrationQuery.data?.decision_rationale ? (
                  <p className="rounded-md bg-muted/30 p-3 leading-relaxed text-muted-foreground">
                    {migrationQuery.data.decision_rationale}
                  </p>
                ) : null}

                {migrationQuery.data?.migration_blockers?.length ? (
                  <div className="space-y-1.5">
                    <span className="font-semibold text-foreground">Migration Blockers:</span>
                    <ul className="list-disc pl-4 space-y-1 text-muted-foreground">
                      {migrationQuery.data.migration_blockers.map((b, i) => (
                        <li key={i}>{b}</li>
                      ))}
                    </ul>
                  </div>
                ) : null}
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* Tab 4: Evidence */}
        <TabsContent value="evidence" className="space-y-4">
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="flex items-center gap-2 text-base">
                <Sparkles className="size-4 text-primary" />
                Discovery Evidence & Provenance
              </CardTitle>
            </CardHeader>
            <CardContent>
              {evidenceQuery.isPending ? (
                <PanelSkeleton lines={4} />
              ) : evidenceQuery.data?.evidence?.length ? (
                <div className="divide-y text-xs">
                  {evidenceQuery.data.evidence.map((ev, i) => (
                    <div key={i} className="py-3 space-y-1.5">
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <div className="flex items-center gap-2">
                          <Badge variant="outline" className="font-mono text-[10px]">
                            {ev.detector}
                          </Badge>
                          <ConfidenceBadge level={ev.confidence} />
                          <span className="font-mono text-muted-foreground">{ev.method}</span>
                        </div>
                        {ev.matched ? (
                          <span className="font-mono text-muted-foreground">Match: {ev.matched}</span>
                        ) : null}
                      </div>

                      {ev.location ? (
                        <div className="font-mono text-[11px] text-foreground">{ev.location}</div>
                      ) : null}

                      {ev.reasoning ? (
                        <p className="text-[11px] text-muted-foreground">{ev.reasoning}</p>
                      ) : null}
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-xs text-muted-foreground">No evidence records found.</p>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* Tab 5: Impact */}
        <TabsContent value="impact" className="space-y-4">
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="flex items-center gap-2 text-base">
                <GitFork className="size-4 text-primary" />
                Graph-Derived Blast Radius
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4 text-xs">
              <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
                <StatBox
                  label="Blast Radius"
                  value={String(impactQuery.data?.impact?.blast_radius ?? 0)}
                  detail="downstream elements"
                />
                <StatBox
                  label="Applications"
                  value={String(impactQuery.data?.impact?.applications?.length ?? 0)}
                  detail="directly touch this"
                />
                <StatBox
                  label="Dependent Assets"
                  value={String(impactQuery.data?.impact?.dependent_assets?.length ?? 0)}
                  detail="rely on this mechanism"
                />
                <StatBox
                  label="Algorithm Siblings"
                  value={String(impactQuery.data?.impact?.algorithm_siblings?.length ?? 0)}
                  detail="share same algorithm"
                />
              </div>

              {impactQuery.data?.impact?.certificates?.length ? (
                <div className="space-y-1">
                  <span className="font-semibold text-foreground">Associated Certificates:</span>
                  <ul className="list-disc pl-4 text-muted-foreground font-mono text-[11px]">
                    {impactQuery.data.impact.certificates.map((c, i) => (
                      <li key={i}>{c}</li>
                    ))}
                  </ul>
                </div>
              ) : null}
            </CardContent>
          </Card>
        </TabsContent>

        {/* Tab 6: Graph */}
        <TabsContent value="graph" className="space-y-4">
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="flex items-center gap-2 text-base">
                <Network className="size-4 text-primary" />
                Dependency Neighbourhood Graph
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-3 text-xs">
              {graphQuery.isPending ? (
                <PanelSkeleton lines={4} />
              ) : graphQuery.data?.graph ? (
                <div className="space-y-3">
                  <div className="flex gap-4 font-mono text-xs">
                    <span>Nodes: {graphQuery.data.graph.nodes?.length ?? 0}</span>
                    <span>Edges: {graphQuery.data.graph.edges?.length ?? 0}</span>
                    <span>Centrality: {graphQuery.data.dependency_centrality_score ?? 0}</span>
                  </div>

                  <div className="max-h-80 overflow-y-auto divide-y rounded border">
                    {graphQuery.data.graph.nodes?.map((node, i) => (
                      <div key={i} className="flex items-center justify-between p-2">
                        <div className="flex items-center gap-2">
                          <Badge variant="outline" className="text-[10px]">
                            {node.type}
                          </Badge>
                          <span className="font-medium text-foreground">{node.label}</span>
                        </div>
                        <span className="font-mono text-[10px] text-muted-foreground">{node.id}</span>
                      </div>
                    ))}
                  </div>
                </div>
              ) : (
                <p className="text-muted-foreground">No graph data available for this asset.</p>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </PageShell>
  );
}

function Row({
  label,
  value,
  mono = false,
}: {
  label: string;
  value: string | number | null | undefined;
  mono?: boolean;
}) {
  if (value === null || value === undefined || value === "") return null;
  return (
    <div className="flex min-w-0 items-baseline justify-between gap-3 border-b border-muted/50 pb-1.5 last:border-0 last:pb-0">
      <span className="text-muted-foreground shrink-0">{label}</span>
      <span className={mono ? "font-mono text-[11px] truncate text-foreground" : "truncate font-medium text-foreground"}>
        {value}
      </span>
    </div>
  );
}

function StatBox({
  label,
  value,
  detail,
}: {
  label: string;
  value: string;
  detail: string;
}) {
  return (
    <div className="rounded-md border p-3">
      <span className="text-[10px] font-semibold uppercase text-muted-foreground">{label}</span>
      <div className="ecdat-numeric mt-1 text-2xl font-bold text-foreground">{value}</div>
      <span className="text-[10px] text-muted-foreground">{detail}</span>
    </div>
  );
}
