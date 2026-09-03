"use client";

import { useState } from "react";
import {
  FolderOpen,
  Sparkles,
} from "lucide-react";

import { PageHeader, PageShell } from "@/components/ecdat/layout";
import { useAssets, useDashboard, useHealth, useScan } from "@/lib/queries";
import { ScanControl } from "@/features/scan/scan-control";
import { ScanCoveragePanel, ScanResultPanel } from "@/features/scan/scan-result";
import {
  ConfidenceSummary,
  DecisionSnapshot,
  QuantumTaxonomySummary,
  RiskSnapshot,
  SecuritySnapshot,
} from "@/features/scan/snapshot";
import type { ScanRequest, ScanResult } from "@/types/api";
import type { PipelinePhase } from "@/features/scan/pipeline";
import { ErrorState } from "@/components/ecdat/states";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";

export default function ScanPage() {
  const health = useHealth();
  const dashboard = useDashboard();
  const topAssetQuery = useAssets({ limit: 1 });
  const scanMutation = useScan();

  const [lastScan, setLastScan] = useState<ScanResult | undefined>(undefined);
  const [scanMode, setScanMode] = useState<"demo" | "custom">("demo");
  const [customPath, setCustomPath] = useState<string>("/Users/tushar/ecdat/datasets/demo/repositories");
  const [selectedPolicy, setSelectedPolicy] = useState<string>("nist_general");
  const [crqcYear, setCrqcYear] = useState<number>(2035);

  const running = scanMutation.isPending;
  const phase: PipelinePhase = running
    ? "running"
    : lastScan
      ? "complete"
      : "idle";

  const handleRunScan = () => {
    const payload: ScanRequest =
      scanMode === "demo"
        ? { demo: true }
        : {
            targets: customPath
              .split(",")
              .map((p) => p.trim())
              .filter(Boolean),
            policy: selectedPolicy,
            crqc_year: Number(crqcYear),
          };

    scanMutation.mutate(payload, {
      onSuccess: (data) => {
        setLastScan(data);
      },
    });
  };

  const topAssetId = topAssetQuery.data?.assets[0]?.asset_id;

  return (
    <PageShell>
      <PageHeader
        title="Scan"
        question="Discover cryptography across a target estate."
        description="Run synchronous cryptographic discovery across repositories, certificates, configurations, and binaries. Target either the bundled demo enterprise estate or specify local folder paths."
      />

      {/* Target Configurator & Mode Selector */}
      <Card className="p-4 shadow-xs">
        <div className="space-y-4">
          <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between border-b pb-3">
            <div>
              <span className="text-xs font-semibold uppercase text-muted-foreground">Scan Target Selection</span>
              <h3 className="text-sm font-bold text-foreground mt-0.5">
                {scanMode === "demo"
                  ? "Bundled Demo Estate (12 Applications, Certs & Binaries)"
                  : "Custom Local File/Folder Targets"}
              </h3>
            </div>

            <div className="flex items-center gap-2">
              <Button
                type="button"
                variant={scanMode === "demo" ? "default" : "outline"}
                size="sm"
                className="text-xs"
                onClick={() => setScanMode("demo")}
              >
                <Sparkles className="mr-1.5 size-3.5" />
                Demo Dataset
              </Button>
              <Button
                type="button"
                variant={scanMode === "custom" ? "default" : "outline"}
                size="sm"
                className="text-xs"
                onClick={() => setScanMode("custom")}
              >
                <FolderOpen className="mr-1.5 size-3.5" />
                Custom Local Folder
              </Button>
            </div>
          </div>

          {scanMode === "custom" ? (
            <div className="space-y-4 pt-1">
              <div className="grid gap-4 sm:grid-cols-4">
                <div className="space-y-1.5 sm:col-span-2">
                  <Label htmlFor="custom-target-path" className="text-xs">
                    Local Target Folder Path(s)
                  </Label>
                  <Input
                    id="custom-target-path"
                    value={customPath}
                    onChange={(e) => setCustomPath(e.target.value)}
                    placeholder="/path/to/repo or ./datasets/demo/repositories"
                    className="font-mono text-xs"
                  />
                  <p className="text-[11px] text-muted-foreground">
                    Comma-separated directory paths accessible to the local backend.
                  </p>
                </div>

                <div className="space-y-1.5">
                  <Label htmlFor="scan-policy" className="text-xs">Policy Profile</Label>
                  <Select value={selectedPolicy} onValueChange={setSelectedPolicy}>
                    <SelectTrigger id="scan-policy" className="text-xs">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="nist_general">NIST General (2035)</SelectItem>
                      <SelectItem value="nsa_cnsa2">NSA CNSA 2.0 (2033)</SelectItem>
                      <SelectItem value="high_assurance_hybrid">High Assurance Hybrid (2030)</SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                <div className="space-y-1.5">
                  <Label htmlFor="scan-crqc-year" className="text-xs">CRQC Year</Label>
                  <Input
                    id="scan-crqc-year"
                    type="number"
                    min={2025}
                    max={2100}
                    value={crqcYear}
                    onChange={(e) => setCrqcYear(Number(e.target.value))}
                    className="font-mono text-xs"
                  />
                </div>
              </div>

              <div className="flex justify-end border-t pt-3">
                <Button
                  type="button"
                  onClick={handleRunScan}
                  disabled={running || !customPath.trim()}
                  className="gap-2"
                >
                  <FolderOpen className="size-4" />
                  {running ? "Scanning Custom Folders…" : "Start Custom Scan"}
                </Button>
              </div>
            </div>
          ) : (
            <div className="rounded-md bg-muted/40 p-3 text-xs text-muted-foreground flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
              <span>
                Includes <strong>12 enterprise codebases</strong> (Java, Python, Go, Node), <strong>14 X.509 certificates</strong>, Docker containers, and compiled binaries in <code>datasets/demo/</code>.
              </span>
              <Badge variant="outline" className="shrink-0 font-mono text-[10px]">
                Target: datasets/demo/
              </Badge>
            </div>
          )}
        </div>
      </Card>

      {scanMutation.isError ? (
        <ErrorState
          error={scanMutation.error}
          onRetry={handleRunScan}
          compact
        />
      ) : null}

      <ScanControl
        phase={phase}
        scan={lastScan}
        onRun={handleRunScan}
        running={running}
        scanLoaded={Boolean(health.data?.scan_loaded)}
        topAssetId={topAssetId}
        targetName={scanMode === "demo" ? "Demo Enterprise" : customPath || "Custom Local Folder"}
        policyName={
          selectedPolicy === "nist_general"
            ? "NIST General (2035)"
            : selectedPolicy === "nsa_cnsa2"
              ? "NSA CNSA 2.0 (2033)"
              : "High Assurance Hybrid (2030)"
        }
        runLabel={scanMode === "demo" ? "Run demo scan" : "Start discovery scan"}
      />

      {lastScan ? (
        <div className="grid min-w-0 gap-4 lg:grid-cols-2">
          <ScanResultPanel scan={lastScan} />
          <ScanCoveragePanel scan={lastScan} />
        </div>
      ) : null}

      {dashboard.data ? (
        <div className="space-y-6 pt-2">
          <SecuritySnapshot data={dashboard.data} />
          <DecisionSnapshot data={dashboard.data} />
          <RiskSnapshot data={dashboard.data} />
          <div className="grid min-w-0 gap-4 lg:grid-cols-2">
            <ConfidenceSummary data={dashboard.data} />
            <QuantumTaxonomySummary data={dashboard.data} />
          </div>
        </div>
      ) : null}
    </PageShell>
  );
}
