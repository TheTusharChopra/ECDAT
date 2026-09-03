/**
 * The scan control: the one card on the page that executes real work.
 *
 * Three states, each honest about what the backend is actually doing:
 *
 *  - READY      no scan in this process yet, or the operator wants another run.
 *  - RUNNING    `POST /scan` is in flight. Synchronous, so there is nothing to
 *               poll and no percentage to invent (§3, §23).
 *  - COMPLETE   the response landed. Every value shown comes from it.
 *
 * The mutation lives in `useScan()` (`src/lib/queries.ts`), which calls the
 * shared API client and invalidates every dependent query on success. No
 * `fetch()` here (§6).
 */

"use client";

import Link from "next/link";
import {
  ArrowRight,
  CheckCircle2,
  Download,
  FileJson,
  Loader2,
  Play,
  RefreshCw,
  Route,
  ShieldAlert,
  Table2,
  Target,
} from "lucide-react";

import { exportUrl } from "@/lib/api-client";
import { formatDateTime, formatDuration, formatNumber } from "@/lib/display";
import { cn } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Separator } from "@/components/ui/separator";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { Field, FieldGrid } from "@/components/ecdat/layout";
import { PipelineStages, type PipelinePhase } from "@/features/scan/pipeline";
import type { ScanResult } from "@/types/api";

export function ScanControl({
  phase,
  scan,
  onRun,
  running,
  scanLoaded,
  topAssetId,
  targetName = "Demo Enterprise",
  policyName = "NIST General",
  runLabel = "Run demo scan",
}: {
  phase: PipelinePhase;
  /** The `POST /scan` response for this session, once there is one. */
  scan: ScanResult | undefined;
  onRun: () => void;
  running: boolean;
  /** `health.scan_loaded`: the server holds a scan, even if this tab did not run it. */
  scanLoaded: boolean;
  /** Highest-priority asset from `GET /assets`, for the completion action. */
  topAssetId: string | undefined;
  targetName?: string;
  policyName?: string;
  runLabel?: string;
}) {
  return (
    <Card className="min-w-0 gap-0 overflow-hidden py-0">
      {/* Accent rail: indigo while working, green once the analysis landed. */}
      <div
        aria-hidden
        className={cn(
          "h-0.5 w-full transition-colors",
          phase === "complete"
            ? "bg-success"
            : phase === "running"
              ? "bg-primary"
              : "bg-border",
        )}
      />
      <CardContent className="min-w-0 space-y-4 p-4 sm:p-5">
        {phase === "complete" && scan ? (
          <CompleteHeader scan={scan} onRun={onRun} running={running} />
        ) : phase === "running" ? (
          <RunningHeader />
        ) : (
          <ReadyHeader
            onRun={onRun}
            running={running}
            scanLoaded={scanLoaded}
            targetName={targetName}
            policyName={policyName}
            runLabel={runLabel}
          />
        )}

        <Separator />
        <PipelineStages phase={phase} />

        {phase === "complete" && scan ? (
          <CompleteActions scan={scan} topAssetId={topAssetId} />
        ) : null}
      </CardContent>
    </Card>
  );
}

// ---------------------------------------------------------------------------
// Ready
// ---------------------------------------------------------------------------

function ReadyHeader({
  onRun,
  running,
  scanLoaded,
  targetName,
  policyName,
  runLabel,
}: {
  onRun: () => void;
  running: boolean;
  scanLoaded: boolean;
  targetName: string;
  policyName: string;
  runLabel: string;
}) {
  return (
    <div className="flex min-w-0 flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
      <div className="min-w-0 space-y-1.5">
        <p className="text-base font-semibold tracking-tight">
          Ready to analyze your enterprise cryptographic estate.
        </p>
        <p className="text-muted-foreground max-w-2xl text-xs leading-relaxed">
          One synchronous run walks the target estate end to end: discovery through
          migration decisions, impact and roadmap. Nothing is precomputed — the numbers
          on this page appear because the scan produced them.
        </p>
        <div className="flex flex-wrap items-center gap-x-5 gap-y-2 pt-1">
          <Meta icon={Target} label="Target" value={targetName} />
          <Meta icon={ShieldAlert} label="Policy" value={policyName} />
          {scanLoaded ? (
            <span className="text-muted-foreground text-[11px]">
              A scan is already loaded on the server. Running again replaces it.
            </span>
          ) : null}
        </div>
      </div>
      <RunButton onRun={onRun} running={running} label={runLabel} />
    </div>
  );
}

function Meta({
  icon: Icon,
  label,
  value,
}: {
  icon: typeof Target;
  label: string;
  value: string;
}) {
  return (
    <span className="flex min-w-0 items-center gap-1.5 text-xs">
      <Icon aria-hidden className="text-muted-foreground size-3.5 shrink-0" />
      <span className="text-muted-foreground">{label}</span>
      <span className="truncate font-medium">{value}</span>
    </span>
  );
}

function RunButton({
  onRun,
  running,
  label,
  variant = "default",
  size = "lg",
}: {
  onRun: () => void;
  running: boolean;
  label: string;
  variant?: "default" | "outline";
  size?: "lg" | "sm";
}) {
  return (
    <Button
      type="button"
      size={size}
      variant={variant}
      // Guarding the click is the point: the backend answers a concurrent scan
      // with 409 rather than queueing it, so a double-click is a wasted error.
      disabled={running}
      onClick={onRun}
      className="shrink-0 gap-2"
    >
      {running ? (
        <>
          <Loader2 aria-hidden className="size-4 animate-spin" />
          Scanning…
        </>
      ) : (
        <>
          {size === "lg" ? (
            <Play aria-hidden className="size-4" />
          ) : (
            <RefreshCw aria-hidden className="size-3.5" />
          )}
          {label}
        </>
      )}
    </Button>
  );
}

// ---------------------------------------------------------------------------
// Running
// ---------------------------------------------------------------------------

function RunningHeader() {
  return (
    <div className="flex min-w-0 flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
      <div className="flex min-w-0 items-center gap-3">
        <span
          aria-hidden
          className="bg-primary/12 text-primary grid size-9 shrink-0 place-items-center rounded-lg"
        >
          <Loader2 className="size-5 animate-spin" />
        </span>
        <div className="min-w-0 space-y-0.5">
          <p
            className="text-base font-semibold tracking-tight"
            role="status"
            aria-live="polite"
          >
            Running cryptographic discovery…
          </p>
          <p className="text-muted-foreground text-xs">
            The API call is synchronous and returns once the whole pipeline has
            finished.
          </p>
        </div>
      </div>
      <Badge variant="outline" className="w-fit shrink-0 gap-1.5 font-normal">
        <span
          aria-hidden
          className="bg-primary size-1.5 animate-pulse rounded-full"
        />
        POST /scan in flight
      </Badge>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Complete
// ---------------------------------------------------------------------------

function CompleteHeader({
  scan,
  onRun,
  running,
}: {
  scan: ScanResult;
  onRun: () => void;
  running: boolean;
}) {
  const targets = scan.target ? scan.target.split(",").map((t) => t.trim()) : [];

  return (
    <div className="min-w-0 space-y-4">
      <div className="flex min-w-0 flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
        <div className="flex min-w-0 items-center gap-3">
          <span
            aria-hidden
            className="bg-success/12 text-success grid size-9 shrink-0 place-items-center rounded-lg"
          >
            <CheckCircle2 className="size-5" />
          </span>
          <div className="min-w-0 space-y-0.5">
            <p className="text-success text-base font-semibold tracking-tight">
              Analysis complete
            </p>
            <p className="text-muted-foreground text-xs">
              {/*
                Quoted from the response's own terminal progress event, so the
                completion claim is the engine's rather than the UI's.
              */}
              Engine reported{" "}
              <span className="font-medium">{scan.progress?.detail ?? "pipeline finished"}</span>
              .
            </p>
          </div>
        </div>
        <RunButton onRun={onRun} running={running} label="Re-run scan" variant="outline" size="sm" />
      </div>

      <FieldGrid columns={4}>
        <Field label="Scan ID" value={scan.scan_id} mono />
        <Field label="Policy" value={scan.policy} />
        <Field label="Completed at" value={formatDateTime(scan.started_at)} />
        <Field
          label="Duration"
          value={formatDuration(scan.stats?.duration_ms)}
          hint="Engine pipeline time, as reported by the scan."
        />
      </FieldGrid>

      {targets.length > 0 ? (
        <div className="flex min-w-0 flex-wrap items-center gap-1.5">
          <span className="text-muted-foreground text-[11px] font-medium tracking-wide uppercase">
            Targets
          </span>
          {targets.map((target) => (
            <Tooltip key={target}>
              <TooltipTrigger asChild>
                <Badge
                  variant="secondary"
                  className="max-w-[16rem] cursor-help font-mono text-[11px] font-normal"
                >
                  <span className="truncate">{target}</span>
                </Badge>
              </TooltipTrigger>
              <TooltipContent className="font-mono text-xs">{target}</TooltipContent>
            </Tooltip>
          ))}
        </div>
      ) : null}
    </div>
  );
}

function CompleteActions({
  scan,
  topAssetId,
}: {
  scan: ScanResult;
  topAssetId: string | undefined;
}) {
  return (
    <>
      <Separator />
      <div className="flex min-w-0 flex-wrap items-center gap-2">
        <Button asChild size="sm" variant="outline" className="gap-1.5">
          <Link href="/inventory">
            <Table2 aria-hidden className="size-3.5" />
            View inventory
            <span className="text-muted-foreground ecdat-numeric">
              {formatNumber(scan.assets)}
            </span>
          </Link>
        </Button>

        {topAssetId ? (
          <Button asChild size="sm" variant="outline" className="gap-1.5">
            <Link href={`/assets/${topAssetId}`}>
              <ArrowRight aria-hidden className="size-3.5" />
              Open priority asset
            </Link>
          </Button>
        ) : null}

        <Button asChild size="sm" variant="outline" className="gap-1.5">
          <Link href="/roadmap">
            <Route aria-hidden className="size-3.5" />
            View roadmap
          </Link>
        </Button>

        {/*
          Both exports point at real endpoints. The CBOM link carries the
          component count from the response and the validation scope as its
          tooltip -- the sentence that bounds the claim travels with it (§16).
        */}
        <Tooltip>
          <TooltipTrigger asChild>
            <Button asChild size="sm" variant="outline" className="gap-1.5">
              <a href={exportUrl("json")} target="_blank" rel="noopener noreferrer">
                <FileJson aria-hidden className="size-3.5" />
                Export CBOM
                {scan.cbom ? (
                  <span className="text-muted-foreground ecdat-numeric">
                    {formatNumber(scan.cbom.components)}
                  </span>
                ) : null}
              </a>
            </Button>
          </TooltipTrigger>
          <TooltipContent className="max-w-80 text-xs leading-relaxed">
            {scan.cbom?.validation_scope ??
              "CycloneDX 1.6 CBOM export from GET /exports/json."}
          </TooltipContent>
        </Tooltip>

        <Button asChild size="sm" variant="ghost" className="gap-1.5">
          <a href={exportUrl("assets.csv")} target="_blank" rel="noopener noreferrer">
            <Download aria-hidden className="size-3.5" />
            Assets CSV
          </a>
        </Button>
      </div>
    </>
  );
}
