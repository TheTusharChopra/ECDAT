/**
 * What the scan reported about itself (§7, §8).
 *
 * Two panels, both fed exclusively by the `POST /scan` response held in this
 * page's state. Every figure is a read of a named field; none is derived.
 *
 * Presentational arithmetic is allowed and used once: `files_analyzed` out of
 * `files_seen`, and `deduplicated` out of `raw_detections`, are stated as the
 * ratio of two returned counters. Both are labelled as exactly that. No
 * "coverage score" is synthesised from them (§8).
 *
 * A field the backend did not return is reported as unavailable rather than
 * filled in. That is the whole point of `Metric` taking `number | undefined`.
 */

"use client";

import {
  Binary,
  Boxes,
  FileCode2,
  FileStack,
  FolderGit2,
  Layers,
  Package,
  ScrollText,
  Settings2,
  ShieldCheck,
  Sigma,
  Timer,
  TriangleAlert,
  type LucideIcon,
} from "lucide-react";

import {
  formatBytes,
  formatDuration,
  formatNumber,
  formatPercent,
} from "@/lib/display";
import { cn } from "@/lib/utils";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { MethodNote, Section } from "@/components/ecdat/layout";
import type { ScanResult } from "@/types/api";

/** A single reported counter. `undefined` means the API did not report it. */
function Metric({
  label,
  value,
  icon: Icon,
  hint,
  detail,
  accent,
}: {
  label: string;
  value: number | string | undefined;
  icon: LucideIcon;
  /** What the counter counts, in the backend's terms. */
  hint: string;
  /** Presentational ratio or unit note. Never a derived conclusion. */
  detail?: string;
  accent?: string;
}) {
  const missing = value === undefined || value === null;
  const shown = typeof value === "number" ? formatNumber(value) : value;

  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <div className="bg-card flex min-w-0 cursor-help flex-col gap-1.5 rounded-lg border p-3">
          <div className="flex items-center justify-between gap-2">
            <span className="text-muted-foreground min-w-0 truncate text-[10.5px] font-medium tracking-wide uppercase">
              {label}
            </span>
            <Icon
              aria-hidden
              className="size-3.5 shrink-0"
              style={{ color: accent ?? "var(--muted-foreground)" }}
            />
          </div>
          {missing ? (
            <span className="text-muted-foreground text-sm">Not available</span>
          ) : (
            <div className="flex items-baseline gap-1.5">
              <span className="ecdat-numeric text-xl leading-none font-semibold tracking-tight">
                {shown}
              </span>
              {detail ? (
                <span className="text-muted-foreground truncate text-[11px]">{detail}</span>
              ) : null}
            </div>
          )}
        </div>
      </TooltipTrigger>
      <TooltipContent className="max-w-72 text-xs leading-relaxed">
        {missing ? `${hint} This scan did not report the field.` : hint}
      </TooltipContent>
    </Tooltip>
  );
}

/**
 * The headline scan result (§7).
 *
 * `stats.certificates` is the number of certificate FILES the scan parsed. It is
 * deliberately not labelled "certificates in the estate" -- that is a different
 * number (`dashboard.asset_types.certificate`), and conflating the two would
 * make an input count read as an inventory count.
 */
export function ScanResultPanel({ scan }: { scan: ScanResult }) {
  const stats = scan.stats;

  return (
    <Section
      title="Scan result"
      description="Reported by this scan run."
      actions={
        <Badge variant="outline" className="gap-1.5 font-mono text-[11px] font-normal">
          {scan.scan_id}
        </Badge>
      }
      help="Every figure here is a field of the POST /scan response body. The frontend does not compute any of them."
      contentClassName="space-y-3"
    >
      <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
        <Metric
          label="Cryptographic assets"
          value={scan.assets}
          icon={ShieldCheck}
          accent="var(--primary)"
          hint="Canonical cryptographic assets built by the pipeline: one per real cryptographic thing, after evidence correlation."
        />
        <Metric
          label="Applications"
          value={scan.applications}
          icon={Boxes}
          accent="var(--chart-2)"
          hint="Applications the estate declares business context for. Operator-declared, not discovered."
        />
        <Metric
          label="Repositories"
          value={stats?.repositories}
          icon={FolderGit2}
          hint="Source repositories walked by the discovery stage."
        />
        <Metric
          label="Files analyzed"
          value={stats?.files_analyzed}
          icon={FileCode2}
          detail={
            stats?.files_seen
              ? `of ${formatNumber(stats.files_seen)} seen`
              : undefined
          }
          hint="Files the detectors actually parsed, against the number discovery walked past. Both counters are the scan's own."
        />
        <Metric
          label="Raw detections"
          value={stats?.raw_detections}
          icon={Sigma}
          accent="var(--chart-4)"
          hint="Individual detector hits before correlation. Several detections can describe the same asset."
        />
        <Metric
          label="Deduplicated"
          value={stats?.deduplicated}
          icon={Layers}
          accent="var(--chart-3)"
          detail={
            stats?.raw_detections
              ? `${formatPercent(stats.deduplicated, stats.raw_detections)} of raw`
              : undefined
          }
          hint="Detections merged away during evidence correlation, expressed against raw detections. Both counters are returned by the scan; the percentage is only their ratio."
        />
        <Metric
          label="Certificate files"
          value={stats?.certificates}
          icon={ScrollText}
          hint="X.509 files the certificate detector parsed. This is an input count, not the number of certificate assets in the inventory."
        />
        <Metric
          label="Scan duration"
          value={stats?.duration_ms === undefined ? undefined : formatDuration(stats.duration_ms)}
          icon={Timer}
          hint="Wall-clock pipeline time reported by the engine, in milliseconds."
        />
      </div>

      {scan.notes?.length ? (
        <div className="space-y-1.5">
          {scan.notes.map((note) => (
            <MethodNote key={note}>{note}</MethodNote>
          ))}
        </div>
      ) : null}
    </Section>
  );
}

/**
 * Coverage: what discovery reached, and what it did not (§8).
 *
 * Skipped files and errors are shown even when they are zero. A scan that
 * silently omits them reads as though nothing was skipped, which is a stronger
 * claim than the data supports.
 */
export function ScanCoveragePanel({ scan }: { scan: ScanResult }) {
  const stats = scan.stats;
  const errors = stats?.errors ?? [];

  return (
    <Section
      title="Scan coverage"
      description="What discovery reached in this run."
      help="These counters exist only on the scan response. No GET endpoint republishes them, so they describe this run rather than a persisted state."
      contentClassName="space-y-3"
    >
      <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
        <Metric
          label="Files seen"
          value={stats?.files_seen}
          icon={FileStack}
          hint="Files discovery walked past, including ones no detector claimed."
        />
        <Metric
          label="Bytes analyzed"
          value={stats?.bytes_analyzed === undefined ? undefined : formatBytes(stats.bytes_analyzed)}
          icon={FileCode2}
          hint="Total volume the detectors read."
        />
        <Metric
          label="Containers"
          value={stats?.containers}
          icon={Boxes}
          hint="Container definitions and image manifests inspected."
        />
        <Metric
          label="Binaries"
          value={stats?.binaries}
          icon={Binary}
          hint="Compiled artefacts inspected by the binary-format detector."
        />
        <Metric
          label="Dependencies"
          value={stats?.dependencies}
          icon={Package}
          hint="Declared dependencies read from manifests."
        />
        <Metric
          label="Manifests"
          value={stats?.manifests}
          icon={ScrollText}
          hint="Dependency manifests parsed."
        />
        <Metric
          label="Config files"
          value={stats?.configs}
          icon={Settings2}
          hint="Configuration files parsed by the config-semantic detector."
        />
        <Metric
          label="Files skipped"
          value={stats?.skipped_files}
          icon={TriangleAlert}
          accent={stats?.skipped_files ? "var(--warning)" : undefined}
          hint="Files discovery declined to parse: unreadable, over the size limit, or an unsupported type."
        />
      </div>

      {stats?.detector_counts ? (
        <DetectorBreakdown counts={stats.detector_counts} />
      ) : null}

      {errors.length > 0 ? (
        <Alert variant="destructive">
          <TriangleAlert />
          <AlertTitle>
            {formatNumber(errors.length)} scan error
            {errors.length === 1 ? "" : "s"} reported
          </AlertTitle>
          <AlertDescription>
            <ul className="list-disc space-y-0.5 pl-4">
              {errors.slice(0, 6).map((error) => (
                <li key={error} className="font-mono text-[11px] break-all">
                  {error}
                </li>
              ))}
            </ul>
            {errors.length > 6 ? (
              <p className="text-[11px]">
                {formatNumber(errors.length - 6)} further error
                {errors.length - 6 === 1 ? "" : "s"} not listed.
              </p>
            ) : null}
          </AlertDescription>
        </Alert>
      ) : (
        <p className="text-muted-foreground text-[11px] leading-relaxed">
          The scan reported no errors. Skipped files, if any, are counted above rather
          than treated as failures.
        </p>
      )}
    </Section>
  );
}

/**
 * Which detectors produced the findings.
 *
 * Worth showing because it is the clearest evidence that detection is
 * deterministic and multi-modal: seven named analysers, each with its own count.
 * Sorted by count purely for readability.
 */
function DetectorBreakdown({ counts }: { counts: Record<string, number> }) {
  const entries = Object.entries(counts).sort((a, b) => b[1] - a[1]);
  if (entries.length === 0) return null;
  const total = entries.reduce((sum, [, count]) => sum + count, 0);

  return (
    <div className="min-w-0 space-y-2 rounded-lg border p-3">
      <div className="flex items-baseline justify-between gap-2">
        <p className="text-[11px] font-medium tracking-wide uppercase">
          Detections by detector
        </p>
        <span className="text-muted-foreground ecdat-numeric text-[11px]">
          {formatNumber(total)} raw
        </span>
      </div>
      <div className="flex min-w-0 flex-wrap gap-1.5">
        {entries.map(([detector, count]) => (
          <span
            key={detector}
            className={cn(
              "bg-muted/50 inline-flex items-center gap-1.5 rounded-md border px-2 py-1",
              "text-[11px]",
            )}
          >
            <span className="font-mono">{detector}</span>
            <span className="ecdat-numeric text-muted-foreground">
              {formatNumber(count)}
            </span>
          </span>
        ))}
      </div>
      <p className="text-muted-foreground text-[11px] leading-relaxed">
        Each detector is a deterministic analyser. No language model participates in
        detection.
      </p>
    </div>
  );
}
