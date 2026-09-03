/**
 * Loading, empty and error states.
 *
 * §23: no screen may show a blank panel. Every data surface renders one of
 * these instead, and each one says what happened and what to do next.
 *
 * The error states distinguish three genuinely different situations, because
 * the fix differs: the API process is not running, no scan has been performed
 * yet (an expected first-run state, not a failure), or the request failed.
 */

"use client";

import type { ReactNode } from "react";
import Link from "next/link";
import {
  AlertTriangle,
  Inbox,
  PlugZap,
  RefreshCw,
  Radar,
  SearchX,
} from "lucide-react";

import { ApiError } from "@/lib/api-client";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";

// ---------------------------------------------------------------------------
// Skeletons
// ---------------------------------------------------------------------------

export function KpiSkeleton() {
  return (
    <Card className="gap-0 py-4">
      <CardContent className="space-y-3 px-4">
        <div className="flex items-center justify-between">
          <Skeleton className="h-3.5 w-24" />
          <Skeleton className="size-7 rounded-md" />
        </div>
        <Skeleton className="h-8 w-16" />
        <Skeleton className="h-3 w-32" />
      </CardContent>
    </Card>
  );
}

export function ChartSkeleton({ height = 240 }: { height?: number }) {
  return (
    <div className="space-y-3" style={{ minHeight: height }}>
      <div className="flex items-end gap-2" style={{ height: height - 32 }}>
        {[62, 88, 44, 74, 34, 56].map((pct, i) => (
          <Skeleton key={i} className="flex-1 rounded-sm" style={{ height: `${pct}%` }} />
        ))}
      </div>
      <div className="flex gap-2">
        <Skeleton className="h-3 w-16" />
        <Skeleton className="h-3 w-16" />
        <Skeleton className="h-3 w-16" />
      </div>
    </div>
  );
}

export function TableSkeleton({ rows = 8, columns = 6 }: { rows?: number; columns?: number }) {
  return (
    <div className="space-y-2" role="status" aria-label="Loading table">
      <div className="flex gap-3 border-b pb-2">
        {Array.from({ length: columns }).map((_, i) => (
          <Skeleton key={i} className="h-3.5 flex-1" />
        ))}
      </div>
      {Array.from({ length: rows }).map((_, r) => (
        <div key={r} className="flex gap-3 py-1.5">
          {Array.from({ length: columns }).map((_, c) => (
            <Skeleton key={c} className="h-4 flex-1" />
          ))}
        </div>
      ))}
    </div>
  );
}

export function PanelSkeleton({ lines = 4 }: { lines?: number }) {
  return (
    <div className="space-y-3" role="status" aria-label="Loading">
      <Skeleton className="h-4 w-40" />
      {Array.from({ length: lines }).map((_, i) => (
        <Skeleton key={i} className="h-3.5" style={{ width: `${100 - i * 9}%` }} />
      ))}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Message states
// ---------------------------------------------------------------------------

interface StateShellProps {
  icon: ReactNode;
  title: string;
  description?: ReactNode;
  action?: ReactNode;
  tone?: "neutral" | "warning" | "danger";
  className?: string;
  compact?: boolean;
}

function StateShell({
  icon,
  title,
  description,
  action,
  tone = "neutral",
  className,
  compact = false,
}: StateShellProps) {
  const color =
    tone === "danger"
      ? "var(--risk-critical)"
      : tone === "warning"
        ? "var(--warning)"
        : "var(--muted-foreground)";
  return (
    <div
      className={cn(
        "flex flex-col items-center justify-center text-center",
        compact ? "gap-2 px-4 py-8" : "gap-3 px-6 py-14",
        className,
      )}
      role="status"
    >
      <div
        aria-hidden
        className="flex size-10 items-center justify-center rounded-lg border"
        style={{
          color,
          borderColor: `color-mix(in oklab, ${color} 28%, transparent)`,
          backgroundColor: `color-mix(in oklab, ${color} 10%, transparent)`,
        }}
      >
        {icon}
      </div>
      <div className="space-y-1">
        <p className="text-sm font-semibold">{title}</p>
        {description ? (
          <p className="text-muted-foreground mx-auto max-w-md text-xs leading-relaxed">
            {description}
          </p>
        ) : null}
      </div>
      {action}
    </div>
  );
}

export function EmptyState({
  title = "Nothing to show",
  description,
  action,
  compact,
  className,
}: {
  title?: string;
  description?: ReactNode;
  action?: ReactNode;
  compact?: boolean;
  className?: string;
}) {
  return (
    <StateShell
      icon={<Inbox className="size-5" />}
      title={title}
      description={description}
      action={action}
      compact={compact}
      className={className}
    />
  );
}

export function NoResultsState({
  onClear,
  compact,
}: {
  onClear?: () => void;
  compact?: boolean;
}) {
  return (
    <StateShell
      icon={<SearchX className="size-5" />}
      title="No assets match these filters"
      description="The scan found assets, but none satisfy every active filter. Loosen one to widen the result set."
      compact={compact}
      action={
        onClear ? (
          <Button size="sm" variant="outline" onClick={onClear}>
            Clear all filters
          </Button>
        ) : null
      }
    />
  );
}

/**
 * No scan has been run. This is the expected state of a fresh backend, not an
 * error, and the only correct next action is to run a scan.
 */
export function NoScanState({ compact, action }: { compact?: boolean; action?: ReactNode }) {
  return (
    <StateShell
      icon={<Radar className="size-5" />}
      title="No scan has been run yet"
      description="ECDAT has no analytical result to show. Run a discovery scan to build the cryptographic inventory, then every screen fills in from that result."
      tone="warning"
      compact={compact}
      action={
        action ?? (
          <Button size="sm" asChild>
            <Link href="/scan">Run a scan</Link>
          </Button>
        )
      }
    />
  );
}

function OfflineState({ onRetry, compact }: { onRetry?: () => void; compact?: boolean }) {
  return (
    <StateShell
      icon={<PlugZap className="size-5" />}
      title="Cannot reach the ECDAT API"
      description={
        <>
          The backend is not responding. Start it with{" "}
          <code className="bg-muted rounded px-1 py-0.5 font-mono text-[11px]">
            python -m ecdat.api
          </code>{" "}
          from the <code className="font-mono text-[11px]">backend/</code> directory, then
          retry.
        </>
      }
      tone="danger"
      compact={compact}
      action={
        onRetry ? (
          <Button size="sm" variant="outline" onClick={onRetry}>
            <RefreshCw className="size-3.5" />
            Retry
          </Button>
        ) : null
      }
    />
  );
}

/**
 * The single error surface. Routes an `ApiError` to the state that matches what
 * actually went wrong; anything else falls through to a generic retry.
 */
export function ErrorState({
  error,
  onRetry,
  compact,
  noScanAction,
}: {
  error: unknown;
  onRetry?: () => void;
  compact?: boolean;
  /** Replaces the "Run a scan" link when the failure is specifically no-scan. */
  noScanAction?: ReactNode;
}) {
  if (error instanceof ApiError) {
    if (error.isOffline) return <OfflineState onRetry={onRetry} compact={compact} />;
    if (error.isNoScan) return <NoScanState compact={compact} action={noScanAction} />;
  }
  const message =
    error instanceof Error ? error.message : "An unexpected error occurred.";
  return (
    <StateShell
      icon={<AlertTriangle className="size-5" />}
      title="Could not load this view"
      description={message}
      tone="danger"
      compact={compact}
      action={
        onRetry ? (
          <Button size="sm" variant="outline" onClick={onRetry}>
            <RefreshCw className="size-3.5" />
            Retry
          </Button>
        ) : null
      }
    />
  );
}

/**
 * Convenience wrapper for the pending / error / empty / data cascade so screens
 * do not each re-derive it. `children` runs only with defined data.
 */
export function QueryState<T>({
  query,
  skeleton,
  empty,
  children,
}: {
  query: {
    data: T | undefined;
    isPending: boolean;
    error: unknown;
    refetch: () => void;
  };
  skeleton: ReactNode;
  empty?: ReactNode;
  children: (data: T) => ReactNode;
}) {
  if (query.isPending) return <>{skeleton}</>;
  if (query.error) return <ErrorState error={query.error} onRetry={() => query.refetch()} />;
  if (query.data === undefined) return <>{empty ?? <EmptyState />}</>;
  return <>{children(query.data)}</>;
}
