/**
 * Top bar: search, estate identity, scan status, notices, theme, operator menu.
 *
 * Everything here is read from the API. The estate name, scan id and timestamp
 * come from `GET /dashboard`; liveness and whether a scan is loaded come from
 * `GET /health`. Nothing is invented -- when there is no scan, the bar says so
 * rather than showing a reassuring placeholder.
 */

"use client";

import Link from "next/link";
import {
  Bell,
  ChevronDown,
  CircleDot,
  Command as CommandIcon,
  Radar,
  Search,
  TriangleAlert,
  UserRound,
} from "lucide-react";

import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover";
import { Separator } from "@/components/ui/separator";
import { SidebarTrigger } from "@/components/ui/sidebar";
import { Skeleton } from "@/components/ui/skeleton";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { Breadcrumbs } from "@/components/shell/breadcrumbs";
import { ThemeToggle } from "@/components/shell/theme-toggle";
import { API_BASE } from "@/lib/api-client";
import { formatDateTime } from "@/lib/display";
import { useDashboard, useHealth } from "@/lib/queries";

/** Live indicator for the API process and whether a scan result is loaded. */
function ScanStatus() {
  const { data: health, isPending, error } = useHealth();
  const { data: dashboard } = useDashboard();

  if (isPending) return <Skeleton className="h-6 w-32" />;

  const offline = Boolean(error) || !health;
  const loaded = health?.scan_loaded ?? false;
  const color = offline
    ? "var(--risk-critical)"
    : loaded
      ? "var(--success)"
      : "var(--warning)";
  const label = offline ? "API offline" : loaded ? "Scan loaded" : "No scan";

  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span
          className="inline-flex h-6 shrink-0 items-center gap-1.5 rounded-md border px-2 text-[11px] font-medium"
          style={{
            color,
            borderColor: `color-mix(in oklab, ${color} 30%, transparent)`,
            backgroundColor: `color-mix(in oklab, ${color} 10%, transparent)`,
          }}
        >
          <CircleDot className="size-3" />
          {label}
        </span>
      </TooltipTrigger>
      <TooltipContent className="max-w-72">
        <div className="space-y-1 text-xs">
          <p className="font-mono text-[11px] opacity-80">{API_BASE}</p>
          {offline ? (
            <p>The ECDAT API is not responding. Start it with `python -m ecdat.api`.</p>
          ) : loaded ? (
            <>
              <p>
                Scan{" "}
                <span className="font-mono">{dashboard?.estate.scan_id ?? "—"}</span>
              </p>
              <p>{formatDateTime(dashboard?.estate.scanned_at)}</p>
            </>
          ) : (
            <p>The API is running but no scan result is loaded yet.</p>
          )}
        </div>
      </TooltipContent>
    </Tooltip>
  );
}

/** The estate currently under analysis, named by the backend, not the UI. */
function ActiveEstate() {
  const { data, isPending, error } = useDashboard();

  if (isPending) return <Skeleton className="h-6 w-40" />;
  if (error || !data) return null;

  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span className="text-muted-foreground hidden max-w-[18rem] items-center gap-1.5 truncate text-xs lg:inline-flex">
          <Radar className="size-3.5 shrink-0" />
          <span className="truncate font-medium">{data.estate.target}</span>
          <span className="ecdat-numeric shrink-0 opacity-70">
            · {data.estate.assets} assets
          </span>
        </span>
      </TooltipTrigger>
      <TooltipContent className="max-w-80">
        <div className="space-y-1 text-xs">
          <p className="font-medium">Active estate</p>
          <p className="opacity-80">{data.estate.target}</p>
          <p className="opacity-80">
            {data.estate.applications} applications · policy{" "}
            <span className="font-mono">{data.estate.policy}</span>
          </p>
        </div>
      </TooltipContent>
    </Tooltip>
  );
}

/**
 * Notices, not "alerts". Every entry is something the backend actually
 * reported: the scan's own methodology notes and its business-context
 * defaulting count. No invented activity feed.
 */
function Notices() {
  const { data } = useDashboard();
  const notes = data?.notes ?? [];
  const defaulted = data?.estate.business_context_defaulted ?? 0;
  const count = notes.length + (defaulted > 0 ? 1 : 0);

  return (
    <Popover>
      <PopoverTrigger asChild>
        <Button variant="ghost" size="icon" className="relative size-8" aria-label="Scan notices">
          <Bell className="size-4" />
          {count > 0 ? (
            <span
              aria-hidden
              className="absolute top-1.5 right-1.5 size-1.5 rounded-full"
              style={{ backgroundColor: "var(--warning)" }}
            />
          ) : null}
        </Button>
      </PopoverTrigger>
      <PopoverContent align="end" className="w-96 p-0">
        <div className="border-b px-3 py-2">
          <p className="text-sm font-semibold">Scan notices</p>
          <p className="text-muted-foreground text-[11px]">
            Reported by the analysis backend for this scan.
          </p>
        </div>
        <div className="ecdat-scrollbar max-h-72 space-y-2 overflow-y-auto p-3">
          {count === 0 ? (
            <p className="text-muted-foreground py-4 text-center text-xs">
              No notices for this scan.
            </p>
          ) : null}
          {defaulted > 0 ? (
            <div className="flex gap-2">
              <TriangleAlert
                className="mt-0.5 size-3.5 shrink-0"
                style={{ color: "var(--warning)" }}
              />
              <p className="text-xs leading-relaxed">
                <span className="font-medium">{defaulted} assets</span> use defaulted
                business context. {data?.estate.business_context_note}
              </p>
            </div>
          ) : null}
          {notes.map((note) => (
            <div key={note} className="flex gap-2">
              <CircleDot className="text-muted-foreground mt-0.5 size-3.5 shrink-0" />
              <p className="text-muted-foreground text-xs leading-relaxed">{note}</p>
            </div>
          ))}
        </div>
      </PopoverContent>
    </Popover>
  );
}

/**
 * Operator menu. ECDAT is a single-user local deployment with no authentication
 * layer, and the menu says exactly that rather than implying an account system
 * that does not exist.
 */
function OperatorMenu() {
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="ghost" size="sm" className="h-8 gap-1.5 px-1.5">
          <span className="bg-muted text-muted-foreground flex size-6 items-center justify-center rounded-md">
            <UserRound className="size-3.5" />
          </span>
          <span className="hidden text-xs font-medium md:inline">Local operator</span>
          <ChevronDown className="size-3.5 opacity-60" />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-72">
        <DropdownMenuLabel className="space-y-1">
          <p className="text-sm">Local operator</p>
          <p className="text-muted-foreground text-[11px] font-normal leading-relaxed">
            ECDAT runs locally with no authentication layer and no account system.
            Analysis never leaves this machine.
          </p>
        </DropdownMenuLabel>
        <DropdownMenuSeparator />
        <DropdownMenuLabel className="text-muted-foreground text-[11px] font-normal">
          Keyboard
        </DropdownMenuLabel>
        <DropdownMenuItem disabled className="justify-between text-xs opacity-100">
          Command palette
          <kbd className="bg-muted rounded px-1.5 py-0.5 font-mono text-[10px]">⌘K</kbd>
        </DropdownMenuItem>
        <DropdownMenuItem disabled className="justify-between text-xs opacity-100">
          Toggle sidebar
          <kbd className="bg-muted rounded px-1.5 py-0.5 font-mono text-[10px]">⌘B</kbd>
        </DropdownMenuItem>
        <DropdownMenuSeparator />
        <DropdownMenuItem asChild>
          <Link href="/settings" className="text-xs">
            Settings
          </Link>
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

export function Topbar({ onOpenSearch }: { onOpenSearch: () => void }) {
  return (
    <header className="bg-background/85 supports-[backdrop-filter]:bg-background/70 sticky top-0 z-30 flex h-14 shrink-0 items-center gap-2 border-b px-3 backdrop-blur">
      <SidebarTrigger className="size-8" />
      <Separator orientation="vertical" className="mr-1 !h-5" />
      <div className="min-w-0 flex-1">
        <Breadcrumbs />
      </div>

      <div className="flex shrink-0 items-center gap-1.5">
        <ActiveEstate />

        {/* Search is a palette trigger, not a second input: one search surface
            for the whole product keeps the vocabulary consistent. */}
        <Button
          variant="outline"
          size="sm"
          onClick={onOpenSearch}
          className="text-muted-foreground h-8 gap-2 px-2 font-normal sm:w-56 sm:justify-start"
        >
          <Search className="size-3.5" />
          <span className="hidden text-xs sm:inline">Search estate…</span>
          <kbd className="bg-muted ml-auto hidden items-center gap-0.5 rounded px-1.5 py-0.5 font-mono text-[10px] sm:inline-flex">
            <CommandIcon className="size-2.5" />K
          </kbd>
        </Button>

        <ScanStatus />
        <Notices />
        <ThemeToggle />
        <Separator orientation="vertical" className="mx-0.5 !h-5" />
        <OperatorMenu />
      </div>
    </header>
  );
}
