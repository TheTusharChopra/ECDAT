/**
 * The inventory screen.
 *
 * Requests, and nothing else:
 *   - `GET /assets` with the URL's filters, sort, limit and offset. This is the
 *     table. The projection is `summary` unless a full-only column is showing.
 *   - `GET /assets?limit=1000` (summary) purely to enumerate open-domain filter
 *     options -- application, owner, library, strategy and the three page-scoped
 *     dimensions. It is the same query key the overview already warms, so
 *     arriving from the dashboard costs nothing.
 *   - `GET /dashboard`, for filter-option counts. Those counts are backend
 *     aggregates over the estate; nothing on this screen counts anything itself.
 *
 * Every value in every cell came out of one of those responses.
 */

"use client";

import { useCallback, useMemo, useState } from "react";
import { ChevronLeft, ChevronRight, RefreshCw } from "lucide-react";

import { useAssets, useAssetsFull, useDashboard } from "@/lib/queries";
import { ApiError } from "@/lib/api-client";
import { formatNumber } from "@/lib/display";
import { PageHeader, PageShell } from "@/components/ecdat/layout";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import {
  EmptyState,
  ErrorState,
  NoResultsState,
  TableSkeleton,
} from "@/components/ecdat/states";
import { NoScanActions } from "@/components/ecdat/run-scan";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";

import { FilterBar } from "./filter-bar";
import { FILTER_BY_KEY } from "./filters";
import {
  DEFAULT_COLUMN_VISIBILITY,
  FULL_VIEW_COLUMNS,
  fullAssetToRow,
  inventoryColumns,
  type InventoryColumnMeta,
  type InventoryRow,
} from "./columns";
import { InventoryTable, applyPageSort } from "./inventory-table";
import { useInventoryState } from "./use-inventory-state";

/** Stable empty array, so an absent response does not churn identities. */
const NO_ROWS: readonly InventoryRow[] = [];

/**
 * The wide summary page that populates open-domain filter options. 1000 is the
 * API's maximum limit, so one request covers the whole demo estate; `matched`
 * on the table's own response is what reports the real total.
 */
const FACET_QUERY = { limit: 1000 } as const;

export function InventoryScreen() {
  const state = useInventoryState();
  const [columnVisibility, setColumnVisibility] = useState<Record<string, boolean>>(
    () => ({ ...DEFAULT_COLUMN_VISIBILITY }),
  );
  // v9 keeps only the selected ids in this map, so the value type is `true`,
  // never `false`.
  const [rowSelection, setRowSelection] = useState<Record<string, true>>({});

  // Only two columns live outside the summary projection. Asking for the full
  // view costs roughly ten times the payload, so it happens when one of them is
  // actually on screen and not before (§4).
  const needsFullView = FULL_VIEW_COLUMNS.some((id) => columnVisibility[id] !== false);

  const summary = useAssets(state.serverQuery, !needsFullView);
  const full = useAssetsFull(state.serverQuery, needsFullView);
  const list = needsFullView ? full : summary;

  const facets = useAssets(FACET_QUERY);
  const dashboard = useDashboard();

  const rows: readonly InventoryRow[] = useMemo(() => {
    if (needsFullView) {
      return full.data ? full.data.assets.map(fullAssetToRow) : NO_ROWS;
    }
    return summary.data ? summary.data.assets : NO_ROWS;
  }, [needsFullView, full.data, summary.data]);

  // Page-scoped narrowing, for the three dimensions the API has no parameter
  // for. It can only ever remove rows the API already returned.
  const clientFiltered = useMemo(() => {
    const entries = Object.entries(state.clientFilters);
    if (entries.length === 0) return rows;
    return rows.filter((row) =>
      entries.every(([key, wanted]) => {
        const filter = FILTER_BY_KEY[key];
        if (!filter) return true;
        const actual = row[filter.field as keyof InventoryRow];
        if (actual === null || actual === undefined) return false;
        // Same comparison the API uses: case-insensitive equality on the
        // canonical value, never a re-derivation of it.
        return String(actual).toLowerCase() === wanted.toLowerCase();
      }),
    );
  }, [rows, state.clientFilters]);

  const visible = useMemo(
    () => applyPageSort(clientFiltered, state.pageSort),
    [clientFiltered, state.pageSort],
  );

  const columnToggles = useMemo(
    () =>
      inventoryColumns
        .filter((column) => column.id !== "select")
        .map((column) => {
          const id = String(column.id);
          return {
            id,
            meta: column.meta as InventoryColumnMeta | undefined,
            isVisible: columnVisibility[id] !== false,
            canHide: column.enableHiding !== false,
            toggle: () =>
              setColumnVisibility((current) => ({
                ...current,
                [id]: current[id] === false,
              })),
          };
        }),
    [columnVisibility],
  );

  const resetColumns = useCallback(
    () => setColumnVisibility({ ...DEFAULT_COLUMN_VISIBILITY }),
    [],
  );

  const refresh = useCallback(() => {
    void list.refetch();
    void dashboard.refetch();
    void facets.refetch();
  }, [list, dashboard, facets]);

  const noScan = list.error instanceof ApiError && list.error.isNoScan;

  if (list.error) {
    return (
      <PageShell>
        <InventoryHeader onRefresh={refresh} isFetching={false} />
        <Card>
          <CardContent>
            <ErrorState
              error={list.error}
              onRetry={noScan ? undefined : refresh}
              noScanAction={<NoScanActions />}
            />
          </CardContent>
        </Card>
      </PageShell>
    );
  }

  const response = list.data;
  const selectedCount = Object.keys(rowSelection).length;

  return (
    <PageShell>
      <InventoryHeader onRefresh={refresh} isFetching={list.isFetching} />

      <div className="flex min-w-0 flex-col gap-3">
        <FilterBar
          state={state}
          dashboard={dashboard.data}
          facetAssets={facets.data?.assets}
          columns={columnToggles}
          onResetColumns={resetColumns}
        />

        <ResultCount
          matched={response?.matched}
          total={response?.total}
          offset={state.offset}
          shown={visible.length}
          pageCount={rows.length}
          clientFilterCount={Object.keys(state.clientFilters).length}
          view={needsFullView ? "full" : "summary"}
          selectedCount={selectedCount}
          onClearSelection={() => setRowSelection({})}
        />

        {list.isPending ? (
          <TableSkeleton rows={12} columns={9} />
        ) : visible.length === 0 ? (
          <Card>
            <CardContent>
              {response && response.total === 0 ? (
                <EmptyState
                  title="This scan found no cryptographic assets"
                  description="The scan completed without recording any asset. Widen the scan target and run it again."
                />
              ) : (
                <NoResultsState onClear={state.clearFilters} />
              )}
            </CardContent>
          </Card>
        ) : (
          <InventoryTable
            rows={visible}
            sort={state.sort}
            pageSort={state.pageSort}
            onSelectServerSort={state.setSort}
            onTogglePageSort={state.togglePageSort}
            columnVisibility={columnVisibility}
            onColumnVisibilityChange={setColumnVisibility}
            rowSelection={rowSelection}
            onRowSelectionChange={setRowSelection}
            isFetching={list.isFetching && !list.isPending}
          />
        )}

        {response ? (
          <Pager
            matched={response.matched}
            offset={state.offset}
            pageSize={state.pageSize}
            onOffset={state.setOffset}
            isFetching={list.isFetching}
          />
        ) : null}
      </div>
    </PageShell>
  );
}

function InventoryHeader({
  onRefresh,
  isFetching,
}: {
  onRefresh: () => void;
  isFetching: boolean;
}) {
  return (
    <PageHeader
      title="Inventory"
      question="What cryptography exists, and what has the assessment decided about it?"
      description="Every canonical asset the scan produced, with both decision levels side by side: the migration decision, and the specific strategy recommended beneath it."
      actions={
        <Button variant="outline" size="sm" onClick={onRefresh} disabled={isFetching}>
          <RefreshCw className={isFetching ? "animate-spin" : undefined} />
          Refresh
        </Button>
      }
    />
  );
}

/**
 * The count line.
 *
 * `matched` and `total` are the API's own figures. When a page-scoped filter is
 * active it is stated separately, because it means the number of rows on screen
 * is smaller than the number the API matched -- and only the API's number
 * describes the estate.
 */
function ResultCount({
  matched,
  total,
  offset,
  shown,
  pageCount,
  clientFilterCount,
  view,
  selectedCount,
  onClearSelection,
}: {
  matched: number | undefined;
  total: number | undefined;
  offset: number;
  shown: number;
  pageCount: number;
  clientFilterCount: number;
  view: "summary" | "full";
  selectedCount: number;
  onClearSelection: () => void;
}) {
  if (matched === undefined || total === undefined) {
    return <div className="text-muted-foreground h-5 text-xs" />;
  }

  const first = matched === 0 ? 0 : offset + 1;
  const last = offset + pageCount;

  return (
    <div className="text-muted-foreground flex flex-wrap items-center gap-x-3 gap-y-1 text-xs">
      <span>
        <span className="ecdat-numeric text-foreground font-medium">
          {formatNumber(first)}–{formatNumber(last)}
        </span>{" "}
        of{" "}
        <Tooltip>
          <TooltipTrigger asChild>
            <span className="ecdat-numeric text-foreground cursor-help border-b border-dotted font-medium">
              {formatNumber(matched)}
            </span>
          </TooltipTrigger>
          <TooltipContent className="max-w-64 text-xs leading-relaxed">
            The API&apos;s <code className="font-mono">matched</code> count: how many assets in the
            whole estate satisfy the filters it applied.
          </TooltipContent>
        </Tooltip>{" "}
        matched
        {matched !== total ? <> · {formatNumber(total)} in the estate</> : null}
      </span>

      {clientFilterCount > 0 && shown !== pageCount ? (
        <span className="border-l pl-3">
          <span className="ecdat-numeric text-foreground font-medium">
            {formatNumber(shown)}
          </span>{" "}
          shown after {clientFilterCount === 1 ? "a page-only filter" : "page-only filters"} —{" "}
          {formatNumber(matched)} is still the estate-wide count
        </span>
      ) : null}

      <span className="border-l pl-3">
        projection <code className="font-mono text-[10.5px]">view={view}</code>
      </span>

      {selectedCount > 0 ? (
        <span className="flex items-center gap-1.5 border-l pl-3">
          <span className="text-foreground font-medium">{selectedCount} selected</span>
          <button
            type="button"
            onClick={onClearSelection}
            className="hover:text-foreground underline underline-offset-2"
          >
            clear
          </button>
        </span>
      ) : null}
    </div>
  );
}

function Pager({
  matched,
  offset,
  pageSize,
  onOffset,
  isFetching,
}: {
  matched: number;
  offset: number;
  pageSize: number;
  onOffset: (offset: number) => void;
  isFetching: boolean;
}) {
  const pageCount = Math.max(1, Math.ceil(matched / pageSize));
  const page = Math.floor(offset / pageSize) + 1;
  if (matched <= pageSize) return null;

  return (
    <div className="flex items-center justify-between gap-3">
      <span className="text-muted-foreground text-xs">
        Page <span className="ecdat-numeric text-foreground font-medium">{page}</span> of{" "}
        <span className="ecdat-numeric">{pageCount}</span>
      </span>
      <div className="flex items-center gap-1.5">
        <Button
          variant="outline"
          size="sm"
          disabled={offset === 0 || isFetching}
          onClick={() => onOffset(Math.max(0, offset - pageSize))}
        >
          <ChevronLeft />
          Previous
        </Button>
        <Button
          variant="outline"
          size="sm"
          disabled={offset + pageSize >= matched || isFetching}
          onClick={() => onOffset(offset + pageSize)}
        >
          Next
          <ChevronRight />
        </Button>
      </div>
    </div>
  );
}
