/**
 * The inventory table.
 *
 * Registers exactly two table features: column visibility and row selection.
 * Sorting is deliberately NOT a table feature here. The API orders the estate by
 * three columns and takes no direction; every other column can only be reordered
 * within the loaded page. Running that through the table's sorting feature would
 * mean flipping `manualSorting` between the two cases and registering a custom
 * comparator for band ordering anyway, so page-scoped ordering is applied to the
 * rows before they reach the table and the header says which kind is in effect.
 */

"use client";

import { useRouter } from "next/navigation";
import { ArrowDown, ArrowDownUp, ArrowUp, Globe } from "lucide-react";
import { useTable } from "@tanstack/react-table";

import { cn } from "@/lib/utils";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import type { PageSort } from "./use-inventory-state";
import {
  DEFAULT_COLUMN_VISIBILITY,
  inventoryColumns,
  inventoryFeatures,
  type InventoryColumnMeta,
  type InventoryRow,
} from "./columns";
import type { ServerSort } from "./filters";

/**
 * A stable empty array. A fresh `[]` each render invalidates the row model on
 * every pass, which at best refetches nothing and at worst loops.
 */
const EMPTY_ROWS: readonly InventoryRow[] = [];

export interface InventoryTableProps {
  rows: readonly InventoryRow[];
  /** Estate-wide sort currently applied by the API. */
  sort: ServerSort;
  /** Page-scoped sort, when the user asked for a column the API cannot order by. */
  pageSort: PageSort | null;
  onSelectServerSort: (sort: ServerSort) => void;
  onTogglePageSort: (column: string) => void;
  columnVisibility: Record<string, boolean>;
  onColumnVisibilityChange: (next: Record<string, boolean>) => void;
  /**
   * Selected asset ids. `Record<string, true>` rather than a boolean map,
   * because v9's `RowSelectionState` holds only the ids that ARE selected --
   * deselecting removes the key instead of writing `false`.
   */
  rowSelection: Record<string, true>;
  onRowSelectionChange: (next: Record<string, true>) => void;
  /** Dimmed while a refetch is in flight, so stale rows are visibly stale. */
  isFetching?: boolean;
}

/**
 * Order rows within the page.
 *
 * Used only for columns the API cannot sort by. Nulls always sink, in both
 * directions, so "not recorded" never occupies the top of a sorted column.
 */
export function applyPageSort(
  rows: readonly InventoryRow[],
  pageSort: PageSort | null,
): readonly InventoryRow[] {
  if (!pageSort) return rows;
  const column = inventoryColumns.find((candidate) => candidate.id === pageSort.column);
  const meta = column?.meta as InventoryColumnMeta | undefined;
  const read = meta?.sortValue;
  if (!read) return rows;

  const direction = pageSort.direction === "asc" ? 1 : -1;
  return [...rows].sort((left, right) => {
    const a = read(left);
    const b = read(right);
    const aMissing = a === null || a === undefined || a === "";
    const bMissing = b === null || b === undefined || b === "";
    if (aMissing && bMissing) return 0;
    if (aMissing) return 1;
    if (bMissing) return -1;
    if (typeof a === "number" && typeof b === "number") return (a - b) * direction;
    return String(a).localeCompare(String(b)) * direction;
  });
}

export function InventoryTable({
  rows,
  sort,
  pageSort,
  onSelectServerSort,
  onTogglePageSort,
  columnVisibility,
  onColumnVisibilityChange,
  rowSelection,
  onRowSelectionChange,
  isFetching = false,
}: InventoryTableProps) {
  const router = useRouter();

  const table = useTable({
    features: inventoryFeatures,
    columns: inventoryColumns,
    data: (rows.length ? rows : EMPTY_ROWS) as InventoryRow[],
    // Selection survives a refetch because it is keyed by asset id, not row index.
    getRowId: (row) => row.asset_id,
    state: { columnVisibility, rowSelection },
    onColumnVisibilityChange: (updater) =>
      onColumnVisibilityChange(
        typeof updater === "function" ? updater(columnVisibility) : updater,
      ),
    onRowSelectionChange: (updater) =>
      onRowSelectionChange(typeof updater === "function" ? updater(rowSelection) : updater),
    enableRowSelection: true,
  });

  return (
    <div
      className={cn(
        "ecdat-scrollbar relative w-full overflow-x-auto rounded-lg border transition-opacity",
        isFetching && "opacity-60",
      )}
    >
      <Table className="w-full text-[12.5px]">
        {/*
          Opaque, and stacked above the body. Both matter once columns are frozen
          to the left edge: a translucent header or a header below the frozen
          cells would let scrolled rows show through them.
        */}
        <TableHeader className="bg-muted sticky top-0 z-20">
          {table.getHeaderGroups().map((group) => (
            <TableRow key={group.id} className="bg-muted hover:bg-muted">
              {group.headers.map((header) => {
                const meta = header.column.columnDef.meta as InventoryColumnMeta | undefined;
                return (
                  <TableHead
                    key={header.id}
                    className={cn(
                      "h-9 px-2.5",
                      meta?.wrapHeader && "whitespace-normal",
                      meta?.className,
                    )}
                    aria-sort={ariaSort(header.column.id, sort, pageSort)}
                  >
                    {header.isPlaceholder ? null : (
                      <HeaderLabel
                        columnId={header.column.id}
                        meta={meta}
                        sort={sort}
                        pageSort={pageSort}
                        onSelectServerSort={onSelectServerSort}
                        onTogglePageSort={onTogglePageSort}
                      >
                        <table.FlexRender header={header} />
                      </HeaderLabel>
                    )}
                  </TableHead>
                );
              })}
            </TableRow>
          ))}
        </TableHeader>
        <TableBody>
          {table.getRowModel().rows.map((row) => (
            <TableRow
              key={row.id}
              data-state={row.getIsSelected() ? "selected" : undefined}
              // Whole-row navigation, with the anchor in the name cell kept so
              // the destination is still visible on hover and openable in a tab.
              onClick={() => router.push(`/assets/${row.original.asset_id}`)}
              // An opaque base, and an opaque hover in place of the default
              // half-transparent one, so the frozen cells can inherit the row's
              // background and still hide what scrolls behind them.
              className="bg-background hover:bg-muted cursor-pointer"
            >
              {row.getVisibleCells().map((cell) => {
                const meta = cell.column.columnDef.meta as InventoryColumnMeta | undefined;
                return (
                  <TableCell key={cell.id} className={cn("px-2.5 py-1.5", meta?.className)}>
                    <table.FlexRender cell={cell} />
                  </TableCell>
                );
              })}
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}

function ariaSort(
  columnId: string,
  sort: ServerSort,
  pageSort: PageSort | null,
): "ascending" | "descending" | undefined {
  const column = inventoryColumns.find((candidate) => candidate.id === columnId);
  const meta = column?.meta as InventoryColumnMeta | undefined;
  if (pageSort?.column === columnId) {
    return pageSort.direction === "asc" ? "ascending" : "descending";
  }
  if (!pageSort && meta?.serverSort === sort) {
    return meta.serverSortDirection === "asc" ? "ascending" : "descending";
  }
  return undefined;
}

function HeaderLabel({
  columnId,
  meta,
  sort,
  pageSort,
  onSelectServerSort,
  onTogglePageSort,
  children,
}: {
  columnId: string;
  meta: InventoryColumnMeta | undefined;
  sort: ServerSort;
  pageSort: PageSort | null;
  onSelectServerSort: (sort: ServerSort) => void;
  onTogglePageSort: (column: string) => void;
  children: React.ReactNode;
}) {
  const serverSort = meta?.serverSort;
  const pageSortable = meta?.pageSortable;
  const sortable = Boolean(serverSort || pageSortable);

  // Which sort, if any, this header currently carries. A page sort always wins
  // visually, because it is what the rows on screen are actually ordered by.
  const isPageSorted = pageSort?.column === columnId;
  const isServerSorted = !pageSort && serverSort === sort;

  const label = (
    <span className={cn("flex gap-1", meta?.wrapHeader ? "items-start" : "items-center")}>
      {/* `truncate` implies nowrap, which is exactly what a wrapping header must not have. */}
      <span className={meta?.wrapHeader ? "leading-tight" : "truncate"}>{children}</span>
      {isServerSorted ? (
        <>
          <Globe className="text-primary size-3 shrink-0" aria-hidden />
          {meta?.serverSortDirection === "asc" ? (
            <ArrowUp className="text-primary size-3 shrink-0" aria-hidden />
          ) : (
            <ArrowDown className="text-primary size-3 shrink-0" aria-hidden />
          )}
        </>
      ) : null}
      {isPageSorted ? (
        <>
          {pageSort.direction === "asc" ? (
            <ArrowUp className="size-3 shrink-0" aria-hidden />
          ) : (
            <ArrowDown className="size-3 shrink-0" aria-hidden />
          )}
          <span className="text-muted-foreground shrink-0 text-[9.5px] tracking-wide uppercase">
            page
          </span>
        </>
      ) : null}
      {sortable && !isPageSorted && !isServerSorted ? (
        <ArrowDownUp
          className="text-muted-foreground/0 group-hover/head:text-muted-foreground/60 size-3 shrink-0 transition-colors"
          aria-hidden
        />
      ) : null}
    </span>
  );

  if (!sortable) {
    return meta?.help ? (
      <Tooltip>
        <TooltipTrigger asChild>
          <span className="cursor-help">{label}</span>
        </TooltipTrigger>
        <TooltipContent className="max-w-72 text-xs leading-relaxed">{meta.help}</TooltipContent>
      </Tooltip>
    ) : (
      label
    );
  }

  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <button
          type="button"
          className="group/head hover:text-foreground -mx-1 flex max-w-full items-center rounded px-1 py-0.5 text-left font-medium"
          onClick={() => {
            if (serverSort) onSelectServerSort(serverSort);
            else onTogglePageSort(columnId);
          }}
        >
          {label}
        </button>
      </TooltipTrigger>
      <TooltipContent className="flex max-w-72 flex-col gap-1 text-xs leading-relaxed">
        {meta?.help ? <span>{meta.help}</span> : null}
        <span className="text-muted-foreground">
          {serverSort
            ? `Sorts the whole inventory through the API (${
                meta?.serverSortDirection === "asc" ? "ascending" : "descending"
              }, the only direction it offers).`
            : "The API cannot sort by this column, so this reorders the loaded page only. Click again to reverse, once more to clear."}
        </span>
      </TooltipContent>
    </Tooltip>
  );
}

export { DEFAULT_COLUMN_VISIBILITY };
