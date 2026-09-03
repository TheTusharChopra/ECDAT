/**
 * Inventory state, held in the URL.
 *
 * The URL is the single source of truth for what the table is showing, so any
 * view is a link: `/inventory?quantum_exposure=critical&decision=hybrid`
 * reproduces exactly on reload and can be pasted into a ticket (§20).
 *
 * Two kinds of state live here and they are not interchangeable:
 *
 *   - `serverQuery` is handed to `GET /assets`. Filters in it narrow the whole
 *     estate, so `matched` from the response is a true count.
 *   - `clientFilters` are the three dimensions the API has no parameter for.
 *     They can only narrow rows already fetched, and are reported that way.
 *
 * Sorting is split the same way. The API implements three sorts and no
 * direction control, so `sort` reorders the entire inventory while `psort`
 * reorders the loaded page. Both are in the URL; neither pretends to be the
 * other.
 */

"use client";

import { useCallback, useMemo } from "react";
import { usePathname, useRouter, useSearchParams } from "next/navigation";

import type { AssetQuery } from "@/lib/api-client";
import { FILTERS, PAGE_SIZES, SERVER_SORTS, type ServerSort } from "./filters";

const DEFAULT_PAGE_SIZE = 50;
const DEFAULT_SORT: ServerSort = "priority";

/** Keys this screen owns. Anything else in the URL is left untouched. */
const OWNED_KEYS = [
  ...FILTERS.map((filter) => filter.key),
  "q",
  "sort",
  "psort",
  "pdir",
  "limit",
  "offset",
];

export type SortDirection = "asc" | "desc";

export interface PageSort {
  /** Column id being sorted within the loaded page. */
  column: string;
  direction: SortDirection;
}

export interface InventoryState {
  /** Everything the API will apply, ready to pass to `api.assets`. */
  serverQuery: AssetQuery;
  /** Filters the API cannot apply, keyed by filter key. */
  clientFilters: Record<string, string>;
  /** Every active filter, server and client together, for the chip row. */
  activeFilters: { key: string; value: string }[];
  q: string;
  sort: ServerSort;
  /** Set only when the user asked for a sort the API does not implement. */
  pageSort: PageSort | null;
  pageSize: number;
  offset: number;

  setFilter: (key: string, value: string | null) => void;
  setSearch: (value: string) => void;
  /** Choose an estate-wide sort. Clears any page-scoped sort. */
  setSort: (sort: ServerSort) => void;
  /** Cycle a page-scoped sort on one column: asc, desc, off. */
  togglePageSort: (column: string) => void;
  setPageSize: (size: number) => void;
  setOffset: (offset: number) => void;
  clearFilters: () => void;
  /** True when any filter, search term or non-default sort is applied. */
  isFiltered: boolean;
}

export function useInventoryState(): InventoryState {
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();

  /** Write a set of key/value changes to the URL, dropping emptied keys. */
  const commit = useCallback(
    (changes: Record<string, string | null>) => {
      const next = new URLSearchParams(searchParams.toString());
      for (const [key, value] of Object.entries(changes)) {
        if (value === null || value === "") next.delete(key);
        else next.set(key, value);
      }
      const query = next.toString();
      // `scroll: false` keeps the table where it was: changing a filter is not a
      // navigation to a new place, and jumping to the top loses the reader.
      router.replace(query ? `${pathname}?${query}` : pathname, { scroll: false });
    },
    [pathname, router, searchParams],
  );

  const raw = useMemo(() => {
    const values: Record<string, string> = {};
    for (const key of OWNED_KEYS) {
      const value = searchParams.get(key);
      if (value) values[key] = value;
    }
    return values;
  }, [searchParams]);

  const state = useMemo(() => {
    const serverFilters: Record<string, string> = {};
    const clientFilters: Record<string, string> = {};
    const activeFilters: { key: string; value: string }[] = [];

    for (const filter of FILTERS) {
      const value = raw[filter.key];
      if (!value) continue;
      activeFilters.push({ key: filter.key, value });
      if (filter.scope === "server") serverFilters[filter.key] = value;
      else clientFilters[filter.key] = value;
    }

    const q = raw.q ?? "";
    const sort = isServerSort(raw.sort) ? raw.sort : DEFAULT_SORT;
    const pageSize = clampPageSize(raw.limit);
    const offset = clampOffset(raw.offset);

    const pageSort: PageSort | null = raw.psort
      ? { column: raw.psort, direction: raw.pdir === "desc" ? "desc" : "asc" }
      : null;

    const serverQuery: AssetQuery = {
      ...serverFilters,
      ...(q ? { q } : {}),
      sort,
      limit: pageSize,
      offset,
    };

    return {
      serverQuery,
      clientFilters,
      activeFilters,
      q,
      sort,
      pageSort,
      pageSize,
      offset,
      isFiltered: activeFilters.length > 0 || q.length > 0,
    };
  }, [raw]);

  const setFilter = useCallback(
    (key: string, value: string | null) => {
      // Any change to what is being selected invalidates the page position:
      // offset 100 of a narrower result set is usually past the end.
      commit({ [key]: value, offset: null });
    },
    [commit],
  );

  const setSearch = useCallback((value: string) => commit({ q: value, offset: null }), [commit]);

  const setSort = useCallback(
    (sort: ServerSort) => commit({ sort, psort: null, pdir: null, offset: null }),
    [commit],
  );

  const togglePageSort = useCallback(
    (column: string) => {
      const current = state.pageSort;
      if (!current || current.column !== column) {
        commit({ psort: column, pdir: "asc" });
        return;
      }
      if (current.direction === "asc") {
        commit({ psort: column, pdir: "desc" });
        return;
      }
      commit({ psort: null, pdir: null });
    },
    [commit, state.pageSort],
  );

  const setPageSize = useCallback(
    (size: number) => commit({ limit: String(size), offset: null }),
    [commit],
  );

  const setOffset = useCallback(
    (offset: number) => commit({ offset: offset > 0 ? String(offset) : null }),
    [commit],
  );

  const clearFilters = useCallback(() => {
    const cleared: Record<string, string | null> = { q: null, offset: null };
    for (const filter of FILTERS) cleared[filter.key] = null;
    commit(cleared);
  }, [commit]);

  return {
    ...state,
    setFilter,
    setSearch,
    setSort,
    togglePageSort,
    setPageSize,
    setOffset,
    clearFilters,
  };
}

function isServerSort(value: string | undefined): value is ServerSort {
  return value !== undefined && value in SERVER_SORTS;
}

function clampPageSize(value: string | undefined): number {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return DEFAULT_PAGE_SIZE;
  // The API accepts 1..1000; the picker offers a subset, and anything else in
  // the URL falls back rather than sending a value the API would reject.
  return (PAGE_SIZES as readonly number[]).includes(parsed) ? parsed : DEFAULT_PAGE_SIZE;
}

function clampOffset(value: string | undefined): number {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed < 0) return 0;
  return Math.min(Math.floor(parsed), 10_000_000);
}

/**
 * Build an inventory URL from filters. Used by other screens to hand off a
 * selection -- a risk band, a decision -- without duplicating the query rules.
 */
export function inventoryHref(filters: Record<string, string | number | undefined>): string {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(filters)) {
    if (value === undefined || value === "") continue;
    params.set(key, String(value));
  }
  const query = params.toString();
  return query ? `/inventory?${query}` : "/inventory";
}
