/**
 * The inventory toolbar: search, filters, sort, page size and column visibility.
 *
 * The one thing this component takes care to get right is scope. A filter the
 * API can apply narrows the whole estate and the result count stays true; a
 * filter it cannot only narrows the rows already on screen. Both are offered,
 * but the second is labelled "page only" everywhere it appears -- on its control,
 * on its chip and in the count line -- because presenting it as the first would
 * overstate what was actually searched (§4).
 */

"use client";

import { useMemo, useState } from "react";
import { ChevronsUpDown, Columns3, ListFilter, Search, X } from "lucide-react";

import type { AssetSummary, DashboardSummary } from "@/types/api";
import { cn } from "@/lib/utils";
import { formatNumber } from "@/lib/display";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Separator } from "@/components/ui/separator";
import {
  DropdownMenu,
  DropdownMenuCheckboxItem,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectLabel,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";

import {
  CLIENT_FILTERS,
  FILTER_BY_KEY,
  OVERFLOW_FILTERS,
  PAGE_SIZES,
  PRIMARY_FILTERS,
  SERVER_SORTS,
  filterOptions,
  optionLabel,
  type FilterDef,
  type ServerSort,
} from "./filters";
import type { InventoryState } from "./use-inventory-state";
import type { InventoryColumnMeta } from "./columns";

/** Radix Select has no empty-string item, so "any" needs a sentinel value. */
const ANY = "__any__";

const SORT_LABEL: Record<ServerSort, string> = {
  priority: "Priority, highest first",
  risk: "Risk score, highest first",
  name: "Name, A to Z",
};

interface ColumnToggle {
  id: string;
  meta: InventoryColumnMeta | undefined;
  isVisible: boolean;
  canHide: boolean;
  toggle: () => void;
}

export interface FilterBarProps {
  state: InventoryState;
  /** `/dashboard`, for backend option counts. Absent until it loads. */
  dashboard: DashboardSummary | undefined;
  /**
   * A wide unfiltered summary page, used only to populate open-domain option
   * lists (application, owner, library, algorithm...). Never counted from.
   */
  facetAssets: readonly AssetSummary[] | undefined;
  columns: ColumnToggle[];
  onResetColumns: () => void;
}

export function FilterBar({
  state,
  dashboard,
  facetAssets,
  columns,
  onResetColumns,
}: FilterBarProps) {
  const overflowActive = OVERFLOW_FILTERS.filter(
    (filter) => state.activeFilters.some((active) => active.key === filter.key),
  ).length;

  const hiddenCount = columns.filter((column) => column.canHide && !column.isVisible).length;

  return (
    <div className="flex flex-col gap-2.5">
      <div className="flex flex-wrap items-center gap-2">
        <SearchBox value={state.q} onChange={state.setSearch} />

        <div className="ml-auto flex items-center gap-2">
          <Select value={state.sort} onValueChange={(value) => state.setSort(value as ServerSort)}>
            <Tooltip>
              <TooltipTrigger asChild>
                <SelectTrigger size="sm" className="w-[13.5rem]" aria-label="Sort order">
                  <ChevronsUpDown className="text-muted-foreground" />
                  <SelectValue />
                </SelectTrigger>
              </TooltipTrigger>
              <TooltipContent className="max-w-72 text-xs leading-relaxed">
                Sorts the whole inventory server-side. These are the three orders the API
                implements; each has a fixed direction. Clicking any other column header sorts the
                loaded page only.
              </TooltipContent>
            </Tooltip>
            <SelectContent>
              <SelectGroup>
                <SelectLabel>Sorted by the API, across the estate</SelectLabel>
                {(Object.keys(SERVER_SORTS) as ServerSort[]).map((sort) => (
                  <SelectItem key={sort} value={sort}>
                    {SORT_LABEL[sort]}
                  </SelectItem>
                ))}
              </SelectGroup>
            </SelectContent>
          </Select>

          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="outline" size="sm">
                <Columns3 />
                Columns
                {hiddenCount > 0 ? (
                  <Badge variant="secondary" className="ml-0.5 h-4 min-w-4 px-1 text-[10px]">
                    {hiddenCount} hidden
                  </Badge>
                ) : null}
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="w-64">
              <DropdownMenuLabel>Visible columns</DropdownMenuLabel>
              <DropdownMenuSeparator />
              {columns
                .filter((column) => column.canHide)
                .map((column) => (
                  <DropdownMenuCheckboxItem
                    key={column.id}
                    checked={column.isVisible}
                    onCheckedChange={column.toggle}
                    onSelect={(event) => event.preventDefault()}
                    className="items-start gap-2"
                  >
                    <span className="flex flex-col gap-0.5">
                      <span>{column.meta?.label ?? column.id}</span>
                      {column.meta?.needsFullView ? (
                        <span className="text-muted-foreground text-[10.5px] leading-snug">
                          Refetches this page with view=full
                        </span>
                      ) : null}
                    </span>
                  </DropdownMenuCheckboxItem>
                ))}
              <DropdownMenuSeparator />
              <DropdownMenuItem onSelect={onResetColumns}>Reset to defaults</DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </div>

      <div className="flex flex-wrap items-center gap-2">
        {PRIMARY_FILTERS.map((filter) => (
          <FilterSelect
            key={filter.key}
            filter={filter}
            value={state.activeFilters.find((active) => active.key === filter.key)?.value ?? null}
            onChange={(value) => state.setFilter(filter.key, value)}
            dashboard={dashboard}
            facetAssets={facetAssets}
          />
        ))}

        <MoreFilters
          state={state}
          dashboard={dashboard}
          facetAssets={facetAssets}
          activeCount={overflowActive}
        />

        <Separator orientation="vertical" className="mx-0.5 !h-5" />

        <Select
          value={String(state.pageSize)}
          onValueChange={(value) => state.setPageSize(Number(value))}
        >
          <SelectTrigger size="sm" className="w-[7.5rem]" aria-label="Rows per page">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {PAGE_SIZES.map((size) => (
              <SelectItem key={size} value={String(size)}>
                {size} rows
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      <ActiveFilterChips state={state} />
    </div>
  );
}

function SearchBox({ value, onChange }: { value: string; onChange: (value: string) => void }) {
  // Local state so typing stays responsive; the URL is written on submit or on
  // clear. Committing per keystroke would push a history entry per character and
  // fire a request for every prefix.
  const [draft, setDraft] = useState(value);
  const dirty = draft !== value;

  return (
    <form
      className="relative flex min-w-0 flex-1 items-center sm:max-w-sm"
      onSubmit={(event) => {
        event.preventDefault();
        onChange(draft.trim());
      }}
      role="search"
    >
      <Search className="text-muted-foreground pointer-events-none absolute left-2.5 size-4" />
      <Input
        value={draft}
        onChange={(event) => setDraft(event.target.value)}
        onKeyDown={(event) => {
          if (event.key === "Escape") {
            setDraft("");
            onChange("");
          }
        }}
        placeholder="Search assets, files, algorithms…"
        aria-label="Search the inventory"
        className="h-8 pr-16 pl-8"
      />
      <div className="absolute right-1 flex items-center gap-0.5">
        {dirty ? (
          <Button type="submit" size="sm" variant="ghost" className="h-6 px-1.5 text-[11px]">
            Search
          </Button>
        ) : null}
        {value ? (
          <Button
            type="button"
            size="icon"
            variant="ghost"
            className="size-6"
            aria-label="Clear search"
            onClick={() => {
              setDraft("");
              onChange("");
            }}
          >
            <X className="size-3.5" />
          </Button>
        ) : null}
      </div>
    </form>
  );
}

function FilterSelect({
  filter,
  value,
  onChange,
  dashboard,
  facetAssets,
  className,
}: {
  filter: FilterDef;
  value: string | null;
  onChange: (value: string | null) => void;
  dashboard: DashboardSummary | undefined;
  facetAssets: readonly AssetSummary[] | undefined;
  className?: string;
}) {
  const options = useMemo(
    () => filterOptions(filter, dashboard, facetAssets),
    [filter, dashboard, facetAssets],
  );
  const isClient = filter.scope === "client";
  // Whether this filter's own source has arrived. Kept apart from
  // `options.length` so an empty list can say which of the two cases it is.
  const sourceLoaded = filter.distribution ? dashboard !== undefined : facetAssets !== undefined;

  return (
    // Deliberately no `disabled` prop. It would have to read `options.length`,
    // and the option lists come from `/dashboard` and `/assets` -- data the
    // server render cannot have. The app shell warms `/dashboard` before this
    // subtree hydrates, so the server would emit `disabled=""` and the client
    // would hydrate `disabled={false}`: an attribute mismatch React refuses to
    // patch up. An empty list says so inside the menu instead, which is also
    // more use than a dead control that gives no reason for being dead.
    <Select value={value ?? ANY} onValueChange={(next) => onChange(next === ANY ? null : next)}>
      <Tooltip>
        <TooltipTrigger asChild>
          <SelectTrigger
            size="sm"
            aria-label={filter.label}
            className={cn(
              "max-w-[13rem]",
              value && "border-primary/40 bg-primary/5 text-foreground",
              className,
            )}
          >
            <span className="flex min-w-0 items-center gap-1.5">
              <span className={cn("shrink-0", value ? "text-muted-foreground" : "")}>
                {filter.label}
              </span>
              {value ? (
                // Labelled from the filter definition, not from `options`: the
                // option list is empty in the server render, so reading the
                // label out of it would spell the same value two ways.
                <span className="truncate font-medium">{optionLabel(filter, value)}</span>
              ) : null}
              {isClient ? (
                <span className="text-muted-foreground/80 shrink-0 text-[10px] tracking-wide uppercase">
                  page
                </span>
              ) : null}
            </span>
          </SelectTrigger>
        </TooltipTrigger>
        <TooltipContent className="max-w-72 text-xs leading-relaxed">{filter.help}</TooltipContent>
      </Tooltip>
      <SelectContent className="max-h-80">
        <SelectGroup>
          <SelectLabel className="flex flex-col items-start gap-0.5">
            <span>{filter.label}</span>
            <span className="text-muted-foreground text-[10.5px] font-normal">
              {isClient
                ? "No API parameter — narrows this page only"
                : `API filter: ${filter.key}=…`}
            </span>
          </SelectLabel>
          <SelectItem value={ANY}>Any</SelectItem>
          {/*
            Content is mounted only while the menu is open, so unlike the
            trigger it can safely depend on fetched data.
          */}
          {options.length === 0 ? (
            <p className="text-muted-foreground px-2 py-1.5 text-[11px] leading-snug">
              {sourceLoaded
                ? "This scan recorded no values for this field."
                : "Loading values from the API…"}
            </p>
          ) : null}
          {options.map((option) => (
            <SelectItem key={option.value} value={option.value}>
              <span className="flex w-full items-baseline gap-2">
                <span className="truncate">{option.label}</span>
                {option.count !== undefined ? (
                  <span className="ecdat-numeric text-muted-foreground ml-auto text-[10.5px]">
                    {formatNumber(option.count)}
                  </span>
                ) : null}
              </span>
            </SelectItem>
          ))}
        </SelectGroup>
      </SelectContent>
    </Select>
  );
}

function MoreFilters({
  state,
  dashboard,
  facetAssets,
  activeCount,
}: {
  state: InventoryState;
  dashboard: DashboardSummary | undefined;
  facetAssets: readonly AssetSummary[] | undefined;
  activeCount: number;
}) {
  const serverOverflow = OVERFLOW_FILTERS.filter((filter) => filter.scope === "server");

  return (
    <Popover>
      <PopoverTrigger asChild>
        <Button variant="outline" size="sm" className={cn(activeCount > 0 && "border-primary/40")}>
          <ListFilter />
          More filters
          {activeCount > 0 ? (
            <Badge variant="secondary" className="ml-0.5 h-4 min-w-4 px-1 text-[10px]">
              {activeCount}
            </Badge>
          ) : null}
        </Button>
      </PopoverTrigger>
      <PopoverContent align="start" className="w-[22rem] p-0">
        <div className="max-h-[26rem] overflow-y-auto p-3">
          <FilterGroup
            title="Applied by the API"
            note="Narrows the whole estate, so the result count stays exact."
            filters={serverOverflow}
            state={state}
            dashboard={dashboard}
            facetAssets={facetAssets}
          />
          <Separator className="my-3" />
          <FilterGroup
            title="Applied in this page only"
            note="The API has no parameter for these three, so they can only narrow the rows already fetched. The count line says so whenever one is on."
            filters={CLIENT_FILTERS}
            state={state}
            dashboard={dashboard}
            facetAssets={facetAssets}
          />
        </div>
      </PopoverContent>
    </Popover>
  );
}

function FilterGroup({
  title,
  note,
  filters,
  state,
  dashboard,
  facetAssets,
}: {
  title: string;
  note: string;
  filters: readonly FilterDef[];
  state: InventoryState;
  dashboard: DashboardSummary | undefined;
  facetAssets: readonly AssetSummary[] | undefined;
}) {
  return (
    <div className="flex flex-col gap-2">
      <div className="flex flex-col gap-0.5">
        <span className="text-xs font-semibold">{title}</span>
        <span className="text-muted-foreground text-[11px] leading-snug">{note}</span>
      </div>
      <div className="flex flex-col gap-1.5">
        {filters.map((filter) => (
          <div key={filter.key} className="grid grid-cols-[7.5rem_1fr] items-center gap-2">
            <Label className="text-muted-foreground truncate text-[11px] font-normal">
              {filter.label}
            </Label>
            <FilterSelect
              filter={filter}
              value={state.activeFilters.find((active) => active.key === filter.key)?.value ?? null}
              onChange={(value) => state.setFilter(filter.key, value)}
              dashboard={dashboard}
              facetAssets={facetAssets}
              className="w-full max-w-none"
            />
          </div>
        ))}
      </div>
    </div>
  );
}

function ActiveFilterChips({ state }: { state: InventoryState }) {
  if (!state.isFiltered && !state.pageSort) return null;

  return (
    <div className="flex flex-wrap items-center gap-1.5">
      {state.q ? (
        <Chip onClear={() => state.setSearch("")} label="Search" value={`“${state.q}”`} />
      ) : null}

      {state.activeFilters.map(({ key, value }) => {
        const filter = FILTER_BY_KEY[key];
        if (!filter) return null;
        return (
          <Chip
            key={key}
            label={filter.label}
            value={optionLabel(filter, value)}
            scope={filter.scope}
            onClear={() => state.setFilter(key, null)}
          />
        );
      })}

      {state.pageSort ? (
        <Chip
          label="Page sort"
          value={`${state.pageSort.column.replace(/_/g, " ")} ${state.pageSort.direction}`}
          scope="client"
          onClear={() => state.togglePageSort(state.pageSort!.column)}
        />
      ) : null}

      {state.isFiltered ? (
        <Button
          variant="ghost"
          size="sm"
          className="h-6 px-2 text-[11px]"
          onClick={state.clearFilters}
        >
          Clear all
        </Button>
      ) : null}
    </div>
  );
}

function Chip({
  label,
  value,
  scope = "server",
  onClear,
}: {
  label: string;
  value: string;
  scope?: "server" | "client";
  onClear: () => void;
}) {
  return (
    <span
      className={cn(
        "inline-flex h-6 items-center gap-1 rounded-md border px-1.5 pl-2 text-[11px]",
        scope === "client"
          ? "border-dashed bg-muted/40 text-muted-foreground"
          : "border-primary/30 bg-primary/5",
      )}
    >
      <span className="text-muted-foreground">{label}</span>
      <span className="max-w-40 truncate font-medium">{value}</span>
      {scope === "client" ? (
        <Tooltip>
          <TooltipTrigger asChild>
            <span className="text-muted-foreground/80 cursor-help text-[9.5px] tracking-wide uppercase">
              page
            </span>
          </TooltipTrigger>
          <TooltipContent className="max-w-64 text-xs leading-relaxed">
            Applied in the browser to the rows already fetched. The API has no parameter for this,
            so it does not narrow the estate-wide count.
          </TooltipContent>
        </Tooltip>
      ) : null}
      <button
        type="button"
        onClick={onClear}
        aria-label={`Remove ${label} filter`}
        className="hover:bg-foreground/10 ml-0.5 grid size-4 place-items-center rounded"
      >
        <X className="size-3" />
      </button>
    </span>
  );
}
