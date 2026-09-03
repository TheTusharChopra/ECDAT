/**
 * Global command palette (Cmd/Ctrl+K).
 *
 * Searches the estate's own vocabulary -- assets, applications, owners,
 * libraries, algorithms, protocols, certificates -- and every screen. The index
 * is one cached `GET /assets` response; the palette groups and filters it for
 * navigation but never derives a verdict from it.
 *
 * Facet selections navigate to the inventory with a real backend filter in the
 * URL, so the palette and the inventory always agree on what a term means.
 * Terms the API does not expose as a filter (algorithm, protocol) go through
 * full-text `q` instead of being approximated client-side.
 */

"use client";

import { useEffect, useMemo, useState, type ReactNode } from "react";
import { useRouter } from "next/navigation";
import {
  ArrowRight,
  Boxes,
  Building2,
  FileBadge,
  KeyRound,
  Library,
  Network,
  UserRound,
} from "lucide-react";

import {
  Command,
  CommandDialog,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
  CommandSeparator,
} from "@/components/ui/command";
import { useAssets } from "@/lib/queries";
import { ALL_NAV_ITEMS } from "@/lib/navigation";
import { assetTypeLabel, shortenPath } from "@/lib/display";
import type { AssetSummary } from "@/types/api";

/** Per-group cap. Enough to be useful, few enough to stay scannable. */
const GROUP_LIMIT = 6;

type FacetKey = "application" | "owner" | "library" | "algorithm_label" | "protocol";

interface Facet {
  value: string;
  count: number;
}

function collectFacet(assets: AssetSummary[], key: FacetKey): Facet[] {
  const counts = new Map<string, number>();
  for (const asset of assets) {
    const value = asset[key];
    if (!value) continue;
    counts.set(value, (counts.get(value) ?? 0) + 1);
  }
  return [...counts.entries()]
    .map(([value, count]) => ({ value, count }))
    .sort((a, b) => b.count - a.count || a.value.localeCompare(b.value));
}

function matches(term: string, ...fields: (string | null | undefined)[]): boolean {
  if (!term) return true;
  const needle = term.toLowerCase();
  return fields.some((field) => field?.toLowerCase().includes(needle));
}

/**
 * One palette row. A single full-width flex row so the primitive's trailing
 * check glyph has no free space to claim and the metadata stays flush right.
 */
function Row({
  icon,
  label,
  meta,
  mono = false,
}: {
  icon: ReactNode;
  label: string;
  meta?: ReactNode;
  mono?: boolean;
}) {
  return (
    <div className="flex w-full items-center gap-2">
      {icon}
      <span className={mono ? "truncate font-mono text-[13px]" : "truncate"}>{label}</span>
      {meta ? (
        <span className="text-muted-foreground ml-auto shrink-0 pl-3 text-[11px]">{meta}</span>
      ) : null}
    </div>
  );
}

export function CommandPalette({
  open,
  onOpenChange,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const router = useRouter();
  const [term, setTerm] = useState("");

  // Fetched only once the palette has been opened, so the shortcut costs
  // nothing until it is used. The response is shared with other screens
  // through the query cache.
  const { data } = useAssets({ limit: 1000 }, open);
  const assets = useMemo(() => data?.assets ?? [], [data]);

  const index = useMemo(
    () => ({
      applications: collectFacet(assets, "application"),
      owners: collectFacet(assets, "owner"),
      libraries: collectFacet(assets, "library"),
      algorithms: collectFacet(assets, "algorithm_label"),
      protocols: collectFacet(assets, "protocol"),
      certificates: assets.filter((asset) => asset.asset_type === "certificate"),
    }),
    [assets],
  );

  const results = useMemo(
    () => ({
      screens: ALL_NAV_ITEMS.filter((item) => matches(term, item.title, item.question)),
      assets: assets
        .filter((asset) =>
          matches(
            term,
            asset.asset_name,
            asset.asset_id,
            asset.algorithm_label,
            asset.application,
            asset.file,
            asset.library,
            asset.owner,
          ),
        )
        .slice(0, GROUP_LIMIT * 2),
      applications: index.applications
        .filter((facet) => matches(term, facet.value))
        .slice(0, GROUP_LIMIT),
      owners: index.owners.filter((f) => matches(term, f.value)).slice(0, GROUP_LIMIT),
      libraries: index.libraries.filter((f) => matches(term, f.value)).slice(0, GROUP_LIMIT),
      algorithms: index.algorithms.filter((f) => matches(term, f.value)).slice(0, GROUP_LIMIT),
      protocols: index.protocols.filter((f) => matches(term, f.value)).slice(0, GROUP_LIMIT),
      certificates: index.certificates
        .filter((asset) => matches(term, asset.asset_name))
        .slice(0, GROUP_LIMIT),
    }),
    [assets, index, term],
  );

  function go(href: string) {
    onOpenChange(false);
    setTerm("");
    router.push(href);
  }

  const total =
    results.screens.length +
    results.assets.length +
    results.applications.length +
    results.owners.length +
    results.libraries.length +
    results.algorithms.length +
    results.protocols.length +
    results.certificates.length;

  return (
    <CommandDialog
      open={open}
      onOpenChange={onOpenChange}
      title="Search ECDAT"
      description="Search assets, applications, owners, libraries, algorithms, protocols and screens."
      className="sm:max-w-2xl"
    >
      {/* Filtering happens above, against the fields that actually identify an
          asset, so cmdk's own fuzzy scoring is switched off. */}
      <Command shouldFilter={false} loop>
        <CommandInput
          placeholder="Search assets, applications, owners, libraries, algorithms…"
          value={term}
          onValueChange={setTerm}
        />
        <CommandList className="ecdat-scrollbar max-h-[26rem]">
          {total === 0 ? (
            <CommandEmpty>
              {assets.length === 0
                ? "No scan result loaded yet."
                : "No matches in this scan."}
            </CommandEmpty>
          ) : null}

          {results.assets.length > 0 ? (
            <CommandGroup heading="Crypto assets">
              {results.assets.map((asset) => (
                <CommandItem
                  key={asset.asset_id}
                  value={asset.asset_id}
                  onSelect={() => go(`/assets/${encodeURIComponent(asset.asset_id)}`)}
                >
                  <Row
                    icon={<Boxes className="size-4 shrink-0" />}
                    label={asset.asset_name}
                    meta={`${assetTypeLabel(asset.asset_type)}${
                      asset.file ? ` · ${shortenPath(asset.file, 28)}` : ""
                    }`}
                  />
                </CommandItem>
              ))}
            </CommandGroup>
          ) : null}

          {results.certificates.length > 0 ? (
            <CommandGroup heading="Certificates">
              {results.certificates.map((asset) => (
                <CommandItem
                  key={`cert-${asset.asset_id}`}
                  value={`cert-${asset.asset_id}`}
                  onSelect={() => go(`/assets/${encodeURIComponent(asset.asset_id)}`)}
                >
                  <Row
                    icon={<FileBadge className="size-4 shrink-0" />}
                    label={asset.asset_name}
                    meta={asset.algorithm_label ?? undefined}
                  />
                </CommandItem>
              ))}
            </CommandGroup>
          ) : null}

          {results.applications.length > 0 ? (
            <CommandGroup heading="Applications">
              {results.applications.map((facet) => (
                <CommandItem
                  key={`app-${facet.value}`}
                  value={`app-${facet.value}`}
                  onSelect={() =>
                    go(`/inventory?application=${encodeURIComponent(facet.value)}`)
                  }
                >
                  <Row
                    icon={<Building2 className="size-4 shrink-0" />}
                    label={facet.value}
                    meta={`${facet.count} assets`}
                  />
                </CommandItem>
              ))}
            </CommandGroup>
          ) : null}

          {results.owners.length > 0 ? (
            <CommandGroup heading="Owners">
              {results.owners.map((facet) => (
                <CommandItem
                  key={`owner-${facet.value}`}
                  value={`owner-${facet.value}`}
                  onSelect={() => go(`/inventory?owner=${encodeURIComponent(facet.value)}`)}
                >
                  <Row
                    icon={<UserRound className="size-4 shrink-0" />}
                    label={facet.value}
                    meta={`${facet.count} assets`}
                  />
                </CommandItem>
              ))}
            </CommandGroup>
          ) : null}

          {results.libraries.length > 0 ? (
            <CommandGroup heading="Libraries">
              {results.libraries.map((facet) => (
                <CommandItem
                  key={`lib-${facet.value}`}
                  value={`lib-${facet.value}`}
                  onSelect={() => go(`/inventory?library=${encodeURIComponent(facet.value)}`)}
                >
                  <Row
                    icon={<Library className="size-4 shrink-0" />}
                    label={facet.value}
                    meta={String(facet.count)}
                    mono
                  />
                </CommandItem>
              ))}
            </CommandGroup>
          ) : null}

          {results.algorithms.length > 0 ? (
            <CommandGroup heading="Algorithms">
              {results.algorithms.map((facet) => (
                <CommandItem
                  key={`alg-${facet.value}`}
                  value={`alg-${facet.value}`}
                  onSelect={() => go(`/inventory?q=${encodeURIComponent(facet.value)}`)}
                >
                  <Row
                    icon={<KeyRound className="size-4 shrink-0" />}
                    label={facet.value}
                    meta={String(facet.count)}
                  />
                </CommandItem>
              ))}
            </CommandGroup>
          ) : null}

          {results.protocols.length > 0 ? (
            <CommandGroup heading="Protocols">
              {results.protocols.map((facet) => (
                <CommandItem
                  key={`proto-${facet.value}`}
                  value={`proto-${facet.value}`}
                  onSelect={() => go(`/inventory?q=${encodeURIComponent(facet.value)}`)}
                >
                  <Row
                    icon={<Network className="size-4 shrink-0" />}
                    label={facet.value}
                    meta={String(facet.count)}
                  />
                </CommandItem>
              ))}
            </CommandGroup>
          ) : null}

          {results.screens.length > 0 ? (
            <>
              <CommandSeparator />
              <CommandGroup heading="Go to">
                {results.screens.map((item) => (
                  <CommandItem key={item.href} value={item.href} onSelect={() => go(item.href)}>
                    <Row
                      icon={<item.icon className="size-4 shrink-0" />}
                      label={item.title}
                      meta={<ArrowRight className="size-3.5" />}
                    />
                  </CommandItem>
                ))}
              </CommandGroup>
            </>
          ) : null}
        </CommandList>
      </Command>
    </CommandDialog>
  );
}

/** Wires Cmd/Ctrl+K to the palette. Cmd/Ctrl+B stays the sidebar toggle. */
export function useCommandPalette() {
  const [open, setOpen] = useState(false);

  useEffect(() => {
    function onKeyDown(event: KeyboardEvent) {
      if (event.key.toLowerCase() === "k" && (event.metaKey || event.ctrlKey)) {
        event.preventDefault();
        setOpen((previous) => !previous);
      }
    }
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, []);

  return { open, setOpen };
}
