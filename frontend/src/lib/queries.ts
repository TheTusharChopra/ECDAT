/**
 * TanStack Query bindings for the ECDAT API.
 *
 * All server state flows through these hooks (§27): caching, loading, error and
 * invalidation live here rather than being re-implemented per screen. Screens
 * consume a hook and render three states -- pending, error, data.
 *
 * A scan replaces the entire analytical result on the backend, so a successful
 * `POST /scan` invalidates every query rather than trying to patch caches.
 */

"use client";

import {
  useMutation,
  useQuery,
  useQueryClient,
  type UseQueryOptions,
} from "@tanstack/react-query";

import { api, ApiError, type AssetQuery } from "@/lib/api-client";
import type { ScanRequest } from "@/types/api";

/**
 * Query key factory. Centralised so an invalidation cannot miss a screen
 * because two files spelled the same key differently.
 */
export const queryKeys = {
  all: ["ecdat"] as const,
  health: () => [...queryKeys.all, "health"] as const,
  dashboard: () => [...queryKeys.all, "dashboard"] as const,
  assets: (query: AssetQuery) => [...queryKeys.all, "assets", query] as const,
  assetsFull: (query: Omit<AssetQuery, "view">) =>
    [...queryKeys.all, "assets", "full", query] as const,
  asset: (id: string) => [...queryKeys.all, "asset", id] as const,
  evidence: (id: string) => [...queryKeys.all, "evidence", id] as const,
  graph: (id: string, depth: number) =>
    [...queryKeys.all, "graph", id, depth] as const,
  risk: (id: string) => [...queryKeys.all, "risk", id] as const,
  migration: (id: string) => [...queryKeys.all, "migration", id] as const,
  impact: (id: string) => [...queryKeys.all, "impact", id] as const,
  roadmap: () => [...queryKeys.all, "roadmap"] as const,
  cbom: () => [...queryKeys.all, "cbom"] as const,
  cbomValidation: () => [...queryKeys.all, "cbom", "validation"] as const,
  report: () => [...queryKeys.all, "report"] as const,
};

/**
 * Shared retry policy. A 409 means "no scan yet" and a 404 means "no such
 * asset" -- both are stable answers, so retrying only delays the empty state.
 */
function retryPolicy(failureCount: number, error: unknown): boolean {
  if (error instanceof ApiError) {
    if (error.isNoScan || error.isNotFound) return false;
    if (error.status >= 400 && error.status < 500) return false;
  }
  return failureCount < 2;
}

type Options<T> = Omit<UseQueryOptions<T, ApiError>, "queryKey" | "queryFn">;

export function useHealth(options?: Options<Awaited<ReturnType<typeof api.health>>>) {
  return useQuery({
    queryKey: queryKeys.health(),
    queryFn: ({ signal }) => api.health(signal),
    retry: retryPolicy,
    refetchInterval: 30_000,
    ...options,
  });
}

export function useDashboard() {
  return useQuery({
    queryKey: queryKeys.dashboard(),
    queryFn: ({ signal }) => api.dashboard(signal),
    retry: retryPolicy,
  });
}

export function useAssets(query: AssetQuery = {}, enabled = true) {
  return useQuery({
    queryKey: queryKeys.assets(query),
    queryFn: ({ signal }) => api.assets(query, signal),
    retry: retryPolicy,
    enabled,
    // Keeps the previous page visible while the next one loads, so the table
    // does not collapse to a skeleton on every keystroke or page change.
    placeholderData: (previous) => previous,
  });
}

/**
 * The full 99-field projection. A separate query key from `useAssets` so the
 * two never overwrite each other in the cache, and `enabled` by default off at
 * the call site for panels that only need it on demand -- the full view of the
 * demo estate is ~2 MB against ~250 kB for the summary (§34).
 */
export function useAssetsFull(
  query: Omit<AssetQuery, "view"> = {},
  enabled = true,
) {
  return useQuery({
    queryKey: queryKeys.assetsFull(query),
    queryFn: ({ signal }) => api.assetsFull(query, signal),
    retry: retryPolicy,
    enabled,
    placeholderData: (previous) => previous,
  });
}

export function useAsset(id: string, enabled = true) {
  return useQuery({
    queryKey: queryKeys.asset(id),
    queryFn: ({ signal }) => api.asset(id, signal),
    retry: retryPolicy,
    enabled: enabled && Boolean(id),
  });
}

export function useEvidence(id: string, enabled = true) {
  return useQuery({
    queryKey: queryKeys.evidence(id),
    queryFn: ({ signal }) => api.evidence(id, signal),
    retry: retryPolicy,
    enabled: enabled && Boolean(id),
  });
}

/**
 * `depth` is a real request parameter, not a client-side filter: the backend
 * traverses the graph, so a deeper view is a new request (§34 -- never pull
 * the whole estate graph to show one neighbourhood).
 */
export function useAssetGraph(id: string, depth = 3, enabled = true) {
  return useQuery({
    queryKey: queryKeys.graph(id, depth),
    queryFn: ({ signal }) => api.graph(id, depth, signal),
    retry: retryPolicy,
    enabled: enabled && Boolean(id),
    placeholderData: (previous) => previous,
  });
}

export function useRisk(id: string, enabled = true) {
  return useQuery({
    queryKey: queryKeys.risk(id),
    queryFn: ({ signal }) => api.risk(id, signal),
    retry: retryPolicy,
    enabled: enabled && Boolean(id),
  });
}

export function useMigration(id: string, enabled = true) {
  return useQuery({
    queryKey: queryKeys.migration(id),
    queryFn: ({ signal }) => api.migration(id, signal),
    retry: retryPolicy,
    enabled: enabled && Boolean(id),
  });
}

export function useImpact(id: string, enabled = true) {
  return useQuery({
    queryKey: queryKeys.impact(id),
    queryFn: ({ signal }) => api.impact(id, signal),
    retry: retryPolicy,
    enabled: enabled && Boolean(id),
  });
}

export function useRoadmap() {
  return useQuery({
    queryKey: queryKeys.roadmap(),
    queryFn: ({ signal }) => api.roadmap(signal),
    retry: retryPolicy,
  });
}

export function useCbomValidation() {
  return useQuery({
    queryKey: queryKeys.cbomValidation(),
    queryFn: ({ signal }) => api.cbomValidation(signal),
    retry: retryPolicy,
  });
}

export function useCbom(enabled = false) {
  return useQuery({
    queryKey: queryKeys.cbom(),
    queryFn: ({ signal }) => api.cbom(signal),
    retry: retryPolicy,
    // The full CycloneDX document is large; fetch it only when asked for.
    enabled,
  });
}

export function useReport(enabled = true) {
  return useQuery({
    queryKey: queryKeys.report(),
    queryFn: ({ signal }) => api.report(signal),
    retry: retryPolicy,
    enabled,
  });
}

/**
 * Run a scan. On success every cached query is invalidated, because a scan
 * produces an entirely new analytical result on the backend -- there is no
 * meaningful partial update.
 */
export function useScan() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (request: ScanRequest) => api.scan(request),
    onSuccess: () => client.invalidateQueries({ queryKey: queryKeys.all }),
  });
}
