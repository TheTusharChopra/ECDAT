/**
 * The single point of contact with the ECDAT backend.
 *
 * Every network call in the application goes through `apiFetch`. Components
 * never call `fetch` directly (§26): one place to attach the base URL, one
 * place to normalise errors, one place to change when the transport changes.
 *
 * The backend is the only source of cryptographic truth. This module moves
 * bytes; it does not interpret them.
 */

import type {
  AssetDetailResponse,
  AssetGraphResponse,
  AssetListFullResponse,
  AssetListResponse,
  ApiErrorBody,
  CbomValidation,
  CycloneDxDocument,
  DashboardSummary,
  EvidenceResponse,
  HealthResponse,
  ImpactResponse,
  MigrationView,
  RiskView,
  RoadmapResponse,
  ScanRequest,
  ScanResult,
} from "@/types/api";

/**
 * Base URL of the ECDAT API -- the single place the API's location is decided.
 *
 * Every request in the app goes through `apiFetch` below, so this constant is the
 * only knob: no component builds its own URL and no port is written anywhere else.
 * Defaults to the loopback address the backend binds by default
 * (`python -m ecdat.api`); override with `NEXT_PUBLIC_ECDAT_API_URL`.
 *
 * The browser talks to this origin directly (see `docs/frontend-integration.md`),
 * which makes it a cross-origin caller -- the backend allow-lists the UI's origin
 * in `ecdat/api/server.py`. If this value is changed to a non-loopback host, that
 * allow-list needs the matching origin via `ECDAT_API_ALLOWED_ORIGINS`.
 */
export const API_BASE =
  process.env.NEXT_PUBLIC_ECDAT_API_URL?.replace(/\/$/, "") ?? "http://127.0.0.1:8787";

/**
 * A failed API call, carrying the backend's own error code so the UI can
 * distinguish "no scan yet" (an expected first-run state that should invite a
 * scan) from a genuine failure (which should offer a retry).
 */
export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly detail?: unknown;

  constructor(status: number, code: string, message: string, detail?: unknown) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
    this.detail = detail;
  }

  /** No scan has been run yet: the empty state, not an error state. */
  get isNoScan(): boolean {
    return this.code === "scan_not_initialized" || this.status === 409;
  }

  get isNotFound(): boolean {
    return this.status === 404;
  }

  /** The API process is not reachable at all (server down, wrong port). */
  get isOffline(): boolean {
    return this.code === "network_unreachable";
  }
}

interface FetchOptions {
  method?: "GET" | "POST";
  body?: unknown;
  signal?: AbortSignal;
  /** Return the raw body text instead of parsing JSON (reports, CSV). */
  raw?: boolean;
}

async function apiFetch<T>(path: string, options: FetchOptions = {}): Promise<T> {
  const { method = "GET", body, signal, raw = false } = options;

  let response: Response;
  try {
    response = await fetch(`${API_BASE}${path}`, {
      method,
      signal,
      headers: body ? { "Content-Type": "application/json" } : undefined,
      body: body ? JSON.stringify(body) : undefined,
      cache: "no-store",
    });
  } catch (cause) {
    // Distinguish "server unreachable" from a real HTTP error: the fix the
    // user needs is different (start the backend vs. retry the request).
    if (cause instanceof DOMException && cause.name === "AbortError") throw cause;
    throw new ApiError(
      0,
      "network_unreachable",
      `Cannot reach the ECDAT API at ${API_BASE}. Is the backend running?`,
      cause,
    );
  }

  if (!response.ok) {
    let code = `http_${response.status}`;
    let message = `Request failed with status ${response.status}.`;
    let detail: unknown;
    try {
      const parsed = (await response.json()) as ApiErrorBody;
      if (parsed?.error) {
        code = parsed.error.code ?? code;
        message = parsed.error.message ?? message;
        detail = parsed.error.detail;
      }
    } catch {
      // Non-JSON error body: keep the status-derived message.
    }
    throw new ApiError(response.status, code, message, detail);
  }

  if (raw) return (await response.text()) as unknown as T;
  return (await response.json()) as T;
}

/**
 * Filters accepted by `GET /assets`, mirroring the backend's FILTERABLE map.
 *
 * Exactly these keys and no others: the API rejects an unknown query parameter
 * with a 400 rather than ignoring it, which is the right behaviour and means a
 * typo here must be a type error rather than a runtime surprise.
 */
export interface AssetQuery {
  application?: string;
  asset_type?: string;
  decision?: string;
  strategy?: string;
  classical_risk?: string;
  quantum_exposure?: string;
  quantum_class?: string;
  urgency?: string;
  band?: string;
  confidence?: string;
  agility?: string;
  interoperability?: string;
  owner?: string;
  library?: string;
  context_source?: string;
  /** Full-text search across the asset's identifying fields. */
  q?: string;
  /** 1..1000. The API rejects anything outside that range. */
  limit?: number;
  offset?: number;
  view?: "summary" | "full";
  /** The only sorts the API implements. Default order is priority-descending. */
  sort?: "priority" | "risk" | "name";
}

/**
 * Serialise a params object, dropping empty values so an unset filter never
 * reaches the API as `?owner=`. Generic over the object type because the query
 * interfaces are closed shapes with no index signature -- deliberately, so a
 * misspelled filter is a type error here rather than a 400 at runtime.
 */
function toQueryString<T extends object>(params: T): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params) as [string, unknown][]) {
    if (value === undefined || value === null || value === "") continue;
    search.set(key, String(value));
  }
  const qs = search.toString();
  return qs ? `?${qs}` : "";
}

// ---------------------------------------------------------------------------
// Endpoints. One function per API route; no logic beyond shaping the URL.
// ---------------------------------------------------------------------------

export const api = {
  health: (signal?: AbortSignal) =>
    apiFetch<HealthResponse>("/health", { signal }),

  scan: (request: ScanRequest, signal?: AbortSignal) =>
    apiFetch<ScanResult>("/scan", { method: "POST", body: request, signal }),

  dashboard: (signal?: AbortSignal) =>
    apiFetch<DashboardSummary>("/dashboard", { signal }),

  assets: (query: AssetQuery = {}, signal?: AbortSignal) =>
    apiFetch<AssetListResponse>(`/assets${toQueryString(query)}`, { signal }),

  /**
   * The same route under `view=full`. Separate function, separate return type:
   * the full projection is ~10x the payload, so the cost should be visible at
   * the call site rather than hidden behind an options bag.
   */
  assetsFull: (query: Omit<AssetQuery, "view"> = {}, signal?: AbortSignal) =>
    apiFetch<AssetListFullResponse>(
      `/assets${toQueryString({ ...query, view: "full" })}`,
      { signal },
    ),

  asset: (id: string, signal?: AbortSignal) =>
    apiFetch<AssetDetailResponse>(`/assets/${encodeURIComponent(id)}`, { signal }),

  evidence: (id: string, signal?: AbortSignal) =>
    apiFetch<EvidenceResponse>(`/assets/${encodeURIComponent(id)}/evidence`, {
      signal,
    }),

  graph: (id: string, depth?: number, signal?: AbortSignal) =>
    apiFetch<AssetGraphResponse>(
      `/assets/${encodeURIComponent(id)}/graph${toQueryString({ depth })}`,
      { signal },
    ),

  risk: (id: string, signal?: AbortSignal) =>
    apiFetch<RiskView>(`/assets/${encodeURIComponent(id)}/risk`, { signal }),

  migration: (id: string, signal?: AbortSignal) =>
    apiFetch<MigrationView>(`/assets/${encodeURIComponent(id)}/migration`, {
      signal,
    }),

  impact: (id: string, signal?: AbortSignal) =>
    apiFetch<ImpactResponse>(`/assets/${encodeURIComponent(id)}/impact`, {
      signal,
    }),

  roadmap: (signal?: AbortSignal) =>
    apiFetch<RoadmapResponse>("/roadmap", { signal }),

  cbom: (signal?: AbortSignal) =>
    apiFetch<CycloneDxDocument>("/cbom", { signal }),

  cbomValidation: (signal?: AbortSignal) =>
    apiFetch<CbomValidation>("/cbom/validation", { signal }),

  report: (signal?: AbortSignal) =>
    apiFetch<string>("/reports", { raw: true, signal }),
};

/** Direct download URL for an export. Used for anchor hrefs, not fetched. */
export function exportUrl(name: "json" | "assets.csv" | "roadmap.csv" | "impact.csv") {
  return `${API_BASE}/exports/${name}`;
}
