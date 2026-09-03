# Frontend ↔ API integration

How the browser UI reaches the analysis backend, and why it is wired this way. This is
the authoritative description; if the code and this file disagree, the code is a bug.

## Topology

```
browser ──▶ http://127.0.0.1:3000        Next.js  (frontend/)
   │
   └──────▶ http://127.0.0.1:8787        ECDAT API (backend/, python -m ecdat.api)
```

Two processes, two ports, both bound to loopback. The browser talks to the API
**directly** — there is no proxy and no rewrite. This is the simplest topology that keeps
one analytical truth: the API is the only source of cryptographic verdicts, and the UI is
the only consumer.

## The single source of the API location

`frontend/src/lib/api-client.ts` is the only file that knows where the API is:

```ts
export const API_BASE =
  process.env.NEXT_PUBLIC_ECDAT_API_URL?.replace(/\/$/, "") ?? "http://127.0.0.1:8787";
```

- One environment variable: **`NEXT_PUBLIC_ECDAT_API_URL`**. No other name is read.
- Every request goes through `apiFetch` in that same file. No component builds a URL, and
  the port `8787` appears nowhere else in `src/`.
- React Query hooks in `src/lib/queries.ts` call those endpoint functions. There is no
  per-page `fetch` wrapper.

To point the UI at an API on another host or port, set the variable — nothing else changes:

```bash
NEXT_PUBLIC_ECDAT_API_URL=http://127.0.0.1:9001 npm run dev
```

`NEXT_PUBLIC_*` values are inlined at build time, so a production bundle must be rebuilt
after changing it.

## CORS: an explicit allow-list, not a wildcard

Because the UI is served from port 3000 and the API from 8787, every API call is
cross-origin and needs CORS. The backend (`backend/ecdat/api/server.py`) echoes the
caller's `Origin` **only when it is allow-listed**, and adds `Vary: Origin`:

| Request | `Access-Control-Allow-Origin` |
| --- | --- |
| no `Origin` (curl, server-side fetch) | *(absent — there is no cross-origin decision to make)* |
| `http://localhost:3000` | `http://localhost:3000` |
| `http://127.0.0.1:3000` | `http://127.0.0.1:3000` |
| anything else | *(absent — the browser blocks the read)* |

Those two loopback origins are the defaults, because they are what `next dev` and
`next start` actually serve on. Add more with a comma-separated list:

```bash
ECDAT_API_ALLOWED_ORIGINS="http://192.168.1.10:3000" python -m ecdat.api
```

**Why not `Access-Control-Allow-Origin: *`** (which is what this used to send): a wildcard
cannot carry credentials at all under the CORS spec, so it would have to be replaced the
moment any authentication is introduced. In the meantime it lets *any* page open in the
browser read this estate's scan results — algorithm inventory, weak-crypto locations,
certificate detail. The allow-list costs nothing and is correct in both states.

ECDAT has no authentication layer today and sends no credentials; the allow-list is about
not having to remember this later.

## Dev-server origins (`allowedDevOrigins`)

Separate mechanism, same theme, and worth knowing about because its failure mode is
confusing. Next.js blocks cross-origin requests to **dev-only assets** by default. The dev
server is initialised with `localhost`, so opening the UI at any other address — including
the LAN address that `next dev` prints in its own banner — makes every
`/_next/static/chunks/*` request 403.

A 403'd chunk means React never hydrates, which means React Query never runs, which means
**no API request is ever made** and the page sits on its server-rendered skeletons. It
looks like a data problem and is not one.

`frontend/next.config.ts` allow-lists `127.0.0.1` plus this machine's current non-internal
IPv4 addresses, read from `os.networkInterfaces()` at startup so it survives a DHCP change:

```ts
allowedDevOrigins: ["127.0.0.1", ...localAddresses()],
```

The guard is narrowed, not disabled: a genuinely foreign origin still gets 403. This is a
development-only restriction — `next build && next start` has no such check.

## Running it

```bash
# 1. API, then load a scan (the API starts with no scan)
cd backend
python -m ecdat.api --port 8787
curl -X POST http://127.0.0.1:8787/scan -H 'Content-Type: application/json' \
  -d '{"targets":["../datasets/demo/repositories",
                  "../datasets/demo/certificates",
                  "../datasets/demo/binaries"],"policy":"nist_general"}'

# 2. UI
cd frontend
npm run dev                      # development
npm run build && npm run start   # production — use this for demos
```

Verify the wiring end to end, in a real browser, with an empty profile:

```bash
cd frontend && node scripts/render-probe.mjs /
```

It reports the theme applied on first paint, every API call with its status code, and
fails on console errors, uncaught exceptions, network failures, non-200 responses,
horizontal overflow, invalid list nesting or stuck skeletons.
