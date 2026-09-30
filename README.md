# ECDAT — Enterprise Cryptographic Discovery & Analysis Tool

[![Python 3.14+](https://img.shields.io/badge/Python-3.14%2B-blue.svg)](https://www.python.org/)
[![Next.js 16](https://img.shields.io/badge/Next.js-16.3-black.svg)](https://nextjs.org/)
[![Vercel Live](https://img.shields.io/badge/Vercel-Live%20Demo-000000.svg?logo=vercel&logoColor=white)](https://ecdat-app.vercel.app)
[![CycloneDX 1.6](https://img.shields.io/badge/CycloneDX-1.6%20CBOM-green.svg)](https://cyclonedx.org/)
[![Tests Passing](https://img.shields.io/badge/Tests-344%20Passing-brightgreen.svg)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> **Deterministic, Graph-Aware Post-Quantum Cryptographic Discovery, Dual-Axis Risk Scoring, and Automated Migration Engine.**
> 🌐 **Live Web Application:** [https://ecdat-app.vercel.app](https://ecdat-app.vercel.app)

ECDAT scans multi-language repositories, infrastructure configs, compiled binaries, and X.509 certificates to build a verified Cryptography Bill of Materials (CBOM). It assesses risks across independent classical and quantum axes, computes timeline urgency via Mosca's Inequality, calculates blast radius via dependency graph traversal, and outputs an executable, phased Post-Quantum Cryptography (PQC) migration roadmap.

---

## 📑 Table of Contents

- [Key Differentiators & USPs](#-key-differentiators--usps)
- [System Architecture](#-system-architecture)
- [How It Works: The 7-Stage Pipeline](#-how-it-works-the-7-stage-pipeline)
- [The Dual-Axis Risk Model](#-the-dual-axis-risk-model)
- [Mosca's Urgency Inequality](#-moscas-urgency-inequality)
- [The 5 Frozen Migration Decisions](#-the-5-frozen-migration-decisions)
- [Enablement Waves & Blast Radius](#-enablement-waves--blast-radius)
- [Project Structure](#-project-structure)
- [Getting Started](#-getting-started)
  - [Prerequisites](#prerequisites)
  - [1. Backend Setup](#1-backend-setup)
  - [2. Frontend Setup](#2-frontend-setup)
- [API Reference](#-api-reference)
- [Testing & Validation](#-testing--validation)

---

## 🌟 Key Differentiators & USPs

1. **Zero AI Hallucinations / 100% Deterministic:**  
   ECDAT does not use non-deterministic LLMs or black-box ML models for risk analysis. Every finding, score, and recommendation is calculated deterministically through structural AST parsing, ASN.1 DER decoding, and graph algorithms grounded in NIST and FIPS standards.
2. **Dual-Axis Risk Model (No Blended Scores):**  
   Classical risk (*is it broken today?*) and Quantum exposure (*will Shor's algorithm break it tomorrow?*) are evaluated independently. An expired SHA-1 certificate is treated as an immediate operational emergency (`UPGRADE`/`HARDEN`), not deferred into a 10-year PQC project.
3. **Graph-Derived Enablement Waves:**  
   The engine builds a directed dependency graph linking Code $\rightarrow$ Repos $\rightarrow$ Services $\rightarrow$ Applications. Upgrades are prioritized by **dependency centrality** so foundational cryptographic providers are migrated before downstream leaf applications.
4. **CycloneDX 1.6 CBOM Native:**  
   Generates and validates Cryptography Bills of Materials against official JSON schemas with strict privacy redactions (no private key bytes or source snippets ever leave the host).

---

## 🏛 System Architecture

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│                            FRONTEND (Next.js 16 + React 19)                      │
│  - TypeScript strict, TailwindCSS/Vanilla CSS design system, Recharts & Lucide  │
│  - TanStack Query v5 cache management with global invalidation on scan mutations │
│  - Pure visualization projection over backend REST APIs (Zero mock data)        │
└────────────────────────────────────────▲─────────────────────────────────────────┘
                                         │ HTTP REST (Port 8787 / JSON & CSV)
┌────────────────────────────────────────▼─────────────────────────────────────────┐
│                           BACKEND ENGINE (Python 3.14+)                          │
│                                                                                  │
│  1. DISCOVERY & PARSING (Multi-Surface Scanners)                                 │
│     ├── scan/source.py      ─── Direct filesystem walker & safety budget limits  │
│     ├── scan/x509.py        ─── Zero-dependency ASN.1 DER parser for certs      │
│     ├── detect/python_ast.py─── Python AST syntax tree analyzer (ast.parse)     │
│     ├── detect/lexical.py   ─── 90+ Regex rules with contextual score tuning     │
│     ├── detect/config.py    ─── Nginx, OpenSSL, HAProxy, SSH config parser       │
│     ├── scan/dependency.py  ─── Manifest parser (pom.xml, package.json, go.mod) │
│     ├── scan/binary.py      ─── String table & linkage analyzer for binaries     │
│     └── scan/container.py   ─── Dockerfile & Kubernetes manifest scanner         │
│                                                                                  │
│  2. NORMALIZATION & CANONICAL DATA MODEL (ecdat/models.py)                       │
│     ├── Deduplication Engine: Raw detections ──► Canonical `CryptoAsset`         │
│     └── Deterministic Hashing: SHA-256(algo, file, line, type) ──► `asset_id`    │
│                                                                                  │
│  3. GRAPH TOPOLOGY & BLAST RADIUS (ecdat/graph.py + analyze/impact.py)           │
│     ├── Directed Multi-Tier Graph (Apps ◄── Services ◄── Repos ◄── Assets)       │
│     ├── Traversal BFS/DFS: Centrality scoring & dependency gating reach          │
│     └── Blast Radius Calculation: Directly & indirectly impacted consumers       │
│                                                                                  │
│  4. DUAL-AXIS RISK & TIMELINE ENGINE (ecdat/analyze/)                            │
│     ├── analyze/risk.py     ─── Independent Classical Risk vs Quantum Exposure   │
│     ├── analyze/mosca.py    ─── Mosca Inequality: x (lifetime) + y (effort) > z │
│     ├── analyze/agility.py  ─── Cryptographic Agility & Interoperability check   │
│     ├── analyze/recommend.py─── Standards-backed strategies (FIPS 203, NIST SP)  │
│     ├── analyze/decide.py   ─── 5 Frozen Decisions (RETAIN/HARDEN/UPGRADE/etc)   │
│     └── analyze/roadmap.py  ─── Phase 0–3+ Gantt scheduling & Enablement Waves   │
│                                                                                  │
│  5. STANDARDS COMPLIANCE & OUTPUTS (ecdat/cbom/ + export.py)                     │
│     ├── CycloneDX 1.6 CBOM Builder with automated schema validation              │
│     └── Zero-Knowledge Redaction: Private key blocks and snippets purged         │
└──────────────────────────────────────────────────────────────────────────────────┘
```

---

## 🔄 How It Works: The 7-Stage Pipeline

```
Filesystem & Configs ──► Discovery ──► Canonical Modeling ──► Dual-Axis Risk ──► Graph Blast Radius ──► Phased Roadmap ──► CycloneDX CBOM
```

1. **Discovery & Multi-Surface Parsing:** Scans code, certificates, binaries, configs, and package manifests.
2. **Canonical Asset Modeling:** Deduplicates raw detections into unified `CryptoAsset` models (~99 fields) with deterministic SHA-256 IDs.
3. **Dual-Axis Assessment:** Evaluates Classical Exploitability (today) and Quantum Exposure (future) independently.
4. **Urgency Modeling:** Evaluates Mosca's Inequality against data lifetime and CRQC threat horizons.
5. **Decision Hierarchy:** Assigns one of 5 frozen executive actions (`RETAIN`, `HARDEN`, `UPGRADE`, `HYBRID`, `PQC-ONLY`).
6. **Graph Impact Analysis:** Computes dependency centrality, blast radius, and unblocking potential.
7. **Phased Roadmap & CBOM Export:** Builds an executable migration schedule and validates CycloneDX 1.6 CBOM artifacts.

---

## ⚖️ The Dual-Axis Risk Model

| Axis | What It Evaluates | Example Findings | Action Triggered |
|---|---|---|---|
| **Classical Risk Axis** | Present-day cryptographic strength against classical supercomputers and cryptanalysis. | MD5 hashing, SHA-1 signatures, RSA-1024, expired certs. | `UPGRADE` / `HARDEN` immediately. |
| **Quantum Exposure Axis** | Vulnerability against quantum algorithms (Shor's and Grover's). | RSA-2048 (Shor broken), ECDSA P-256, AES-128 (halved). | `HYBRID` / `PQC-ONLY` transition. |

---

## ⏱️ Mosca's Urgency Inequality

To protect against **Harvest Now, Decrypt Later (HNDL)** attacks:

$$\text{Urgency Formula: } x + y > z$$

* **$x$ (Data Lifetime):** Number of years data must remain confidential (e.g., 10 years).
* **$y$ (Migration Effort):** Number of years required to re-engineer and deploy new crypto (e.g., 2 years).
* **$z$ (Threat Horizon):** Years until a Cryptographically Relevant Quantum Computer (CRQC) exists (default: 2035 NIST policy anchor).
* **Verdict:** If $x + y > z$ (e.g., $10 + 2 = 12 > 9$), urgency is **Critical / Already-Late**.

---

## 🎯 The 5 Frozen Migration Decisions

| Decision | Meaning & Strategy | Example |
|---|---|---|
| **`RETAIN`** | Already quantum-safe or symmetric with sufficient bit security. No change required. Eliminates wasted engineering spend. | `AES-256-GCM`, `SHA-256`, `ML-KEM-768` |
| **`HARDEN`** | Retain algorithm, but fix parameters, rotation, or lifecycle. | Renewing an expired certificate, expanding key size. |
| **`UPGRADE`** | Replace a classically broken algorithm immediately with modern classical standards. | Replacing `MD5` or `DES` with `SHA-256` / `AES-256`. |
| **`HYBRID`** | Deploy Post-Quantum alongside Classical for backwards compatibility with external peers. | `X25519MLKEM768` hybrid key exchange. |
| **`PQC-ONLY`** | Direct standalone migration to FIPS 203/204 algorithms in closed systems. | `ML-KEM-1024` for internal storage. |

---

## 📂 Project Structure

```
ecdat/
├── backend/                        # Python 3.14+ Analysis Backend
│   ├── ecdat/
│   │   ├── analyze/                # Risk, Mosca, Agility, Decision, Impact & Roadmap
│   │   ├── api/                    # HTTP REST Server & OpenAPI 3.1 Specs
│   │   ├── cbom/                   # CycloneDX 1.6 CBOM Generator & Schema Validator
│   │   ├── detect/                 # AST, Lexical, and Config Pattern Detectors
│   │   ├── knowledge/              # NIST, FIPS, Algorithm & Library Databases
│   │   ├── scan/                   # X.509, Source, Binary, Container & Dependency Scanners
│   │   ├── engine.py               # Core Pipeline Orchestrator
│   │   ├── graph.py                # Directed Dependency Graph Engine
│   │   ├── models.py               # Canonical CryptoAsset Data Model
│   │   └── reports.py              # Dashboard & Executive Report Aggregators
│   └── tests/                      # 344 Unit & Integration Tests (Phases 1–11)
│
├── frontend/                       # Next.js 16 + React 19 Frontend Console
│   ├── src/
│   │   ├── app/(app)/              # All Active Routes (Overview, Scan, Inventory, Risk, etc.)
│   │   ├── components/             # Layouts, Badges, Charts & UI Primitives
│   │   ├── features/               # Dashboard, Inventory, and Scan Feature Suites
│   │   ├── lib/                    # API Client, Queries, Display Helpers, Navigation
│   │   └── types/                  # Strict TypeScript API Data Contracts
│   └── scripts/                    # Automated Verification & Hardcoded Audit Probes
│
└── datasets/
    └── demo/                       # 12 Sample Repositories, X.509 Certs, Binaries & Configs
```

---

## 🚀 Getting Started

### Prerequisites
* **Python 3.10+** (Python 3.14 recommended)
* **Node.js 18+** (Node.js 20+ recommended)
* `git`

### 1. Backend Setup

```bash
# Navigate to backend directory
cd backend

# (Optional) Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Run test suite to verify installation
python3 -m pytest tests/ -v

# Start the API server on port 8787
python3 -m ecdat.api
```
*API will be listening at `http://127.0.0.1:8787` (OpenAPI specs available at `http://127.0.0.1:8787/openapi.json`).*

### 2. Frontend Setup

```bash
# Navigate to frontend directory in a new terminal
cd frontend

# Install dependencies
npm install

# Start the Next.js development server
npm run dev
```
*Open [http://localhost:3000](http://localhost:3000) in your browser.*

---

## 📡 API Reference

| Endpoint | Method | Description |
|---|---|---|
| `/health` | `GET` | Server status, loaded scan ID, and total assets. |
| `/dashboard` | `GET` | Aggregated estate roll-up (headlines, dual-axis distributions, decisions). |
| `/assets` | `GET` | Paginated 42-column cryptographic inventory with search and filters. |
| `/assets/{id}` | `GET` | Single asset record with full cryptographic and business context. |
| `/assets/{id}/evidence` | `GET` | Complete discovery audit trail with detector confidence. |
| `/assets/{id}/risk` | `GET` | Scoring factors, weights, and Mosca inequality calculation. |
| `/assets/{id}/migration` | `GET` | Decision rationale, standards citations, and blockers. |
| `/assets/{id}/impact` | `GET` | Graph blast radius and directly affected applications. |
| `/assets/{id}/graph` | `GET` | Dependency neighborhood subgraph with depth traversal (1–4). |
| `/roadmap` | `GET` | Phased execution plan (Phase 0–3+) and enablement waves. |
| `/cbom` | `GET` | Full CycloneDX 1.6 CBOM document. |
| `/cbom/validation` | `GET` | Official schema conformance validation results. |
| `/scan` | `POST` | Trigger synchronous scan on demo estate or local directory paths. |
| `/exports/{format}` | `GET` | Stream CSV/JSON exports (`assets.csv`, `roadmap.csv`, `impact.csv`, `json`). |

---

## 🧪 Testing & Validation

### Backend Tests
```bash
cd backend
python3 -m pytest tests/
# Result: 344 passed in ~3.8s
```

### Frontend Typecheck & Lint
```bash
cd frontend
npx tsc --noEmit
npx eslint src/ --ext .ts,.tsx --max-warnings=0
node scripts/audit-hardcoded.mjs
# Result: 0 errors, 0 warnings, 0 hardcoded analytical data
```

---

## 📄 License
This project is open-source under the [MIT License](LICENSE).
