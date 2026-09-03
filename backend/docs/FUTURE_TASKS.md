# ECDAT — deferred engineering tasks

Known, reproduced issues that are deliberately **not** fixed yet, with the reason for
deferral and the intended fix. Each entry states how it was observed so a future
implementer can reproduce it before changing anything.

Status vocabulary: `OPEN` (reproduced, unfixed) · `SCOPED` (fix agreed) · `DONE`.

---

## NORM-001 — Elliptic-curve names are not normalised to a canonical spelling

**Status:** OPEN · **Raised:** 2026-08-24 (during Phase 11 API) · **Area:** `normalize.py`,
`detect/`, `scan/x509.py`, `knowledge/algorithms.py`

### What was observed

The demo estate carries five distinct spellings across 11 assets, three of which denote
**the same curve** (NIST P-256 = secp256r1 = prime256v1):

| spelling      | count | example asset            |
|---------------|-------|--------------------------|
| `prime256v1`  | 2     | certificate / ecdsa      |
| `P-256`       | 1     | source-finding / ecdsa   |
| `P256`        | 1     | source-finding / ecdh    |
| `secp384r1`   | 3     | source-finding           |
| `curve25519`  | 4     | source-finding           |

Reproduce:

```python
from ecdat.api.service import Api
api = Api(); api.request("POST", "/scan", {"demo": True})
print({a.curve for a in api.engine.result.assets if a.curve})
```

### Why it happens

Three detectors each emit the curve in the vocabulary of the source they read, which is
correct behaviour for a detector — the evidence should say what was actually found:

- `detect/python_ast.py:165` `_CURVE_CLASSES` — `cryptography` class names → SEC form
  (`SECP256R1` → `secp256r1`).
- `detect/lexical.py:153` `_CURVE` — captures the literal source text, so whatever the
  developer wrote (`prime256v1`, `P-256`, `P256`) survives verbatim.
- `scan/x509.py:73` `CURVE_OIDS` — curve OIDs → OpenSSL form; the comment at line 75
  already notes `1.2.840.10045.3.1.7` is `prime256v1 == P-256 == secp256r1`.

No layer downstream reconciles them, because doing so at the point of use would create a
second, disagreeing version of a fact the canonical model owns. `cbom/generate.py:176-179`
makes that choice explicitly and documents it.

### Actual impact today

Mostly absorbed, with one real gap and one latent correctness risk:

- **Absorbed:** `knowledge/algorithms.py:570` `_CURVE_STRENGTH` is alias-tolerant, holding
  separate entries for `secp256r1` / `prime256v1` / `p-256` (all 128) and
  `curve25519` / `x25519` / `ed25519` (all 128). So classical strength, and therefore risk
  and the migration decision, are **not** currently wrong for those spellings.
- **Real gap (benign in the demo):** the un-hyphenated `P###` spellings (`P256`, `P192`,
  `P521`, …) are absent from that table, so `curve_strength("P256")` returns `None`.
  `strength_for` then falls back to the algorithm's `default_strength`
  (`algorithms.py:strength_for`). For the one `P256` demo asset that fallback yields 128,
  which happens to be P-256's true strength, so nothing is visibly wrong today —
  confirmed: that asset reports `security_strength=128`, `quantum_class=shor_broken`.
- **Latent correctness risk (not in the demo):** the same fallback is wrong for any curve
  whose real strength is not the algorithm default. Reproduced:
  `strength_for(get("ecdsa"), curve="P192")` → **128** (should be 96 — security
  *overstated* for a weak curve); `curve="P521"` → **128** (should be 256 — understated).
  The hyphenated forms resolve correctly (`P-192` → 96, `P-521` → 256). No demo asset
  uses these spellings, so this is latent, but it is the reason the fix is a correctness
  task and not merely cosmetic normalisation.
- **Latent (UI):** any consumer that groups or facets by `curve` sees one P-256 estate
  split into three buckets. A live concern for the Phase 12 UI, not for the API, which
  passes the canonical value through unchanged.

The quantum verdict is unaffected in every case above: ECDH/ECDSA are `shor_broken`
from their algorithm family regardless of curve spelling or strength.

### Intended fix (do NOT implement inside the API or in a detector)

1. Add a canonical curve registry and resolver to `normalize.py` — one alias table,
   SEC names (`secp256r1`, `secp384r1`, `x25519`) as the canonical form, since that is
   what the PQ/T hybrid identifiers in `knowledge/algorithms.py:497` already use.
2. Populate a new canonical field (e.g. `curve_canonical`) during normalisation and
   **retain `curve` verbatim** as the as-found value. Non-destructive, matching the
   Phase 1 rule on preserving aliases rather than renaming.
3. Point `_CURVE_STRENGTH` lookups at the canonical form, which closes the `P###` gap
   as a side effect and removes the need for the alias entries to be maintained by hand.
   Consider also making `strength_for` distinguish "no curve given" from "curve given but
   unrecognised" — silently falling back to `default_strength` for an unknown curve is
   what turns a spelling miss into a wrong strength number.
4. Tests: every spelling in the table above resolves to one canonical name; `curve`
   still reports what was found; `curve_strength` agrees across all synonyms of a curve;
   and specifically `P192`/`P-192` → 96 and `P521`/`P-521` → 256 through `strength_for`.

**Deferred because** it touches the normalisation layer that discovery, CBOM, and risk all
read, so it belongs in its own change with its own tests — not folded into an API phase
whose contract is to project canonical values without altering them.
