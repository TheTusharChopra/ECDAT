"""CycloneDX 1.6 (ECMA-424) CBOM generation -- a pure projection of the canonical model.

This module adds no cryptographic fact. Every value it emits is read off a
`CryptoAsset` or an `Application` that earlier stages already produced, which is what
keeps the canonical asset model the single source of truth (contract: "no feature may
create a competing cryptographic truth").

Two rules give that claim teeth, and both are enforced by tests:

  1. ONE COMPONENT PER CANONICAL RECORD. The generator never synthesises a component
     for something that is not in the inventory. If a crypto asset names a provider
     library that was never discovered as an asset of its own, that provider is
     recorded as a property -- not invented as a component. A dangling `bom-ref` and
     a fabricated component are both ways of growing a second inventory, so neither
     is allowed.

  2. NO SOURCE CODE, NO KEY MATERIAL. Evidence is projected as detector + method +
     matched token + location. Code snippets are deliberately dropped: a CBOM is a
     shareable artefact and §30 forbids source-code exfiltration. For key material,
     `relatedCryptoMaterialProperties.value` is never populated -- the schema has a
     field for the secret and ECDAT leaves it empty on purpose.

Enum vocabularies below are mirrored from the vendored schema rather than imported at
runtime, so generation stays fast. `tests/test_phase10_outputs.py` asserts the mirrors
still match `schema/bom-1.6.schema.json`, so they cannot silently drift.
"""

from __future__ import annotations

import hashlib
from typing import Any, Iterable

from ..models import Application, CryptoAsset, ScanResult

# ======================================================================================
# Constants
# ======================================================================================
BOM_FORMAT = "CycloneDX"
SPEC_VERSION = "1.6"
SCHEMA_URL = "http://cyclonedx.org/schema/bom-1.6.schema.json"

TOOL_NAME = "ECDAT"
TOOL_VENDOR = "ECDAT"
TOOL_VERSION = "0.1.0"

#: Property namespace. CycloneDX reserves the `cdx:` prefix; vendors use their own.
NS = "ecdat:"

# --- enum mirrors (see module docstring; a test asserts these match the schema) -------
PRIMITIVES = frozenset({
    "drbg", "mac", "block-cipher", "stream-cipher", "signature", "hash", "pke", "xof",
    "kdf", "key-agree", "kem", "ae", "combiner", "other", "unknown"})
MODES = frozenset({"cbc", "ecb", "ccm", "gcm", "cfb", "ofb", "ctr", "other", "unknown"})
PADDINGS = frozenset({"pkcs5", "pkcs7", "pkcs1v15", "oaep", "raw", "other", "unknown"})
CRYPTO_FUNCTIONS = frozenset({
    "generate", "keygen", "encrypt", "decrypt", "digest", "tag", "keyderive", "sign",
    "verify", "encapsulate", "decapsulate", "other", "unknown"})
PROTOCOL_TYPES = frozenset({"tls", "ssh", "ipsec", "ike", "sstp", "wpa", "other",
                            "unknown"})
MATERIAL_TYPES = frozenset({
    "private-key", "public-key", "secret-key", "key", "ciphertext", "signature",
    "digest", "initialization-vector", "nonce", "seed", "salt", "shared-secret", "tag",
    "additional-data", "password", "credential", "token", "other", "unknown"})
MATERIAL_STATES = frozenset({"pre-activation", "active", "suspended", "deactivated",
                             "compromised", "destroyed"})
ASSET_TYPES = frozenset({"algorithm", "certificate", "protocol",
                         "related-crypto-material"})

#: Never emitted, at any confidence, for any asset. The schema offers `value` for the
#: secret itself; populating it would turn a shareable inventory into a key leak.
FORBIDDEN_MATERIAL_FIELDS = ("value",)

REDACTION_NOTE = ("Key material is inventoried by metadata only. ECDAT never writes a "
                  "key value into a CBOM.")
EVIDENCE_NOTE = ("Evidence is projected as detector, method, matched token and "
                 "location. Source snippets are withheld from exported artefacts.")


# ======================================================================================
# Helpers
# ======================================================================================
def _enum(value: Any, allowed: frozenset[str], fallback: str | None = None) -> str | None:
    """Return `value` only if the schema accepts it, else `fallback` (or nothing).

    Emitting an out-of-vocabulary string would produce a CBOM that fails validation in
    every other tool, so an unrecognised value degrades to the schema's own `unknown`
    rather than being smuggled through.
    """
    if value is None:
        return fallback
    v = str(value).strip().lower()
    if v in allowed:
        return v
    return fallback


def _clean(d: dict[str, Any]) -> dict[str, Any]:
    """Drop keys whose value is None, "" or []. CycloneDX prefers absent over empty,
    and `additionalProperties: false` makes a stray null an outright validation error."""
    return {k: v for k, v in d.items()
            if v is not None and v != "" and v != [] and v != {}}


def _prop(name: str, value: Any) -> dict[str, str] | None:
    """A namespaced name-value property. `value` must be a string per the schema."""
    if value is None or value == "" or value == []:
        return None
    if isinstance(value, bool):
        value = "true" if value else "false"
    elif isinstance(value, (list, tuple)):
        value = ", ".join(str(v) for v in value)
    return {"name": f"{NS}{name}", "value": str(value)}


def _props(pairs: Iterable[tuple[str, Any]]) -> list[dict[str, str]]:
    out = []
    for name, value in pairs:
        p = _prop(name, value)
        if p:
            out.append(p)
    return out


def _enum_value(v: Any) -> Any:
    """Unwrap an Enum to its value, pass everything else through."""
    return v.value if hasattr(v, "value") else v


def serial_number(seed: str) -> str:
    """A deterministic, well-formed URN UUID derived from `seed`.

    Deliberately not `uuid4`: two runs over the same estate must produce byte-identical
    output so a CBOM can be diffed across scans. Deliberately not `uuid5` either, which
    would put SHA-1 in the pipeline of a post-quantum tool for no reason. The layout is
    version 8 -- RFC 9562's "custom format" -- because that is what this actually is.
    """
    h = hashlib.sha256(seed.encode("utf-8")).hexdigest()
    b = bytearray(bytes.fromhex(h[:32]))
    b[6] = (b[6] & 0x0F) | 0x80          # version 8 (custom)
    b[8] = (b[8] & 0x3F) | 0x80          # RFC 9562 variant
    x = b.hex()
    return f"urn:uuid:{x[:8]}-{x[8:12]}-{x[12:16]}-{x[16:20]}-{x[20:32]}"


# ======================================================================================
# cryptoProperties
# ======================================================================================
def asset_type_of(a: CryptoAsset) -> str | None:
    """Which of the four CycloneDX crypto asset types this canonical asset is.

    Returns None when the asset is a package/provider with no cryptographic content of
    its own -- those become `library` components, not `cryptographic-asset` components,
    because a library that merely *offers* crypto is not itself a cryptographic asset.
    """
    kind = _enum_value(a.asset_type)
    if kind == "certificate":
        return "certificate"
    if kind == "key-material":
        return "related-crypto-material"
    if kind == "protocol-config":
        return "protocol"
    if a.algorithm:
        return "algorithm"
    if kind in ("library", "dependency", "container-package"):
        return None
    if a.protocol:
        return "protocol"
    return "algorithm"


def _algorithm_properties(a: CryptoAsset) -> dict[str, Any]:
    functions = [f for f in (a.crypto_functions or [])
                 if _enum(f, CRYPTO_FUNCTIONS) is not None]
    props: dict[str, Any] = {
        "primitive": _enum(a.primitive, PRIMITIVES, "unknown"),
        # Free-form in the schema. Emitted verbatim from the canonical field rather
        # than re-derived, even where estate data is inconsistent (e.g. `P-256` and
        # `prime256v1` for one curve) -- normalising here would create a second,
        # disagreeing version of a fact the canonical model owns.
        "curve": a.curve,
        "mode": _enum(a.mode, MODES),
        "padding": _enum(a.padding, PADDINGS),
        "cryptoFunctions": sorted(set(functions)) or None,
        "classicalSecurityLevel": a.security_strength,
    }
    if a.key_size:
        props["parameterSetIdentifier"] = str(a.key_size)
    elif a.algorithm_label and a.pqc_readiness == "native":
        # ML-KEM-768 and friends carry their parameter set in the name itself.
        props["parameterSetIdentifier"] = a.algorithm_label
    # `nistQuantumSecurityLevel` is the NIST PQC security *category* (1-5). ECDAT does
    # not carry a category for every algorithm, and inventing one would be a fabricated
    # standards claim, so the field is emitted only when the knowledge base supplied a
    # quantum strength that maps to a category.
    level = _nist_category(a)
    if level is not None:
        props["nistQuantumSecurityLevel"] = level
    return _clean(props)


_NIST_CATEGORY = {
    # NIST PQC security categories, from the FIPS 203/204/205 parameter tables.
    "ml-kem-512": 1, "ml-kem-768": 3, "ml-kem-1024": 5,
    "ml-dsa-44": 2, "ml-dsa-65": 3, "ml-dsa-87": 5,
    "slh-dsa-sha2-128s": 1, "slh-dsa-sha2-128f": 1,
    "slh-dsa-sha2-192s": 3, "slh-dsa-sha2-192f": 3,
    "slh-dsa-sha2-256s": 5, "slh-dsa-sha2-256f": 5,
}


def _nist_category(a: CryptoAsset) -> int | None:
    for key in (a.algorithm, a.algorithm_label):
        if key and str(key).strip().lower() in _NIST_CATEGORY:
            return _NIST_CATEGORY[str(key).strip().lower()]
    return None


def _certificate_properties(a: CryptoAsset) -> dict[str, Any]:
    # `signatureAlgorithmRef` and `subjectPublicKeyRef` are refLinkTypes: they must
    # point at a component that exists in this BOM. ECDAT does not mint a separate
    # component for a certificate's signature algorithm, so the refs are omitted and
    # the algorithm name is carried as a property instead. An omitted ref is honest;
    # a dangling one is not.
    return _clean({
        "subjectName": a.certificate_subject,
        "issuerName": a.certificate_issuer,
        "notValidBefore": a.certificate_not_before,
        "notValidAfter": a.certificate_expiry,
        "certificateFormat": "X.509" if a.certificate_subject else None,
        "certificateExtension": _cert_extension(a.file),
    })


def _cert_extension(path: str | None) -> str | None:
    if not path or "." not in path:
        return None
    ext = path.rsplit(".", 1)[-1].lower()
    return ext if ext in ("pem", "crt", "cer", "der", "p7b", "pfx", "p12") else None


def _protocol_properties(a: CryptoAsset) -> dict[str, Any]:
    return _clean({
        "type": _enum(a.protocol, PROTOCOL_TYPES, "unknown"),
        "version": a.protocol_version,
    })


def _material_properties(a: CryptoAsset) -> dict[str, Any]:
    """Key-material metadata. `value` is never populated -- see FORBIDDEN_MATERIAL_FIELDS.

    The `state` is read from the canonical asset where discovery established one. A key
    found committed to a repository is reported as `compromised`, which is a factual
    statement about its exposure, not a severity judgement.
    """
    exposed = "key-material-exposure" in (a.tags or []) or "key-material-exposure" in (
        a.risk_factors or {})
    return _clean({
        "type": _enum(a.primitive, MATERIAL_TYPES, "private-key"),
        "state": "compromised" if exposed else None,
        "size": a.key_size,
        "expirationDate": a.certificate_expiry,
    })


def crypto_properties(a: CryptoAsset) -> dict[str, Any] | None:
    kind = asset_type_of(a)
    if kind is None:
        return None
    cp: dict[str, Any] = {"assetType": kind}
    if a.oid:
        cp["oid"] = a.oid
    if kind == "algorithm":
        cp["algorithmProperties"] = _algorithm_properties(a)
    elif kind == "certificate":
        cp["certificateProperties"] = _certificate_properties(a)
    elif kind == "protocol":
        cp["protocolProperties"] = _protocol_properties(a)
    elif kind == "related-crypto-material":
        cp["relatedCryptoMaterialProperties"] = _material_properties(a)
    return _clean(cp)


# ======================================================================================
# Evidence
# ======================================================================================
def component_evidence(a: CryptoAsset) -> dict[str, Any] | None:
    """Project the evidence trail into `componentEvidence.occurrences`.

    Snippets are excluded by design (see EVIDENCE_NOTE). What survives is enough for an
    auditor to re-run the finding by hand: which detector fired, by what method, on what
    token, at what location.
    """
    occurrences: list[dict[str, Any]] = []
    seen: set[tuple] = set()
    for ev in a.evidence or []:
        location = ev.location or a.file
        if not location:
            continue
        context = " | ".join(x for x in (
            f"detector={ev.detector}" if ev.detector else "",
            f"method={ev.method}" if ev.method else "",
            f"evidence={_enum_value(ev.evidence_type)}" if ev.evidence_type else "",
            f"confidence={_enum_value(ev.confidence)}" if ev.confidence else "",
            f"matched={ev.matched}" if ev.matched else "",
        ) if x)
        entry = _clean({
            "location": location,
            "line": a.line if location == a.file else None,
            "symbol": ev.matched or None,
            "additionalContext": context or None,
        })
        key = tuple(sorted(entry.items()))
        if key in seen:
            continue
        seen.add(key)
        occurrences.append(entry)

    if not occurrences and a.file:
        occurrences.append(_clean({"location": a.file, "line": a.line}))
    if not occurrences:
        return None
    return {"occurrences": occurrences}


# ======================================================================================
# Components
# ======================================================================================
def _asset_properties(a: CryptoAsset) -> list[dict[str, str]]:
    """ECDAT's own analysis, namespaced so a consumer can tell it from spec fields.

    `business-context-source` is deliberately included: a downstream reader must be able
    to see that a criticality of "mission-critical" was operator-declared rather than an
    ECDAT default (§12/§36 -- never represent an assumption as a discovered fact).
    """
    pairs: list[tuple[str, Any]] = [
        ("asset-id", a.asset_id),
        ("asset-type", _enum_value(a.asset_type)),
        ("algorithm", a.algorithm_label or a.algorithm),
        ("algorithm-family", a.algorithm_family),
        ("cryptographic-role", a.cryptographic_role),
        # provenance / confidence
        ("confidence", _enum_value(a.confidence)),
        ("confidence-score", round(a.confidence_score, 3) if a.confidence_score else None),
        ("evidence-type", _enum_value(a.evidence_type)),
        ("detectors", sorted(set(a.detectors or []))),
        ("provenance", a.provenance),
        ("duplicate-count", a.duplicate_count if a.duplicate_count > 1 else None),
        # dual-axis assessment
        ("classical-risk", _enum_value(a.classical_risk)),
        ("classical-security-status", a.classical_security_status),
        ("quantum-exposure", _enum_value(a.quantum_exposure)),
        ("quantum-class", a.quantum_class),
        ("quantum-vulnerable", a.quantum_vulnerable),
        # urgency
        ("mosca-urgency", a.mosca_urgency),
        ("mosca-gap-years", a.mosca_gap_years),
        ("priority", a.migration_priority),
        ("priority-band", a.priority_band),
        # decision (two levels, never collapsed)
        ("migration-decision", _enum_value(a.migration_decision)),
        ("recommended-strategy", a.recommended_strategy),
        ("recommended-pqc", a.recommended_pqc),
        ("recommended-hybrid", a.recommended_hybrid),
        ("decision-blocked-on", a.decision_blocked_on),
        ("standards", sorted(set(a.recommendation_citations or []))),
        # migration shape
        ("migration-effort", _enum_value(a.migration_effort)),
        ("migration-months", a.migration_months),
        ("crypto-agility", _enum_value(a.crypto_agility)),
        ("interoperability", _enum_value(a.interoperability)),
        ("pqc-readiness", a.pqc_readiness),
        ("dependency-centrality", a.dependency_centrality or None),
        ("migration-blockers", a.migration_blockers),
        # business context
        ("application", a.application),
        ("owner", a.owner),
        ("business-unit", a.business_unit),
        ("business-criticality", _enum_value(a.business_criticality)),
        ("data-classification", _enum_value(a.data_classification)),
        ("exposure", _enum_value(a.exposure)),
        ("internet-exposed", a.internet_exposed),
        ("business-context-source", a.context_source),
        ("compliance-tags", sorted(set(a.compliance_tags or []))),
        ("tags", sorted(set(a.tags or []))),
        ("triage-state", _enum_value(a.triage_state)),
    ]
    props = _props(pairs)
    if asset_type_of(a) == "related-crypto-material":
        props.append({"name": f"{NS}redaction", "value": REDACTION_NOTE})
    return props


def asset_component(a: CryptoAsset) -> dict[str, Any]:
    """One canonical asset -> exactly one component."""
    cp = crypto_properties(a)
    comp: dict[str, Any] = {
        "type": "cryptographic-asset" if cp else "library",
        "bom-ref": a.asset_id,
        "name": a.asset_name,
        "version": a.library_version if not cp else None,
        "description": a.usage or None,
        "group": a.library if cp and a.library else None,
        "purl": _purl(a),
        "evidence": component_evidence(a),
        "cryptoProperties": cp,
        "properties": _asset_properties(a),
    }
    return _clean(comp)


def _purl(a: CryptoAsset) -> str | None:
    """A package URL, only where the canonical asset actually carries package identity."""
    if not a.package:
        return None
    eco = {"python": "pypi", "javascript": "npm", "typescript": "npm", "java": "maven",
           "go": "golang", "ruby": "gem", "rust": "cargo"}.get(
        (a.language or "").lower())
    if not eco:
        return None
    name = a.package.strip().lower()
    return f"pkg:{eco}/{name}@{a.library_version}" if a.library_version else \
        f"pkg:{eco}/{name}"


def application_component(app: Application) -> dict[str, Any]:
    """An application from the operator-declared estate manifest.

    Business context, not a cryptographic fact -- which is why this is allowed to be a
    component without breaking the single-source-of-truth rule.
    """
    return _clean({
        "type": "application",
        "bom-ref": app.app_id,
        "name": app.name,
        "description": app.description or None,
        "properties": _props([
            ("owner", app.owner),
            ("business-unit", app.business_unit),
            ("environment", app.environment),
            ("criticality", _enum_value(app.criticality)),
            ("exposure", _enum_value(app.exposure)),
            ("data-classification", _enum_value(app.data_classification)),
            ("data-lifetime-years", app.data_lifetime_years),
            ("business-function", app.business_function),
            ("services", sorted(set(app.services or []))),
            ("repositories", sorted(set(app.repositories or []))),
            ("regulatory", sorted(set(app.regulatory or []))),
            ("context-source", app.context_source),
        ]),
    })


# ======================================================================================
# Dependencies
# ======================================================================================
def dependencies(assets: list[CryptoAsset], applications: list[Application],
                 root_ref: str) -> list[dict[str, Any]]:
    """The dependency graph, restricted to refs that exist as components.

    Three relationships are expressed, all read off canonical fields:

      * estate -> applications, application -> its assets  (containment)
      * library asset `provides` the crypto assets it implements  (CycloneDX 1.6
        `provides`, which is exactly the "this library implements that algorithm"
        relationship a CBOM consumer needs)
      * certificate -> its issuer  (PKI chain, via issuer/subject matching)

    A relationship whose other end was never discovered is dropped rather than pointed
    at a synthesised component.
    """
    refs = {a.asset_id for a in assets} | {app.app_id for app in applications}
    by_app: dict[str, list[str]] = {}
    for a in assets:
        if a.application and a.application in refs:
            by_app.setdefault(a.application, []).append(a.asset_id)

    # library name -> the asset that *is* that library, when one was discovered
    provider_asset: dict[str, str] = {}
    for a in assets:
        if crypto_properties(a) is None and (a.library or a.package):
            for key in (a.library, a.package, a.asset_name):
                if key:
                    provider_asset.setdefault(str(key).strip().lower(), a.asset_id)
    provides: dict[str, list[str]] = {}
    for a in assets:
        if not a.library or crypto_properties(a) is None:
            continue
        owner = provider_asset.get(str(a.library).strip().lower())
        if owner and owner != a.asset_id:
            provides.setdefault(owner, []).append(a.asset_id)

    # certificate subject -> ref, for chain edges
    by_subject: dict[str, str] = {}
    for a in assets:
        if a.certificate_subject:
            by_subject.setdefault(a.certificate_subject.strip(), a.asset_id)

    out: list[dict[str, Any]] = [{
        "ref": root_ref,
        "dependsOn": sorted(app.app_id for app in applications),
    }]
    for app in applications:
        out.append(_clean({"ref": app.app_id,
                           "dependsOn": sorted(set(by_app.get(app.app_id, [])))}))
    for a in assets:
        entry: dict[str, Any] = {"ref": a.asset_id}
        issuer = (a.certificate_issuer or "").strip()
        if issuer and not a.certificate_self_signed:
            parent = by_subject.get(issuer)
            if parent and parent != a.asset_id:
                entry["dependsOn"] = [parent]
        if a.asset_id in provides:
            entry["provides"] = sorted(set(provides[a.asset_id]))
        if len(entry) > 1:
            out.append(entry)
    return [e for e in out if e.get("dependsOn") or e.get("provides")]


# ======================================================================================
# Metadata
# ======================================================================================
def _metadata_properties(result: ScanResult, extra: dict[str, Any] | None,
                         demo: bool, notice: str) -> list[dict[str, str]]:
    """Estate-level labelling, including the honesty legend the contract requires."""
    stats = result.stats
    pairs: list[tuple[str, Any]] = [
        ("scan-id", result.scan_id),
        ("scan-target", result.target),
        ("policy", result.policy),
        ("asset-count", len(result.assets)),
        ("application-count", len(result.applications)),
        # Coverage, so a reader can see what the inventory is drawn from rather than
        # assuming it is exhaustive. Field names track models.ScanStats exactly.
        ("repositories", stats.repositories),
        ("files-seen", stats.files_seen),
        ("files-analyzed", stats.files_analyzed),
        ("files-skipped", stats.skipped_files),
        ("certificates-parsed", stats.certificates),
        ("containers-parsed", stats.containers),
        ("binaries-parsed", stats.binaries),
        ("raw-detections", stats.raw_detections),
        ("deduplicated", stats.deduplicated),
        ("scan-errors", len(stats.errors) if stats.errors else None),
        ("scan-duration-ms", stats.duration_ms),
        ("dataset", "DEMO -- synthetic estate" if demo else "operator-supplied"),
        ("evidence-policy", EVIDENCE_NOTE),
        ("key-material-policy", REDACTION_NOTE),
        ("derivation",
         "All cryptoProperties are projected from ECDAT's canonical cryptographic asset "
         "model. Values under the ecdat: namespace are ECDAT analysis, not CycloneDX "
         "specification fields."),
        ("assessment-status",
         "Migration decisions and risk bands are ECDAT-derived recommendations. They are "
         "not a compliance certification and not an assertion of standards conformance."),
        ("business-context-note",
         "Business context is operator-declared. Assets carry ecdat:business-context-source "
         "so a defaulted value can be told apart from a declared one."),
    ]
    if notice:
        pairs.append(("notice", notice))
    for k, v in (extra or {}).items():
        pairs.append((k, v))
    return _props(pairs)


def _metadata(result: ScanResult, timestamp: str, root_ref: str, estate_name: str,
              demo: bool, notice: str, extra: dict[str, Any] | None) -> dict[str, Any]:
    return _clean({
        "timestamp": timestamp,
        "lifecycles": [{"phase": "operations"}],
        "tools": {"components": [{
            "type": "application",
            "name": TOOL_NAME,
            "version": TOOL_VERSION,
            "publisher": TOOL_VENDOR,
            "description": "Enterprise Cryptographic Discovery & Analysis Tool",
        }]},
        "component": _clean({
            "type": "application",
            "bom-ref": root_ref,
            "name": estate_name,
            "description": "Cryptographic estate inventoried by ECDAT",
        }),
        "properties": _metadata_properties(result, extra, demo, notice),
    })


# ======================================================================================
# Entry point
# ======================================================================================
def build(result: ScanResult, estate_name: str = "", demo: bool = False,
          notice: str = "", timestamp: str | None = None,
          properties: dict[str, Any] | None = None,
          bom_version: int = 1) -> dict[str, Any]:
    """Produce a CycloneDX 1.6 CBOM document from a completed scan.

    Deterministic: the serial number is derived from the scan identity and the timestamp
    defaults to the scan's own `started_at`, so re-generating from the same result yields
    byte-identical JSON and two scans can be diffed.
    """
    assets = list(result.assets)
    applications = list(result.applications)
    root_ref = f"estate:{result.scan_id}"
    ts = timestamp or result.started_at

    components = [application_component(app) for app in applications]
    components.extend(asset_component(a) for a in assets)

    doc = {
        "$schema": SCHEMA_URL,
        "bomFormat": BOM_FORMAT,
        "specVersion": SPEC_VERSION,
        "serialNumber": serial_number(f"{result.scan_id}|{result.target}|{len(assets)}"),
        "version": bom_version,
        "metadata": _metadata(result, ts, root_ref,
                              estate_name or result.target or "Cryptographic estate",
                              demo, notice, properties),
        "components": components,
        "dependencies": dependencies(assets, applications, root_ref),
    }
    return doc


def counts(doc: dict[str, Any]) -> dict[str, int]:
    """A small tally, for progress messages and tests."""
    comps = doc.get("components", [])
    out: dict[str, int] = {
        "components": len(comps),
        "cryptographic_assets": sum(
            1 for c in comps if c.get("type") == "cryptographic-asset"),
        "libraries": sum(1 for c in comps if c.get("type") == "library"),
        "applications": sum(1 for c in comps if c.get("type") == "application"),
        "dependencies": len(doc.get("dependencies", [])),
        "with_evidence": sum(1 for c in comps if c.get("evidence")),
    }
    for kind in sorted(ASSET_TYPES):
        out[kind.replace("-", "_")] = sum(
            1 for c in comps
            if c.get("cryptoProperties", {}).get("assetType") == kind)
    return out
