"""ECDAT normalized data model.

Deliberately stdlib-only (dataclasses + a hand-rolled validation pass) so the
analysis core has zero third-party dependencies and can be dropped into an
air-gapped environment. `to_pydantic_schema()` emits the equivalent JSON Schema
for the FastAPI adapter in `ecdat.api`.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field, fields
from datetime import date, datetime
from enum import Enum
from typing import Any


# ======================================================================================
# Enumerations
# ======================================================================================
class AssetType(str, Enum):
    SOURCE_FINDING = "source-finding"
    CERTIFICATE = "certificate"
    PROTOCOL_CONFIG = "protocol-config"
    LIBRARY = "library"
    DEPENDENCY = "dependency"
    CONTAINER_PACKAGE = "container-package"
    BINARY_ARTIFACT = "binary-artifact"
    KEY_MATERIAL = "key-material"
    HARDWARE_MODULE = "hardware-module"
    CLOUD_SERVICE = "cloud-service"


class Confidence(str, Enum):
    """Evidence strength. Drives triage order and is never silently upgraded."""

    HIGH = "high"      # structured/parsed evidence: AST call, parsed X.509, manifest
    MEDIUM = "medium"  # strong contextual evidence: crypto API on the same line
    LOW = "low"        # lexical/pattern evidence only

    @property
    def weight(self) -> float:
        return {"high": 1.0, "medium": 0.72, "low": 0.42}[self.value]


class Role(str, Enum):
    """Canonical cryptographic role vocabulary (frozen contract §5).

    Deliberately finer-grained than "signature": a key used only to *verify* is a
    different migration problem from one used to *sign*. A verifier must accept the
    new algorithm before any signer can emit it, which inverts the rollout order.
    """

    DIGITAL_SIGNATURE = "digital-signature"
    SIGNATURE_VERIFICATION = "signature-verification"
    KEY_ESTABLISHMENT = "key-establishment"
    KEY_TRANSPORT = "key-transport"
    ENCRYPTION = "encryption"
    DECRYPTION = "decryption"
    AUTHENTICATION = "authentication"
    CERTIFICATE_VALIDATION = "certificate-validation"
    HASHING = "hashing"
    KEY_DERIVATION = "key-derivation"
    MESSAGE_AUTHENTICATION = "message-authentication"
    UNKNOWN = "unknown"

    @property
    def is_signature_family(self) -> bool:
        return self in (Role.DIGITAL_SIGNATURE, Role.SIGNATURE_VERIFICATION,
                        Role.AUTHENTICATION, Role.CERTIFICATE_VALIDATION)

    @property
    def is_key_establishment_family(self) -> bool:
        return self in (Role.KEY_ESTABLISHMENT, Role.KEY_TRANSPORT)

    @property
    def is_symmetric_family(self) -> bool:
        return self in (Role.ENCRYPTION, Role.DECRYPTION, Role.HASHING,
                        Role.KEY_DERIVATION, Role.MESSAGE_AUTHENTICATION)


class MigrationDecision(str, Enum):
    """The FROZEN five outcomes (contract §4). No sixth value may be added.

    The specific action lives in `recommended_strategy`; this enum is the coarse,
    stable decision an executive or programme tracker consumes.
    """

    RETAIN = "RETAIN"          # no change needed; includes "no PQC required"
    HARDEN = "HARDEN"          # same primitive, safer parameters/config/handling
    UPGRADE = "UPGRADE"        # replace a broken/legacy mechanism, classically
    HYBRID = "HYBRID"          # PQ/T hybrid: PQC alongside a classical mechanism
    PQC_ONLY = "PQC-ONLY"      # standalone post-quantum mechanism

    @property
    def rank(self) -> int:
        return {"RETAIN": 0, "HARDEN": 1, "UPGRADE": 2,
                "HYBRID": 3, "PQC-ONLY": 4}[self.value]


class CryptoAgility(str, Enum):
    """How easily this asset's algorithm can be changed (contract §18)."""

    HIGH = "high"        # negotiated or configuration-driven; no rebuild
    MEDIUM = "medium"    # provider abstraction, but a redeploy is required
    LOW = "low"          # hard-coded, vendored, or binary-only

    @property
    def score(self) -> int:
        return {"high": 1, "medium": 2, "low": 3}[self.value]


class Interoperability(str, Enum):
    """Whether peers constrain what this asset may negotiate (contract §20).

    This is the input that decides HYBRID vs PQC-ONLY: an asset that must remain
    interoperable with third parties cannot unilaterally go PQC-only.
    """

    OPEN = "open"                # closed ecosystem, both ends under our control
    NEGOTIATED = "negotiated"    # protocol negotiates; hybrid degrades gracefully
    CONSTRAINED = "constrained"  # external peers/CA/vendor pin the mechanism

    @property
    def requires_hybrid(self) -> bool:
        return self in (Interoperability.NEGOTIATED, Interoperability.CONSTRAINED)


class RemediationStatus(str, Enum):
    """Migration progress lifecycle (contract §30). Lives on the canonical asset."""

    DETECTED = "detected"
    RECOMMENDED = "recommended"
    ACCEPTED = "accepted"
    IN_PROGRESS = "in-progress"
    MIGRATED = "migrated"
    VERIFIED = "verified"

    @property
    def order(self) -> int:
        return ["detected", "recommended", "accepted", "in-progress",
                "migrated", "verified"].index(self.value)


class EvidenceType(str, Enum):
    """What kind of proof underpins a finding (contract §10)."""

    SOURCE_API = "source-api"              # resolved AST call to a crypto API
    SOURCE_LEXICAL = "source-lexical"      # pattern match in source text
    CONFIG_DIRECTIVE = "config-directive"  # declarative configuration
    CERTIFICATE = "certificate"            # parsed X.509 structure
    MANIFEST = "manifest"                  # declared dependency
    BINARY_LINKAGE = "binary-linkage"      # dynamic linkage table
    BINARY_SYMBOL = "binary-symbol"        # symbol/import table
    BINARY_STRING = "binary-string"        # string literal only
    CONTAINER_PACKAGE = "container-package"
    KEY_MATERIAL = "key-material"


# Maps a detector's `method` string onto the canonical evidence taxonomy.
METHOD_TO_EVIDENCE_TYPE: dict[str, EvidenceType] = {
    "ast-call": EvidenceType.SOURCE_API,
    "regex+context": EvidenceType.SOURCE_LEXICAL,
    "regex": EvidenceType.SOURCE_LEXICAL,
    "config-directive": EvidenceType.CONFIG_DIRECTIVE,
    "config-cipher-suite": EvidenceType.CONFIG_DIRECTIVE,
    "x509-parse": EvidenceType.CERTIFICATE,
    "pem-scan": EvidenceType.KEY_MATERIAL,
    "manifest": EvidenceType.MANIFEST,
    "dynamic-linkage": EvidenceType.BINARY_LINKAGE,
    "symbol-table": EvidenceType.BINARY_SYMBOL,
    "strings": EvidenceType.BINARY_STRING,
    "base-image": EvidenceType.CONTAINER_PACKAGE,
    "os-package": EvidenceType.CONTAINER_PACKAGE,
    "lang-package": EvidenceType.CONTAINER_PACKAGE,
    "image-file": EvidenceType.CONTAINER_PACKAGE,
    "env-config": EvidenceType.CONFIG_DIRECTIVE,
}


class DataClassification(str, Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    SENSITIVE = "sensitive"
    MISSION_CRITICAL = "mission-critical"

    @property
    def score(self) -> int:
        return {"public": 1, "internal": 2, "confidential": 3,
                "sensitive": 4, "mission-critical": 5}[self.value]


class Exposure(str, Enum):
    ISOLATED = "isolated"
    INTERNAL = "internal"
    CONTROLLED = "controlled"
    EXTERNAL = "external-facing"
    INTERNET_CRITICAL = "internet-facing-critical"

    @property
    def score(self) -> int:
        return {"isolated": 0, "internal": 1, "controlled": 2,
                "external-facing": 3, "internet-facing-critical": 4}[self.value]


class Criticality(str, Enum):
    NON_CRITICAL = "non-critical"
    LOW = "low"
    IMPORTANT = "important"
    HIGH = "high"
    MISSION_CRITICAL = "mission-critical"

    @property
    def score(self) -> int:
        return {"non-critical": 1, "low": 2, "important": 3,
                "high": 4, "mission-critical": 5}[self.value]


class MigrationEffort(str, Enum):
    TRIVIAL = "trivial"
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"
    VERY_HIGH = "very-high"

    @property
    def score(self) -> int:
        return {"trivial": 1, "low": 2, "moderate": 3, "high": 4, "very-high": 5}[self.value]

    @property
    def months(self) -> int:
        """Default migration duration estimate; user-overridable in the simulator."""
        return {"trivial": 3, "low": 6, "moderate": 12, "high": 24, "very-high": 36}[self.value]


class RiskBand(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class TriageState(str, Enum):
    OPEN = "open"
    ACCEPTED = "accepted"
    DISMISSED = "dismissed"
    FALSE_POSITIVE = "false-positive"
    EXCEPTION = "exception"


def risk_band(score: float) -> RiskBand:
    if score >= 80:
        return RiskBand.CRITICAL
    if score >= 60:
        return RiskBand.HIGH
    if score >= 40:
        return RiskBand.MEDIUM
    if score >= 20:
        return RiskBand.LOW
    return RiskBand.INFO


# ======================================================================================
# Evidence
# ======================================================================================
@dataclass
class Evidence:
    """Why ECDAT believes a finding. Every asset carries at least one.

    An asset's confidence is the MAXIMUM over its evidence, but each individual
    piece keeps its own grade so the UI can show that (say) a HIGH-confidence
    certificate parse and a LOW-confidence binary string both point at one asset.
    """

    detector: str                     # detector id, e.g. "python-ast"
    method: str                       # "ast-call" | "x509-parse" | "regex" | "symbol-table"
    location: str                     # file:line, cert path, image layer digest
    evidence_type: EvidenceType | None = None
    confidence: Confidence | None = None
    snippet: str | None = None        # redacted source excerpt
    matched: str | None = None        # exact token matched
    reasoning: str = ""

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {}
        for k, v in asdict(self).items():
            if v is None:
                continue
            d[k] = v.value if isinstance(v, Enum) else v
        return d

    @property
    def proves_execution(self) -> bool:
        """Whether this evidence shows the algorithm is actually reachable.

        Linkage, symbol, string and package evidence do NOT: a binary linking
        libcrypto proves the library is present, not that any particular algorithm
        is invoked. A lexical match counts only at HIGH confidence, which the
        detector grants solely when a recognised cryptographic API appears on the
        same line -- prose and comments never qualify. The distinction is enforced
        here so no downstream module can quietly upgrade presence into use.
        """
        if self.evidence_type in (EvidenceType.SOURCE_API, EvidenceType.CONFIG_DIRECTIVE,
                                  EvidenceType.CERTIFICATE, EvidenceType.KEY_MATERIAL):
            return True
        return (self.evidence_type is EvidenceType.SOURCE_LEXICAL
                and self.confidence is Confidence.HIGH)


# ======================================================================================
# Business context (PART 14 B/C/E) -- supplied by the operator, not guessed
# ======================================================================================
@dataclass
class Application:
    app_id: str
    name: str
    owner: str = "unassigned"
    business_unit: str = "unassigned"
    environment: str = "production"
    criticality: Criticality = Criticality.IMPORTANT
    exposure: Exposure = Exposure.INTERNAL
    data_classification: DataClassification = DataClassification.INTERNAL
    data_lifetime_years: int = 3
    description: str = ""
    repositories: list[str] = field(default_factory=list)
    containers: list[str] = field(default_factory=list)
    regulatory: list[str] = field(default_factory=list)
    services: list[str] = field(default_factory=list)
    business_function: str = ""
    # "operator-declared" when a human supplied this context; "default" when ECDAT
    # fell back to its own baseline. The UI must render defaults as assumptions,
    # never as discovered facts (contract §12/§36).
    context_source: str = "operator-declared"

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        for k in ("criticality", "exposure", "data_classification"):
            d[k] = getattr(self, k).value
        return d


# ======================================================================================
# The normalized cryptographic asset -- PART 12 schema
# ======================================================================================
@dataclass
class CryptoAsset:
    # --- identity
    asset_id: str
    asset_type: AssetType
    asset_name: str

    # --- where it came from
    application: str | None = None
    repository: str | None = None
    file: str | None = None
    line: int | None = None
    language: str | None = None
    container: str | None = None

    # --- what it is
    algorithm: str | None = None            # knowledge-base id
    algorithm_label: str | None = None      # display name
    algorithm_family: str | None = None
    primitive: str | None = None            # CycloneDX primitive enum
    mode: str | None = None
    padding: str | None = None
    key_size: int | None = None
    curve: str | None = None
    security_strength: int | None = None    # classical bits
    quantum_strength: int | None = None
    cryptographic_role: str | None = None
    crypto_functions: list[str] = field(default_factory=list)
    protocol: str | None = None
    protocol_version: str | None = None
    library: str | None = None
    library_version: str | None = None
    package: str | None = None
    oid: str | None = None

    # --- certificate specifics
    certificate_subject: str | None = None
    certificate_issuer: str | None = None
    certificate_serial: str | None = None
    certificate_not_before: str | None = None
    certificate_expiry: str | None = None
    certificate_self_signed: bool | None = None
    certificate_san: list[str] = field(default_factory=list)
    certificate_sig_algorithm: str | None = None
    days_to_expiry: int | None = None

    # --- business context (denormalized from Application for fast filtering)
    usage: str | None = None
    owner: str | None = None
    business_unit: str | None = None
    data_classification: DataClassification | None = None
    data_lifetime_years: int | None = None
    business_criticality: Criticality | None = None
    internet_exposed: bool = False
    exposure: Exposure | None = None
    context_source: str = "default"          # "operator-declared" | "default" | "inferred"

    # --- analysis output
    quantum_vulnerable: bool = False
    quantum_class: str | None = None
    classical_security_status: str | None = None
    classical_risk: RiskBand | None = None       # canonical: classical axis
    quantum_exposure: RiskBand | None = None     # canonical: quantum axis
    quantum_risk: RiskBand | None = None         # retained alias of quantum_exposure
    risk_score: float = 0.0
    risk_factors: dict[str, Any] = field(default_factory=dict)
    risk_explanation: list[str] = field(default_factory=list)
    migration_effort: MigrationEffort | None = None
    migration_months: int | None = None
    confidence: Confidence = Confidence.LOW
    confidence_score: float = 0.0
    evidence_type: EvidenceType | None = None    # strongest evidence class present
    source: str | None = None                    # scan target this came from
    provenance: str | None = None                # human-readable origin chain

    # --- Mosca
    mosca_urgency: str | None = None
    mosca_gap_years: float | None = None
    mosca_detail: dict[str, Any] = field(default_factory=dict)

    # --- recommendation
    recommended_action: str | None = None
    recommended_pqc: str | None = None
    recommended_hybrid: str | None = None
    recommendation_rationale: str | None = None
    recommendation_citations: list[str] = field(default_factory=list)
    migration_steps: list[str] = field(default_factory=list)
    pqc_readiness: str | None = None
    pqc_readiness_note: str | None = None
    migration_priority: int | None = None
    priority_band: str | None = None

    # --- migration decision layer (frozen contract §4: exactly five outcomes) -------
    # `migration_decision` is the coarse, stable outcome an executive consumes.
    # `recommended_strategy` is the specific standards-grounded action beneath it.
    # Two levels, never collapsed into one.
    migration_decision: MigrationDecision | None = None
    recommended_strategy: str | None = None
    decision_rationale: str | None = None
    decision_inputs: dict[str, Any] = field(default_factory=dict)
    decision_blocked_on: str | None = None      # e.g. "role determination"

    # --- graph-derived migration context --------------------------------------------
    dependency_centrality: int = 0              # count of dependent graph nodes
    dependency_centrality_score: float = 0.0    # 0-100, normalized across the estate
    affected_assets: list[str] = field(default_factory=list)
    affected_summary: dict[str, Any] = field(default_factory=dict)
    crypto_agility: CryptoAgility | None = None
    crypto_agility_signals: list[str] = field(default_factory=list)
    interoperability: Interoperability | None = None
    interoperability_reason: str | None = None
    migration_blockers: list[str] = field(default_factory=list)

    # --- governance -------------------------------------------------------------------
    compliance_tags: list[str] = field(default_factory=list)
    remediation_status: RemediationStatus = RemediationStatus.DETECTED
    remediation_history: list[dict[str, Any]] = field(default_factory=list)

    # --- provenance & triage
    evidence: list[Evidence] = field(default_factory=list)
    detectors: list[str] = field(default_factory=list)
    triage_state: TriageState = TriageState.OPEN
    triage_notes: str | None = None
    overrides: dict[str, Any] = field(default_factory=dict)
    audit_log: list[dict[str, Any]] = field(default_factory=list)
    duplicate_count: int = 1
    tags: list[str] = field(default_factory=list)

    # ---------------------------------------------------------------------------------
    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {}
        for f in fields(self):
            v = getattr(self, f.name)
            if isinstance(v, Enum):
                d[f.name] = v.value
            elif f.name == "evidence":
                d[f.name] = [e.to_dict() for e in v]
            else:
                d[f.name] = v
        return d

    @property
    def location(self) -> str:
        if self.file and self.line:
            return f"{self.file}:{self.line}"
        return self.file or self.container or self.asset_name

    # ---------------------------------------------------------------------------------
    # Frozen-contract name aliases. The stored field names are kept because several
    # are unit-explicit (`data_lifetime_years`) or disambiguating (`asset_name` vs the
    # builtin-shadowing `name`/`type`). These read-only properties let contract-named
    # access work without a destructive rename across 20 modules.
    # ---------------------------------------------------------------------------------
    @property
    def name(self) -> str:
        return self.asset_name

    @property
    def type(self) -> AssetType:
        return self.asset_type

    @property
    def role(self) -> str:
        return self.cryptographic_role or Role.UNKNOWN.value

    @property
    def notes(self) -> str | None:
        return self.triage_notes

    @property
    def data_lifetime(self) -> int | None:
        return self.data_lifetime_years

    @property
    def detector(self) -> list[str]:
        return self.detectors

    @property
    def certificate(self) -> dict[str, Any] | None:
        """Contract-shaped certificate sub-object, rebuilt from the flat fields."""
        if self.asset_type is not AssetType.CERTIFICATE and not self.certificate_subject:
            return None
        return {
            "subject": self.certificate_subject,
            "issuer": self.certificate_issuer,
            "serial": self.certificate_serial,
            "not_before": self.certificate_not_before,
            "not_after": self.certificate_expiry,
            "self_signed": self.certificate_self_signed,
            "san": self.certificate_san,
            "signature_algorithm": self.certificate_sig_algorithm,
            "days_to_expiry": self.days_to_expiry,
        }

    # ---------------------------------------------------------------------------------
    def advance_remediation(self, new: RemediationStatus, actor: str = "operator",
                            note: str | None = None) -> bool:
        """Move the remediation lifecycle forward, recording an audit entry.

        Backwards transitions are permitted (a failed migration must be able to
        return to in-progress) but are always logged with the direction, so the
        history cannot be quietly rewritten.
        """
        old = self.remediation_status
        self.remediation_status = new
        self.remediation_history.append({
            "from": old.value, "to": new.value, "actor": actor,
            "note": note, "direction": "forward" if new.order >= old.order else "backward",
            "at": datetime.now().isoformat(timespec="seconds"),
        })
        return True

    def set_override(self, field_name: str, value: Any, actor: str = "operator",
                     reason: str | None = None) -> None:
        """Operator override of a business-context or effort field, fully audited."""
        previous = getattr(self, field_name, None)
        self.overrides[field_name] = {
            "value": value,
            "previous": previous.value if isinstance(previous, Enum) else previous,
            "actor": actor, "reason": reason,
            "at": datetime.now().isoformat(timespec="seconds"),
        }
        setattr(self, field_name, value)
        self.context_source = "operator-declared"
        self.audit_log.append({
            "event": "override", "field": field_name, "actor": actor,
            "at": datetime.now().isoformat(timespec="seconds"),
        })


# ======================================================================================
# Scan session
# ======================================================================================
@dataclass
class ScanStats:
    repositories: int = 0
    files_seen: int = 0
    files_analyzed: int = 0
    bytes_analyzed: int = 0
    certificates: int = 0
    containers: int = 0
    binaries: int = 0
    dependencies: int = 0
    manifests: int = 0
    configs: int = 0
    raw_detections: int = 0
    deduplicated: int = 0
    skipped_files: int = 0
    errors: list[str] = field(default_factory=list)
    duration_ms: int = 0
    detector_counts: dict[str, int] = field(default_factory=dict)
    language_counts: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScanResult:
    scan_id: str
    started_at: str
    target: str
    assets: list[CryptoAsset] = field(default_factory=list)
    applications: list[Application] = field(default_factory=list)
    stats: ScanStats = field(default_factory=ScanStats)
    policy: str = "nist_general"

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "started_at": self.started_at,
            "target": self.target,
            "policy": self.policy,
            "stats": self.stats.to_dict(),
            "applications": [a.to_dict() for a in self.applications],
            "assets": [a.to_dict() for a in self.assets],
        }


# ======================================================================================
# Helpers
# ======================================================================================
def stable_id(*parts: Any, prefix: str = "asset") -> str:
    """Deterministic id so re-scanning the same estate yields identical asset ids.

    Required for delta analysis and for triage decisions to survive a re-scan.
    """
    raw = "|".join("" if p is None else str(p) for p in parts)
    return f"{prefix}-{hashlib.sha256(raw.encode()).hexdigest()[:16]}"


def redact(snippet: str, max_len: int = 180) -> str:
    """Trim and strip anything that looks like embedded key material.

    ECDAT must never persist private keys (PART 9/30).
    """
    s = snippet.strip()
    markers = ("BEGIN RSA PRIVATE KEY", "BEGIN PRIVATE KEY", "BEGIN EC PRIVATE KEY",
               "BEGIN OPENSSH PRIVATE KEY", "BEGIN ENCRYPTED PRIVATE KEY",
               "BEGIN DSA PRIVATE KEY", "BEGIN PGP PRIVATE")
    upper = s.upper()
    for m in markers:
        if m in upper:
            return "[REDACTED: private key material detected]"
    # long base64-ish runs are treated as possible secrets
    for tok in s.split():
        stripped = tok.strip("'\"`,;()[]{}")
        if len(stripped) >= 40 and sum(c.isalnum() or c in "+/=" for c in stripped) == len(stripped):
            s = s.replace(stripped, f"[REDACTED:{len(stripped)}B]")
    return s[:max_len]


def today() -> date:
    return datetime.now().date()


def json_dump(obj: Any, **kw) -> str:
    return json.dumps(obj, indent=2, sort_keys=False, default=str, **kw)
