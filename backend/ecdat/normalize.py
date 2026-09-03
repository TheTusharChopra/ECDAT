"""Normalization and deduplication (PART 12).

Several detection layers legitimately observe the same cryptographic fact. The
Python AST detector and the lexical detector both fire on `hashlib.md5(...)`; a
container's package list and a binary's linkage table both name OpenSSL. Reporting
those as separate assets would inflate every count on the dashboard, which is the
fastest way to lose a security team's trust.

The merge rule: detections that describe the same (application, location,
algorithm-or-protocol, parameters) collapse into one asset. Facts union; the
confidence of the merged asset is the *highest* contributing confidence, and every
contributing detector is retained in `detectors` and `evidence` so the provenance
of each field stays inspectable in the UI.

Parameter conflicts are resolved by evidence strength, not by order: a HIGH
confidence AST detection stating key_size=2048 beats a LOW lexical guess.
"""

from __future__ import annotations

from collections import defaultdict

from .detect.base import Detection
from .knowledge import algorithms as alg
from .models import (
    Application,
    AssetType,
    Confidence,
    CryptoAsset,
    Evidence,
    EvidenceType,
    METHOD_TO_EVIDENCE_TYPE,
    redact,
    stable_id,
)

_CONF_RANK = {Confidence.LOW: 0, Confidence.MEDIUM: 1, Confidence.HIGH: 2}


def _asset_type_for(det: Detection) -> AssetType:
    if det.certificate is not None or det.detector == "certificate-x509":
        if det.extra.get("key_material_in_repo"):
            return AssetType.KEY_MATERIAL
        return AssetType.CERTIFICATE
    if det.detector == "container":
        return AssetType.CONTAINER_PACKAGE
    if det.detector == "binary-format":
        return AssetType.BINARY_ARTIFACT
    if det.detector == "dependency-manifest":
        return AssetType.DEPENDENCY
    if det.algorithm is None and det.protocol is not None:
        return AssetType.PROTOCOL_CONFIG
    if det.algorithm is None and det.library is not None:
        return AssetType.LIBRARY
    return AssetType.SOURCE_FINDING


def _identity_alg(alg_id: str | None) -> str | None:
    """Algorithm identity for deduplication purposes.

    Parameter-size variants of ONE primitive share an identity, so a LOW-confidence
    "AES" guess and a HIGH-confidence "AES-256-GCM" parse merge into a single asset
    whose size is then resolved by evidence strength. Genuinely distinct primitives
    never share identity -- ECDSA and ECDH are both EC but are different assets, and
    SHA-1 and SHA-256 on one line are two real findings.
    """
    if not alg_id:
        return None
    spec = alg.get(alg_id)
    if spec is None:
        return alg_id
    if spec.family == "AES":
        return "aes"
    if spec.family in ("ML-KEM", "ML-DSA", "SLH-DSA"):
        return spec.family.lower()
    return alg_id


def _dedup_key(det: Detection, application: str | None) -> tuple:
    """Identity of the underlying cryptographic fact.

    Deliberately excludes the detector: that is the whole point -- two layers
    describing one fact must land on the same key. It also excludes key_size, curve
    and mode, which are *attributes* of the fact to be reconciled by evidence
    strength, not part of its identity.
    """
    cert = det.certificate or {}
    if cert:
        # A certificate asset is identified by serial + which component of the cert.
        return ("cert", cert.get("serial"), det.extra.get("cert_component"),
                det.algorithm, application)
    if det.detector in ("dependency-manifest", "container"):
        return ("lib", det.library, det.library_version, det.package,
                det.extra.get("image"), application, det.file)
    if det.detector == "binary-format":
        return ("bin", det.file, _identity_alg(det.algorithm), det.library, det.method,
                det.protocol, det.protocol_version)
    if det.algorithm is None and det.protocol:
        return ("proto", det.protocol, det.protocol_version, det.file, det.line,
                application)
    return ("src", det.file, det.line, _identity_alg(det.algorithm), application)


def _better(new: Detection, cur_conf: Confidence) -> bool:
    return _CONF_RANK[new.confidence] > _CONF_RANK[cur_conf]


class Normalizer:
    def __init__(self, applications: list[Application] | None = None,
                 repo_to_app: dict[str, str] | None = None,
                 source: str | None = None):
        self.applications = {a.app_id: a for a in (applications or [])}
        self.repo_to_app = repo_to_app or {}
        # Label for the scan target these detections came from. Recorded on every
        # asset so a multi-target scan stays attributable.
        self.source = source

    # ---------------------------------------------------------------------------------
    def application_for(self, det: Detection) -> str | None:
        path = det.file or ""
        # longest matching repository prefix wins
        best: tuple[int, str | None] = (0, None)
        for repo, app_id in self.repo_to_app.items():
            if path == repo or path.startswith(repo.rstrip("/") + "/"):
                if len(repo) > best[0]:
                    best = (len(repo), app_id)
        if best[1]:
            return best[1]
        container = det.extra.get("container")
        if isinstance(container, str):
            for app in self.applications.values():
                if container in app.containers:
                    return app.app_id
        return None

    def repository_for(self, det: Detection) -> str | None:
        path = det.file or ""
        best: tuple[int, str | None] = (0, None)
        for repo in self.repo_to_app:
            if path == repo or path.startswith(repo.rstrip("/") + "/"):
                if len(repo) > best[0]:
                    best = (len(repo), repo)
        return best[1]

    # ---------------------------------------------------------------------------------
    def normalize(self, detections: list[Detection]) -> list[CryptoAsset]:
        groups: dict[tuple, list[Detection]] = defaultdict(list)
        for det in detections:
            app = self.application_for(det)
            groups[_dedup_key(det, app)].append(det)

        assets: list[CryptoAsset] = []
        for key, dets in groups.items():
            asset = self._merge(dets)
            if asset is not None:
                assets.append(asset)
        return assets

    # ---------------------------------------------------------------------------------
    def _merge(self, dets: list[Detection]) -> CryptoAsset | None:
        # strongest evidence first, so the primary detection defines the base facts
        dets = sorted(dets, key=lambda d: (-_CONF_RANK[d.confidence],
                                           0 if d.method in ("ast-call", "x509-parse") else 1))
        primary = dets[0]
        app_id = self.application_for(primary)
        app = self.applications.get(app_id) if app_id else None
        repo = self.repository_for(primary)

        spec = alg.get(primary.algorithm)
        # union of parameters, resolved by confidence
        key_size = None
        curve = None
        mode = None
        padding = None
        role = None
        protocol = None
        protocol_version = None
        library = None
        library_version = None
        package = None
        best_conf = primary.confidence
        chosen_alg = primary.algorithm

        conf_of_field: dict[str, Confidence] = {}

        def take(field: str, value, det: Detection, current):
            """Adopt `value` if it is set and comes from at least as strong evidence."""
            if value in (None, ""):
                return current
            prev = conf_of_field.get(field)
            if prev is None or _CONF_RANK[det.confidence] > _CONF_RANK[prev]:
                conf_of_field[field] = det.confidence
                return value
            return current

        for det in dets:
            if _CONF_RANK[det.confidence] > _CONF_RANK[best_conf]:
                best_conf = det.confidence
            chosen_alg = take("algorithm", det.algorithm, det, chosen_alg)
            key_size = take("key_size", det.key_size, det, key_size)
            curve = take("curve", det.curve, det, curve)
            mode = take("mode", det.mode, det, mode)
            padding = take("padding", det.padding, det, padding)
            protocol = take("protocol", det.protocol, det, protocol)
            protocol_version = take("protocol_version", det.protocol_version, det,
                                    protocol_version)
            library = take("library", det.library, det, library)
            library_version = take("library_version", det.library_version, det,
                                   library_version)
            package = take("package", det.package, det, package)
            # a claimed role only wins if it is not the placeholder
            if det.role and det.role != alg.ROLE_UNKNOWN:
                role = take("role", det.role, det, role)

        spec = alg.get(chosen_alg)
        if role is None:
            # A capability default may only be applied when at least one piece of
            # evidence could actually establish a role. Linkage, symbol, package and
            # string evidence prove PRESENCE, not use -- defaulting a role from them
            # would manufacture a fact the scanner cannot support (contract §10).
            can_establish_role = any(
                METHOD_TO_EVIDENCE_TYPE.get(d.method) in (
                    EvidenceType.SOURCE_API, EvidenceType.CONFIG_DIRECTIVE,
                    EvidenceType.CERTIFICATE, EvidenceType.SOURCE_LEXICAL)
                for d in dets)
            role = alg.default_role(spec) if can_establish_role else alg.ROLE_UNKNOWN

        cert = primary.certificate or {}

        # asset name: human-readable and stable
        if spec:
            label_bits = [spec.name]
            if key_size and spec.family in ("RSA", "DSA", "DH"):
                label_bits.append(str(key_size))
            if curve and spec.family == "EC":
                label_bits.append(curve)
            if mode and spec.primitive in ("block-cipher", "ae", "stream-cipher"):
                label_bits.append(mode.upper())
            name = "-".join(label_bits)
        elif protocol:
            name = f"{protocol} {protocol_version}".strip()
        elif library:
            from .knowledge import libraries as libs
            lib_spec = libs.get(library)
            name = lib_spec.name if lib_spec else library
            if library_version:
                name = f"{name} {library_version}"
        else:
            name = primary.matched or "cryptographic artefact"

        asset_type = _asset_type_for(primary)

        asset_id = stable_id(
            app_id, primary.file, primary.line, chosen_alg, protocol, protocol_version,
            library, library_version, cert.get("serial"),
            primary.extra.get("cert_component"), primary.extra.get("image"),
            primary.method if asset_type == AssetType.BINARY_ARTIFACT else None,
            prefix="ca",
        )

        strength = alg.strength_for(spec, key_size, curve) if spec else None
        qstrength = alg.quantum_strength_for(spec, key_size, curve) if spec else None

        asset = CryptoAsset(
            asset_id=asset_id,
            asset_type=asset_type,
            asset_name=name,
            application=app_id,
            repository=repo,
            file=primary.file,
            line=primary.line,
            language=primary.language,
            container=primary.extra.get("container") or primary.extra.get("image"),
            algorithm=chosen_alg,
            algorithm_label=spec.name if spec else None,
            algorithm_family=spec.family if spec else None,
            primitive=spec.primitive if spec else None,
            mode=mode,
            padding=padding,
            key_size=key_size,
            curve=curve,
            security_strength=strength,
            quantum_strength=qstrength,
            cryptographic_role=role,
            crypto_functions=list(spec.crypto_functions) if spec else [],
            protocol=protocol,
            protocol_version=protocol_version,
            library=library,
            library_version=library_version,
            package=package,
            oid=(spec.oid if spec else None) or primary.extra.get("oid"),
            confidence=best_conf,
            confidence_score=round(best_conf.weight * 100, 1),
            duplicate_count=len(dets),
            detectors=sorted({d.detector for d in dets}),
        )

        # --- certificate fields ---------------------------------------------------------
        if cert:
            asset.certificate_subject = cert.get("subject")
            asset.certificate_issuer = cert.get("issuer")
            asset.certificate_serial = cert.get("serial")
            asset.certificate_not_before = cert.get("not_before")
            asset.certificate_expiry = cert.get("not_after")
            asset.certificate_self_signed = cert.get("self_signed")
            asset.certificate_san = list(cert.get("san") or [])
            asset.certificate_sig_algorithm = cert.get("sig_algorithm_label")
            asset.days_to_expiry = cert.get("days_to_expiry")
            if cert.get("is_ca"):
                asset.tags.append("certificate-authority")
            if cert.get("self_signed"):
                asset.tags.append("self-signed")

        # --- business context from the application record --------------------------------
        if app:
            asset.usage = app.description or app.name
            asset.data_classification = app.data_classification
            asset.data_lifetime_years = app.data_lifetime_years
            asset.business_criticality = app.criticality
            asset.exposure = app.exposure
            asset.internet_exposed = app.exposure.value in (
                "external-facing", "internet-facing-critical")

        # --- tags used by the UI filters -------------------------------------------------
        for det in dets:
            if det.extra.get("suspected_non_security_use"):
                asset.tags.append("suspected-non-security-use")
            if det.extra.get("in_test_path"):
                asset.tags.append("test-path")
            if det.extra.get("key_size_assumed"):
                asset.tags.append("key-size-assumed")
            if det.extra.get("key_material_in_repo") or det.extra.get("key_material_in_image"):
                asset.tags.append("key-material-exposure")
            if det.extra.get("crypto_agility_blocker") or det.extra.get("floating_tag"):
                asset.tags.append("crypto-agility-blocker")
            if det.extra.get("hybrid_non_nist"):
                asset.tags.append("hybrid-non-nist")
            if det.extra.get("pqc_capability"):
                asset.pqc_readiness = str(det.extra["pqc_capability"])
                asset.pqc_readiness_note = str(det.extra.get("pqc_note") or "")
            if det.extra.get("weak_suite_tokens"):
                asset.tags.append("weak-cipher-suite")
            ev_tier = det.extra.get("evidence_tier")
            if ev_tier:
                asset.tags.append(f"evidence-{ev_tier}")
        asset.tags = sorted(set(asset.tags))

        # --- evidence ---------------------------------------------------------------------
        for det in dets:
            asset.evidence.append(Evidence(
                detector=det.detector,
                method=det.method,
                evidence_type=METHOD_TO_EVIDENCE_TYPE.get(det.method),
                confidence=det.confidence,
                location=(f"{det.file}:{det.line}" if det.file and det.line
                          else (det.file or det.extra.get("container") or "n/a")),
                snippet=redact(det.snippet) if det.snippet else None,
                matched=det.matched,
                reasoning=det.reasoning,
            ))

        # --- evidence taxonomy, source and provenance (contract §6) ----------------------
        # evidence_type reflects the STRONGEST evidence class present, ranked by what it
        # can actually prove -- not by scan order.
        ranked = sorted(
            (e for e in asset.evidence if e.evidence_type is not None),
            key=lambda e: (_CONF_RANK[e.confidence or Confidence.LOW],
                           1 if e.proves_execution else 0),
            reverse=True)
        asset.evidence_type = ranked[0].evidence_type if ranked else None
        asset.source = self.source or repo or primary.file

        # A single sentence a reviewer can read to understand where this asset came
        # from, including whether anything here proves the algorithm is reachable.
        chain = " + ".join(
            f"{e.detector}({e.method})" for e in asset.evidence[:4])
        if len(asset.evidence) > 4:
            chain += f" +{len(asset.evidence) - 4} more"
        executable = any(e.proves_execution for e in asset.evidence)
        asset.provenance = (
            f"{len(asset.evidence)} detection(s) via {chain}; "
            f"highest confidence {best_conf.value}; "
            + ("evidence demonstrates the algorithm is reachable in this component."
               if executable else
               "NO evidence here proves the algorithm is actually invoked -- presence "
               "was inferred from linkage, packaging or lexical context only."))
        if not executable:
            asset.tags.append("presence-only-evidence")
            asset.tags = sorted(set(asset.tags))
        return asset
