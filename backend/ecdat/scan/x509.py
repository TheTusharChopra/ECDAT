"""X.509 certificate analysis built on the stdlib DER reader.

Extracts subject, issuer, serial, validity window, signature algorithm, public-key
algorithm with key size or named curve, SANs, basic constraints and key usage --
then classifies the certificate against both classical policy (SHA-1 signatures,
short RSA moduli, expiry) and quantum exposure (every one of RSA/ECDSA/Ed25519 is
Shor-vulnerable, so *all* TLS PKI is in scope for migration).

Where the `openssl` binary is present, `crosscheck()` compares our parse against
it. That is a real correctness control, not decoration: it is how we justify HIGH
confidence on certificate findings.

Private keys: PEM blocks containing private key material are recognised and
recorded as a boolean fact with a location. The bytes are never parsed, stored,
logged or returned (PART 9/30).
"""

from __future__ import annotations

import base64
import binascii
import os
import re
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone

from ..knowledge import algorithms as alg
from ..models import Confidence
from . import asn1
from ..detect.base import Detection

# --- OID tables -------------------------------------------------------------------------
SIG_ALG_OIDS = {
    "1.2.840.113549.1.1.4": ("md5", "rsa", "md5WithRSAEncryption"),
    "1.2.840.113549.1.1.5": ("sha-1", "rsa", "sha1WithRSAEncryption"),
    "1.2.840.113549.1.1.11": ("sha-256", "rsa", "sha256WithRSAEncryption"),
    "1.2.840.113549.1.1.12": ("sha-384", "rsa", "sha384WithRSAEncryption"),
    "1.2.840.113549.1.1.13": ("sha-512", "rsa", "sha512WithRSAEncryption"),
    "1.2.840.113549.1.1.14": ("sha-224", "rsa", "sha224WithRSAEncryption"),
    "1.2.840.113549.1.1.10": (None, "rsa", "RSASSA-PSS"),
    "1.2.840.10040.4.3": ("sha-1", "dsa", "dsa-with-sha1"),
    "2.16.840.1.101.3.4.3.2": ("sha-256", "dsa", "dsa-with-sha256"),
    "1.2.840.10045.4.1": ("sha-1", "ecdsa", "ecdsa-with-SHA1"),
    "1.2.840.10045.4.3.1": ("sha-224", "ecdsa", "ecdsa-with-SHA224"),
    "1.2.840.10045.4.3.2": ("sha-256", "ecdsa", "ecdsa-with-SHA256"),
    "1.2.840.10045.4.3.3": ("sha-384", "ecdsa", "ecdsa-with-SHA384"),
    "1.2.840.10045.4.3.4": ("sha-512", "ecdsa", "ecdsa-with-SHA512"),
    "1.3.101.112": (None, "ed25519", "Ed25519"),
    "1.3.101.113": (None, "ed448", "Ed448"),
    # PQC signature OIDs (NIST/IETF assignments) -- present so a post-migration estate
    # is recognised as migrated rather than reported as "unknown".
    "2.16.840.1.101.3.4.3.17": (None, "ml-dsa-44", "ML-DSA-44"),
    "2.16.840.1.101.3.4.3.18": (None, "ml-dsa-65", "ML-DSA-65"),
    "2.16.840.1.101.3.4.3.19": (None, "ml-dsa-87", "ML-DSA-87"),
    "2.16.840.1.101.3.4.3.20": (None, "slh-dsa-sha2-128s", "SLH-DSA-SHA2-128s"),
}

PUBKEY_ALG_OIDS = {
    "1.2.840.113549.1.1.1": "rsa",
    "1.2.840.10040.4.1": "dsa",
    "1.2.840.10045.2.1": "ecdsa",     # id-ecPublicKey
    "1.3.101.112": "ed25519",
    "1.3.101.113": "ed448",
    "1.3.101.110": "x25519",
    "1.3.101.111": "x448",
    "1.2.840.113549.1.3.1": "dh",
    "2.16.840.1.101.3.4.4.1": "ml-kem-512",
    "2.16.840.1.101.3.4.4.2": "ml-kem-768",
    "2.16.840.1.101.3.4.4.3": "ml-kem-1024",
}

CURVE_OIDS = {
    "1.2.840.10045.3.1.1": "secp192r1",
    "1.2.840.10045.3.1.7": "prime256v1",   # == P-256 / secp256r1
    "1.3.132.0.33": "secp224r1",
    "1.3.132.0.34": "secp384r1",
    "1.3.132.0.35": "secp521r1",
    "1.3.132.0.10": "secp256k1",
    "1.3.36.3.3.2.8.1.1.7": "brainpoolp256r1",
    "1.3.36.3.3.2.8.1.1.11": "brainpoolp384r1",
}

RDN_OIDS = {
    "2.5.4.3": "CN", "2.5.4.6": "C", "2.5.4.7": "L", "2.5.4.8": "ST",
    "2.5.4.10": "O", "2.5.4.11": "OU", "2.5.4.5": "serialNumber",
    "2.5.4.4": "SN", "2.5.4.42": "GN", "0.9.2342.19200300.100.1.25": "DC",
    "1.2.840.113549.1.9.1": "emailAddress",
}

EXT_SAN = "2.5.29.17"
EXT_BASIC_CONSTRAINTS = "2.5.29.19"
EXT_KEY_USAGE = "2.5.29.15"
EXT_EXT_KEY_USAGE = "2.5.29.37"

KEY_USAGE_BITS = ["digitalSignature", "nonRepudiation", "keyEncipherment",
                  "dataEncipherment", "keyAgreement", "keyCertSign", "cRLSign",
                  "encipherOnly", "decipherOnly"]

EKU_OIDS = {
    "1.3.6.1.5.5.7.3.1": "serverAuth",
    "1.3.6.1.5.5.7.3.2": "clientAuth",
    "1.3.6.1.5.5.7.3.3": "codeSigning",
    "1.3.6.1.5.5.7.3.4": "emailProtection",
    "1.3.6.1.5.5.7.3.8": "timeStamping",
    "1.3.6.1.5.5.7.3.9": "OCSPSigning",
}

PEM_BLOCK = re.compile(
    rb"-----BEGIN ([A-Z0-9 ]+)-----\r?\n(.*?)-----END \1-----", re.DOTALL)

PRIVATE_KEY_LABELS = ("PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY",
                      "DSA PRIVATE KEY", "ENCRYPTED PRIVATE KEY",
                      "OPENSSH PRIVATE KEY", "PGP PRIVATE KEY BLOCK")


@dataclass
class Certificate:
    subject: str = ""
    issuer: str = ""
    subject_cn: str | None = None
    issuer_cn: str | None = None
    serial: str = ""
    not_before: str | None = None
    not_after: str | None = None
    sig_algorithm: str | None = None       # knowledge-base id of the signing PK alg
    sig_hash: str | None = None            # knowledge-base id of the digest
    sig_algorithm_label: str | None = None
    sig_oid: str | None = None
    pubkey_algorithm: str | None = None
    pubkey_oid: str | None = None
    key_size: int | None = None
    curve: str | None = None
    san: list[str] = field(default_factory=list)
    is_ca: bool = False
    path_len: int | None = None
    key_usage: list[str] = field(default_factory=list)
    ext_key_usage: list[str] = field(default_factory=list)
    self_signed: bool = False
    version: int = 1
    fmt: str = "PEM"
    path: str = ""
    parse_errors: list[str] = field(default_factory=list)
    crosschecked: bool = False
    # Raw DER of *this* certificate. Retained so the openssl cross-check can target
    # one specific certificate inside a multi-cert bundle (a fullchain PEM) rather
    # than whatever `openssl x509 -in <file>` happens to read first.
    der: bytes | None = field(default=None, repr=False, compare=False)

    @property
    def days_to_expiry(self) -> int | None:
        if not self.not_after:
            return None
        try:
            exp = datetime.fromisoformat(self.not_after)
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            return (exp - datetime.now(timezone.utc)).days
        except ValueError:
            return None

    @property
    def expired(self) -> bool:
        d = self.days_to_expiry
        return d is not None and d < 0


# ======================================================================================
# Parsing
# ======================================================================================
def _parse_time(node: asn1.Node) -> str | None:
    raw = node.as_text().strip()
    try:
        if node.tag_number == asn1.UTC_TIME:
            # YYMMDDHHMMSSZ -- RFC 5280: 50-99 => 19xx, 00-49 => 20xx
            core = raw.rstrip("Z")
            yy = int(core[0:2])
            year = 1900 + yy if yy >= 50 else 2000 + yy
            rest = core[2:]
            fmt_len = len(rest)
            month, day, hour, minute = (int(rest[0:2]), int(rest[2:4]),
                                        int(rest[4:6]), int(rest[6:8]))
            second = int(rest[8:10]) if fmt_len >= 10 else 0
        else:
            core = raw.rstrip("Z").split(".")[0]
            year, month, day = int(core[0:4]), int(core[4:6]), int(core[6:8])
            hour = int(core[8:10]) if len(core) >= 10 else 0
            minute = int(core[10:12]) if len(core) >= 12 else 0
            second = int(core[12:14]) if len(core) >= 14 else 0
        return datetime(year, month, day, hour, minute, second,
                        tzinfo=timezone.utc).isoformat()
    except (ValueError, IndexError):
        return None


def _parse_name(node: asn1.Node) -> tuple[str, dict[str, str]]:
    """RDNSequence -> ('C=IN, O=..., CN=...', {'CN': ...})."""
    parts: list[str] = []
    attrs: dict[str, str] = {}
    for rdn in node.children:                     # SET OF AttributeTypeAndValue
        for atv in rdn.children:
            if len(atv.children) < 2:
                continue
            try:
                oid = atv.children[0].as_oid()
                val = atv.children[1].as_text()
            except (asn1.Asn1Error, UnicodeDecodeError):
                continue
            label = RDN_OIDS.get(oid, oid)
            parts.append(f"{label}={val}")
            attrs.setdefault(label, val)
    return ", ".join(parts), attrs


def _parse_algorithm_identifier(node: asn1.Node) -> tuple[str | None, asn1.Node | None]:
    if not node.children:
        return None, None
    try:
        oid = node.children[0].as_oid()
    except asn1.Asn1Error:
        return None, None
    params = node.children[1] if len(node.children) > 1 else None
    return oid, params


def _rsa_key_size(spki_bits: bytes) -> int | None:
    """RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }."""
    try:
        seq = asn1.parse_one(spki_bits)
        if not seq.children:
            return None
        modulus = seq.children[0].as_uint()
        return modulus.bit_length()
    except (asn1.Asn1Error, IndexError):
        return None


def _parse_san(ext_value: bytes) -> list[str]:
    out: list[str] = []
    try:
        seq = asn1.parse_one(ext_value)
    except asn1.Asn1Error:
        return out
    for gn in seq.children:
        num = gn.tag_number
        try:
            if num == 2:      # dNSName
                out.append(gn.value.decode("ascii", "replace"))
            elif num == 1:    # rfc822Name
                out.append("email:" + gn.value.decode("ascii", "replace"))
            elif num == 6:    # uniformResourceIdentifier
                out.append("uri:" + gn.value.decode("ascii", "replace"))
            elif num == 7:    # iPAddress
                b = gn.value
                if len(b) == 4:
                    out.append("ip:" + ".".join(str(x) for x in b))
                elif len(b) == 16:
                    out.append("ip:" + ":".join(
                        f"{b[i]:02x}{b[i+1]:02x}" for i in range(0, 16, 2)))
        except Exception:
            continue
    return out


def _parse_key_usage(ext_value: bytes) -> list[str]:
    try:
        bs = asn1.parse_one(ext_value)
        payload = bs.bitstring_bytes()
        unused = bs.value[0] if bs.value else 0
    except (asn1.Asn1Error, IndexError):
        return []
    bits: list[str] = []
    total = len(payload) * 8 - unused
    for i in range(min(total, len(KEY_USAGE_BITS))):
        if payload[i // 8] & (0x80 >> (i % 8)):
            bits.append(KEY_USAGE_BITS[i])
    return bits


def parse_certificate(der: bytes, path: str = "", fmt: str = "DER") -> Certificate:
    """Parse an X.509 certificate from DER bytes. Raises Asn1Error on garbage."""
    cert = Certificate(path=path, fmt=fmt, der=der)
    root = asn1.parse_one(der)
    if not root.is_seq or len(root.children) < 3:
        raise asn1.Asn1Error("not a Certificate SEQUENCE")

    tbs, sig_alg_node = root.children[0], root.children[1]

    # signatureAlgorithm (outer)
    sig_oid, _ = _parse_algorithm_identifier(sig_alg_node)
    cert.sig_oid = sig_oid
    if sig_oid in SIG_ALG_OIDS:
        h, pk, label = SIG_ALG_OIDS[sig_oid]
        cert.sig_hash, cert.sig_algorithm, cert.sig_algorithm_label = h, pk, label
    elif sig_oid:
        cert.sig_algorithm_label = f"unknown ({sig_oid})"
        cert.parse_errors.append(f"unrecognised signature algorithm OID {sig_oid}")

    # --- TBSCertificate ----------------------------------------------------------------
    idx = 0
    kids = tbs.children
    if kids and kids[0].tag_class == asn1.CLASS_CONTEXT and kids[0].tag_number == 0:
        inner = asn1.parse_explicit(kids[0])
        cert.version = (inner.as_int() + 1) if inner else 1
        idx = 1

    def take() -> asn1.Node | None:
        nonlocal idx
        if idx < len(kids):
            n = kids[idx]
            idx += 1
            return n
        return None

    serial_node = take()
    if serial_node is not None:
        cert.serial = format(serial_node.as_uint(), "X").rjust(2, "0")

    take()  # inner signature AlgorithmIdentifier (must equal the outer one)

    issuer_node = take()
    if issuer_node is not None:
        cert.issuer, issuer_attrs = _parse_name(issuer_node)
        cert.issuer_cn = issuer_attrs.get("CN")

    validity = take()
    if validity is not None and len(validity.children) >= 2:
        cert.not_before = _parse_time(validity.children[0])
        cert.not_after = _parse_time(validity.children[1])

    subject_node = take()
    if subject_node is not None:
        cert.subject, subject_attrs = _parse_name(subject_node)
        cert.subject_cn = subject_attrs.get("CN")

    cert.self_signed = bool(cert.subject) and cert.subject == cert.issuer

    # --- SubjectPublicKeyInfo -----------------------------------------------------------
    spki = take()
    if spki is not None and spki.children:
        pk_oid, params = _parse_algorithm_identifier(spki.children[0])
        cert.pubkey_oid = pk_oid
        cert.pubkey_algorithm = PUBKEY_ALG_OIDS.get(pk_oid or "")
        if cert.pubkey_algorithm is None and pk_oid:
            cert.parse_errors.append(f"unrecognised public key OID {pk_oid}")
        if params is not None and params.tag_number == asn1.OID:
            try:
                cert.curve = CURVE_OIDS.get(params.as_oid(), params.as_oid())
            except asn1.Asn1Error:
                pass
        if len(spki.children) > 1 and cert.pubkey_algorithm == "rsa":
            try:
                cert.key_size = _rsa_key_size(spki.children[1].bitstring_bytes())
            except asn1.Asn1Error as e:
                cert.parse_errors.append(f"RSA modulus parse failed: {e}")
        elif cert.pubkey_algorithm in ("ed25519", "x25519"):
            cert.key_size = 256
        elif cert.pubkey_algorithm in ("ed448", "x448"):
            cert.key_size = 448
        elif cert.pubkey_algorithm == "ecdsa" and cert.curve:
            bits = alg.curve_strength(cert.curve)
            cert.key_size = {128: 256, 192: 384, 256: 521, 112: 224, 96: 192}.get(bits or 0)

    # --- extensions ---------------------------------------------------------------------
    while idx < len(kids):
        node = kids[idx]
        idx += 1
        if node.tag_class != asn1.CLASS_CONTEXT or node.tag_number != 3:
            continue
        ext_seq = asn1.parse_explicit(node)
        if ext_seq is None:
            continue
        for ext in ext_seq.children:
            if not ext.children:
                continue
            try:
                oid = ext.children[0].as_oid()
            except asn1.Asn1Error:
                continue
            octets = None
            for c in ext.children[1:]:
                if c.tag_number == asn1.OCTET_STRING:
                    octets = c.value
            if octets is None:
                continue
            try:
                if oid == EXT_SAN:
                    cert.san = _parse_san(octets)
                elif oid == EXT_BASIC_CONSTRAINTS:
                    bc = asn1.parse_one(octets)
                    for c in bc.children:
                        if c.tag_number == asn1.BOOLEAN:
                            cert.is_ca = c.as_bool()
                        elif c.tag_number == asn1.INTEGER:
                            cert.path_len = c.as_int()
                elif oid == EXT_KEY_USAGE:
                    cert.key_usage = _parse_key_usage(octets)
                elif oid == EXT_EXT_KEY_USAGE:
                    eku = asn1.parse_one(octets)
                    cert.ext_key_usage = [
                        EKU_OIDS.get(c.as_oid(), c.as_oid()) for c in eku.children
                        if c.tag_number == asn1.OID]
            except (asn1.Asn1Error, IndexError, UnicodeDecodeError) as e:
                cert.parse_errors.append(f"extension {oid}: {e}")

    return cert


# ======================================================================================
# File loading
# ======================================================================================
@dataclass
class CertFileResult:
    certificates: list[Certificate] = field(default_factory=list)
    private_key_detected: bool = False
    private_key_labels: list[str] = field(default_factory=list)
    pkcs12_detected: bool = False
    csr_detected: bool = False
    errors: list[str] = field(default_factory=list)


def load_cert_file(path: str, data: bytes | None = None) -> CertFileResult:
    """Load PEM or DER certificates (and note, without reading, private keys)."""
    res = CertFileResult()
    if data is None:
        try:
            with open(path, "rb") as fh:
                data = fh.read(4 * 1024 * 1024)
        except OSError as e:
            res.errors.append(f"{path}: {e}")
            return res

    ext = os.path.splitext(path)[1].lower()

    # PKCS#12 / PFX: a password-protected container. We record its existence and stop.
    if ext in (".p12", ".pfx") or data[:2] == b"\x30\x82" and ext in (".p12", ".pfx"):
        res.pkcs12_detected = True
        res.errors.append(
            f"{path}: PKCS#12 container detected. Not opened -- decryption requires a "
            f"credential and ECDAT does not prompt for or store key passwords. "
            f"Recorded as metadata only.")
        return res

    blocks = PEM_BLOCK.findall(data)
    if blocks:
        for label_b, b64 in blocks:
            label = label_b.decode("ascii", "replace")
            if label in PRIVATE_KEY_LABELS or "PRIVATE KEY" in label:
                # Never decode. Never store. Record the fact only.
                res.private_key_detected = True
                res.private_key_labels.append(label)
                continue
            if "CERTIFICATE REQUEST" in label:
                res.csr_detected = True
                continue
            if label not in ("CERTIFICATE", "X509 CERTIFICATE", "TRUSTED CERTIFICATE"):
                continue
            try:
                der = base64.b64decode(re.sub(rb"\s+", b"", b64), validate=True)
            except binascii.Error as e:
                res.errors.append(f"{path}: base64 decode failed: {e}")
                continue
            try:
                res.certificates.append(parse_certificate(der, path, "PEM"))
            except (asn1.Asn1Error, ValueError, IndexError) as e:
                res.errors.append(f"{path}: certificate parse failed: {e}")
        return res

    # raw DER
    if data[:1] == b"\x30":
        try:
            res.certificates.append(parse_certificate(data, path, "DER"))
        except (asn1.Asn1Error, ValueError, IndexError) as e:
            res.errors.append(f"{path}: DER parse failed: {e}")
    return res


# ======================================================================================
# openssl cross-check -- an independent correctness control on our own parser
# ======================================================================================
_OPENSSL: str | None | bool = False


def _openssl_path() -> str | None:
    global _OPENSSL
    if _OPENSSL is False:
        from shutil import which
        _OPENSSL = which("openssl")
    return _OPENSSL  # type: ignore[return-value]


def crosscheck(cert: Certificate) -> dict[str, object]:
    """Compare our DER parse against the openssl binary, when available.

    The exact DER of this certificate is piped in on stdin rather than passing the
    file path: a fullchain PEM holds several certificates and `openssl x509 -in`
    would only ever read the first one, producing spurious mismatches for the rest.

    Returns {'available': bool, 'agree': bool, 'mismatches': [...]}.
    """
    exe = _openssl_path()
    if not exe or not cert.der:
        return {"available": False, "agree": None, "mismatches": []}
    try:
        proc = subprocess.run(
            [exe, "x509", "-inform", "DER", "-noout", "-subject", "-issuer",
             "-serial", "-dates", "-text"],
            input=cert.der, capture_output=True, timeout=10, check=False,
        )
    except (OSError, subprocess.SubprocessError) as e:
        return {"available": False, "agree": None, "mismatches": [str(e)]}
    if proc.returncode != 0:
        return {"available": True, "agree": None,
                "mismatches": [f"openssl exit {proc.returncode}"]}

    out = proc.stdout.decode("utf-8", "replace")
    mismatches: list[str] = []

    m = re.search(r"^serial=([0-9A-Fa-f]+)", out, re.M)
    if m and cert.serial and m.group(1).upper().lstrip("0") != cert.serial.upper().lstrip("0"):
        mismatches.append(f"serial: openssl={m.group(1)} ecdat={cert.serial}")

    if cert.subject_cn:
        if f"CN = {cert.subject_cn}" not in out and f"CN={cert.subject_cn}" not in out:
            mismatches.append(f"subject CN not confirmed: {cert.subject_cn}")

    if cert.key_size and cert.pubkey_algorithm == "rsa":
        km = re.search(r"Public-Key:\s*\((\d+)\s*bit\)", out)
        if km and int(km.group(1)) != cert.key_size:
            mismatches.append(f"key size: openssl={km.group(1)} ecdat={cert.key_size}")

    if cert.sig_algorithm_label:
        sm = re.search(r"Signature Algorithm:\s*(\S+)", out)
        if sm and sm.group(1).lower() not in cert.sig_algorithm_label.lower() \
                and cert.sig_algorithm_label.lower() not in sm.group(1).lower():
            mismatches.append(
                f"sig alg: openssl={sm.group(1)} ecdat={cert.sig_algorithm_label}")

    cert.crosschecked = True
    return {"available": True, "agree": not mismatches, "mismatches": mismatches}


# ======================================================================================
# Certificate -> Detections
# ======================================================================================
def certificate_detections(cert: Certificate, verify: bool = True) -> list[Detection]:
    """Turn one parsed certificate into normalized detections.

    A certificate yields up to three distinct cryptographic assets, which is the
    correct model: the subject public key, the signature algorithm used by the
    issuing CA, and the certificate object itself. They can have different risk
    profiles -- an ECDSA P-384 key signed with SHA-1 is a classical problem on the
    signature side and a quantum problem on the key side.
    """
    dets: list[Detection] = []
    cc = crosscheck(cert) if verify else {"available": False, "agree": None, "mismatches": []}
    base_extra = {
        "certificate": {
            "subject": cert.subject, "issuer": cert.issuer, "serial": cert.serial,
            "not_before": cert.not_before, "not_after": cert.not_after,
            "san": cert.san, "is_ca": cert.is_ca, "self_signed": cert.self_signed,
            "key_usage": cert.key_usage, "ext_key_usage": cert.ext_key_usage,
            "version": cert.version, "format": cert.fmt,
            "days_to_expiry": cert.days_to_expiry,
            "sig_algorithm_label": cert.sig_algorithm_label,
            "parse_errors": cert.parse_errors,
        },
        "openssl_crosscheck": cc,
    }

    verify_note = ""
    if cc.get("available"):
        verify_note = (" Independently cross-checked against the openssl binary: "
                       + ("fields agree." if cc.get("agree") else
                          f"MISMATCH {cc.get('mismatches')}."))

    # --- 1. subject public key ---------------------------------------------------------
    if cert.pubkey_algorithm:
        spec = alg.get(cert.pubkey_algorithm)
        # Role comes from the keyUsage/basicConstraints extensions, not from a guess.
        role = alg.ROLE_SIGNATURE
        if cert.is_ca or "keyCertSign" in cert.key_usage:
            role = alg.ROLE_CERTIFICATE_VALIDATION
        elif "keyEncipherment" in cert.key_usage or "dataEncipherment" in cert.key_usage:
            role = alg.ROLE_KEY_TRANSPORT
        elif "keyAgreement" in cert.key_usage:
            role = alg.ROLE_KEY_ESTABLISHMENT
        if spec and spec.primitive in ("key-agree", "kem"):
            role = alg.ROLE_KEY_ESTABLISHMENT

        usage_desc = ", ".join(cert.key_usage) or "keyUsage extension absent"
        dets.append(Detection(
            detector="certificate-x509", method="x509-parse",
            confidence=Confidence.HIGH,
            algorithm=cert.pubkey_algorithm, role=role,
            key_size=cert.key_size, curve=cert.curve,
            file=cert.path, language="x509",
            matched=f"{cert.pubkey_algorithm} subject public key",
            reasoning=(f"Subject public key parsed from the certificate's "
                       f"SubjectPublicKeyInfo (DER). keyUsage: {usage_desc}. Role "
                       f"derived from keyUsage rather than assumed." + verify_note),
            api_call="x509-subjectPublicKeyInfo",
            certificate=base_extra["certificate"],
            extra={**base_extra, "cert_component": "subject-public-key",
                   "oid": cert.pubkey_oid},
        ))

    # --- 2. CA signature algorithm ------------------------------------------------------
    if cert.sig_hash or cert.sig_algorithm:
        sig_alg_id = cert.sig_hash or cert.sig_algorithm
        dets.append(Detection(
            detector="certificate-x509", method="x509-parse",
            confidence=Confidence.HIGH,
            algorithm=sig_alg_id, role=alg.ROLE_SIGNATURE_VERIFICATION,
            file=cert.path, language="x509",
            matched=cert.sig_algorithm_label or sig_alg_id,
            reasoning=(f"Certificate signed with {cert.sig_algorithm_label}. The digest "
                       f"determines classical forgery resistance; the public-key "
                       f"algorithm determines quantum exposure of the issuing CA."
                       + verify_note),
            api_call="x509-signatureAlgorithm",
            certificate=base_extra["certificate"],
            extra={**base_extra, "cert_component": "signature-algorithm",
                   "oid": cert.sig_oid,
                   "signing_pk_algorithm": cert.sig_algorithm},
        ))

    return dets
