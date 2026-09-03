"""Configuration-file detector: protocols, cipher suites, TLS/SSH/IPsec parameters.

Configuration is where an enterprise's *effective* cryptography actually lives. A
service can link a PQC-capable OpenSSL and still negotiate TLS 1.0 with a SHA-1
certificate because of one line in an nginx file. These detections are HIGH
confidence: a directive in a config file is structured, declarative evidence of
deployed behaviour, not an inference about code paths.
"""

from __future__ import annotations

import os
import re

from ..knowledge import algorithms as alg
from ..models import Confidence
from .base import Detection

_CONFIG_HINTS = (
    "nginx", "httpd", "apache", "ssl.conf", "tls.conf", "openssl.cnf", "openssl.conf",
    "sshd_config", "ssh_config", "ipsec.conf", "strongswan", "haproxy", "envoy",
    "postgresql.conf", "my.cnf", "application.properties", "application.yml",
    "server.xml", "web.xml", "java.security", "wsgi", "gunicorn", "traefik",
)
_CONFIG_EXT = (".conf", ".cnf", ".ini", ".properties", ".yaml", ".yml", ".toml",
               ".xml", ".tf", ".hcl", ".json", ".env")

# --- protocol version directives -------------------------------------------------------
_PROTO_PATTERNS = [
    (re.compile(r"ssl_protocols\s+([^;]+);", re.I), "TLS", "nginx ssl_protocols"),
    (re.compile(r"SSLProtocol\s+(.+)$", re.I | re.M), "TLS", "apache SSLProtocol"),
    (re.compile(r"^\s*(?:min_)?tls[-_ ]?version\s*[:=]\s*['\"]?([A-Za-z0-9._]+)", re.I | re.M),
     "TLS", "tls version setting"),
    (re.compile(r"minimum_protocol_version\s*=\s*\"?([A-Za-z0-9._]+)", re.I),
     "TLS", "cloud TLS policy"),
    (re.compile(r"^\s*Protocol\s+(\d(?:,\s*\d)*)\s*$", re.I | re.M), "SSH", "sshd Protocol"),
    (re.compile(r"^\s*ike[-_ ]?version\s*[:=]\s*(\S+)", re.I | re.M), "IKE", "ipsec ike version"),
]

_TLS_TOKEN = re.compile(r"\b(SSLv2|SSLv3|TLSv?1\.3|TLSv?1\.2|TLSv?1\.1|TLSv?1\.0|TLSv1|"
                        r"TLS1[._]?3|TLS1[._]?2|TLS1[._]?1|TLS1[._]?0|TLS_1_[0-3])\b", re.I)

_VERSION_NORMAL = {
    "sslv2": ("SSL", "2.0"), "sslv3": ("SSL", "3.0"),
    "tlsv1": ("TLS", "1.0"), "tlsv1.0": ("TLS", "1.0"), "tls1.0": ("TLS", "1.0"),
    "tls10": ("TLS", "1.0"), "tls_1_0": ("TLS", "1.0"),
    "tlsv1.1": ("TLS", "1.1"), "tls1.1": ("TLS", "1.1"), "tls11": ("TLS", "1.1"),
    "tls_1_1": ("TLS", "1.1"),
    "tlsv1.2": ("TLS", "1.2"), "tls1.2": ("TLS", "1.2"), "tls12": ("TLS", "1.2"),
    "tls_1_2": ("TLS", "1.2"), "tlsv1_2": ("TLS", "1.2"),
    "tlsv1.3": ("TLS", "1.3"), "tls1.3": ("TLS", "1.3"), "tls13": ("TLS", "1.3"),
    "tls_1_3": ("TLS", "1.3"), "tlsv1_3": ("TLS", "1.3"),
}

# --- cipher suite directives ------------------------------------------------------------
_CIPHER_DIRECTIVE = re.compile(
    r"(?:ssl_ciphers|SSLCipherSuite|ciphers|cipher_suites|CipherSuite|Ciphers|"
    r"ssl_conf_ciphersuites|CipherString)\s*[:= ]\s*['\"]?([^'\";\n]+)", re.I)

# --- key exchange group directives (this is where PQC hybrids show up) ------------------
_GROUPS_DIRECTIVE = re.compile(
    r"(?:ssl_ecdh_curve|Curves|groups|SSLOpenSSLConfCmd\s+Groups|KexAlgorithms|"
    r"curves|supported_groups)\s*[:= ]\s*['\"]?([^'\";\n]+)", re.I)

# --- certificate / key file references --------------------------------------------------
_CERT_REF = re.compile(
    r"(?:ssl_certificate|SSLCertificateFile|ssl_certificate_key|SSLCertificateKeyFile|"
    r"tls_cert_file|tls_key_file|HostKey|cert_file|key_file|keystore|truststore)"
    r"\s*[:= ]\s*['\"]?([^\s'\";]+)", re.I)

_SUITE_ALGS = [
    (re.compile(r"AES[-_]?256[-_]?GCM", re.I), "aes-256"),
    (re.compile(r"AES[-_]?128[-_]?GCM", re.I), "aes-128"),
    (re.compile(r"AES[-_]?256[-_]?CBC|AES256[-_]?SHA", re.I), "aes-256"),
    (re.compile(r"AES[-_]?128[-_]?CBC|AES128[-_]?SHA", re.I), "aes-128"),
    (re.compile(r"CHACHA20[-_]?POLY1305", re.I), "chacha20-poly1305"),
    (re.compile(r"3DES|DES[-_]?CBC3", re.I), "3des"),
    (re.compile(r"\bRC4\b", re.I), "rc4"),
    (re.compile(r"\bECDHE\b", re.I), "ecdh"),
    (re.compile(r"\bDHE\b", re.I), "dh"),
    (re.compile(r"\bECDSA\b", re.I), "ecdsa"),
    (re.compile(r"\bRSA\b", re.I), "rsa"),
    (re.compile(r"\bSHA384\b", re.I), "sha-384"),
    (re.compile(r"\bSHA256\b", re.I), "sha-256"),
    (re.compile(r"\bSHA\b(?!\d)", re.I), "sha-1"),
    (re.compile(r"\bMD5\b", re.I), "md5"),
    (re.compile(r"\bNULL\b", re.I), None),
]

_WEAK_SUITE_TOKENS = re.compile(r"\b(NULL|EXPORT|aNULL|eNULL|LOW|MEDIUM|DES|RC4|MD5|"
                                r"ADH|AECDH|PSK|SEED|IDEA)\b", re.I)


class ConfigDetector:
    id = "config-semantic"

    def supports(self, path: str) -> bool:
        base = os.path.basename(path).lower()
        ext = os.path.splitext(base)[1]
        if any(h in path.lower() for h in _CONFIG_HINTS):
            return True
        return ext in _CONFIG_EXT

    def detect(self, path: str, text: str) -> list[Detection]:
        out: list[Detection] = []
        lines = text.splitlines()

        def line_of(offset: int) -> int:
            return text.count("\n", 0, offset) + 1

        # ---- protocol versions -------------------------------------------------------
        for rx, family, label in _PROTO_PATTERNS:
            for m in rx.finditer(text):
                value = m.group(1)
                ln = line_of(m.start())
                found_any = False
                for tm in _TLS_TOKEN.finditer(value):
                    tok = tm.group(1).lower().replace("v", "v")
                    proto, ver = _VERSION_NORMAL.get(
                        tok.replace("tlsv", "tlsv").replace(" ", ""), (None, None))
                    if proto is None:
                        proto, ver = _VERSION_NORMAL.get(tok.replace(".", ""), (family, tok))
                    found_any = True
                    out.append(Detection(
                        detector=self.id, method="config-directive",
                        confidence=Confidence.HIGH,
                        protocol=proto, protocol_version=ver,
                        file=path, line=ln, language="config",
                        snippet=lines[ln - 1] if ln <= len(lines) else value,
                        matched=tm.group(1),
                        reasoning=f"{label} directive declares {proto} {ver}. Declarative "
                                  f"configuration is direct evidence of negotiated protocol.",
                        api_call=label,
                    ))
                if not found_any and family in ("SSH", "IKE"):
                    out.append(Detection(
                        detector=self.id, method="config-directive",
                        confidence=Confidence.HIGH, protocol=family,
                        protocol_version=value.strip(),
                        file=path, line=ln, language="config",
                        snippet=lines[ln - 1] if ln <= len(lines) else value,
                        matched=value.strip(),
                        reasoning=f"{label} directive.", api_call=label,
                    ))

        # ---- cipher suites ------------------------------------------------------------
        for m in _CIPHER_DIRECTIVE.finditer(text):
            suite_str = m.group(1).strip()
            ln = line_of(m.start())
            seen: set[str] = set()
            for rx, alg_id in _SUITE_ALGS:
                if alg_id is None or alg_id in seen:
                    continue
                if not rx.search(suite_str):
                    continue
                spec = alg.get(alg_id)
                if not spec:
                    continue
                seen.add(alg_id)
                role = alg.default_role(spec)
                if role == alg.ROLE_UNKNOWN and spec.primitive == "key-agree":
                    role = alg.ROLE_KEY_ESTABLISHMENT
                if spec.family == "RSA":
                    # In a TLS cipher-suite string, RSA denotes the certificate/auth
                    # algorithm, not key transport (TLS 1.3 removed RSA key exchange).
                    role = alg.ROLE_AUTHENTICATION
                out.append(Detection(
                    detector=self.id, method="config-cipher-suite",
                    confidence=Confidence.HIGH, algorithm=alg_id, role=role,
                    protocol="TLS", file=path, line=ln, language="config",
                    snippet=(lines[ln - 1][:200] if ln <= len(lines) else suite_str[:200]),
                    matched=alg_id,
                    reasoning=f"Declared in a TLS cipher-suite string: '{suite_str[:90]}'. "
                              f"Role assigned from the suite's position semantics.",
                    api_call="cipher-suite-config",
                    extra={"cipher_suite_string": suite_str[:300]},
                ))
            weak = _WEAK_SUITE_TOKENS.findall(suite_str)
            if weak:
                out.append(Detection(
                    detector=self.id, method="config-cipher-suite",
                    confidence=Confidence.HIGH, protocol="TLS",
                    file=path, line=ln, language="config",
                    snippet=suite_str[:200], matched=",".join(sorted(set(weak))),
                    reasoning=f"Cipher-suite string permits weak/legacy families: "
                              f"{', '.join(sorted(set(weak)))}.",
                    api_call="cipher-suite-config",
                    extra={"weak_suite_tokens": sorted(set(weak))},
                ))

        # ---- key-exchange groups ------------------------------------------------------
        for m in _GROUPS_DIRECTIVE.finditer(text):
            val = m.group(1).strip()
            ln = line_of(m.start())
            for token in re.split(r"[:,\s]+", val):
                if not token:
                    continue
                spec = alg.resolve(token)
                if spec and spec.primitive in ("key-agree", "kem", "combiner"):
                    out.append(Detection(
                        detector=self.id, method="config-directive",
                        confidence=Confidence.HIGH, algorithm=spec.id,
                        role=alg.ROLE_KEY_ESTABLISHMENT, protocol="TLS",
                        file=path, line=ln, language="config",
                        snippet=(lines[ln - 1][:200] if ln <= len(lines) else val),
                        matched=token,
                        reasoning=f"Key-exchange group '{token}' declared in configuration.",
                        api_call="supported-groups-config",
                    ))
                elif token.lower().startswith("sntrup"):
                    out.append(Detection(
                        detector=self.id, method="config-directive",
                        confidence=Confidence.HIGH, algorithm="x25519",
                        role=alg.ROLE_KEY_ESTABLISHMENT, protocol="SSH",
                        file=path, line=ln, language="config", matched=token,
                        snippet=(lines[ln - 1][:200] if ln <= len(lines) else val),
                        reasoning="OpenSSH sntrup761x25519 hybrid KEX detected. Provides "
                                  "store-now-decrypt-later protection but sntrup761 is "
                                  "not a NIST-selected KEM; plan a move to "
                                  "mlkem768x25519-sha256.",
                        api_call="ssh-kex-config",
                        extra={"hybrid_non_nist": True, "kex": token},
                    ))

        # ---- certificate / keystore references ----------------------------------------
        for m in _CERT_REF.finditer(text):
            ref = m.group(1)
            ln = line_of(m.start())
            is_key = bool(re.search(r"key", m.group(0), re.I)) and "keystore" not in m.group(0).lower()
            out.append(Detection(
                detector=self.id, method="config-directive",
                confidence=Confidence.HIGH, file=path, line=ln, language="config",
                snippet=(lines[ln - 1][:200] if ln <= len(lines) else ref),
                matched=ref,
                reasoning=("Private key file referenced by configuration. ECDAT records "
                           "the reference only and never reads key material."
                           if is_key else
                           "Certificate/keystore reference; links this service to a PKI asset."),
                api_call="pki-file-reference",
                extra={"pki_reference": ref, "reference_kind": "private-key" if is_key else "certificate"},
            ))

        return out
