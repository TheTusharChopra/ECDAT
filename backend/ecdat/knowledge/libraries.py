"""Cryptographic library / provider knowledge base.

Two jobs:
  1. Recognise a cryptographic library from a package manifest, a container package
     list, or a binary's linkage table.
  2. Record whether that library can *actually* offer PQC today, because a migration
     recommendation is worthless if the underlying provider cannot implement it.
     `pqc_support` is what turns "you should adopt ML-KEM" into "you can adopt
     ML-KEM here, at this version".
"""

from __future__ import annotations

from dataclasses import dataclass, field

PQC_NATIVE = "native"        # PQC available in a mainline release
PQC_PROVIDER = "provider"    # PQC via an add-on provider/module
PQC_NONE = "none"            # no PQC path today
PQC_UNKNOWN = "unknown"


@dataclass(frozen=True)
class LibrarySpec:
    id: str
    name: str
    ecosystem: str                     # c, java, python, node, go, rust, ...
    pqc_support: str
    pqc_since: str | None = None
    pqc_note: str = ""
    package_names: tuple[str, ...] = ()   # names as they appear in manifests
    binary_symbols: tuple[str, ...] = ()  # symbol/soname fragments for binary scanning
    sonames: tuple[str, ...] = ()
    aliases: tuple[str, ...] = ()
    note: str = ""


_LIBS: list[LibrarySpec] = [
    LibrarySpec(
        id="openssl", name="OpenSSL", ecosystem="c",
        pqc_support=PQC_NATIVE, pqc_since="3.5",
        pqc_note="OpenSSL 3.5 added ML-KEM, ML-DSA and SLH-DSA in the mainline "
                 "release; 3.2-3.4 need the oqsprovider add-on. Versions 1.x are "
                 "end-of-life and have no PQC path.",
        package_names=("openssl", "libssl", "libssl1.1", "libssl3", "openssl-libs",
                       "libcrypto", "libssl-dev"),
        binary_symbols=("EVP_", "SSL_CTX_", "RSA_", "EC_KEY_", "OPENSSL_",
                        "X509_", "BN_", "ERR_", "CRYPTO_"),
        sonames=("libssl.so", "libcrypto.so", "libssl.dylib", "libcrypto.dylib"),
    ),
    LibrarySpec(
        id="boringssl", name="BoringSSL", ecosystem="c",
        pqc_support=PQC_NATIVE,
        pqc_note="Ships X25519MLKEM768 for TLS; not a general-purpose PQC API and "
                 "explicitly has no API/ABI stability guarantee.",
        package_names=("boringssl",),
        binary_symbols=("SSL_CTX_", "EVP_", "bssl"), sonames=("libssl",),
    ),
    LibrarySpec(
        id="libressl", name="LibreSSL", ecosystem="c", pqc_support=PQC_NONE,
        pqc_note="No PQC key establishment in mainline; migration requires switching "
                 "provider.",
        package_names=("libressl",), sonames=("libtls.so",),
    ),
    LibrarySpec(
        id="libsodium", name="libsodium", ecosystem="c", pqc_support=PQC_NONE,
        pqc_note="Deliberately minimal primitive set (X25519/Ed25519); no PQC. "
                 "Applications must add a separate KEM implementation.",
        package_names=("libsodium", "libsodium23", "pynacl", "sodium"),
        binary_symbols=("crypto_box_", "crypto_sign_", "sodium_"),
        sonames=("libsodium.so",),
    ),
    LibrarySpec(
        id="wolfssl", name="wolfSSL", ecosystem="c",
        pqc_support=PQC_NATIVE,
        pqc_note="Supports ML-KEM and ML-DSA; a common choice for constrained and "
                 "embedded targets where PQC key sizes matter most.",
        package_names=("wolfssl",), binary_symbols=("wolfSSL_", "wc_"),
        sonames=("libwolfssl.so",),
    ),
    LibrarySpec(
        id="gnutls", name="GnuTLS", ecosystem="c", pqc_support=PQC_NATIVE,
        pqc_note="Recent releases add ML-KEM hybrid groups.",
        package_names=("gnutls", "libgnutls30"), sonames=("libgnutls.so",),
    ),
    LibrarySpec(
        id="nss", name="Mozilla NSS", ecosystem="c", pqc_support=PQC_NATIVE,
        pqc_note="Implements X25519MLKEM768 for TLS.",
        package_names=("nss", "libnss3"), sonames=("libnss3.so", "libssl3.so"),
    ),
    LibrarySpec(
        id="bouncycastle", name="Bouncy Castle", ecosystem="java",
        pqc_support=PQC_NATIVE,
        pqc_note="The most mature PQC surface on the JVM: ML-KEM, ML-DSA and SLH-DSA "
                 "in the post-quantum provider. Practical migration target for "
                 "legacy Java estates.",
        package_names=("bcprov-jdk18on", "bcprov-jdk15on", "bcpkix-jdk18on",
                       "bctls-jdk18on", "org.bouncycastle"),
        aliases=("bc", "bcprov"),
    ),
    LibrarySpec(
        id="jca", name="Java JCA/JCE (SunJCE)", ecosystem="java",
        pqc_support=PQC_PROVIDER,
        pqc_note="JDK 24+ added ML-KEM/ML-DSA; earlier JDKs need Bouncy Castle as a "
                 "registered provider. Determine the JDK version before promising a "
                 "drop-in migration.",
        package_names=("javax.crypto", "java.security"),
        aliases=("sunjce", "jce", "jca"),
    ),
    LibrarySpec(
        id="python-cryptography", name="python cryptography (pyca)",
        ecosystem="python", pqc_support=PQC_PROVIDER,
        pqc_note="Wraps OpenSSL; PQC availability tracks the linked libcrypto. "
                 "Check the bundled OpenSSL version, not the Python package version.",
        package_names=("cryptography",),
    ),
    LibrarySpec(
        id="pycryptodome", name="PyCryptodome", ecosystem="python",
        pqc_support=PQC_NONE,
        pqc_note="No PQC primitives. Long-term migrations should move to a "
                 "provider-backed library.",
        package_names=("pycryptodome", "pycryptodomex", "pycrypto"),
        aliases=("crypto", "cryptodome"),
    ),
    LibrarySpec(
        id="pyopenssl", name="pyOpenSSL", ecosystem="python",
        pqc_support=PQC_PROVIDER, pqc_note="Thin binding; inherits OpenSSL support.",
        package_names=("pyopenssl",),
    ),
    LibrarySpec(
        id="paramiko", name="Paramiko (SSH)", ecosystem="python",
        pqc_support=PQC_NONE,
        pqc_note="No PQC SSH key exchange; OpenSSH's PQC KEX is not available here.",
        package_names=("paramiko",),
    ),
    LibrarySpec(
        id="node-crypto", name="Node.js crypto", ecosystem="node",
        pqc_support=PQC_PROVIDER,
        pqc_note="Backed by the OpenSSL that Node was built against; PQC depends on "
                 "the Node build, not on application code.",
        package_names=("crypto", "node:crypto"),
    ),
    LibrarySpec(
        id="node-forge", name="node-forge", ecosystem="node", pqc_support=PQC_NONE,
        pqc_note="Pure-JS classical crypto only.", package_names=("node-forge",)),
    LibrarySpec(
        id="jsrsasign", name="jsrsasign", ecosystem="node", pqc_support=PQC_NONE,
        package_names=("jsrsasign",)),
    LibrarySpec(
        id="go-crypto", name="Go standard crypto", ecosystem="go",
        pqc_support=PQC_NATIVE,
        pqc_note="crypto/mlkem is in the standard library and X25519MLKEM768 is "
                 "enabled by default in crypto/tls on current Go releases.",
        package_names=("crypto/tls", "crypto/rsa", "crypto/ecdsa", "crypto/mlkem",
                       "crypto/x509", "crypto/ed25519", "crypto/aes", "crypto/sha256"),
    ),
    LibrarySpec(
        id="rustls", name="rustls", ecosystem="rust", pqc_support=PQC_NATIVE,
        pqc_note="Supports X25519MLKEM768 through its aws-lc-rs backend.",
        package_names=("rustls", "rustls-webpki")),
    LibrarySpec(
        id="rust-crypto", name="RustCrypto crates", ecosystem="rust",
        pqc_support=PQC_PROVIDER,
        pqc_note="ml-kem / ml-dsa crates exist but several are pre-1.0 and not yet "
                 "independently audited.",
        package_names=("aes-gcm", "sha2", "rsa", "p256", "ed25519-dalek",
                       "x25519-dalek", "ring", "chacha20poly1305", "ml-kem")),
    LibrarySpec(
        id="aws-lc", name="AWS-LC", ecosystem="c", pqc_support=PQC_NATIVE,
        pqc_note="FIPS-validated builds with ML-KEM support.",
        package_names=("aws-lc", "aws-lc-rs"), sonames=("libcrypto.so",)),
    LibrarySpec(
        id="openssh", name="OpenSSH", ecosystem="c", pqc_support=PQC_NATIVE,
        pqc_since="9.0",
        pqc_note="sntrup761x25519-sha512 hybrid KEX since 9.0 (default since 9.9) and "
                 "mlkem768x25519-sha256 in recent releases. Note sntrup761 is a "
                 "hybrid with a non-NIST-selected KEM -- good against "
                 "store-now-decrypt-later, but not a FIPS 203 mechanism.",
        package_names=("openssh", "openssh-client", "openssh-server"),
        binary_symbols=("ssh_", "kex_"),
    ),
    LibrarySpec(
        id="mbedtls", name="Mbed TLS", ecosystem="c", pqc_support=PQC_PROVIDER,
        pqc_note="PQC through PSA crypto drivers; embedded targets need careful "
                 "memory budgeting for ML-KEM key sizes.",
        package_names=("mbedtls",), sonames=("libmbedtls.so", "libmbedcrypto.so")),
    LibrarySpec(
        id="jsse", name="Java JSSE (TLS)", ecosystem="java", pqc_support=PQC_PROVIDER,
        package_names=("javax.net.ssl",)),
]

ALL_LIBRARIES = _LIBS
BY_ID: dict[str, LibrarySpec] = {l.id: l for l in _LIBS}

_PKG_INDEX: dict[str, str] = {}
for _l in _LIBS:
    _PKG_INDEX[_l.id] = _l.id
    _PKG_INDEX[_l.name.lower()] = _l.id
    for _p in _l.package_names:
        _PKG_INDEX.setdefault(_p.lower(), _l.id)
    for _p in _l.aliases:
        _PKG_INDEX.setdefault(_p.lower(), _l.id)


def get(lib_id: str | None) -> LibrarySpec | None:
    return BY_ID.get(lib_id or "")


def resolve_package(name: str | None) -> LibrarySpec | None:
    """Map a manifest/OS package name onto a known cryptographic library."""
    if not name:
        return None
    key = name.strip().lower()
    if key in _PKG_INDEX:
        return BY_ID[_PKG_INDEX[key]]
    # Go import paths: crypto/tls, golang.org/x/crypto/...
    if key.startswith("crypto/") or key.startswith("golang.org/x/crypto"):
        return BY_ID["go-crypto"]
    if key.startswith("org.bouncycastle") or key.startswith("bcprov"):
        return BY_ID["bouncycastle"]
    # substring fallback for versioned OS packages, e.g. libssl1.1t64
    for pkg, lid in _PKG_INDEX.items():
        if len(pkg) >= 6 and pkg in key:
            return BY_ID[lid]
    return None


def _ver_tuple(v: str) -> tuple[int, ...]:
    out: list[int] = []
    for part in v.replace("-", ".").split("."):
        digits = "".join(c for c in part if c.isdigit())
        if not digits:
            break
        out.append(int(digits))
    return tuple(out) or (0,)


def pqc_capability(lib: LibrarySpec | None, version: str | None) -> tuple[str, str]:
    """(capability, human explanation) for a library at a concrete version.

    Returns the *deployment blocker* view: can this component implement a PQC
    recommendation as it stands today?
    """
    if lib is None:
        return PQC_UNKNOWN, "Library not recognised; PQC support must be verified manually."
    if lib.pqc_support == PQC_NATIVE and lib.pqc_since and version:
        try:
            if _ver_tuple(version) < _ver_tuple(lib.pqc_since):
                return (
                    PQC_PROVIDER,
                    f"{lib.name} {version} predates native PQC support "
                    f"({lib.pqc_since}+). Upgrade or add a PQC provider first -- this "
                    f"is a prerequisite, not an optional step.",
                )
        except Exception:  # pragma: no cover - defensive version parsing
            pass
    return lib.pqc_support, lib.pqc_note or f"{lib.name}: {lib.pqc_support} PQC support."
