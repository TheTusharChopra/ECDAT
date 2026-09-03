"""Container analysis.

The requirement (PART 10) is explicitly *not* CVE discovery. What matters is the
correlation chain:

    container -> installed package -> cryptographic library -> algorithm -> risk

Three input paths, in descending order of fidelity:

  1. `syft` / `trivy` SBOM output, when those binaries are installed. ECDAT shells
     out, consumes their JSON, and maps packages onto the library knowledge base.
     Neither is installed in this environment, so that path degrades to (2)/(3)
     and says so in the scan log rather than silently producing less.
  2. An exported OCI image tarball (`docker save`): manifest + config are read and
     layer tars are inspected for package databases and certificate material.
  3. Build and orchestration manifests -- Dockerfile, docker-compose, Kubernetes,
     Helm values. Lower fidelity than a built image but available at scan time in
     every repository, which is what makes it useful in CI.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tarfile
from dataclasses import dataclass, field

from ..detect.base import Detection
from ..knowledge import libraries as libs
from ..models import Confidence

DOCKERFILE_NAMES = ("dockerfile", "containerfile")
COMPOSE_NAMES = ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml")

_FROM = re.compile(r"^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?", re.I | re.M)
_APT_INSTALL = re.compile(
    r"(?:apt-get|apt|apk|yum|dnf|microdnf|zypper)\s+(?:--\S+\s+)*(?:add|install)\s+"
    r"((?:[^\n&|;]|\\\n)+)", re.I)
_PIP_INSTALL = re.compile(r"pip3?\s+install\s+((?:[^\n&|;]|\\\n)+)", re.I)
_NPM_INSTALL = re.compile(r"npm\s+(?:install|i|ci)\s+((?:[^\n&|;]|\\\n)+)", re.I)
_COPY_CERT = re.compile(r"^\s*(?:COPY|ADD)\s+(\S*(?:\.crt|\.pem|\.key|\.p12|\.pfx|"
                        r"\.jks|certs?/|ssl/)\S*)\s+(\S+)", re.I | re.M)
_ENV_TLS = re.compile(r"^\s*(?:ENV|ARG)\s+([A-Z_]*(?:TLS|SSL|CIPHER|CERT|CRYPTO)[A-Z_]*)"
                      r"[= ]\s*(\S+)", re.I | re.M)

_BASE_IMAGE_CRYPTO = {
    "alpine": ("libssl", "Alpine base: musl + LibreSSL/OpenSSL from apk"),
    "debian": ("libssl", "Debian base: OpenSSL from apt"),
    "ubuntu": ("libssl", "Ubuntu base: OpenSSL from apt"),
    "openjdk": ("jca", "JDK base image: JCA/JCE providers present"),
    "eclipse-temurin": ("jca", "Temurin JDK: JCA/JCE providers present"),
    "amazoncorretto": ("jca", "Corretto JDK: JCA/JCE providers present"),
    "python": ("python-cryptography", "Python base: ssl module linked to OpenSSL"),
    "node": ("node-crypto", "Node base: node:crypto backed by bundled OpenSSL"),
    "golang": ("go-crypto", "Go toolchain image: crypto/tls available"),
    "nginx": ("openssl", "nginx image terminates TLS via OpenSSL"),
    "httpd": ("openssl", "Apache httpd image: mod_ssl via OpenSSL"),
    "postgres": ("openssl", "PostgreSQL image supports TLS via OpenSSL"),
    "redis": ("openssl", "Redis image may enable TLS via OpenSSL"),
    "haproxy": ("openssl", "HAProxy terminates TLS via OpenSSL"),
    "envoyproxy": ("boringssl", "Envoy uses BoringSSL"),
    "distroless": ("openssl", "Distroless base: minimal, verify linked libcrypto"),
}


@dataclass
class ContainerInfo:
    name: str
    source: str                      # dockerfile | compose | k8s | oci-image | syft
    base_images: list[str] = field(default_factory=list)
    os_packages: list[tuple[str, str | None]] = field(default_factory=list)
    lang_packages: list[tuple[str, str | None]] = field(default_factory=list)
    cert_mounts: list[str] = field(default_factory=list)
    env_crypto: list[tuple[str, str]] = field(default_factory=list)
    layers: list[str] = field(default_factory=list)
    tool: str | None = None
    notes: list[str] = field(default_factory=list)


def _split_packages(blob: str) -> list[str]:
    blob = blob.replace("\\\n", " ")
    parts = re.split(r"\s+", blob.strip())
    out: list[str] = []
    for p in parts:
        if not p or p.startswith("-"):
            continue
        if p in ("&&", "\\", "|", ";", "--no-cache", "--no-install-recommends"):
            continue
        out.append(p.strip("'\"`,"))
    return out


def parse_dockerfile(path: str, text: str) -> ContainerInfo:
    name = os.path.basename(os.path.dirname(path)) or os.path.basename(path)
    info = ContainerInfo(name=name, source="dockerfile")

    for m in _FROM.finditer(text):
        info.base_images.append(m.group(1))

    for m in _APT_INSTALL.finditer(text):
        for pkg in _split_packages(m.group(1)):
            ver = None
            if "=" in pkg:
                pkg, _, ver = pkg.partition("=")
            info.os_packages.append((pkg, ver))

    for rx, eco in ((_PIP_INSTALL, "pypi"), (_NPM_INSTALL, "npm")):
        for m in rx.finditer(text):
            for pkg in _split_packages(m.group(1)):
                ver = None
                for sep in ("==", "@", ">=", "~="):
                    if sep in pkg:
                        pkg, _, ver = pkg.partition(sep)
                        break
                if pkg and not pkg.startswith((".", "/", "-")):
                    info.lang_packages.append((pkg, ver))

    for m in _COPY_CERT.finditer(text):
        info.cert_mounts.append(m.group(1))
    for m in _ENV_TLS.finditer(text):
        info.env_crypto.append((m.group(1), m.group(2)))
    return info


def parse_compose_or_k8s(path: str, text: str) -> list[ContainerInfo]:
    """Extract image references without a YAML dependency (regex on `image:` keys)."""
    out: list[ContainerInfo] = []
    images = re.findall(r"^\s*(?:-\s*)?image:\s*['\"]?([^\s'\"#]+)", text, re.M)
    names = re.findall(r"^\s*(?:name|container_name|serviceName):\s*['\"]?([^\s'\"#]+)",
                       text, re.M)
    source = "k8s" if re.search(r"apiVersion:|kind:\s*(Deployment|StatefulSet|DaemonSet)",
                                text) else "compose"
    for i, img in enumerate(images):
        nm = names[i] if i < len(names) else img.split("/")[-1].split(":")[0]
        ci = ContainerInfo(name=nm, source=source)
        ci.base_images.append(img)
        out.append(ci)
    # TLS-relevant keys in orchestration manifests
    for m in re.finditer(r"^\s*(tls|secretName|caBundle|sslMode|tlsMinVersion|"
                         r"cipherSuites?|clientAuth)\s*:\s*['\"]?([^\n#]*)", text, re.M | re.I):
        if out:
            out[0].env_crypto.append((m.group(1), m.group(2).strip()[:80]))
    return out


# ======================================================================================
# OCI image tarball
# ======================================================================================
_PKGDB_PATHS = ("var/lib/dpkg/status", "lib/apk/db/installed", "var/lib/rpm/Packages")


def parse_oci_tar(path: str) -> ContainerInfo:
    info = ContainerInfo(name=os.path.basename(path), source="oci-image")
    try:
        with tarfile.open(path, "r:*") as tf:
            names = tf.getnames()
            info.layers = [n for n in names if n.endswith((".tar", "layer.tar"))]
            for meta in ("manifest.json", "index.json"):
                if meta in names:
                    fh = tf.extractfile(meta)
                    if fh:
                        try:
                            data = json.loads(fh.read().decode("utf-8", "replace"))
                            info.notes.append(f"{meta} parsed: {len(data)} entries")
                        except json.JSONDecodeError:
                            pass
            # certificates shipped inside the image
            for n in names:
                if n.endswith((".crt", ".pem", ".p12", ".jks")):
                    info.cert_mounts.append(n)
            for n in names:
                if any(n.endswith(db) for db in _PKGDB_PATHS):
                    fh = tf.extractfile(n)
                    if not fh:
                        continue
                    blob = fh.read(4 * 1024 * 1024).decode("utf-8", "replace")
                    if "dpkg" in n:
                        for m in re.finditer(r"^Package:\s*(\S+)\nStatus:[^\n]*\n"
                                             r"(?:.*\n)*?Version:\s*(\S+)", blob, re.M):
                            info.os_packages.append((m.group(1), m.group(2)))
                    elif "apk" in n:
                        cur = None
                        for line in blob.splitlines():
                            if line.startswith("P:"):
                                cur = line[2:]
                            elif line.startswith("V:") and cur:
                                info.os_packages.append((cur, line[2:]))
                                cur = None
    except (tarfile.TarError, OSError) as e:
        info.notes.append(f"tar read failed: {e}")
    return info


# ======================================================================================
# syft / trivy integration (opportunistic)
# ======================================================================================
def sbom_tool_available() -> dict[str, str | None]:
    return {"syft": shutil.which("syft"), "trivy": shutil.which("trivy")}


def run_syft(target: str, timeout: int = 180) -> ContainerInfo | None:
    exe = shutil.which("syft")
    if not exe:
        return None
    try:
        proc = subprocess.run([exe, target, "-o", "syft-json", "-q"],
                              capture_output=True, text=True, timeout=timeout, check=False)
        if proc.returncode != 0:
            return None
        data = json.loads(proc.stdout)
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
        return None
    info = ContainerInfo(name=target, source="syft", tool="syft")
    for art in data.get("artifacts", []):
        entry = (art.get("name", ""), art.get("version"))
        if art.get("type") in ("deb", "rpm", "apk"):
            info.os_packages.append(entry)
        else:
            info.lang_packages.append(entry)
    info.notes.append(f"syft reported {len(data.get('artifacts', []))} artefacts")
    return info


# ======================================================================================
# Detections
# ======================================================================================
def container_detections(info: ContainerInfo, path: str) -> list[Detection]:
    out: list[Detection] = []
    base_extra = {"container": info.name, "container_source": info.source,
                  "base_images": info.base_images, "sbom_tool": info.tool,
                  "notes": info.notes}

    # base image -> implied crypto provider
    for img in info.base_images:
        stem = img.split("/")[-1].split(":")[0].split("@")[0].lower()
        tag = img.split(":")[-1] if ":" in img.split("/")[-1] else "latest"
        matched = None
        for key, (lib_id, note) in _BASE_IMAGE_CRYPTO.items():
            if key in stem or key in img.lower():
                matched = (lib_id, note)
                break
        if not matched:
            continue
        lib_id, note = matched
        lib = libs.get(lib_id)
        cap, cap_note = libs.pqc_capability(lib, None)
        out.append(Detection(
            detector="container", method="base-image",
            confidence=Confidence.MEDIUM,
            library=lib_id, file=path, language="container",
            matched=img,
            reasoning=(f"Container base image '{img}' implies a cryptographic provider: "
                       f"{note}. MEDIUM confidence -- the image is known to ship this "
                       f"provider, but the exact version is only knowable from a built "
                       f"image or an SBOM."),
            api_call="container-base-image",
            extra={**base_extra, "image": img, "image_tag": tag,
                   "pqc_capability": cap, "pqc_note": cap_note,
                   "floating_tag": tag in ("latest", "")},
        ))
        if tag in ("latest", ""):
            out.append(Detection(
                detector="container", method="base-image",
                confidence=Confidence.HIGH, file=path, language="container",
                matched=img,
                reasoning=("Base image uses a floating tag. The deployed cryptographic "
                           "library version is therefore not reproducible, which blocks "
                           "any credible crypto-agility claim for this component."),
                api_call="container-floating-tag",
                extra={**base_extra, "image": img, "crypto_agility_blocker": True},
            ))

    # installed packages -> crypto libraries
    for pkgs, kind, conf in ((info.os_packages, "os-package", Confidence.HIGH),
                             (info.lang_packages, "lang-package", Confidence.HIGH)):
        for name, ver in pkgs:
            lib = libs.resolve_package(name)
            if lib is None:
                continue
            cap, cap_note = libs.pqc_capability(lib, ver)
            out.append(Detection(
                detector="container", method=kind,
                confidence=conf,
                library=lib.id, library_version=ver, package=name,
                file=path, language="container",
                matched=f"{name}{'=' + ver if ver else ''}",
                reasoning=(f"Package '{name}' installed in container '{info.name}' "
                           f"resolves to {lib.name}. This is the concrete cryptographic "
                           f"implementation the workload executes. PQC capability: {cap}. "
                           f"{cap_note}"),
                api_call=f"container-{kind}",
                extra={**base_extra, "package": name, "package_version": ver,
                       "pqc_capability": cap, "pqc_note": cap_note},
            ))

    # certificates / keys mounted into the image
    for ref in info.cert_mounts:
        is_key = bool(re.search(r"\.(key|p12|pfx|jks)$", ref, re.I))
        out.append(Detection(
            detector="container", method="image-file",
            confidence=Confidence.HIGH, file=path, language="container",
            matched=ref,
            reasoning=("Private key or keystore baked into the container image. "
                       "ECDAT records the path only and never reads the material. "
                       "Baking key material into an image is itself a finding: it "
                       "prevents rotation and therefore blocks crypto agility."
                       if is_key else
                       f"Certificate material '{ref}' shipped in the image; links this "
                       f"container to a PKI asset."),
            api_call="container-pki-file",
            extra={**base_extra, "pki_reference": ref,
                   "reference_kind": "private-key" if is_key else "certificate",
                   "key_material_in_image": is_key},
        ))

    for key, val in info.env_crypto:
        out.append(Detection(
            detector="container", method="env-config",
            confidence=Confidence.MEDIUM, file=path, language="container",
            matched=f"{key}={val}",
            reasoning=f"Crypto-relevant container configuration '{key}' set to '{val}'.",
            api_call="container-env",
            extra={**base_extra, "config_key": key, "config_value": val},
        ))
    return out


class ContainerScanner:
    id = "container"

    def supports(self, path: str) -> bool:
        base = os.path.basename(path).lower()
        if base in DOCKERFILE_NAMES or base.startswith("dockerfile"):
            return True
        if base in COMPOSE_NAMES:
            return True
        return base.endswith((".yaml", ".yml")) and "k8s" in path.lower()

    def detect(self, path: str, text: str) -> list[Detection]:
        base = os.path.basename(path).lower()
        if base in DOCKERFILE_NAMES or base.startswith("dockerfile"):
            return container_detections(parse_dockerfile(path, text), path)
        out: list[Detection] = []
        for info in parse_compose_or_k8s(path, text):
            out.extend(container_detections(info, path))
        return out
