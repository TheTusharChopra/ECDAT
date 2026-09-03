"""Source-tree scanner: filesystem walk, safety limits, detector fan-out.

Safety properties that matter for a tool pointed at classified source (PART 30):
  * scanned code is never executed -- only read and parsed;
  * per-file size ceiling and a global byte budget bound memory and time;
  * symlinks are not followed, so a scan cannot be walked out of its target tree;
  * binary files are routed to the binary scanner, never decoded as text;
  * every skip is counted and reported, so "0 findings" can be distinguished from
    "nothing was actually analysed".
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field

from ..detect.base import Detection, language_for
from ..detect.config import ConfigDetector
from ..detect.lexical import LexicalDetector
from ..detect.python_ast import PythonAstDetector
from ..models import Confidence, ScanStats
from . import x509
from .binary import BinaryScanner, analyze_binary, binary_detections
from .container import ContainerScanner
from .dependency import DependencyScanner

MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_TOTAL_BYTES = 512 * 1024 * 1024
MAX_FILES = 200_000

SKIP_DIRS = {
    ".git", ".svn", ".hg", "node_modules", "__pycache__", ".venv", "venv", "env",
    ".tox", ".mypy_cache", ".pytest_cache", "dist", "build", ".next", ".nuxt",
    "target", ".gradle", ".idea", ".vscode", "vendor", "site-packages", ".terraform",
    "coverage", ".cache", "bower_components", ".DS_Store", "eggs", ".eggs",
}

TEXT_EXTS = {
    ".py", ".pyi", ".java", ".kt", ".scala", ".js", ".mjs", ".cjs", ".ts", ".tsx",
    ".jsx", ".go", ".rs", ".c", ".h", ".cc", ".cpp", ".hpp", ".cs", ".rb", ".php",
    ".swift", ".sh", ".bash", ".yaml", ".yml", ".json", ".toml", ".ini", ".cnf",
    ".conf", ".properties", ".xml", ".tf", ".hcl", ".md", ".txt", ".env", ".gradle",
    ".sql", ".tpl", ".j2", ".cfg", ".service",
}

CERT_EXTS = {".crt", ".cer", ".pem", ".der", ".p7b", ".p12", ".pfx", ".jks",
             ".keystore", ".truststore", ".key", ".pub", ".csr"}

BINARY_EXTS = {".so", ".dylib", ".dll", ".exe", ".a", ".o", ".bin", ".elf",
               ".class", ".jar", ".war", ".node", ".wasm"}

IMAGE_TAR_EXTS = {".tar"}

# Files that are never worth reading
IGNORE_EXTS = {".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2",
               ".ttf", ".eot", ".mp4", ".mp3", ".pdf", ".zip", ".gz", ".bz2", ".xz",
               ".7z", ".rar", ".lock", ".map", ".min.js", ".pyc", ".pyo", ".webp"}


@dataclass
class SourceScanConfig:
    max_file_bytes: int = MAX_FILE_BYTES
    max_total_bytes: int = MAX_TOTAL_BYTES
    max_files: int = MAX_FILES
    follow_symlinks: bool = False
    scan_binaries: bool = True
    scan_certificates: bool = True
    verify_certificates: bool = True
    extra_skip_dirs: set[str] = field(default_factory=set)


class SourceScanner:
    """Walks a tree and fans each file out to every detector that supports it."""

    def __init__(self, config: SourceScanConfig | None = None):
        self.config = config or SourceScanConfig()
        self.text_detectors = [
            PythonAstDetector(),      # Layer 2: real AST
            ConfigDetector(),         # declarative configuration
            DependencyScanner(),      # manifests
            ContainerScanner(),       # Dockerfile / compose / k8s
            LexicalDetector(),        # Layer 1 + context scoring (always last)
        ]
        self.binary_scanner = BinaryScanner()

    # ---------------------------------------------------------------------------------
    def scan_tree(self, root: str, stats: ScanStats | None = None
                  ) -> tuple[list[Detection], ScanStats]:
        stats = stats or ScanStats()
        detections: list[Detection] = []
        started = time.time()
        total_bytes = 0
        skip = SKIP_DIRS | self.config.extra_skip_dirs

        for dirpath, dirnames, filenames in os.walk(root, followlinks=self.config.follow_symlinks):
            dirnames[:] = [d for d in dirnames if d not in skip and not d.startswith(".git")]
            for fname in sorted(filenames):
                if stats.files_seen >= self.config.max_files:
                    stats.errors.append(
                        f"file cap {self.config.max_files} reached; scan truncated")
                    break
                full = os.path.join(dirpath, fname)
                stats.files_seen += 1

                if os.path.islink(full) and not self.config.follow_symlinks:
                    stats.skipped_files += 1
                    continue
                try:
                    size = os.path.getsize(full)
                except OSError:
                    stats.skipped_files += 1
                    continue

                ext = os.path.splitext(fname)[1].lower()
                if ext in IGNORE_EXTS:
                    stats.skipped_files += 1
                    continue
                if size > self.config.max_file_bytes:
                    stats.skipped_files += 1
                    stats.errors.append(
                        f"{os.path.relpath(full, root)}: {size} bytes exceeds per-file "
                        f"ceiling; skipped (recorded so coverage is not overstated)")
                    continue
                if total_bytes > self.config.max_total_bytes:
                    stats.errors.append("global byte budget exhausted; scan truncated")
                    break

                rel = os.path.relpath(full, root)
                new = self._scan_file(full, rel, ext, stats)
                if new:
                    detections.extend(new)
                total_bytes += size
                stats.bytes_analyzed += size

        # Accumulate: scan_tree is called once per target with a shared stats
        # object, so assignment would discard every earlier target's count.
        stats.raw_detections += len(detections)
        stats.duration_ms += int((time.time() - started) * 1000)
        for d in detections:
            stats.detector_counts[d.detector] = stats.detector_counts.get(d.detector, 0) + 1
        return detections, stats

    # ---------------------------------------------------------------------------------
    def _scan_file(self, full: str, rel: str, ext: str, stats: ScanStats) -> list[Detection]:
        out: list[Detection] = []

        # --- certificates / key material -------------------------------------------
        if self.config.scan_certificates and ext in CERT_EXTS:
            res = x509.load_cert_file(full)
            stats.errors.extend(res.errors)
            for cert in res.certificates:
                cert.path = rel
                stats.certificates += 1
                out.extend(x509.certificate_detections(
                    cert, verify=self.config.verify_certificates))
            if res.private_key_detected:
                out.append(Detection(
                    detector="certificate-x509", method="pem-scan",
                    confidence=Confidence.HIGH,
                    file=rel, language="pem",
                    matched="private key material",
                    reasoning=("Private key material detected. Contents were NOT read, "
                               "parsed, logged or stored -- only the fact of its presence "
                               "and its location are recorded. Key material committed to "
                               "a repository is a finding in its own right."),
                    api_call="private-key-detection",
                    extra={"private_key_labels": res.private_key_labels,
                           "key_material_in_repo": True},
                ))
            if res.pkcs12_detected:
                stats.errors.append(f"{rel}: PKCS#12 recorded as metadata only")
            if res.certificates or res.private_key_detected:
                stats.files_analyzed += 1
                return out

        # --- binaries -----------------------------------------------------------------
        if ext in BINARY_EXTS or (ext == "" and self.config.scan_binaries):
            if self.config.scan_binaries:
                info = analyze_binary(full)
                if info.fmt != "unknown":
                    info.path = rel
                    stats.binaries += 1
                    stats.files_analyzed += 1
                    return binary_detections(info)
            if ext in BINARY_EXTS:
                stats.skipped_files += 1
                return out

        # --- text ----------------------------------------------------------------------
        if ext not in TEXT_EXTS and ext != "" and ext not in CERT_EXTS:
            stats.skipped_files += 1
            return out

        try:
            with open(full, "rb") as fh:
                raw = fh.read(self.config.max_file_bytes)
        except OSError as e:
            stats.errors.append(f"{rel}: {e}")
            stats.skipped_files += 1
            return out

        if b"\x00" in raw[:8192]:      # binary content behind a text extension
            stats.skipped_files += 1
            return out

        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            text = raw.decode("utf-8", "replace")

        stats.files_analyzed += 1
        lang = language_for(rel)
        if lang:
            stats.language_counts[lang] = stats.language_counts.get(lang, 0) + 1

        basename = os.path.basename(rel)
        from .dependency import MANIFEST_FILES
        if basename in MANIFEST_FILES:
            stats.manifests += 1
        if ext in (".conf", ".cnf", ".properties", ".ini") or "config" in basename.lower():
            stats.configs += 1

        for det in self.text_detectors:
            try:
                if det.supports(rel):
                    found = det.detect(rel, text)
                    out.extend(found)
                    if isinstance(det, ContainerScanner) and found:
                        stats.containers += 1
                    if isinstance(det, DependencyScanner):
                        stats.dependencies += len(found)
            except Exception as e:      # a detector fault must not abort the scan
                stats.errors.append(f"{det.id} on {rel}: {type(e).__name__}: {e}")
        return out
