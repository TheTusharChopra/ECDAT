"""Dependency / package-manifest scanning.

Crypto usually enters an application through a dependency, not through code the team
wrote. This scanner reads manifests across six ecosystems, resolves each package
against the library knowledge base, and -- critically -- records the *version*,
because the version determines whether a PQC migration is even possible at that
component (see `libraries.pqc_capability`).
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass

from ..detect.base import Detection
from ..knowledge import libraries as libs
from ..models import Confidence

MANIFEST_FILES = {
    "requirements.txt": "pypi", "requirements-dev.txt": "pypi",
    "pyproject.toml": "pypi", "Pipfile": "pypi", "setup.py": "pypi",
    "package.json": "npm", "package-lock.json": "npm",
    "pom.xml": "maven", "build.gradle": "gradle", "build.gradle.kts": "gradle",
    "go.mod": "go", "go.sum": "go",
    "Cargo.toml": "cargo", "Cargo.lock": "cargo",
    "Gemfile": "rubygems", "composer.json": "composer",
    "packages.config": "nuget",
}

_PY_REQ = re.compile(r"^\s*([A-Za-z0-9._-]+)\s*(?:\[[^\]]*\])?\s*"
                     r"(?:[=<>!~]=?\s*([0-9][A-Za-z0-9._+-]*))?", re.M)
_GO_MOD = re.compile(r"^\s*(?:require\s+)?([a-z0-9./_-]+\.[a-z]{2,}/[^\s]+|crypto/[a-z0-9/]+)"
                     r"\s+v?([0-9][^\s]*)", re.M | re.I)
_GO_IMPORT = re.compile(r'"((?:crypto|golang\.org/x/crypto)[a-z0-9/._-]*)"')
_CARGO = re.compile(r'^\s*([a-zA-Z0-9_-]+)\s*=\s*(?:"([^"]+)"|\{[^}]*version\s*=\s*"([^"]+)")',
                    re.M)
_GRADLE = re.compile(r"""['"]([a-zA-Z0-9._-]+):([a-zA-Z0-9._-]+):([0-9][A-Za-z0-9._-]*)['"]""")


@dataclass
class Dependency:
    name: str
    version: str | None
    ecosystem: str
    manifest: str
    line: int
    direct: bool = True


def _lineno(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def parse_manifest(path: str, text: str) -> list[Dependency]:
    base = os.path.basename(path)
    eco = MANIFEST_FILES.get(base)
    deps: list[Dependency] = []
    if eco is None:
        return deps

    try:
        if base.startswith("requirements") or base in ("Pipfile", "setup.py", "pyproject.toml"):
            for m in _PY_REQ.finditer(text):
                name = m.group(1)
                if name.lower() in ("python", "r", "e", "c", "git+https", "requires",
                                    "dependencies", "name", "version", "description"):
                    continue
                if text[m.start():m.start() + 1] in ("#",):
                    continue
                deps.append(Dependency(name, m.group(2), "pypi", path, _lineno(text, m.start())))

        elif base == "package.json":
            data = json.loads(text)
            for section, direct in (("dependencies", True), ("devDependencies", False),
                                    ("optionalDependencies", False)):
                for name, ver in (data.get(section) or {}).items():
                    ln = _lineno(text, text.find(f'"{name}"'))
                    deps.append(Dependency(name, str(ver).lstrip("^~>=< "), "npm",
                                           path, ln, direct))

        elif base == "package-lock.json":
            data = json.loads(text)
            pkgs = data.get("packages") or data.get("dependencies") or {}
            for key, meta in pkgs.items():
                if not isinstance(meta, dict):
                    continue
                name = key.split("node_modules/")[-1] or data.get("name", "")
                if not name:
                    continue
                deps.append(Dependency(name, meta.get("version"), "npm", path, 1,
                                       direct=False))

        elif base == "pom.xml":
            for m in re.finditer(
                    r"<dependency>(.*?)</dependency>", text, re.S):
                blk = m.group(1)
                gid = re.search(r"<groupId>([^<]+)</groupId>", blk)
                aid = re.search(r"<artifactId>([^<]+)</artifactId>", blk)
                ver = re.search(r"<version>([^<]+)</version>", blk)
                if aid:
                    full = f"{gid.group(1)}:{aid.group(1)}" if gid else aid.group(1)
                    deps.append(Dependency(full, ver.group(1) if ver else None, "maven",
                                           path, _lineno(text, m.start())))

        elif eco == "gradle":
            for m in _GRADLE.finditer(text):
                deps.append(Dependency(f"{m.group(1)}:{m.group(2)}", m.group(3), "gradle",
                                       path, _lineno(text, m.start())))

        elif base in ("go.mod", "go.sum"):
            for m in _GO_MOD.finditer(text):
                deps.append(Dependency(m.group(1), m.group(2), "go", path,
                                       _lineno(text, m.start())))

        elif base.startswith("Cargo"):
            in_deps = False
            for i, line in enumerate(text.splitlines(), 1):
                s = line.strip()
                if s.startswith("["):
                    in_deps = "dependencies" in s
                    continue
                if not in_deps:
                    continue
                m = _CARGO.match(line)
                if m:
                    deps.append(Dependency(m.group(1), m.group(2) or m.group(3),
                                           "cargo", path, i))
    except (json.JSONDecodeError, ValueError):
        return deps

    # de-duplicate by (name, version)
    seen: set[tuple[str, str | None]] = set()
    out: list[Dependency] = []
    for d in deps:
        k = (d.name.lower(), d.version)
        if k not in seen:
            seen.add(k)
            out.append(d)
    return out


def go_crypto_imports(path: str, text: str) -> list[str]:
    return sorted(set(_GO_IMPORT.findall(text)))


class DependencyScanner:
    """Emits one detection per *cryptographically relevant* dependency."""

    id = "dependency-manifest"

    def supports(self, path: str) -> bool:
        return os.path.basename(path) in MANIFEST_FILES

    def detect(self, path: str, text: str) -> list[Detection]:
        out: list[Detection] = []
        for dep in parse_manifest(path, text):
            lib = libs.resolve_package(dep.name)
            if lib is None:
                continue
            cap, cap_note = libs.pqc_capability(lib, dep.version)
            out.append(Detection(
                detector=self.id, method="manifest",
                confidence=Confidence.HIGH,
                library=lib.id, library_version=dep.version, package=dep.name,
                file=path, line=dep.line, language=dep.ecosystem,
                matched=f"{dep.name}{'@' + dep.version if dep.version else ''}",
                reasoning=(f"Cryptographic library '{lib.name}' declared in "
                           f"{os.path.basename(path)} ({dep.ecosystem})"
                           f"{' as a direct dependency' if dep.direct else ' transitively'}. "
                           f"PQC capability: {cap}. {cap_note}"),
                api_call="package-manifest",
                extra={"ecosystem": dep.ecosystem, "direct": dep.direct,
                       "pqc_capability": cap, "pqc_note": cap_note},
            ))
        return out
