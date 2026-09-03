"""Detector contract shared by every discovery layer.

A Detection is a *claim about a location*, not yet a normalized asset. The
normalizer later merges detections into `CryptoAsset` records. Keeping the two
apart is what lets several layers observe the same line of code and contribute
different facts (Layer 1 says "the token AES appears"; Layer 2 says "this is an
AES-256-GCM Cipher.getInstance call") without double-counting the asset.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

from ..models import Confidence


@dataclass
class Detection:
    detector: str
    method: str                      # ast-call | regex | x509-parse | symbol-table | manifest
    confidence: Confidence

    algorithm: str | None = None     # knowledge-base algorithm id
    role: str | None = None          # cryptographic role, only when evidence supports it
    key_size: int | None = None
    curve: str | None = None
    mode: str | None = None
    padding: str | None = None
    protocol: str | None = None
    protocol_version: str | None = None
    library: str | None = None
    library_version: str | None = None
    package: str | None = None

    file: str | None = None
    line: int | None = None
    language: str | None = None
    snippet: str | None = None
    matched: str | None = None
    reasoning: str = ""
    api_call: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    # populated by the certificate scanner
    certificate: dict[str, Any] | None = None


class Detector(Protocol):
    id: str

    def supports(self, path: str) -> bool: ...

    def detect(self, path: str, text: str) -> list[Detection]: ...


EXT_LANGUAGE = {
    ".py": "python", ".pyi": "python",
    ".java": "java", ".kt": "kotlin", ".scala": "scala",
    ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "typescript", ".tsx": "typescript", ".jsx": "javascript",
    ".go": "go",
    ".rs": "rust",
    ".c": "c", ".h": "c", ".cc": "cpp", ".cpp": "cpp", ".hpp": "cpp", ".cxx": "cpp",
    ".cs": "csharp",
    ".rb": "ruby",
    ".php": "php",
    ".swift": "swift",
    ".sh": "shell", ".bash": "shell",
    ".yaml": "yaml", ".yml": "yaml",
    ".json": "json", ".toml": "toml", ".ini": "ini", ".cnf": "config",
    ".conf": "config", ".properties": "properties", ".xml": "xml",
    ".tf": "terraform", ".hcl": "terraform",
}


def language_for(path: str) -> str | None:
    import os

    return EXT_LANGUAGE.get(os.path.splitext(path)[1].lower())
