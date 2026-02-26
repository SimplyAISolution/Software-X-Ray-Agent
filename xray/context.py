"""Analysis context passed to analyzers."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_MAX_FILES = 5000
DEFAULT_MAX_BYTES = 100 * 1024 * 1024  # 100 MB


@dataclass
class AnalysisContext:
    """Holds runtime configuration for an analysis run."""

    target_path: Path
    max_files: int = DEFAULT_MAX_FILES
    max_bytes: int = DEFAULT_MAX_BYTES
    include_sbom: bool = False
    redact: bool = False
    deterministic: bool = False
    _file_count: int = field(default=0, init=False)
    _byte_count: int = field(default=0, init=False)

    def register_file(self, size: int) -> bool:
        """Register a file; return False if limits exceeded."""
        if self._file_count >= self.max_files:
            return False
        if self._byte_count + size > self.max_bytes:
            return False
        self._file_count += 1
        self._byte_count += size
        return True
