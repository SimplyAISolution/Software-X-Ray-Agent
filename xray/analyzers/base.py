"""Base Analyzer interface."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from xray.context import AnalysisContext
from xray.models import Claim


class Analyzer(ABC):
    """Abstract base for all analyzers."""

    name: str = "base"

    @abstractmethod
    def supports(self, target_path: Path) -> bool:
        """Return True if this analyzer can contribute to the given target."""
        ...

    @abstractmethod
    def analyze(self, target_path: Path, ctx: AnalysisContext) -> list[Claim]:
        """Run analysis and return a list of claims."""
        ...
