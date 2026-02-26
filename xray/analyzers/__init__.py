"""Analyzer package."""

from xray.analyzers.base import Analyzer
from xray.analyzers.binaries import BinaryAnalyzer
from xray.analyzers.cicd import CICDAnalyzer
from xray.analyzers.containers import ContainerAnalyzer
from xray.analyzers.manifests import ManifestAnalyzer
from xray.analyzers.tree import TreeAnalyzer

__all__ = [
    "Analyzer",
    "BinaryAnalyzer",
    "CICDAnalyzer",
    "ContainerAnalyzer",
    "ManifestAnalyzer",
    "TreeAnalyzer",
]

ALL_ANALYZERS: list[Analyzer] = [
    TreeAnalyzer(),
    ManifestAnalyzer(),
    CICDAnalyzer(),
    ContainerAnalyzer(),
    BinaryAnalyzer(),
]
