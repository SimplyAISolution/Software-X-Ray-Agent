"""Tests for data models."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from xray.models import Claim, ClaimLabel, EvidencePointer, Report, ReportSection


def test_evidence_pointer_str_basic() -> None:
    ep = EvidencePointer(file_path="pyproject.toml", manifest_key="project.name")
    assert "pyproject.toml" in str(ep)
    assert "project.name" in str(ep)


def test_evidence_pointer_str_with_lines() -> None:
    ep = EvidencePointer(file_path="src/main.py", line_start=10, line_end=20)
    s = str(ep)
    assert "src/main.py" in s
    assert "10" in s


def test_claim_valid() -> None:
    c = Claim(claim="Test claim", label=ClaimLabel.VERIFIED, confidence=90)
    assert c.confidence == 90
    assert c.label == ClaimLabel.VERIFIED


def test_claim_confidence_bounds() -> None:
    with pytest.raises(ValidationError):
        Claim(claim="bad", label=ClaimLabel.VERIFIED, confidence=101)
    with pytest.raises(ValidationError):
        Claim(claim="bad", label=ClaimLabel.VERIFIED, confidence=-1)


def test_claim_with_evidence() -> None:
    ep = EvidencePointer(file_path="README.md")
    c = Claim(claim="Has README", label=ClaimLabel.VERIFIED, confidence=100, evidence=ep)
    assert c.evidence is not None
    assert c.evidence.file_path == "README.md"


def test_report_section() -> None:
    c = Claim(claim="Test", label=ClaimLabel.INFERRED, confidence=70)
    section = ReportSection(title="Test Section", content="Some content", claims=[c])
    assert section.title == "Test Section"
    assert len(section.claims) == 1


def test_report_basic() -> None:
    report = Report(target=".", tier_used=3)
    assert report.tier_used == 3
    assert report.claims_table == []
    assert report.sections == []
    assert report.unknowns == []


def test_claim_labels() -> None:
    for label in ClaimLabel:
        c = Claim(claim="x", label=label, confidence=50)
        assert c.label == label
