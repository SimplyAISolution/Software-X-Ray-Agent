"""Tests for reporters."""

from __future__ import annotations

import json

from xray.models import Claim, ClaimLabel, EvidencePointer, Report, ReportSection
from xray.reporters import render_json, render_markdown


def make_sample_report() -> Report:
    ep = EvidencePointer(file_path="pyproject.toml", manifest_key="project.name")
    claims = [
        Claim(
            claim="Python project detected",
            label=ClaimLabel.VERIFIED,
            confidence=100,
            evidence=ep,
        ),
        Claim(claim="Primary language is Python", label=ClaimLabel.INFERRED, confidence=85),
        Claim(claim="Build system unknown", label=ClaimLabel.UNKNOWN, confidence=0),
    ]
    sections = [
        ReportSection(title="Scope & Tier Used", content="Target: `.`\nTier 3"),
        ReportSection(title="What It Is", content="Python project", claims=claims[:1]),
    ]
    return Report(
        target=".",
        tier_used=3,
        sections=sections,
        claims_table=claims,
        unknowns=["Build system unknown"],
    )


def test_markdown_report_contains_sections() -> None:
    report = make_sample_report()
    md = render_markdown(report)
    assert "# Software X-Ray Report" in md
    assert "## Scope & Tier Used" in md
    assert "## What It Is" in md
    assert "## Confidence & Evidence Trail" in md
    assert "## Unknowns & Next Best Artifacts" in md


def test_markdown_report_contains_claims_table() -> None:
    report = make_sample_report()
    md = render_markdown(report)
    assert "Python project detected" in md
    assert "Verified" in md
    assert "Inferred" in md
    assert "100%" in md
    assert "85%" in md


def test_markdown_report_evidence_pointer() -> None:
    report = make_sample_report()
    md = render_markdown(report)
    assert "pyproject.toml" in md


def test_markdown_report_unknowns() -> None:
    report = make_sample_report()
    md = render_markdown(report)
    assert "Build system unknown" in md


def test_json_report_valid_json() -> None:
    report = make_sample_report()
    json_str = render_json(report)
    data = json.loads(json_str)
    assert data["target"] == "."
    assert data["tier_used"] == 3
    assert "sections" in data
    assert "claims_table" in data
    assert len(data["claims_table"]) == 3


def test_json_report_structure() -> None:
    report = make_sample_report()
    json_str = render_json(report)
    data = json.loads(json_str)
    first_claim = data["claims_table"][0]
    assert "claim" in first_claim
    assert "label" in first_claim
    assert "confidence" in first_claim
    assert first_claim["label"] == "Verified"
    assert first_claim["confidence"] == 100


def test_empty_report() -> None:
    report = Report(target="empty", tier_used=1)
    md = render_markdown(report)
    assert "# Software X-Ray Report" in md
    json_str = render_json(report)
    data = json.loads(json_str)
    assert data["tier_used"] == 1
