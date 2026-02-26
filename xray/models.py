"""Core data models for Software X-Ray Lab."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field


class ClaimLabel(StrEnum):
    VERIFIED = "Verified"
    OBSERVED = "Observed"
    INFERRED = "Inferred"
    UNKNOWN = "Unknown"


class EvidencePointer(BaseModel):
    """Points to a specific artifact that supports a claim."""

    file_path: str
    line_start: int | None = None
    line_end: int | None = None
    manifest_key: str | None = None
    doc_section: str | None = None

    def __str__(self) -> str:
        parts = [self.file_path]
        if self.manifest_key:
            parts.append(f":{self.manifest_key}")
        if self.line_start is not None:
            parts.append(f":L{self.line_start}")
            if self.line_end is not None and self.line_end != self.line_start:
                parts.append(f"-L{self.line_end}")
        if self.doc_section:
            parts.append(f" §{self.doc_section}")
        return "".join(parts)


class Claim(BaseModel):
    """A single evidence-backed statement about the target software."""

    claim: str
    label: ClaimLabel
    confidence: int = Field(ge=0, le=100)
    evidence: EvidencePointer | None = None
    notes: str | None = None


class ReportSection(BaseModel):
    """A section of the final report."""

    title: str
    content: str
    claims: list[Claim] = Field(default_factory=list)


class Report(BaseModel):
    """Full analysis report."""

    target: str
    tier_used: int
    sections: list[ReportSection] = Field(default_factory=list)
    claims_table: list[Claim] = Field(default_factory=list)
    unknowns: list[str] = Field(default_factory=list)
