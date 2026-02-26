"""Markdown report generator."""

from __future__ import annotations

from xray.models import Report


def render_markdown(report: Report) -> str:
    """Render a Report as a Markdown string."""
    lines: list[str] = []
    lines.append("# Software X-Ray Report\n")

    for section in report.sections:
        lines.append(f"## {section.title}\n")
        lines.append(section.content)
        lines.append("")

    # Claims Table
    lines.append("## Confidence & Evidence Trail\n")
    lines.append("| Claim | Label | Confidence | Evidence Pointer |")
    lines.append("|-------|-------|-----------|-----------------|")
    for claim in report.claims_table:
        evidence_str = str(claim.evidence) if claim.evidence else "—"
        label = claim.label.value
        conf = f"{claim.confidence}%"
        # Escape pipe characters
        claim_text = claim.claim.replace("|", "\\|")
        evidence_str = evidence_str.replace("|", "\\|")
        lines.append(f"| {claim_text} | {label} | {conf} | {evidence_str} |")
    lines.append("")

    # Unknowns
    lines.append("## Unknowns & Next Best Artifacts\n")
    for u in report.unknowns:
        lines.append(f"- {u}")
    lines.append("")

    return "\n".join(lines)
