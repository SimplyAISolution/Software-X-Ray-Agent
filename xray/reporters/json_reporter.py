"""JSON report generator."""

from __future__ import annotations

from xray.models import Report


def render_json(report: Report) -> str:
    """Render a Report as a JSON string."""
    return report.model_dump_json(indent=2)
