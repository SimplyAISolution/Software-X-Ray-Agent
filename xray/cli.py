"""CLI entry point for xray."""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console

from xray.context import AnalysisContext
from xray.engine import run_analysis
from xray.loader import LoadError, load_target
from xray.reporters import render_json, render_markdown

app = typer.Typer(
    name="xray",
    help="Software X-Ray Lab – evidence-backed software reconnaissance tool.",
    add_completion=False,
)
console = Console()
err_console = Console(stderr=True)


@app.command("analyze")
def analyze(
    target: str = typer.Argument(..., help="Local path, git URL, or archive path"),
    out: Path = typer.Option(Path("xray-report.md"), "--out", help="Output file path"),
    format: str = typer.Option("md", "--format", help="Output format: md or json"),
    tier: str = typer.Option("auto", "--tier", help="Analysis tier: auto|1|2|3|4|5"),
    include_sbom: bool = typer.Option(False, "--include-sbom", help="Include SBOM (best-effort)"),
    redact: bool = typer.Option(False, "--redact", help="Mask suspected secrets in output"),
    max_files: int = typer.Option(5000, "--max-files", help="Maximum number of files to scan"),
    max_bytes: int = typer.Option(
        100 * 1024 * 1024, "--max-bytes", help="Maximum total bytes to scan"
    ),
    deterministic: bool = typer.Option(
        False, "--deterministic", help="Stable ordering and IDs"
    ),
) -> None:
    """Analyze a software target and produce an evidence-backed report."""
    if format not in ("md", "json"):
        err_console.print(f"[red]Error:[/red] Invalid format '{format}'. Must be 'md' or 'json'.")
        raise typer.Exit(code=1)

    if tier not in ("auto", "1", "2", "3", "4", "5"):
        err_console.print(f"[red]Error:[/red] Invalid tier '{tier}'. Must be auto|1|2|3|4|5.")
        raise typer.Exit(code=1)

    try:
        loaded = load_target(target, max_bytes=max_bytes)
    except LoadError as e:
        err_console.print(f"[red]Error loading target:[/red] {e}")
        raise typer.Exit(code=1)

    with loaded:
        ctx = AnalysisContext(
            target_path=loaded.path,
            max_files=max_files,
            max_bytes=max_bytes,
            include_sbom=include_sbom,
            redact=redact,
            deterministic=deterministic,
        )

        console.print(f"[cyan]Analyzing:[/cyan] {loaded.original}")
        console.print(f"[cyan]Tier:[/cyan] {tier}")

        report = run_analysis(loaded.path, ctx, tier=tier, deterministic=deterministic)

        if format == "md":
            content = render_markdown(report)
        else:
            content = render_json(report)

        out.write_text(content, encoding="utf-8")
        console.print(f"[green]Report written to:[/green] {out}")
        console.print(f"[green]Tier used:[/green] {report.tier_used}")
        console.print(f"[green]Claims found:[/green] {len(report.claims_table)}")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
