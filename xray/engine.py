"""Analysis engine: orchestrates analyzers, determines tier, aggregates claims."""

from __future__ import annotations

import os
from pathlib import Path

from xray.analyzers import ALL_ANALYZERS
from xray.context import AnalysisContext
from xray.models import Claim, ClaimLabel, Report, ReportSection


def _determine_tier(target_path: Path) -> int:
    """Determine highest supportable tier for given target."""
    if target_path.is_file():
        # Single file
        from xray.analyzers.binaries import _detect_file_type, _is_likely_binary

        if _detect_file_type(target_path) or _is_likely_binary(target_path):
            return 5  # binary
        return 2  # single manifest/config

    if not target_path.is_dir():
        return 1

    # Check for manifests
    manifest_files = {
        "package.json",
        "pyproject.toml",
        "requirements.txt",
        "Cargo.toml",
        "go.mod",
        "pom.xml",
        "build.gradle",
        "build.gradle.kts",
        "Gemfile",
        "composer.json",
    }
    has_manifests = any((target_path / m).exists() for m in manifest_files)

    # Check for source files
    has_source = False
    src_exts = {".py", ".js", ".ts", ".java", ".go", ".rs", ".cs", ".rb", ".php", ".cpp", ".c"}
    for root, dirs, files in os.walk(target_path):
        dirs[:] = [
            d
            for d in dirs
            if not d.startswith(".") and d not in {"node_modules", "__pycache__", ".git"}
        ]
        for f in files:
            if Path(f).suffix.lower() in src_exts:
                has_source = True
                break
        if has_source:
            break

    if has_source:
        return 3
    if has_manifests:
        return 2
    return 1


def run_analysis(
    target_path: Path,
    ctx: AnalysisContext,
    tier: str = "auto",
    deterministic: bool = False,
) -> Report:
    """Run full analysis pipeline and return a Report."""
    if tier == "auto":
        tier_int = _determine_tier(target_path)
    else:
        try:
            tier_int = int(tier)
        except ValueError:
            tier_int = _determine_tier(target_path)

    all_claims: list[Claim] = []
    for analyzer in ALL_ANALYZERS:
        try:
            if analyzer.supports(target_path):
                claims = analyzer.analyze(target_path, ctx)
                if deterministic:
                    claims = sorted(claims, key=lambda c: (c.claim, c.label.value))
                all_claims.extend(claims)
        except Exception as e:
            all_claims.append(
                Claim(
                    claim=f"Analyzer '{analyzer.name}' failed: {e}",
                    label=ClaimLabel.UNKNOWN,
                    confidence=0,
                )
            )

    if deterministic:
        all_claims = sorted(all_claims, key=lambda c: (c.claim, c.label.value))

    return _build_report(
        target=str(target_path),
        tier_used=tier_int,
        claims=all_claims,
    )


def _build_report(target: str, tier_used: int, claims: list[Claim]) -> Report:
    """Organize claims into report sections."""
    # Categorize claims
    identity_claims: list[Claim] = []
    stack_claims: list[Claim] = []
    arch_claims: list[Claim] = []
    cicd_claims: list[Claim] = []
    container_claims: list[Claim] = []
    binary_claims: list[Claim] = []
    other_claims: list[Claim] = []

    identity_keywords = {
        "name",
        "description",
        "version",
        "package",
        "crate",
        "module",
        "artifactid",
        "groupid",
    }
    stack_keywords = {
        "language",
        "framework",
        "dependenc",
        "require",
        "runtime",
        "sdk",
        "library",
        "gem",
        "nuget",
    }
    arch_keywords = {
        "directory",
        "structure",
        "file",
        "top-level",
        "scaffold",
        "service",
        "microservice",
    }
    cicd_keywords = {
        "github actions",
        "gitlab",
        "circleci",
        "workflow",
        "pipeline",
        "trigger",
        "job",
        "stage",
    }
    container_keywords = {
        "docker",
        "kubernetes",
        "k8s",
        "container",
        "image",
        "compose",
        "base image",
        "exposed port",
    }
    binary_keywords = {"binary", "elf", "pe binary", "mach-o", "jar"}

    for claim in claims:
        text = claim.claim.lower()
        if any(k in text for k in binary_keywords):
            binary_claims.append(claim)
        elif any(k in text for k in container_keywords):
            container_claims.append(claim)
        elif any(k in text for k in cicd_keywords):
            cicd_claims.append(claim)
        elif any(k in text for k in stack_keywords):
            stack_claims.append(claim)
        elif any(k in text for k in arch_keywords):
            arch_claims.append(claim)
        elif any(k in text for k in identity_keywords):
            identity_claims.append(claim)
        else:
            other_claims.append(claim)

    sections: list[ReportSection] = []

    # 1. Scope & Tier
    tier_desc = {
        1: "name/metadata only",
        2: "manifests/configs present",
        3: "source structure + semantic hints",
        4: "runtime/UI observation",
        5: "binary/installer analysis",
    }
    tier_label = tier_desc.get(tier_used, "unknown")
    sections.append(
        ReportSection(
            title="Scope & Tier Used",
            content=f"**Target:** `{target}`\n\n**Tier {tier_used}** – {tier_label}",
        )
    )

    # 2. Product Identity
    if identity_claims:
        content_lines = [c.claim for c in identity_claims if c.label == ClaimLabel.VERIFIED]
        sections.append(
            ReportSection(
                title="What It Is (Product Identity)",
                content="\n".join(content_lines)
                if content_lines
                else "No strong identity signals found.",
                claims=identity_claims,
            )
        )
    else:
        sections.append(
            ReportSection(
                title="What It Is (Product Identity)",
                content="No strong identity signals found.",
            )
        )

    # 3. Use Cases
    sections.append(
        ReportSection(
            title="Use Cases",
            content=(
                "Use cases are inferred from the product identity and stack. "
                "Review the stack section for more details."
            ),
        )
    )

    # 4. Stack & Dependencies
    if stack_claims:
        content_lines = [f"- {c.claim}" for c in stack_claims]
        sections.append(
            ReportSection(
                title="Likely Stack & Dependencies",
                content="\n".join(content_lines),
                claims=stack_claims,
            )
        )
    else:
        sections.append(
            ReportSection(
                title="Likely Stack & Dependencies",
                content="No manifest or dependency files detected.",
            )
        )

    # 5. Architecture
    arch_all = arch_claims + container_claims
    if arch_all:
        content_lines = [f"- {c.claim}" for c in arch_all]
        sections.append(
            ReportSection(
                title="Probable Architecture / Scaffolding",
                content="\n".join(content_lines),
                claims=arch_all,
            )
        )
    else:
        sections.append(
            ReportSection(
                title="Probable Architecture / Scaffolding",
                content="Insufficient structural information available.",
            )
        )

    # 6. Behavior Model
    sections.append(
        ReportSection(
            title="Behavior Model",
            content="Tier 4 (runtime/UI observation) not performed in this analysis.",
        )
    )

    # 8. Unknowns
    unknowns: list[str] = []
    for c in claims:
        if c.label == ClaimLabel.UNKNOWN:
            unknowns.append(c.claim)
    if not unknowns:
        unknowns.append("No explicit unknowns flagged.")

    return Report(
        target=target,
        tier_used=tier_used,
        sections=sections,
        claims_table=claims,
        unknowns=unknowns,
    )
