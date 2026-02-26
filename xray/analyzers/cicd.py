"""CI/CD analyzer: GitHub Actions, GitLab CI, CircleCI."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from xray.analyzers.base import Analyzer
from xray.context import AnalysisContext
from xray.models import Claim, ClaimLabel, EvidencePointer


class CICDAnalyzer(Analyzer):
    name = "cicd"

    def supports(self, target_path: Path) -> bool:
        if not target_path.is_dir():
            return False
        return (
            (target_path / ".github" / "workflows").exists()
            or (target_path / ".gitlab-ci.yml").exists()
            or (target_path / ".circleci" / "config.yml").exists()
        )

    def analyze(self, target_path: Path, ctx: AnalysisContext) -> list[Claim]:
        claims: list[Claim] = []

        # GitHub Actions
        gha_dir = target_path / ".github" / "workflows"
        if gha_dir.is_dir():
            claims.append(
                Claim(
                    claim="GitHub Actions CI/CD configured",
                    label=ClaimLabel.VERIFIED,
                    confidence=100,
                    evidence=EvidencePointer(file_path=".github/workflows"),
                )
            )
            for wf in sorted(gha_dir.iterdir()):
                if wf.suffix in (".yml", ".yaml"):
                    rel = str(wf.relative_to(target_path))
                    claims.extend(self._parse_gha_workflow(wf, rel))

        # GitLab CI
        gitlab_ci = target_path / ".gitlab-ci.yml"
        if gitlab_ci.exists():
            rel = ".gitlab-ci.yml"
            claims.append(
                Claim(
                    claim="GitLab CI/CD configured",
                    label=ClaimLabel.VERIFIED,
                    confidence=100,
                    evidence=EvidencePointer(file_path=rel),
                )
            )
            claims.extend(self._parse_yaml_file(gitlab_ci, rel, "GitLab CI"))

        # CircleCI
        circle_cfg = target_path / ".circleci" / "config.yml"
        if circle_cfg.exists():
            rel = ".circleci/config.yml"
            claims.append(
                Claim(
                    claim="CircleCI configured",
                    label=ClaimLabel.VERIFIED,
                    confidence=100,
                    evidence=EvidencePointer(file_path=rel),
                )
            )
            claims.extend(self._parse_yaml_file(circle_cfg, rel, "CircleCI"))

        return claims

    def _parse_gha_workflow(self, path: Path, rel: str) -> list[Claim]:
        claims: list[Claim] = []
        try:
            import yaml

            data: Any = yaml.safe_load(path.read_text(encoding="utf-8", errors="replace"))
            if not isinstance(data, dict):
                return claims
            if wf_name := data.get("name"):
                claims.append(
                    Claim(
                        claim=f"GitHub Actions workflow: {wf_name}",
                        label=ClaimLabel.VERIFIED,
                        confidence=100,
                        evidence=EvidencePointer(file_path=rel, manifest_key="name"),
                    )
                )
            # Extract triggers
            on_triggers = data.get("on", {})
            if isinstance(on_triggers, dict):
                triggers = sorted(on_triggers.keys())
                claims.append(
                    Claim(
                        claim=f"Workflow triggers: {', '.join(triggers)}",
                        label=ClaimLabel.VERIFIED,
                        confidence=100,
                        evidence=EvidencePointer(file_path=rel, manifest_key="on"),
                    )
                )
            # Extract job names
            jobs = data.get("jobs", {})
            if isinstance(jobs, dict) and jobs:
                job_names = sorted(jobs.keys())
                claims.append(
                    Claim(
                        claim=f"GitHub Actions jobs: {', '.join(job_names)}",
                        label=ClaimLabel.VERIFIED,
                        confidence=100,
                        evidence=EvidencePointer(file_path=rel, manifest_key="jobs"),
                    )
                )
        except Exception:
            pass
        return claims

    def _parse_yaml_file(self, path: Path, rel: str, system: str) -> list[Claim]:
        claims: list[Claim] = []
        try:
            import yaml

            data: Any = yaml.safe_load(path.read_text(encoding="utf-8", errors="replace"))
            if isinstance(data, dict):
                stages = data.get("stages", [])
                if stages:
                    claims.append(
                        Claim(
                            claim=f"{system} stages: {', '.join(stages)}",
                            label=ClaimLabel.VERIFIED,
                            confidence=100,
                            evidence=EvidencePointer(file_path=rel, manifest_key="stages"),
                        )
                    )
        except Exception:
            pass
        return claims
