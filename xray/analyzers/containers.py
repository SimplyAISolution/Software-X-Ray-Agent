"""Container & deploy analyzer: Dockerfile, docker-compose, k8s YAML."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from xray.analyzers.base import Analyzer
from xray.context import AnalysisContext
from xray.models import Claim, ClaimLabel, EvidencePointer


class ContainerAnalyzer(Analyzer):
    name = "containers"

    def supports(self, target_path: Path) -> bool:
        if not target_path.is_dir():
            return False
        checks = [
            "Dockerfile",
            "dockerfile",
            "Dockerfile.dev",
            "Dockerfile.prod",
            "docker-compose.yml",
            "docker-compose.yaml",
            "docker-compose.override.yml",
        ]
        for c in checks:
            if (target_path / c).exists():
                return True
        # k8s
        for p in target_path.rglob("*.yaml"):
            try:
                text = p.read_text(encoding="utf-8", errors="replace")
                if "apiVersion:" in text and "kind:" in text:
                    return True
            except OSError:
                pass
        return False

    def analyze(self, target_path: Path, ctx: AnalysisContext) -> list[Claim]:
        claims: list[Claim] = []

        # Dockerfiles
        for fname in sorted(["Dockerfile", "Dockerfile.dev", "Dockerfile.prod", "dockerfile"]):
            df = target_path / fname
            if df.exists():
                rel = str(df.relative_to(target_path))
                claims.extend(self._parse_dockerfile(df, rel))

        # docker-compose
        for fname in sorted(
            ["docker-compose.override.yml", "docker-compose.yaml", "docker-compose.yml"]
        ):
            dc = target_path / fname
            if dc.exists():
                rel = str(dc.relative_to(target_path))
                claims.extend(self._parse_docker_compose(dc, rel))

        # k8s
        claims.extend(self._scan_k8s(target_path))

        return claims

    def _parse_dockerfile(self, path: Path, rel: str) -> list[Claim]:
        claims: list[Claim] = []
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
            claims.append(
                Claim(
                    claim=f"Dockerfile present: {rel}",
                    label=ClaimLabel.VERIFIED,
                    confidence=100,
                    evidence=EvidencePointer(file_path=rel),
                )
            )
            # Base images
            froms = re.findall(r"^FROM\s+(\S+)", text, re.MULTILINE | re.IGNORECASE)
            for base in froms:
                claims.append(
                    Claim(
                        claim=f"Docker base image: {base}",
                        label=ClaimLabel.VERIFIED,
                        confidence=100,
                        evidence=EvidencePointer(file_path=rel),
                    )
                )
            # Exposed ports
            ports = re.findall(r"^EXPOSE\s+(\d+)", text, re.MULTILINE | re.IGNORECASE)
            if ports:
                claims.append(
                    Claim(
                        claim=f"Docker exposed port(s): {', '.join(ports)}",
                        label=ClaimLabel.VERIFIED,
                        confidence=100,
                        evidence=EvidencePointer(file_path=rel),
                    )
                )
        except OSError:
            pass
        return claims

    def _parse_docker_compose(self, path: Path, rel: str) -> list[Claim]:
        claims: list[Claim] = []
        try:
            import yaml

            data: Any = yaml.safe_load(path.read_text(encoding="utf-8", errors="replace"))
            if not isinstance(data, dict):
                return claims
            claims.append(
                Claim(
                    claim=f"Docker Compose file present: {rel}",
                    label=ClaimLabel.VERIFIED,
                    confidence=100,
                    evidence=EvidencePointer(file_path=rel),
                )
            )
            services = data.get("services", {})
            if isinstance(services, dict) and services:
                service_names = sorted(services.keys())
                claims.append(
                    Claim(
                        claim=f"Docker Compose services: {', '.join(service_names)}",
                        label=ClaimLabel.VERIFIED,
                        confidence=100,
                        evidence=EvidencePointer(file_path=rel, manifest_key="services"),
                    )
                )
        except Exception:
            pass
        return claims

    def _scan_k8s(self, target_path: Path) -> list[Claim]:
        claims: list[Claim] = []
        k8s_kinds: dict[str, list[str]] = {}
        for yaml_file in sorted(target_path.rglob("*.yaml")):
            try:
                import yaml

                text = yaml_file.read_text(encoding="utf-8", errors="replace")
                if "apiVersion:" not in text or "kind:" not in text:
                    continue
                data: Any = yaml.safe_load(text)
                if not isinstance(data, dict):
                    continue
                kind = data.get("kind", "")
                api = data.get("apiVersion", "")
                if kind and (
                    api.startswith("apps/")
                    or api in ("v1", "networking.k8s.io/v1", "batch/v1")
                ):
                    rel = str(yaml_file.relative_to(target_path))
                    k8s_kinds.setdefault(kind, []).append(rel)
            except Exception:
                continue

        if k8s_kinds:
            kinds_str = ", ".join(f"{k} ({len(v)})" for k, v in sorted(k8s_kinds.items()))
            claims.append(
                Claim(
                    claim=f"Kubernetes manifests detected: {kinds_str}",
                    label=ClaimLabel.VERIFIED,
                    confidence=95,
                )
            )

        return claims
