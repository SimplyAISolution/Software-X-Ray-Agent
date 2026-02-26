"""Manifest & build file analyzer."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from xray.analyzers.base import Analyzer
from xray.context import AnalysisContext
from xray.models import Claim, ClaimLabel, EvidencePointer

_MANIFEST_FILES = {
    "package.json",
    "pyproject.toml",
    "requirements.txt",
    "requirements-dev.txt",
    "requirements-test.txt",
    "setup.py",
    "setup.cfg",
    "Cargo.toml",
    "go.mod",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "Gemfile",
    "composer.json",
    "pubspec.yaml",
}

MAX_DEPENDENCIES_TO_REPORT = 20


class ManifestAnalyzer(Analyzer):
    name = "manifests"

    def supports(self, target_path: Path) -> bool:
        if target_path.is_dir():
            for m in _MANIFEST_FILES:
                if (target_path / m).exists():
                    return True
            for _p in target_path.rglob("*.csproj"):
                return True
        return target_path.is_file() and target_path.name in _MANIFEST_FILES

    def analyze(self, target_path: Path, ctx: AnalysisContext) -> list[Claim]:
        claims: list[Claim] = []
        search_root = target_path if target_path.is_dir() else target_path.parent

        for manifest_name in sorted(_MANIFEST_FILES):
            manifest_path = search_root / manifest_name
            if manifest_path.exists():
                rel = str(manifest_path.relative_to(search_root))
                claims.extend(self._parse_manifest(manifest_path, rel))

        # .csproj files
        for csproj in sorted(search_root.rglob("*.csproj")):
            try:
                rel = str(csproj.relative_to(search_root))
            except ValueError:
                rel = str(csproj)
            claims.extend(self._parse_csproj(csproj, rel))

        return claims

    def _parse_manifest(self, path: Path, rel: str) -> list[Claim]:
        name = path.name
        if name == "package.json":
            return self._parse_package_json(path, rel)
        if name in ("pyproject.toml", "Cargo.toml"):
            return self._parse_toml(path, rel)
        if name in ("requirements.txt", "requirements-dev.txt", "requirements-test.txt"):
            return self._parse_requirements_txt(path, rel)
        if name == "go.mod":
            return self._parse_go_mod(path, rel)
        if name == "pom.xml":
            return self._parse_pom_xml(path, rel)
        if name in ("build.gradle", "build.gradle.kts"):
            return self._parse_gradle(path, rel)
        if name == "Gemfile":
            return self._parse_gemfile(path, rel)
        return [
            Claim(
                claim=f"Manifest file present: {rel}",
                label=ClaimLabel.VERIFIED,
                confidence=100,
                evidence=EvidencePointer(file_path=rel),
            )
        ]

    def _parse_package_json(self, path: Path, rel: str) -> list[Claim]:
        claims: list[Claim] = []
        try:
            data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except (json.JSONDecodeError, OSError):
            return [
                Claim(
                    claim=f"package.json present but could not be parsed: {rel}",
                    label=ClaimLabel.VERIFIED,
                    confidence=90,
                    evidence=EvidencePointer(file_path=rel),
                )
            ]

        claims.append(
            Claim(
                claim=f"Node.js/JavaScript project detected via {rel}",
                label=ClaimLabel.VERIFIED,
                confidence=100,
                evidence=EvidencePointer(file_path=rel),
            )
        )

        if pkg_name := data.get("name"):
            claims.append(
                Claim(
                    claim=f"Package name: {pkg_name}",
                    label=ClaimLabel.VERIFIED,
                    confidence=100,
                    evidence=EvidencePointer(file_path=rel, manifest_key="name"),
                )
            )
        if desc := data.get("description"):
            claims.append(
                Claim(
                    claim=f"Package description: {desc}",
                    label=ClaimLabel.VERIFIED,
                    confidence=100,
                    evidence=EvidencePointer(file_path=rel, manifest_key="description"),
                )
            )
        if version := data.get("version"):
            claims.append(
                Claim(
                    claim=f"Package version: {version}",
                    label=ClaimLabel.VERIFIED,
                    confidence=100,
                    evidence=EvidencePointer(file_path=rel, manifest_key="version"),
                )
            )

        deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
        if deps:
            dep_list = sorted(deps.keys())[:MAX_DEPENDENCIES_TO_REPORT]
            dep_str = (
                f"npm dependencies (first {MAX_DEPENDENCIES_TO_REPORT}): "
                f"{', '.join(dep_list)}"
            )
            claims.append(
                Claim(
                    claim=dep_str,
                    label=ClaimLabel.VERIFIED,
                    confidence=100,
                    evidence=EvidencePointer(file_path=rel, manifest_key="dependencies"),
                )
            )
            # Framework detection
            for framework, kw in [
                ("React", "react"),
                ("Vue.js", "vue"),
                ("Angular", "@angular/core"),
                ("Next.js", "next"),
                ("Express.js", "express"),
                ("NestJS", "@nestjs/core"),
                ("Svelte", "svelte"),
                ("Fastify", "fastify"),
            ]:
                if kw in deps:
                    claims.append(
                        Claim(
                            claim=f"Uses {framework} framework",
                            label=ClaimLabel.VERIFIED,
                            confidence=95,
                            evidence=EvidencePointer(
                                file_path=rel, manifest_key=f"dependencies.{kw}"
                            ),
                        )
                    )

        return claims

    def _parse_toml(self, path: Path, rel: str) -> list[Claim]:
        claims: list[Claim] = []
        try:
            import tomllib

            data = tomllib.loads(path.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            try:
                import tomli as tomllib  # type: ignore[no-redef]

                data = tomllib.loads(path.read_text(encoding="utf-8", errors="replace"))
            except Exception:
                return [
                    Claim(
                        claim=f"TOML manifest present: {rel}",
                        label=ClaimLabel.VERIFIED,
                        confidence=90,
                        evidence=EvidencePointer(file_path=rel),
                    )
                ]

        if path.name == "pyproject.toml":
            claims.append(
                Claim(
                    claim=f"Python project detected via {rel}",
                    label=ClaimLabel.VERIFIED,
                    confidence=100,
                    evidence=EvidencePointer(file_path=rel),
                )
            )
            project = data.get("project", {})
            if pkg_name := project.get("name"):
                claims.append(
                    Claim(
                        claim=f"Python package name: {pkg_name}",
                        label=ClaimLabel.VERIFIED,
                        confidence=100,
                        evidence=EvidencePointer(file_path=rel, manifest_key="project.name"),
                    )
                )
            if desc := project.get("description"):
                claims.append(
                    Claim(
                        claim=f"Python package description: {desc}",
                        label=ClaimLabel.VERIFIED,
                        confidence=100,
                        evidence=EvidencePointer(file_path=rel, manifest_key="project.description"),
                    )
                )
            if version := project.get("version"):
                claims.append(
                    Claim(
                        claim=f"Python package version: {version}",
                        label=ClaimLabel.VERIFIED,
                        confidence=100,
                        evidence=EvidencePointer(file_path=rel, manifest_key="project.version"),
                    )
                )
            if requires_python := project.get("requires-python"):
                claims.append(
                    Claim(
                        claim=f"Requires Python {requires_python}",
                        label=ClaimLabel.VERIFIED,
                        confidence=100,
                        evidence=EvidencePointer(
                            file_path=rel, manifest_key="project.requires-python"
                        ),
                    )
                )
            deps = project.get("dependencies", [])
            if deps:
                dep_names = sorted(
                    [re.split(r"[>=<!;]", d)[0].strip() for d in deps]
                )[:MAX_DEPENDENCIES_TO_REPORT]
                dep_str = (
                    f"Python dependencies (first {MAX_DEPENDENCIES_TO_REPORT}): "
                    f"{', '.join(dep_names)}"
                )
                claims.append(
                    Claim(
                        claim=dep_str,
                        label=ClaimLabel.VERIFIED,
                        confidence=100,
                        evidence=EvidencePointer(
                            file_path=rel, manifest_key="project.dependencies"
                        ),
                    )
                )
            # Build backend
            build = data.get("build-system", {})
            if backend := build.get("build-backend"):
                claims.append(
                    Claim(
                        claim=f"Python build backend: {backend}",
                        label=ClaimLabel.VERIFIED,
                        confidence=100,
                        evidence=EvidencePointer(
                            file_path=rel, manifest_key="build-system.build-backend"
                        ),
                    )
                )

        elif path.name == "Cargo.toml":
            claims.append(
                Claim(
                    claim=f"Rust project detected via {rel}",
                    label=ClaimLabel.VERIFIED,
                    confidence=100,
                    evidence=EvidencePointer(file_path=rel),
                )
            )
            package = data.get("package", {})
            if pkg_name := package.get("name"):
                claims.append(
                    Claim(
                        claim=f"Rust crate name: {pkg_name}",
                        label=ClaimLabel.VERIFIED,
                        confidence=100,
                        evidence=EvidencePointer(file_path=rel, manifest_key="package.name"),
                    )
                )
            if edition := package.get("edition"):
                claims.append(
                    Claim(
                        claim=f"Rust edition: {edition}",
                        label=ClaimLabel.VERIFIED,
                        confidence=100,
                        evidence=EvidencePointer(file_path=rel, manifest_key="package.edition"),
                    )
                )
            deps = data.get("dependencies", {})
            if deps:
                dep_list = sorted(deps.keys())[:MAX_DEPENDENCIES_TO_REPORT]
                dep_str = (
                    f"Rust dependencies (first {MAX_DEPENDENCIES_TO_REPORT}): "
                    f"{', '.join(dep_list)}"
                )
                claims.append(
                    Claim(
                        claim=dep_str,
                        label=ClaimLabel.VERIFIED,
                        confidence=100,
                        evidence=EvidencePointer(file_path=rel, manifest_key="dependencies"),
                    )
                )

        return claims

    def _parse_requirements_txt(self, path: Path, rel: str) -> list[Claim]:
        claims: list[Claim] = [
            Claim(
                claim=f"Python project with {rel} detected",
                label=ClaimLabel.VERIFIED,
                confidence=100,
                evidence=EvidencePointer(file_path=rel),
            )
        ]
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            deps = []
            for line in lines:
                line = line.strip()
                if line and not line.startswith("#") and not line.startswith("-"):
                    pkg = re.split(r"[>=<!;#\[]", line)[0].strip()
                    if pkg:
                        deps.append(pkg)
            if deps:
                dep_str = (
                    f"Python requirements (first {MAX_DEPENDENCIES_TO_REPORT}): "
                    f"{', '.join(sorted(deps[:MAX_DEPENDENCIES_TO_REPORT]))}"
                )
                claims.append(
                    Claim(
                        claim=dep_str,
                        label=ClaimLabel.VERIFIED,
                        confidence=100,
                        evidence=EvidencePointer(file_path=rel),
                    )
                )
        except OSError:
            pass
        return claims

    def _parse_go_mod(self, path: Path, rel: str) -> list[Claim]:
        claims: list[Claim] = [
            Claim(
                claim=f"Go project detected via {rel}",
                label=ClaimLabel.VERIFIED,
                confidence=100,
                evidence=EvidencePointer(file_path=rel),
            )
        ]
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
            if m := re.search(r"^module\s+(\S+)", text, re.MULTILINE):
                claims.append(
                    Claim(
                        claim=f"Go module path: {m.group(1)}",
                        label=ClaimLabel.VERIFIED,
                        confidence=100,
                        evidence=EvidencePointer(file_path=rel, manifest_key="module"),
                    )
                )
            if m := re.search(r"^go\s+(\S+)", text, re.MULTILINE):
                claims.append(
                    Claim(
                        claim=f"Go version requirement: {m.group(1)}",
                        label=ClaimLabel.VERIFIED,
                        confidence=100,
                        evidence=EvidencePointer(file_path=rel, manifest_key="go"),
                    )
                )
            requires = re.findall(r"^\s+(\S+)\s+v[\w.+-]+", text, re.MULTILINE)
            if requires:
                dep_str = (
                    f"Go dependencies (first {MAX_DEPENDENCIES_TO_REPORT}): "
                    f"{', '.join(sorted(requires[:MAX_DEPENDENCIES_TO_REPORT]))}"
                )
                claims.append(
                    Claim(
                        claim=dep_str,
                        label=ClaimLabel.VERIFIED,
                        confidence=100,
                        evidence=EvidencePointer(file_path=rel, manifest_key="require"),
                    )
                )
        except OSError:
            pass
        return claims

    def _parse_pom_xml(self, path: Path, rel: str) -> list[Claim]:
        claims: list[Claim] = [
            Claim(
                claim=f"Java/Maven project detected via {rel}",
                label=ClaimLabel.VERIFIED,
                confidence=100,
                evidence=EvidencePointer(file_path=rel),
            )
        ]
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
            if m := re.search(r"<artifactId>([^<]+)</artifactId>", text):
                claims.append(
                    Claim(
                        claim=f"Maven artifactId: {m.group(1).strip()}",
                        label=ClaimLabel.VERIFIED,
                        confidence=100,
                        evidence=EvidencePointer(file_path=rel, manifest_key="artifactId"),
                    )
                )
            if m := re.search(r"<groupId>([^<]+)</groupId>", text):
                claims.append(
                    Claim(
                        claim=f"Maven groupId: {m.group(1).strip()}",
                        label=ClaimLabel.VERIFIED,
                        confidence=100,
                        evidence=EvidencePointer(file_path=rel, manifest_key="groupId"),
                    )
                )
            # Java version
            if m := re.search(r"<java\.version>([^<]+)</java\.version>", text):
                claims.append(
                    Claim(
                        claim=f"Java version: {m.group(1).strip()}",
                        label=ClaimLabel.VERIFIED,
                        confidence=100,
                        evidence=EvidencePointer(file_path=rel, manifest_key="java.version"),
                    )
                )
            # Spring Boot
            if "spring-boot" in text.lower():
                claims.append(
                    Claim(
                        claim="Spring Boot framework detected",
                        label=ClaimLabel.VERIFIED,
                        confidence=95,
                        evidence=EvidencePointer(file_path=rel),
                    )
                )
        except OSError:
            pass
        return claims

    def _parse_gradle(self, path: Path, rel: str) -> list[Claim]:
        claims: list[Claim] = [
            Claim(
                claim=f"Java/Gradle project detected via {rel}",
                label=ClaimLabel.VERIFIED,
                confidence=100,
                evidence=EvidencePointer(file_path=rel),
            )
        ]
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
            if "spring-boot" in text.lower():
                claims.append(
                    Claim(
                        claim="Spring Boot framework detected (Gradle)",
                        label=ClaimLabel.VERIFIED,
                        confidence=90,
                        evidence=EvidencePointer(file_path=rel),
                    )
                )
            if "kotlin" in text.lower():
                claims.append(
                    Claim(
                        claim="Kotlin language plugin detected in Gradle",
                        label=ClaimLabel.INFERRED,
                        confidence=80,
                        evidence=EvidencePointer(file_path=rel),
                    )
                )
        except OSError:
            pass
        return claims

    def _parse_gemfile(self, path: Path, rel: str) -> list[Claim]:
        claims: list[Claim] = [
            Claim(
                claim=f"Ruby project detected via {rel}",
                label=ClaimLabel.VERIFIED,
                confidence=100,
                evidence=EvidencePointer(file_path=rel),
            )
        ]
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
            gems = re.findall(r"""gem\s+['"]([^'"]+)['"]""", text)
            if gems:
                dep_str = (
                    f"Ruby gems (first {MAX_DEPENDENCIES_TO_REPORT}): "
                    f"{', '.join(sorted(gems[:MAX_DEPENDENCIES_TO_REPORT]))}"
                )
                claims.append(
                    Claim(
                        claim=dep_str,
                        label=ClaimLabel.VERIFIED,
                        confidence=100,
                        evidence=EvidencePointer(file_path=rel),
                    )
                )
            if "rails" in [g.lower() for g in gems]:
                claims.append(
                    Claim(
                        claim="Ruby on Rails framework detected",
                        label=ClaimLabel.VERIFIED,
                        confidence=95,
                        evidence=EvidencePointer(file_path=rel),
                    )
                )
        except OSError:
            pass
        return claims

    def _parse_csproj(self, path: Path, rel: str) -> list[Claim]:
        claims: list[Claim] = [
            Claim(
                claim=f".NET/C# project detected via {rel}",
                label=ClaimLabel.VERIFIED,
                confidence=100,
                evidence=EvidencePointer(file_path=rel),
            )
        ]
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
            if m := re.search(r"<TargetFramework>([^<]+)</TargetFramework>", text):
                claims.append(
                    Claim(
                        claim=f".NET target framework: {m.group(1).strip()}",
                        label=ClaimLabel.VERIFIED,
                        confidence=100,
                        evidence=EvidencePointer(file_path=rel, manifest_key="TargetFramework"),
                    )
                )
            packages = re.findall(r'PackageReference\s+Include="([^"]+)"', text)
            if packages:
                dep_str = (
                    f".NET NuGet packages (first {MAX_DEPENDENCIES_TO_REPORT}): "
                    f"{', '.join(sorted(packages[:MAX_DEPENDENCIES_TO_REPORT]))}"
                )
                claims.append(
                    Claim(
                        claim=dep_str,
                        label=ClaimLabel.VERIFIED,
                        confidence=100,
                        evidence=EvidencePointer(file_path=rel),
                    )
                )
        except OSError:
            pass
        return claims
