"""Repo tree & key files detection analyzer."""

from __future__ import annotations

import os
from pathlib import Path

from xray.analyzers.base import Analyzer
from xray.context import AnalysisContext
from xray.models import Claim, ClaimLabel, EvidencePointer

_KEY_FILES = {
    "README.md",
    "README.rst",
    "README.txt",
    "readme.md",
    "LICENSE",
    "LICENSE.txt",
    "LICENSE.md",
    "CHANGELOG.md",
    "CHANGELOG.rst",
    "CHANGELOG.txt",
    "CONTRIBUTING.md",
    ".gitignore",
    ".editorconfig",
    "Makefile",
    "makefile",
}

_LANGUAGE_EXTENSIONS: dict[str, str] = {
    ".py": "Python",
    ".js": "JavaScript",
    ".ts": "TypeScript",
    ".jsx": "JavaScript (React)",
    ".tsx": "TypeScript (React)",
    ".java": "Java",
    ".kt": "Kotlin",
    ".go": "Go",
    ".rs": "Rust",
    ".cs": "C#",
    ".cpp": "C++",
    ".c": "C",
    ".rb": "Ruby",
    ".php": "PHP",
    ".swift": "Swift",
    ".scala": "Scala",
    ".sh": "Shell",
    ".bash": "Bash",
    ".ps1": "PowerShell",
    ".r": "R",
    ".R": "R",
    ".jl": "Julia",
    ".hs": "Haskell",
    ".ex": "Elixir",
    ".exs": "Elixir",
    ".erl": "Erlang",
    ".clj": "Clojure",
    ".lua": "Lua",
    ".dart": "Dart",
}


class TreeAnalyzer(Analyzer):
    name = "tree"

    def supports(self, target_path: Path) -> bool:
        return target_path.is_dir()

    def analyze(self, target_path: Path, ctx: AnalysisContext) -> list[Claim]:
        claims: list[Claim] = []
        lang_counts: dict[str, int] = {}
        file_count = 0
        dirs_seen: set[str] = set()

        for root, dirs, files in os.walk(target_path):
            # Skip hidden dirs and common noise
            dirs[:] = sorted(
                d
                for d in dirs
                if not d.startswith(".")
                and d
                not in {
                    "node_modules",
                    "__pycache__",
                    ".git",
                    "venv",
                    ".venv",
                    "dist",
                    "build",
                    "target",
                }
            )
            rel_root = Path(root).relative_to(target_path)

            for fname in sorted(files):
                file_path = Path(root) / fname
                size = file_path.stat().st_size
                if not ctx.register_file(size):
                    claims.append(
                        Claim(
                            claim="Analysis hit file/size limits; some files were skipped.",
                            label=ClaimLabel.VERIFIED,
                            confidence=100,
                        )
                    )
                    return claims

                file_count += 1
                ext = Path(fname).suffix.lower()
                if ext in _LANGUAGE_EXTENSIONS:
                    lang = _LANGUAGE_EXTENSIONS[ext]
                    lang_counts[lang] = lang_counts.get(lang, 0) + 1

                rel_path = str(rel_root / fname)
                if fname in _KEY_FILES:
                    claims.append(
                        Claim(
                            claim=f"Key file present: {fname}",
                            label=ClaimLabel.VERIFIED,
                            confidence=100,
                            evidence=EvidencePointer(file_path=rel_path),
                        )
                    )

                # Detect top-level directory structure
                parts = rel_root.parts
                if parts and parts[0] not in dirs_seen:
                    dirs_seen.add(parts[0])

        if file_count > 0:
            claims.append(
                Claim(
                    claim=f"Repository contains {file_count} file(s) (within scan limits).",
                    label=ClaimLabel.VERIFIED,
                    confidence=100,
                )
            )

        if lang_counts:
            sorted_langs = sorted(lang_counts.items(), key=lambda x: (-x[1], x[0]))
            primary = sorted_langs[0]
            count_str = f"{primary[1]} source file(s) detected"
            claims.append(
                Claim(
                    claim=f"Primary language is likely {primary[0]} ({count_str}).",
                    label=ClaimLabel.INFERRED,
                    confidence=min(95, 60 + primary[1] * 2),
                )
            )
            if len(sorted_langs) > 1:
                other_langs = ", ".join(f"{lang} ({count})" for lang, count in sorted_langs[1:6])
                claims.append(
                    Claim(
                        claim=f"Additional languages detected: {other_langs}.",
                        label=ClaimLabel.INFERRED,
                        confidence=80,
                    )
                )

        if dirs_seen:
            sorted_dirs = sorted(dirs_seen)
            claims.append(
                Claim(
                    claim=f"Top-level directories: {', '.join(sorted_dirs)}.",
                    label=ClaimLabel.VERIFIED,
                    confidence=100,
                )
            )

        return claims
