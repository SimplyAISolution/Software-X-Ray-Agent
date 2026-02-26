"""Tests for analyzers."""

from __future__ import annotations

import json
from pathlib import Path

from xray.analyzers.manifests import ManifestAnalyzer
from xray.analyzers.tree import TreeAnalyzer
from xray.context import AnalysisContext


def make_ctx(tmp_path: Path) -> AnalysisContext:
    return AnalysisContext(target_path=tmp_path)


def test_tree_analyzer_supports_dir(tmp_path: Path) -> None:
    analyzer = TreeAnalyzer()
    assert analyzer.supports(tmp_path) is True


def test_tree_analyzer_does_not_support_file(tmp_path: Path) -> None:
    f = tmp_path / "file.txt"
    f.write_text("hello")
    analyzer = TreeAnalyzer()
    assert analyzer.supports(f) is False


def test_tree_analyzer_detects_python(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text("print('hello')")
    (tmp_path / "utils.py").write_text("def foo(): pass")
    analyzer = TreeAnalyzer()
    claims = analyzer.analyze(tmp_path, make_ctx(tmp_path))
    texts = [c.claim for c in claims]
    assert any("Python" in t for t in texts)


def test_tree_analyzer_detects_key_files(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("# Test")
    (tmp_path / "LICENSE").write_text("MIT")
    analyzer = TreeAnalyzer()
    claims = analyzer.analyze(tmp_path, make_ctx(tmp_path))
    texts = [c.claim for c in claims]
    assert any("README.md" in t for t in texts)
    assert any("LICENSE" in t for t in texts)


def test_tree_analyzer_file_count(tmp_path: Path) -> None:
    for i in range(5):
        (tmp_path / f"file{i}.py").write_text(f"# file {i}")
    analyzer = TreeAnalyzer()
    claims = analyzer.analyze(tmp_path, make_ctx(tmp_path))
    count_claims = [c for c in claims if "Repository contains" in c.claim]
    assert len(count_claims) == 1
    assert "5" in count_claims[0].claim


def test_manifest_analyzer_package_json(tmp_path: Path) -> None:
    pkg = {
        "name": "my-app",
        "version": "1.0.0",
        "description": "A test app",
        "dependencies": {"react": "^18.0.0", "express": "^4.18.0"},
    }
    (tmp_path / "package.json").write_text(json.dumps(pkg))
    analyzer = ManifestAnalyzer()
    assert analyzer.supports(tmp_path)
    claims = analyzer.analyze(tmp_path, make_ctx(tmp_path))
    texts = [c.claim for c in claims]
    assert any("my-app" in t for t in texts)
    assert any("React" in t for t in texts)
    assert any("Express" in t.title() or "express" in t.lower() for t in texts)


def test_manifest_analyzer_pyproject_toml(tmp_path: Path) -> None:
    toml_content = """
[project]
name = "my-pkg"
version = "2.0.0"
description = "A Python package"
requires-python = ">=3.11"
dependencies = ["typer", "pydantic"]

[build-system]
build-backend = "hatchling.build"
requires = ["hatchling"]
"""
    (tmp_path / "pyproject.toml").write_text(toml_content)
    analyzer = ManifestAnalyzer()
    assert analyzer.supports(tmp_path)
    claims = analyzer.analyze(tmp_path, make_ctx(tmp_path))
    texts = [c.claim for c in claims]
    assert any("my-pkg" in t for t in texts)
    assert any("Python" in t for t in texts)
    assert any("hatchling" in t for t in texts)


def test_manifest_analyzer_requirements_txt(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("flask\nrequests\npytest\n")
    analyzer = ManifestAnalyzer()
    assert analyzer.supports(tmp_path)
    claims = analyzer.analyze(tmp_path, make_ctx(tmp_path))
    texts = [c.claim for c in claims]
    assert any("flask" in t.lower() for t in texts)


def test_manifest_analyzer_go_mod(tmp_path: Path) -> None:
    go_mod = (
        "module github.com/example/myapp\n\ngo 1.21\n\n"
        "require (\n\tgithub.com/gin-gonic/gin v1.9.0\n)\n"
    )
    (tmp_path / "go.mod").write_text(go_mod)
    analyzer = ManifestAnalyzer()
    assert analyzer.supports(tmp_path)
    claims = analyzer.analyze(tmp_path, make_ctx(tmp_path))
    texts = [c.claim for c in claims]
    assert any("Go" in t for t in texts)
    assert any("github.com/example/myapp" in t for t in texts)


def test_manifest_analyzer_cargo_toml(tmp_path: Path) -> None:
    cargo_toml = (
        '[package]\nname = "my-crate"\nversion = "0.1.0"\nedition = "2021"\n\n'
        '[dependencies]\ntokio = "1.0"\n'
    )
    (tmp_path / "Cargo.toml").write_text(cargo_toml)
    analyzer = ManifestAnalyzer()
    assert analyzer.supports(tmp_path)
    claims = analyzer.analyze(tmp_path, make_ctx(tmp_path))
    texts = [c.claim for c in claims]
    assert any("Rust" in t for t in texts)
    assert any("my-crate" in t for t in texts)


def test_manifest_analyzer_no_manifests(tmp_path: Path) -> None:
    analyzer = ManifestAnalyzer()
    assert analyzer.supports(tmp_path) is False


def test_deterministic_ordering(tmp_path: Path) -> None:
    """Claims should be in stable order when deterministic=True."""
    for i in range(5):
        (tmp_path / f"module{i}.py").write_text(f"# module {i}")
    (tmp_path / "README.md").write_text("# Test")
    analyzer = TreeAnalyzer()
    ctx = make_ctx(tmp_path)
    claims1 = analyzer.analyze(tmp_path, ctx)
    claims2 = analyzer.analyze(tmp_path, ctx)
    # Same calls should always produce same order
    assert [c.claim for c in claims1] == [c.claim for c in claims2]
