"""Tests for target loading."""

from __future__ import annotations

import tarfile
import zipfile
from pathlib import Path

import pytest

from xray.loader import LoadedTarget, LoadError, load_target


def test_load_local_directory(tmp_path: Path) -> None:
    result = load_target(str(tmp_path))
    assert isinstance(result, LoadedTarget)
    assert result.path == tmp_path
    result.close()


def test_load_single_file(tmp_path: Path) -> None:
    f = tmp_path / "pyproject.toml"
    f.write_text("[project]\nname = 'test'\n")
    result = load_target(str(f))
    assert result.path == f
    result.close()


def test_load_nonexistent_target() -> None:
    with pytest.raises(LoadError, match="does not exist"):
        load_target("/nonexistent/path/to/target")


def test_load_zip_archive(tmp_path: Path) -> None:
    # Create a zip archive
    src = tmp_path / "src"
    src.mkdir()
    (src / "hello.py").write_text("print('hello')")

    zip_path = tmp_path / "test.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.write(src / "hello.py", "hello.py")

    result = load_target(str(zip_path))
    assert result._cleanup is True
    assert (result.path / "hello.py").exists()
    result.close()


def test_load_tar_archive(tmp_path: Path) -> None:
    src = tmp_path / "src"
    src.mkdir()
    (src / "hello.py").write_text("print('hello')")

    tar_path = tmp_path / "test.tar.gz"
    with tarfile.open(tar_path, "w:gz") as tf:
        tf.add(src / "hello.py", arcname="hello.py")

    result = load_target(str(tar_path))
    assert result._cleanup is True
    assert (result.path / "hello.py").exists()
    result.close()


def test_loaded_target_context_manager(tmp_path: Path) -> None:
    with load_target(str(tmp_path)) as lt:
        assert lt.path.exists()
    # No cleanup for non-temp paths
    assert tmp_path.exists()


def test_zip_slip_protection(tmp_path: Path) -> None:
    """Test that zip slip attacks are prevented."""
    zip_path = tmp_path / "evil.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        # Add a file with a path traversal
        zf.writestr("../../../etc/malicious.txt", "evil content")

    result = load_target(str(zip_path))
    # The traversal file should NOT be extracted outside dest
    evil_path = Path("/etc/malicious.txt")
    assert not evil_path.exists() or evil_path.read_text() != "evil content"
    result.close()
