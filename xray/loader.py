"""Target loading: local directory, git URL, zip/tar archive, single file."""

from __future__ import annotations

import re
import shutil
import tarfile
import tempfile
import zipfile
from pathlib import Path

_GIT_URL_RE = re.compile(
    r"^(https?://|git@|ssh://git@).*\.git$|^(https?://github\.com|https?://gitlab\.com|https?://bitbucket\.org)/",
    re.IGNORECASE,
)
_ARCHIVE_SUFFIXES = {".zip", ".tar", ".gz", ".bz2", ".xz", ".tgz", ".tbz2"}


class LoadError(Exception):
    pass


class LoadedTarget:
    """Represents a loaded analysis target."""

    def __init__(self, path: Path, cleanup: bool = False, original: str = "") -> None:
        self.path = path
        self._cleanup = cleanup
        self.original = original or str(path)

    def __enter__(self) -> LoadedTarget:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def close(self) -> None:
        if self._cleanup and self.path.exists():
            shutil.rmtree(self.path, ignore_errors=True)


def load_target(target: str, max_bytes: int = 100 * 1024 * 1024) -> LoadedTarget:
    """Load a target from a path, git URL, or archive."""
    if _GIT_URL_RE.match(target):
        return _load_git(target)

    path = Path(target)
    if not path.exists():
        raise LoadError(f"Target does not exist: {target}")

    if path.is_dir():
        return LoadedTarget(path, cleanup=False, original=target)

    if path.is_file():
        file_size = path.stat().st_size
        if file_size > max_bytes:
            raise LoadError(
                f"Target file size ({file_size:,} bytes) exceeds "
                f"--max-bytes limit ({max_bytes:,} bytes)."
            )
        suffix = path.suffix.lower()
        suffixes = "".join(path.suffixes).lower()
        if suffix in _ARCHIVE_SUFFIXES or suffixes in {".tar.gz", ".tar.bz2", ".tar.xz"}:
            return _load_archive(path)
        # Single file
        return LoadedTarget(path, cleanup=False, original=target)

    raise LoadError(f"Cannot load target: {target}")


def _load_git(url: str) -> LoadedTarget:
    try:
        import git  # type: ignore[import-untyped]
    except ImportError as e:
        raise LoadError(
            "GitPython is required to clone git URLs. Install it with: pip install GitPython"
        ) from e

    tmp = Path(tempfile.mkdtemp(prefix="xray-git-"))
    try:
        git.Repo.clone_from(url, tmp, depth=1, no_single_branch=False)
    except Exception as exc:
        shutil.rmtree(tmp, ignore_errors=True)
        raise LoadError(f"Failed to clone {url}: {exc}") from exc
    return LoadedTarget(tmp, cleanup=True, original=url)


def _load_archive(path: Path) -> LoadedTarget:
    tmp = Path(tempfile.mkdtemp(prefix="xray-archive-"))
    try:
        if zipfile.is_zipfile(path):
            with zipfile.ZipFile(path) as zf:
                _safe_zip_extract(zf, tmp)
        elif tarfile.is_tarfile(path):
            with tarfile.open(path) as tf:
                _safe_tar_extract(tf, tmp)
        else:
            shutil.rmtree(tmp, ignore_errors=True)
            raise LoadError(f"Unrecognized archive format: {path}")
    except Exception:
        shutil.rmtree(tmp, ignore_errors=True)
        raise
    return LoadedTarget(tmp, cleanup=True, original=str(path))


def _safe_zip_extract(zf: zipfile.ZipFile, dest: Path) -> None:
    for member in zf.infolist():
        member_path = dest / member.filename
        # Prevent zip slip
        try:
            member_path.resolve().relative_to(dest.resolve())
        except ValueError:
            continue
        zf.extract(member, dest)


def _safe_tar_extract(tf: tarfile.TarFile, dest: Path) -> None:
    for member in tf.getmembers():
        member_path = dest / member.name
        try:
            member_path.resolve().relative_to(dest.resolve())
        except ValueError:
            continue
        tf.extract(member, dest, set_attrs=False)
