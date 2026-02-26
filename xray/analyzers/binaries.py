"""Binary file analyzer: file type detection + safe strings sampling."""

from __future__ import annotations

from pathlib import Path

from xray.analyzers.base import Analyzer
from xray.context import AnalysisContext
from xray.models import Claim, ClaimLabel, EvidencePointer

# Max bytes to read for string extraction
_MAX_BINARY_BYTES = 64 * 1024  # 64 KB
_MAX_STRINGS = 50
_MIN_STRING_LEN = 6

_MAGIC_BYTES: dict[bytes, str] = {
    b"\x7fELF": "ELF binary (Linux/Unix executable)",
    b"MZ": "PE binary (Windows executable or DLL)",
    b"\xca\xfe\xba\xbe": "Java class file or Mach-O fat binary",
    b"\xce\xfa\xed\xfe": "Mach-O binary (macOS 32-bit)",
    b"\xcf\xfa\xed\xfe": "Mach-O binary (macOS 64-bit)",
    b"PK\x03\x04": "ZIP archive (or JAR/APK/DOCX)",
    b"\x1f\x8b": "gzip compressed",
    b"BZh": "bzip2 compressed",
    b"\xfd7zXZ\x00": "XZ compressed",
    b"\x89PNG": "PNG image",
    b"\xff\xd8\xff": "JPEG image",
    b"GIF87a": "GIF image",
    b"GIF89a": "GIF image",
    b"%PDF": "PDF document",
}


def _detect_file_type(path: Path) -> str | None:
    try:
        with open(path, "rb") as f:
            header = f.read(16)
        for magic, desc in _MAGIC_BYTES.items():
            if header.startswith(magic):
                return desc
    except OSError:
        pass
    return None


def _extract_strings(path: Path) -> list[str]:
    """Extract printable ASCII strings from a binary file (safe, size-limited)."""
    results: list[str] = []
    try:
        with open(path, "rb") as f:
            data = f.read(_MAX_BINARY_BYTES)
        current: list[int] = []
        for byte in data:
            if 0x20 <= byte < 0x7F:
                current.append(byte)
            else:
                if len(current) >= _MIN_STRING_LEN:
                    results.append(bytes(current).decode("ascii", errors="replace"))
                    if len(results) >= _MAX_STRINGS:
                        break
                current = []
        if current and len(current) >= _MIN_STRING_LEN and len(results) < _MAX_STRINGS:
            results.append(bytes(current).decode("ascii", errors="replace"))
    except OSError:
        pass
    return results


def _is_likely_binary(path: Path) -> bool:
    try:
        with open(path, "rb") as f:
            chunk = f.read(1024)
        if not chunk:
            return False
        # Check for null bytes (common in binaries)
        return b"\x00" in chunk
    except OSError:
        return False


class BinaryAnalyzer(Analyzer):
    name = "binaries"

    def supports(self, target_path: Path) -> bool:
        if target_path.is_file():
            return _is_likely_binary(target_path) or _detect_file_type(target_path) is not None
        if target_path.is_dir():
            # Quick check for any binary files
            for p in target_path.rglob("*"):
                if p.is_file() and p.suffix in {
                    ".exe",
                    ".dll",
                    ".so",
                    ".dylib",
                    ".bin",
                    ".jar",
                    ".whl",
                    ".class",
                }:
                    return True
        return False

    def analyze(self, target_path: Path, ctx: AnalysisContext) -> list[Claim]:
        claims: list[Claim] = []
        targets = [target_path] if target_path.is_file() else list(target_path.rglob("*"))

        binary_count = 0
        for p in sorted(targets):
            if not p.is_file():
                continue
            file_type = _detect_file_type(p)
            if file_type is None and not _is_likely_binary(p):
                continue
            try:
                rel = str(p.relative_to(target_path)) if target_path.is_dir() else str(p)
            except ValueError:
                rel = str(p)
            binary_count += 1
            if binary_count > 20:
                claims.append(
                    Claim(
                        claim="More than 20 binary files detected; listing truncated.",
                        label=ClaimLabel.VERIFIED,
                        confidence=100,
                    )
                )
                break
            if file_type:
                claims.append(
                    Claim(
                        claim=f"Binary file detected: {rel} ({file_type})",
                        label=ClaimLabel.VERIFIED,
                        confidence=90,
                        evidence=EvidencePointer(file_path=rel),
                    )
                )

        return claims
