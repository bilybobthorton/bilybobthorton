from __future__ import annotations
"""
Main static analysis orchestrator.
Runs all analysis layers and produces a unified StaticAnalysisResult.
"""
import os
from pathlib import Path
from typing import Optional

try:
    import magic
    MAGIC_AVAILABLE = True
except ImportError:
    MAGIC_AVAILABLE = False

from .hasher import compute_hashes
from .models import FileType, StaticAnalysisResult, ThreatLevel
from .pe_analyzer import analyze_pe, get_suspicious_imports
from .strings_extractor import extract_strings
from .yara_scanner import scan_with_yara


def _detect_file_type(file_path: Path) -> tuple[FileType, str]:
    if MAGIC_AVAILABLE:
        mime = magic.from_file(str(file_path), mime=True)
    else:
        mime = "application/octet-stream"

    mime_lower = mime.lower()

    if "x-dosexec" in mime_lower or "x-msdownload" in mime_lower:
        return FileType.PE, mime
    if "x-executable" in mime_lower or "x-elf" in mime_lower:
        return FileType.ELF, mime
    if "x-mach" in mime_lower:
        return FileType.MACHO, mime
    if "pdf" in mime_lower:
        return FileType.PDF, mime
    if "officedocument" in mime_lower or "msword" in mime_lower or "excel" in mime_lower:
        return FileType.OFFICE, mime
    if "text" in mime_lower or "script" in mime_lower:
        return FileType.SCRIPT, mime
    if "zip" in mime_lower or "gzip" in mime_lower or "x-tar" in mime_lower or "rar" in mime_lower:
        return FileType.ARCHIVE, mime

    # Fallback: check magic bytes
    with open(file_path, "rb") as f:
        header = f.read(4)
    if header[:2] == b"MZ":
        return FileType.PE, mime
    if header[:4] == b"\x7fELF":
        return FileType.ELF, mime

    return FileType.UNKNOWN, mime


def _score_threat(
    file_type: FileType,
    pe_info,
    yara_matches,
    strings_result,
    suspicious_imports,
) -> tuple[ThreatLevel, float, list[str]]:
    score = 0.0
    indicators = []

    if yara_matches:
        score += 0.6 * min(len(yara_matches), 3) / 3
        for match in yara_matches:
            indicators.append(f"YARA rule matched: {match.rule_name}")

    if pe_info and pe_info.is_pe:
        if pe_info.is_packed:
            score += 0.25
            indicators.append("PE sections indicate packing/encryption (high entropy)")
        if pe_info.has_overlay:
            score += 0.1
            indicators.append(f"PE has {pe_info.overlay_size} byte overlay")

    if suspicious_imports:
        score += min(len(suspicious_imports), 5) * 0.05
        for imp in suspicious_imports[:5]:
            indicators.append(f"Suspicious import: {imp}")

    if strings_result:
        if strings_result.urls:
            score += 0.05
            indicators.append(f"Contains {len(strings_result.urls)} embedded URL(s)")
        if strings_result.suspicious_apis:
            score += min(len(strings_result.suspicious_apis), 5) * 0.04
            for api in strings_result.suspicious_apis[:3]:
                indicators.append(f"Suspicious string found: {api}")
        if strings_result.ips:
            score += 0.05
            indicators.append(f"Contains {len(strings_result.ips)} embedded IP address(es)")

    score = min(score, 1.0)

    if score >= 0.6:
        level = ThreatLevel.MALICIOUS
    elif score >= 0.3:
        level = ThreatLevel.SUSPICIOUS
    elif score > 0.0:
        level = ThreatLevel.SUSPICIOUS
    else:
        level = ThreatLevel.CLEAN

    return level, round(score, 4), indicators


def analyze_file(file_path: str | Path) -> StaticAnalysisResult:
    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

    file_size = path.stat().st_size
    errors = []

    file_type, mime_type = _detect_file_type(path)
    hashes = compute_hashes(path)

    # PE analysis
    pe_info = None
    suspicious_imports = []
    if file_type == FileType.PE:
        try:
            pe_info = analyze_pe(path)
            if pe_info and pe_info.is_pe:
                suspicious_imports = get_suspicious_imports(pe_info)
        except Exception as e:
            errors.append(f"PE analysis error: {e}")

    # YARA
    yara_matches = []
    try:
        yara_matches = scan_with_yara(path)
    except Exception as e:
        errors.append(f"YARA scan error: {e}")

    # String extraction
    strings_result = None
    try:
        strings_result = extract_strings(path)
    except Exception as e:
        errors.append(f"String extraction error: {e}")

    threat_level, confidence, indicators = _score_threat(
        file_type, pe_info, yara_matches, strings_result, suspicious_imports
    )

    return StaticAnalysisResult(
        file_path=str(path),
        file_size=file_size,
        file_type=file_type,
        mime_type=mime_type,
        threat_level=threat_level,
        confidence=confidence,
        hashes=hashes,
        pe_info=pe_info,
        yara_matches=yara_matches,
        strings=strings_result,
        indicators=indicators,
        errors=errors,
    )
