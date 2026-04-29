"""
Feature extraction for ML model.
Converts a StaticAnalysisResult into a flat numeric feature vector.
All features are bounded and normalized to work well with tree-based models.
"""
from __future__ import annotations

import math
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from engine.static.models import StaticAnalysisResult

# Fixed feature names — order MUST stay stable across train/inference
FEATURE_NAMES = [
    # File basics
    "file_size_kb",
    "file_size_log",
    # PE presence
    "is_pe",
    "is_64bit",
    "is_packed",
    "has_overlay",
    "is_signed",
    "is_dotnet",
    # Section stats
    "num_sections",
    "avg_section_entropy",
    "max_section_entropy",
    "high_entropy_section_count",
    "has_exec_writable_section",
    # Import stats
    "num_import_dlls",
    "num_import_functions",
    "num_suspicious_imports",
    "imports_kernel32",
    "imports_ntdll",
    "imports_wininet",
    "imports_crypt",
    "imports_ws2_32",
    # Export stats
    "num_exports",
    # YARA
    "yara_match_count",
    "yara_critical_count",
    "yara_high_count",
    # String analysis
    "num_urls",
    "num_ips",
    "num_suspicious_apis",
    "num_registry_keys",
    # Overlay
    "overlay_size_kb",
    "overlay_size_log",
]

NUM_FEATURES = len(FEATURE_NAMES)

_SUSPICIOUS_APIS = {
    "VirtualAlloc", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
    "NtUnmapViewOfSection", "SetWindowsHookEx", "GetProcAddress", "LoadLibrary",
    "OpenProcess", "CreateProcess", "ShellExecute", "WinExec",
    "URLDownloadToFile", "InternetOpen", "InternetConnect",
    "RegSetValue", "RegCreateKey", "CryptEncrypt", "CryptDecrypt",
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
}


def extract_features(result: "StaticAnalysisResult") -> list[float]:
    """Return a FEATURE_NAMES-ordered list of floats for one file."""
    pe = result.pe_info
    strings = result.strings

    file_kb = result.file_size / 1024.0
    file_size_log = math.log1p(result.file_size)

    # Section features
    sections = pe.sections if pe and pe.is_pe else []
    entropies = [s.entropy for s in sections]
    avg_ent = sum(entropies) / len(entropies) if entropies else 0.0
    max_ent = max(entropies) if entropies else 0.0
    high_ent_count = sum(1 for e in entropies if e > 7.0)
    exec_writable = int(any(
        ("executable" in s.flags and "writable" in s.flags)
        for s in sections
    ))

    # Import features
    imports = pe.imports if pe and pe.is_pe else {}
    all_funcs = [f for funcs in imports.values() for f in funcs]
    suspicious_imp_count = sum(1 for f in all_funcs if f in _SUSPICIOUS_APIS)

    dll_lower = {d.lower() for d in imports}
    imports_kernel32 = int(any("kernel32" in d for d in dll_lower))
    imports_ntdll = int(any("ntdll" in d for d in dll_lower))
    imports_wininet = int(any("wininet" in d or "winhttp" in d for d in dll_lower))
    imports_crypt = int(any("crypt" in d or "bcrypt" in d for d in dll_lower))
    imports_ws2 = int(any("ws2_32" in d or "wsock" in d for d in dll_lower))

    # YARA features
    yara_count = len(result.yara_matches)
    yara_critical = sum(
        1 for m in result.yara_matches
        if m.meta.get("severity", "").lower() == "critical"
    )
    yara_high = sum(
        1 for m in result.yara_matches
        if m.meta.get("severity", "").lower() == "high"
    )

    # String features
    num_urls = len(strings.urls) if strings else 0
    num_ips = len(strings.ips) if strings else 0
    num_sus_apis = len(strings.suspicious_apis) if strings else 0
    num_reg = len(strings.registry_keys) if strings else 0

    # Overlay
    overlay_size = pe.overlay_size if pe and pe.is_pe else 0
    overlay_kb = overlay_size / 1024.0
    overlay_log = math.log1p(overlay_size)

    return [
        min(file_kb, 1e6),
        file_size_log,
        float(pe.is_pe if pe else False),
        float(pe.is_64bit if pe and pe.is_pe else False),
        float(pe.is_packed if pe and pe.is_pe else False),
        float(pe.has_overlay if pe and pe.is_pe else False),
        float(pe.is_signed if pe and pe.is_pe else False),
        float(pe.is_dotnet if pe and pe.is_pe else False),
        float(len(sections)),
        avg_ent,
        max_ent,
        float(high_ent_count),
        float(exec_writable),
        float(len(imports)),
        float(len(all_funcs)),
        float(suspicious_imp_count),
        float(imports_kernel32),
        float(imports_ntdll),
        float(imports_wininet),
        float(imports_crypt),
        float(imports_ws2),
        float(len(pe.exports) if pe and pe.is_pe else 0),
        float(yara_count),
        float(yara_critical),
        float(yara_high),
        float(num_urls),
        float(num_ips),
        float(num_sus_apis),
        float(num_reg),
        min(overlay_kb, 1e6),
        overlay_log,
    ]
