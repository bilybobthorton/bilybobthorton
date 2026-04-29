import math
from pathlib import Path
from typing import Optional

from .models import PEInfo, SectionInfo

try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False


# High-entropy threshold: packed/encrypted sections typically exceed 7.0
ENTROPY_PACKED_THRESHOLD = 7.0

# APIs commonly abused by malware
SUSPICIOUS_APIS = {
    "VirtualAlloc", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
    "NtUnmapViewOfSection", "ZwUnmapViewOfSection", "SetWindowsHookEx",
    "GetProcAddress", "LoadLibrary", "LoadLibraryA", "LoadLibraryW",
    "OpenProcess", "CreateProcess", "ShellExecute", "WinExec",
    "URLDownloadToFile", "InternetOpen", "InternetConnect",
    "RegSetValue", "RegCreateKey", "RegOpenKey",
    "CryptEncrypt", "CryptDecrypt",
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
}


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    entropy = 0.0
    length = len(data)
    for count in counts:
        if count:
            p = count / length
            entropy -= p * math.log2(p)
    return entropy


def analyze_pe(file_path: str | Path) -> Optional[PEInfo]:
    if not PEFILE_AVAILABLE:
        return None

    path = Path(file_path)
    try:
        pe = pefile.PE(str(path))
    except pefile.PEFormatError:
        return PEInfo(is_pe=False)
    except Exception:
        return PEInfo(is_pe=False)

    info = PEInfo(is_pe=True)

    # Basic header info
    info.machine_type = pefile.MACHINE_TYPE.get(pe.FILE_HEADER.Machine, "UNKNOWN")
    info.timestamp = pe.FILE_HEADER.TimeDateStamp
    info.entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    info.image_base = pe.OPTIONAL_HEADER.ImageBase
    info.is_64bit = pe.FILE_HEADER.Machine == 0x8664

    # Sections + entropy
    raw_data = path.read_bytes()
    high_entropy_sections = 0

    for section in pe.sections:
        name = section.Name.decode("utf-8", errors="replace").rstrip("\x00")
        sect_data = section.get_data()
        ent = _entropy(sect_data)

        flags = []
        if section.Characteristics & 0x20000000:
            flags.append("executable")
        if section.Characteristics & 0x40000000:
            flags.append("readable")
        if section.Characteristics & 0x80000000:
            flags.append("writable")

        if ent > ENTROPY_PACKED_THRESHOLD:
            high_entropy_sections += 1

        info.sections.append(SectionInfo(
            name=name,
            virtual_address=section.VirtualAddress,
            virtual_size=section.Misc_VirtualSize,
            raw_size=section.SizeOfRawData,
            entropy=round(ent, 4),
            flags=flags,
        ))

    # Packed heuristic: majority of sections have high entropy
    if info.sections and high_entropy_sections / len(info.sections) >= 0.5:
        info.is_packed = True

    # Overlay (data appended after last section — common in malware droppers)
    overlay_offset = pe.get_overlay_data_start_offset()
    if overlay_offset and overlay_offset < len(raw_data):
        info.has_overlay = True
        info.overlay_size = len(raw_data) - overlay_offset

    # Imports
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode("utf-8", errors="replace")
            funcs = []
            for imp in entry.imports:
                if imp.name:
                    fname = imp.name.decode("utf-8", errors="replace")
                    funcs.append(fname)
            info.imports[dll] = funcs

    # Exports
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name:
                info.exports.append(exp.name.decode("utf-8", errors="replace"))

    # .NET assembly detection
    if hasattr(pe, "DIRECTORY_ENTRY_COM_DESCRIPTOR"):
        info.is_dotnet = True

    # Signature (Authenticode) check — presence only, not validity
    if hasattr(pe, "DIRECTORY_ENTRY_SECURITY") and pe.DIRECTORY_ENTRY_SECURITY:
        info.is_signed = True

    pe.close()
    return info


def get_suspicious_imports(pe_info: PEInfo) -> list[str]:
    found = []
    for dll, funcs in pe_info.imports.items():
        for func in funcs:
            if func in SUSPICIOUS_APIS:
                found.append(f"{dll}::{func}")
    return found
