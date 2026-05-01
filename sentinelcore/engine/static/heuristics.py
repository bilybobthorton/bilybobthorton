from __future__ import annotations
"""
Heuristic analysis engine.

Performs rule-based behavioral pattern matching against static analysis
data — PE imports, strings, entropy, and structural anomalies. Each rule
is tagged with a MITRE ATT&CK technique ID for triage and reporting.

Heuristic layers:
  1. API combination rules  — dangerous import patterns (injectors, ransomware, etc.)
  2. Structural PE rules    — packed sections, anomalous EP, large overlay, tiny PE
  3. String-based rules     — VM/sandbox evasion keywords, credential harvesting, C2 IOCs
  4. Entropy rules          — high-entropy non-code sections (encrypted payload)
"""

import re
from dataclasses import dataclass, field
from typing import Optional

from .models import PEInfo, StringsResult

# ── Data model ────────────────────────────────────────────────────────────────

@dataclass
class HeuristicHit:
    name: str
    description: str
    severity: str          # low | medium | high | critical
    confidence: float      # 0.0 – 1.0 contribution to overall score
    evidence: list[str] = field(default_factory=list)
    mitre_technique: Optional[str] = None
    mitre_tactic: Optional[str] = None


@dataclass
class HeuristicResult:
    hits: list[HeuristicHit] = field(default_factory=list)
    score: float = 0.0     # aggregate 0.0 – 1.0
    verdict: str = "clean" # clean | suspicious | malicious

    @property
    def indicators(self) -> list[str]:
        out = []
        for h in self.hits:
            ev = f" [{', '.join(h.evidence[:2])}]" if h.evidence else ""
            out.append(f"Heuristic [{h.severity.upper()}] {h.name}{ev}")
        return out


# ── API combination rules ─────────────────────────────────────────────────────

# Each rule: (name, description, required_apis, severity, confidence, mitre_technique, mitre_tactic)
_API_RULES: list[tuple] = [
    (
        "Process Injection",
        "Classic OpenProcess + WriteProcessMemory + CreateRemoteThread pattern used to inject "
        "shellcode or DLLs into a running process.",
        {"OpenProcess", "WriteProcessMemory", "CreateRemoteThread"},
        "critical", 0.75,
        "T1055", "Defense Evasion / Privilege Escalation",
    ),
    (
        "Process Hollowing",
        "NtUnmapViewOfSection or ZwUnmapViewOfSection combined with VirtualAllocEx and "
        "WriteProcessMemory — hallmark of process hollowing (T1055.012).",
        {"VirtualAllocEx", "WriteProcessMemory"},
        "critical", 0.70,
        "T1055.012", "Defense Evasion",
    ),
    (
        "DLL Injection via LoadLibrary",
        "LoadLibraryA/W combined with CreateRemoteThread to force a target process to load a "
        "malicious DLL.",
        {"CreateRemoteThread", "LoadLibraryA"},
        "high", 0.60,
        "T1055.001", "Defense Evasion",
    ),
    (
        "DLL Injection via LoadLibrary (W)",
        "LoadLibraryW variant of DLL injection.",
        {"CreateRemoteThread", "LoadLibraryW"},
        "high", 0.60,
        "T1055.001", "Defense Evasion",
    ),
    (
        "Keylogger",
        "SetWindowsHookEx combined with GetAsyncKeyState or GetKeyState — typical low-level "
        "keyboard hook for capturing keystrokes.",
        {"SetWindowsHookEx", "GetAsyncKeyState"},
        "high", 0.65,
        "T1056.001", "Collection",
    ),
    (
        "Ransomware Encryption Pattern",
        "File enumeration (FindFirstFile/FindNextFile) combined with CryptEncrypt or "
        "BCryptEncrypt — characteristic of file-encrypting ransomware.",
        {"FindFirstFileW", "CryptEncrypt"},
        "critical", 0.80,
        "T1486", "Impact",
    ),
    (
        "Ransomware Encryption Pattern (BCrypt)",
        "BCrypt API variant of ransomware file encryption.",
        {"FindFirstFileW", "BCryptEncrypt"},
        "critical", 0.80,
        "T1486", "Impact",
    ),
    (
        "Remote File Download + Execute",
        "URLDownloadToFile or InternetOpenUrl combined with WinExec or CreateProcess — "
        "dropper/downloader behaviour.",
        {"URLDownloadToFile", "WinExec"},
        "high", 0.65,
        "T1105", "Command and Control",
    ),
    (
        "Remote File Download + Execute (CreateProcess)",
        "URLDownloadToFile with CreateProcess execution.",
        {"URLDownloadToFile", "CreateProcessA"},
        "high", 0.65,
        "T1105", "Command and Control",
    ),
    (
        "LSASS Memory Dump",
        "MiniDumpWriteDump combined with OpenProcess — used by credential dumping tools "
        "(Mimikatz, ProcDump) to read LSASS memory.",
        {"MiniDumpWriteDump", "OpenProcess"},
        "critical", 0.85,
        "T1003.001", "Credential Access",
    ),
    (
        "DPAPI Credential Harvesting",
        "CredEnumerate + CryptUnprotectData — reads and decrypts credentials stored by "
        "Windows Data Protection API (browser passwords, RDP creds).",
        {"CredEnumerate", "CryptUnprotectData"},
        "critical", 0.80,
        "T1555", "Credential Access",
    ),
    (
        "Anti-Debugging",
        "IsDebuggerPresent and/or CheckRemoteDebuggerPresent used to detect analysis "
        "environments and alter behaviour accordingly.",
        {"IsDebuggerPresent", "CheckRemoteDebuggerPresent"},
        "medium", 0.40,
        "T1622", "Defense Evasion",
    ),
    (
        "Registry Persistence",
        "RegSetValueEx combined with CreateProcess or WinExec — writes a value to a Run key "
        "for persistence across reboots.",
        {"RegSetValueExA", "CreateProcessA"},
        "high", 0.55,
        "T1547.001", "Persistence",
    ),
    (
        "Registry Persistence (W variants)",
        "Wide-character Registry + CreateProcess persistence.",
        {"RegSetValueExW", "CreateProcessW"},
        "high", 0.55,
        "T1547.001", "Persistence",
    ),
    (
        "Token Privilege Escalation",
        "AdjustTokenPrivileges + OpenProcessToken — requests elevated privileges at runtime, "
        "used by privilege escalation exploits.",
        {"AdjustTokenPrivileges", "OpenProcessToken"},
        "high", 0.60,
        "T1134", "Privilege Escalation",
    ),
    (
        "Memory Allocation + Execution",
        "VirtualAlloc + VirtualProtect combined — allocates and makes memory executable, "
        "common in shellcode loaders and in-memory PE loaders.",
        {"VirtualAlloc", "VirtualProtect"},
        "medium", 0.45,
        "T1620", "Defense Evasion",
    ),
]


def _all_imports(pe_info: PEInfo) -> set[str]:
    apis: set[str] = set()
    for funcs in pe_info.imports.values():
        apis.update(funcs)
    return apis


def _check_api_rules(pe_info: PEInfo) -> list[HeuristicHit]:
    hits: list[HeuristicHit] = []
    all_apis = _all_imports(pe_info)

    for (name, desc, required, sev, conf, mitre, tactic) in _API_RULES:
        matched = required & all_apis
        if matched == required:
            hits.append(HeuristicHit(
                name=name,
                description=desc,
                severity=sev,
                confidence=conf,
                evidence=sorted(matched),
                mitre_technique=mitre,
                mitre_tactic=tactic,
            ))

    return hits


# ── Structural PE rules ───────────────────────────────────────────────────────

def _check_structural(pe_info: PEInfo, file_size: int) -> list[HeuristicHit]:
    hits: list[HeuristicHit] = []

    # Entry point outside the .text section
    if pe_info.entry_point and pe_info.sections:
        text_sections = [s for s in pe_info.sections if ".text" in s.name.lower() and "executable" in s.flags]
        if text_sections:
            ep = pe_info.entry_point
            in_text = any(
                s.virtual_address <= ep < s.virtual_address + s.virtual_size
                for s in text_sections
            )
            if not in_text:
                hits.append(HeuristicHit(
                    name="Entry Point Outside .text Section",
                    description="Executable entry point resides outside the standard .text code section — "
                                "indicative of packed or custom-loaded code.",
                    severity="high",
                    confidence=0.55,
                    evidence=[f"EP=0x{ep:08x}"],
                    mitre_technique="T1027",
                    mitre_tactic="Defense Evasion",
                ))

    # High-entropy executable section (not already flagged as packed globally)
    for section in pe_info.sections:
        if "executable" in section.flags and section.entropy > 7.2:
            hits.append(HeuristicHit(
                name="High-Entropy Executable Section",
                description=f"Section '{section.name}' is marked executable and has entropy "
                            f"{section.entropy:.2f} — strongly suggests encrypted or packed code.",
                severity="high",
                confidence=0.60,
                evidence=[f"{section.name}: entropy={section.entropy:.2f}"],
                mitre_technique="T1027.002",
                mitre_tactic="Defense Evasion",
            ))

    # Large overlay data (appended after last PE section — dropper technique)
    if pe_info.has_overlay and pe_info.overlay_size > 50_000:
        hits.append(HeuristicHit(
            name="Large PE Overlay",
            description=f"File has {pe_info.overlay_size // 1024} KB of data appended after the last PE "
                        "section — a common dropper technique to carry an embedded payload.",
            severity="medium",
            confidence=0.40,
            evidence=[f"overlay={pe_info.overlay_size} bytes"],
            mitre_technique="T1027.009",
            mitre_tactic="Defense Evasion",
        ))

    # Tiny PE (< 10 KB) — likely a loader stub
    if 0 < file_size < 10_240:
        hits.append(HeuristicHit(
            name="Unusually Small PE",
            description=f"PE file is only {file_size} bytes — may be a shellcode stub, loader, or "
                        "dropper that downloads a secondary payload.",
            severity="medium",
            confidence=0.30,
            evidence=[f"size={file_size} bytes"],
            mitre_technique="T1027",
            mitre_tactic="Defense Evasion",
        ))

    # Section count anomaly: single executable section + no readable section
    if len(pe_info.sections) == 1 and pe_info.sections[0].entropy > 6.5:
        hits.append(HeuristicHit(
            name="Single High-Entropy Section (Packed Binary)",
            description="PE has only one section with high entropy — characteristic of aggressive "
                        "packing (UPX, Themida, custom packer).",
            severity="high",
            confidence=0.65,
            evidence=[f"sections=1, entropy={pe_info.sections[0].entropy:.2f}"],
            mitre_technique="T1027.002",
            mitre_tactic="Defense Evasion",
        ))

    # Suspicious section names (blank, padded with nulls, random chars)
    for section in pe_info.sections:
        stripped = section.name.strip("\x00 ")
        if not stripped or (len(stripped) > 1 and all(c not in "abcdefghijklmnopqrstuvwxyz._ " for c in stripped.lower())):
            hits.append(HeuristicHit(
                name="Anomalous PE Section Name",
                description=f"Section name '{repr(section.name)}' is blank or non-standard — "
                            "packers and obfuscators frequently use random/null names.",
                severity="low",
                confidence=0.20,
                evidence=[f"name={repr(section.name)}"],
                mitre_technique="T1027",
                mitre_tactic="Defense Evasion",
            ))

    return hits


# ── String-based rules ────────────────────────────────────────────────────────

_VM_KEYWORDS = [
    "VBoxService", "vmtoolsd", "vmwaretray", "vmwareuser",
    "VBOX", "VMWARE", "QEMU", "BOCHS", "VIRTUAL",
    "SbieDll", "dbghelp.dll", "sbiedll.dll",
]

_SANDBOX_KEYWORDS = [
    "sample", "malware", "virus", "sandbox", "cuckoo",
    "wireshark", "procmon", "fiddler", "processhacker",
]

_CREDENTIAL_KEYWORDS = [
    "password", "passwd", "credential", "NTLM", "kerberos",
    "SAMKey", "lsass", "sekurlsa", "wce.exe", "fgdump",
]

_EXFIL_KEYWORDS = [
    "pastebin.com", "transfer.sh", "mega.nz", "anonfiles",
    "temp.sh", "discord.com/api/webhooks",
]


def _check_strings(strings: StringsResult) -> list[HeuristicHit]:
    hits: list[HeuristicHit] = []
    all_strings = strings.ascii_strings + strings.unicode_strings

    # VM / sandbox evasion keywords
    vm_found = [kw for kw in _VM_KEYWORDS if any(kw.lower() in s.lower() for s in all_strings)]
    if vm_found:
        hits.append(HeuristicHit(
            name="Virtual Machine / Sandbox Evasion Strings",
            description="File contains strings referencing hypervisor or sandbox artefacts — "
                        "common in samples that avoid executing in analysis environments.",
            severity="high",
            confidence=0.55,
            evidence=vm_found[:4],
            mitre_technique="T1497.001",
            mitre_tactic="Defense Evasion",
        ))

    # Sandbox tool detection
    sb_found = [kw for kw in _SANDBOX_KEYWORDS if any(kw.lower() in s.lower() for s in all_strings)]
    if len(sb_found) >= 2:
        hits.append(HeuristicHit(
            name="Sandbox / Analysis Tool Detection Strings",
            description="Multiple strings reference analysis tools (Wireshark, Process Monitor, etc.) "
                        "suggesting the sample checks for running analysis software.",
            severity="medium",
            confidence=0.40,
            evidence=sb_found[:4],
            mitre_technique="T1497.001",
            mitre_tactic="Defense Evasion",
        ))

    # Credential harvesting strings
    cred_found = [kw for kw in _CREDENTIAL_KEYWORDS if any(kw.lower() in s.lower() for s in all_strings)]
    if cred_found:
        hits.append(HeuristicHit(
            name="Credential Harvesting Strings",
            description="File contains strings associated with credential theft — password fields, "
                        "NTLM/Kerberos references, or known credential-dumping tool names.",
            severity="high",
            confidence=0.60,
            evidence=cred_found[:4],
            mitre_technique="T1555",
            mitre_tactic="Credential Access",
        ))

    # Exfiltration endpoints
    exfil_found = [kw for kw in _EXFIL_KEYWORDS if any(kw.lower() in s.lower() for s in all_strings)]
    if exfil_found:
        hits.append(HeuristicHit(
            name="Known Exfiltration Endpoint",
            description="File references a site commonly used for data exfiltration (Pastebin, "
                        "Discord webhooks, file-sharing services).",
            severity="critical",
            confidence=0.75,
            evidence=exfil_found[:4],
            mitre_technique="T1567",
            mitre_tactic="Exfiltration",
        ))

    # Embedded base64 blobs (indicative of encoded payload or C2 config)
    b64_pattern = re.compile(r"[A-Za-z0-9+/]{60,}={0,2}")
    b64_hits = [m.group() for s in all_strings for m in [b64_pattern.search(s)] if m]
    if len(b64_hits) >= 2:
        hits.append(HeuristicHit(
            name="Embedded Base64 Blobs",
            description=f"{len(b64_hits)} long base64-encoded string(s) found — frequently used "
                        "to conceal encrypted payloads or obfuscated C2 configuration.",
            severity="medium",
            confidence=0.35,
            evidence=[b[:40] + "…" for b in b64_hits[:2]],
            mitre_technique="T1027",
            mitre_tactic="Defense Evasion",
        ))

    # Hardcoded IP addresses in URLs (C2 over raw IP)
    if strings.ips and len(strings.ips) >= 2:
        hits.append(HeuristicHit(
            name="Multiple Hardcoded IP Addresses",
            description=f"{len(strings.ips)} IP address(es) embedded in file strings — "
                        "C2 implants often hardcode infrastructure IPs.",
            severity="medium",
            confidence=0.30,
            evidence=strings.ips[:4],
            mitre_technique="T1071",
            mitre_tactic="Command and Control",
        ))

    return hits


# ── Scoring + verdict ─────────────────────────────────────────────────────────

_SEVERITY_WEIGHT = {"low": 0.15, "medium": 0.30, "high": 0.55, "critical": 0.80}


def _compute_score(hits: list[HeuristicHit]) -> float:
    if not hits:
        return 0.0
    score = 0.0
    for h in hits:
        score += h.confidence * _SEVERITY_WEIGHT.get(h.severity, 0.30)
    return round(min(score, 1.0), 4)


# ── Public API ────────────────────────────────────────────────────────────────

def run_heuristics(
    pe_info: PEInfo | None,
    strings: StringsResult | None,
    file_size: int,
) -> HeuristicResult:
    """Run all heuristic checks and return a consolidated HeuristicResult."""
    hits: list[HeuristicHit] = []

    if pe_info and pe_info.is_pe:
        hits.extend(_check_api_rules(pe_info))
        hits.extend(_check_structural(pe_info, file_size))

    if strings:
        hits.extend(_check_strings(strings))

    # Deduplicate by name (structural + API rules can overlap on packed check)
    seen: set[str] = set()
    deduped = []
    for h in hits:
        if h.name not in seen:
            seen.add(h.name)
            deduped.append(h)

    score = _compute_score(deduped)

    if score >= 0.65:
        verdict = "malicious"
    elif score >= 0.25:
        verdict = "suspicious"
    else:
        verdict = "clean"

    return HeuristicResult(hits=deduped, score=score, verdict=verdict)
