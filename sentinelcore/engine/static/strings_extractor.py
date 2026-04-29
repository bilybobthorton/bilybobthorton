import re
from pathlib import Path

from .models import StringsResult

# Minimum string length to extract
MIN_STRING_LEN = 5

URL_RE = re.compile(
    r"https?://[^\s\x00-\x1f\"'<>]{6,}",
    re.IGNORECASE,
)
IP_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)
REGISTRY_RE = re.compile(
    r"(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKLM|HKCU|HKEY_\w+)\\[^\x00\n\"]{4,}",
    re.IGNORECASE,
)
EMAIL_RE = re.compile(
    r"[a-zA-Z0-9._%+\-]{2,}@[a-zA-Z0-9.\-]{2,}\.[a-zA-Z]{2,}"
)

SUSPICIOUS_API_STRINGS = {
    "VirtualAlloc", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
    "URLDownloadToFile", "WinExec", "ShellExecute", "cmd.exe", "powershell",
    "base64", "decode", "CreateService", "sc.exe", "netsh", "reg add",
    "mimikatz", "sekurlsa", "lsass", "procdump", "certutil",
}


def _extract_ascii(data: bytes, min_len: int = MIN_STRING_LEN) -> list[str]:
    pattern = re.compile(b"[ -~]{" + str(min_len).encode() + b",}")
    return [m.group().decode("ascii", errors="replace") for m in pattern.finditer(data)]


def _extract_unicode(data: bytes, min_len: int = MIN_STRING_LEN) -> list[str]:
    pattern = re.compile(b"(?:[ -~]\x00){" + str(min_len).encode() + b",}")
    return [m.group().decode("utf-16-le", errors="replace") for m in pattern.finditer(data)]


def extract_strings(file_path: str | Path) -> StringsResult:
    data = Path(file_path).read_bytes()

    ascii_strings = _extract_ascii(data)
    unicode_strings = _extract_unicode(data)
    all_strings = ascii_strings + unicode_strings

    combined = "\n".join(all_strings)

    urls = list(set(URL_RE.findall(combined)))
    ips = list(set(IP_RE.findall(combined)))
    reg_keys = list(set(REGISTRY_RE.findall(combined)))
    emails = list(set(EMAIL_RE.findall(combined)))

    suspicious = []
    lower_strings = {s.lower() for s in all_strings}
    for api in SUSPICIOUS_API_STRINGS:
        if api.lower() in lower_strings:
            suspicious.append(api)

    return StringsResult(
        ascii_strings=ascii_strings[:500],
        unicode_strings=unicode_strings[:200],
        urls=urls,
        ips=ips,
        registry_keys=reg_keys,
        suspicious_apis=suspicious,
        email_addresses=emails,
    )
