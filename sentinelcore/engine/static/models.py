from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class ThreatLevel(str, Enum):
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    UNKNOWN = "unknown"


class FileType(str, Enum):
    PE = "pe"
    ELF = "elf"
    MACHO = "macho"
    PDF = "pdf"
    OFFICE = "office"
    SCRIPT = "script"
    ARCHIVE = "archive"
    UNKNOWN = "unknown"


@dataclass
class HashResult:
    md5: str
    sha1: str
    sha256: str
    ssdeep: Optional[str] = None
    tlsh: Optional[str] = None


@dataclass
class SectionInfo:
    name: str
    virtual_address: int
    virtual_size: int
    raw_size: int
    entropy: float
    flags: list[str] = field(default_factory=list)


@dataclass
class PEInfo:
    is_pe: bool
    machine_type: Optional[str] = None
    timestamp: Optional[int] = None
    entry_point: Optional[int] = None
    image_base: Optional[int] = None
    sections: list[SectionInfo] = field(default_factory=list)
    imports: dict[str, list[str]] = field(default_factory=dict)
    exports: list[str] = field(default_factory=list)
    is_packed: bool = False
    has_overlay: bool = False
    overlay_size: int = 0
    is_signed: bool = False
    is_dotnet: bool = False
    is_64bit: bool = False


@dataclass
class YaraMatch:
    rule_name: str
    tags: list[str]
    meta: dict
    strings: list[tuple[int, str, bytes]]


@dataclass
class StringsResult:
    ascii_strings: list[str] = field(default_factory=list)
    unicode_strings: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    ips: list[str] = field(default_factory=list)
    registry_keys: list[str] = field(default_factory=list)
    suspicious_apis: list[str] = field(default_factory=list)
    email_addresses: list[str] = field(default_factory=list)


@dataclass
class HeuristicHit:
    name: str
    description: str
    severity: str
    confidence: float
    evidence: list[str] = field(default_factory=list)
    mitre_technique: Optional[str] = None
    mitre_tactic: Optional[str] = None


@dataclass
class HeuristicResult:
    hits: list[HeuristicHit] = field(default_factory=list)
    score: float = 0.0
    verdict: str = "clean"


@dataclass
class StaticAnalysisResult:
    file_path: str
    file_size: int
    file_type: FileType
    mime_type: str
    threat_level: ThreatLevel
    confidence: float  # 0.0 to 1.0
    hashes: HashResult
    pe_info: Optional[PEInfo] = None
    yara_matches: list[YaraMatch] = field(default_factory=list)
    strings: Optional[StringsResult] = None
    indicators: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    heuristics: Optional[HeuristicResult] = None
