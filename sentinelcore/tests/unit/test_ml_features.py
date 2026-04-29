"""Unit tests for ML feature extraction."""
import pytest
from engine.ml.features import extract_features, FEATURE_NAMES, NUM_FEATURES
from engine.static.models import (
    StaticAnalysisResult, FileType, ThreatLevel,
    HashResult, PEInfo, SectionInfo, StringsResult, YaraMatch
)


def _make_result(**kwargs) -> StaticAnalysisResult:
    defaults = dict(
        file_path="/tmp/test.exe",
        file_size=102400,
        file_type=FileType.PE,
        mime_type="application/x-dosexec",
        threat_level=ThreatLevel.UNKNOWN,
        confidence=0.0,
        hashes=HashResult(md5="a" * 32, sha1="b" * 40, sha256="c" * 64),
        pe_info=None,
        yara_matches=[],
        strings=None,
        indicators=[],
        errors=[],
    )
    defaults.update(kwargs)
    return StaticAnalysisResult(**defaults)


def test_feature_vector_length():
    result = _make_result()
    features = extract_features(result)
    assert len(features) == NUM_FEATURES
    assert len(FEATURE_NAMES) == NUM_FEATURES


def test_all_features_are_numeric():
    result = _make_result()
    features = extract_features(result)
    for i, f in enumerate(features):
        assert isinstance(f, (int, float)), f"Feature {FEATURE_NAMES[i]} is not numeric: {f}"


def test_packed_pe_flags():
    packed_section = SectionInfo(
        name=".upx0", virtual_address=0x1000, virtual_size=0x5000,
        raw_size=0x5000, entropy=7.8, flags=["executable", "writable"]
    )
    pe = PEInfo(is_pe=True, is_packed=True, sections=[packed_section])
    result = _make_result(pe_info=pe)
    features = extract_features(result)
    idx = FEATURE_NAMES.index("is_packed")
    assert features[idx] == 1.0
    idx_ent = FEATURE_NAMES.index("max_section_entropy")
    assert features[idx_ent] == pytest.approx(7.8)


def test_yara_match_counts():
    matches = [
        YaraMatch("Mimikatz", [], {"severity": "critical"}, []),
        YaraMatch("Reverse_Shell", [], {"severity": "high"}, []),
        YaraMatch("Packed_PE", [], {"severity": "medium"}, []),
    ]
    result = _make_result(yara_matches=matches)
    features = extract_features(result)
    assert features[FEATURE_NAMES.index("yara_match_count")] == 3.0
    assert features[FEATURE_NAMES.index("yara_critical_count")] == 1.0
    assert features[FEATURE_NAMES.index("yara_high_count")] == 1.0


def test_strings_features():
    strings = StringsResult(
        urls=["http://evil.com", "http://c2.bad"],
        ips=["1.2.3.4"],
        suspicious_apis=["VirtualAlloc", "CreateRemoteThread"],
        registry_keys=["HKLM\\Software\\Run"],
    )
    result = _make_result(strings=strings)
    features = extract_features(result)
    assert features[FEATURE_NAMES.index("num_urls")] == 2.0
    assert features[FEATURE_NAMES.index("num_ips")] == 1.0
    assert features[FEATURE_NAMES.index("num_suspicious_apis")] == 2.0
    assert features[FEATURE_NAMES.index("num_registry_keys")] == 1.0


def test_non_pe_file_zeros_pe_features():
    result = _make_result(file_type=FileType.SCRIPT, pe_info=None)
    features = extract_features(result)
    assert features[FEATURE_NAMES.index("is_pe")] == 0.0
    assert features[FEATURE_NAMES.index("is_packed")] == 0.0
    assert features[FEATURE_NAMES.index("num_sections")] == 0.0
