from __future__ import annotations
import hashlib
from pathlib import Path

from .models import HashResult

try:
    import ssdeep
    SSDEEP_AVAILABLE = True
except ImportError:
    SSDEEP_AVAILABLE = False

try:
    import tlsh  # python-tlsh package
    TLSH_AVAILABLE = True
except ImportError:
    TLSH_AVAILABLE = False


def compute_hashes(file_path: str | Path) -> HashResult:
    path = Path(file_path)
    data = path.read_bytes()

    md5 = hashlib.md5(data).hexdigest()
    sha1 = hashlib.sha1(data).hexdigest()
    sha256 = hashlib.sha256(data).hexdigest()

    fuzzy = ssdeep.hash(data) if SSDEEP_AVAILABLE else None
    tlsh_hash = tlsh.hash(data) if TLSH_AVAILABLE and len(data) >= 50 else None

    return HashResult(
        md5=md5,
        sha1=sha1,
        sha256=sha256,
        ssdeep=fuzzy,
        tlsh=tlsh_hash,
    )
