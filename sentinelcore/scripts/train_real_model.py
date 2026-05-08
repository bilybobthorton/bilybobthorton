#!/usr/bin/env python3
"""
RedGuard Real ML Model Trainer
================================
Downloads real malware samples from MalwareBazaar (multiple families) +
collects benign samples from the local system, then trains a RandomForest
classifier with 10,000+ samples.

Run from the sentinelcore/ directory:
    pip install requests scikit-learn pefile yara-python lief numpy
    python scripts/train_real_model.py

Options:
    --malware-count   Malware samples to download per family (default: 1000)
    --benign-count    Benign samples to collect (default: 8000)
    --threads         Parallel download workers (default: 20)
    --skip-download   Skip download, use existing scripts/samples/ directory
    --output          .pkl path (default: engine/ml/sentinel_rf.pkl)
    --upload          SCP model to server + hot-reload API after training
"""
from __future__ import annotations

import argparse
import io
import logging
import os
import shutil
import sys
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

# ── PYTHONPATH fix — must run before any engine imports ──────────────────────
_repo_root = Path(__file__).parent.parent
if str(_repo_root) not in sys.path:
    sys.path.insert(0, str(_repo_root))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("trainer")

# ── Paths ─────────────────────────────────────────────────────────────────────

SCRIPT_DIR    = Path(__file__).parent
REPO_ROOT     = SCRIPT_DIR.parent
SAMPLES_DIR   = SCRIPT_DIR / "samples"
MALWARE_DIR   = SAMPLES_DIR / "malware"
BENIGN_DIR    = SAMPLES_DIR / "benign"
FEATURES_CACHE = SAMPLES_DIR / "features_cache.npz"
DEFAULT_OUT   = REPO_ROOT / "engine" / "ml" / "sentinel_rf.pkl"

MB_API      = "https://mb-api.abuse.ch/api/v1/"
ZIP_PASS    = b"infected"

# Malware families to pull — diversity improves model generalisation
MALWARE_TAGS = [
    "ransomware",
    "trojan",
    "stealer",
    "loader",
    "backdoor",
    "botnet",
    "rootkit",
    "exploit",
    "dropper",
    "miner",
    "worm",
    "keylogger",
    "rat",
    "banker",
    "adware",
]

PE_TYPES = {"exe", "dll", "sys", "drv"}

# ── MalwareBazaar helpers ─────────────────────────────────────────────────────

MB_BULK_CSV = "https://bazaar.abuse.ch/export/csv/full/"


def _mb_post(data: dict, timeout: int = 30) -> dict:
    import requests
    r = requests.post(MB_API, data=data, timeout=timeout)
    r.raise_for_status()
    return r.json()


def _get_hashes_recent(limit: int = 1000) -> list[str]:
    """Recent PE hashes — no API key required."""
    try:
        res = _mb_post({"query": "get_recent", "selector": str(min(limit, 1000))})
        if res.get("query_status") != "ok":
            return []
        return [
            s["sha256_hash"]
            for s in res.get("data", [])
            if (s.get("file_type") or "").lower() in PE_TYPES and s.get("sha256_hash")
        ]
    except Exception as e:
        log.warning("get_recent failed: %s", e)
        return []


def _get_hashes_bulk_csv(target: int = 15000) -> list[str]:
    """
    Download the full MalwareBazaar CSV export and extract PE SHA256 hashes.
    No API key required. ~50 MB download, thousands of diverse samples.

    MalwareBazaar CSV has NO header row — column names live in #-prefixed comment
    lines that we must skip. Positional layout (0-indexed):
      0=first_seen  1=sha256_hash  2=md5  3=sha1  4=reporter
      5=file_name   6=file_type_guess  7=mime_type  ...
    """
    import csv
    import requests
    log.info("Downloading MalwareBazaar full CSV export (~50 MB)...")
    try:
        r = requests.get(MB_BULK_CSV, timeout=180, stream=True)
        r.raise_for_status()
        raw = r.content
        with zipfile.ZipFile(io.BytesIO(raw)) as zf:
            csv_name = next((n for n in zf.namelist() if n.endswith(".csv")), None)
            if not csv_name:
                log.warning("No CSV found in bulk export ZIP")
                return []
            csv_text = zf.read(csv_name).decode("utf-8", errors="replace")

        # Column indices in the headerless CSV
        SHA256_COL = 1
        FTYPE_COL  = 6

        hashes: list[str] = []
        for line in csv_text.splitlines():
            if not line or line.startswith("#"):
                continue
            try:
                row = next(csv.reader([line]))
                if len(row) <= max(SHA256_COL, FTYPE_COL):
                    continue
                sha = row[SHA256_COL].strip().strip('"')
                ft  = row[FTYPE_COL].strip().strip('"').lower()
                if sha and ft in PE_TYPES:
                    hashes.append(sha)
                if len(hashes) >= target:
                    break
            except Exception:
                continue

        log.info("Bulk CSV: %d PE hashes found.", len(hashes))
        return hashes
    except Exception as e:
        log.warning("Bulk CSV download failed: %s", e)
        return []


# ── Malshare helpers ──────────────────────────────────────────────────────────

MALSHARE_API = "https://malshare.com/api.php"


def _get_hashes_malshare(api_key: str, target: int = 10000) -> list[str]:
    """Fetch recent hashes from Malshare (returns MD5 or SHA256 depending on action)."""
    import requests
    log.info("Fetching hash list from Malshare...")
    hashes: list[str] = []
    try:
        r = requests.get(
            MALSHARE_API,
            params={"api_key": api_key, "action": "getlist"},
            timeout=60,
        )
        r.raise_for_status()
        text = r.text.strip()
        if not text or "error" in text[:80].lower():
            log.error("Malshare error response: %s", text[:300])
            return []
        # Response is JSON: [{"md5":"...","sha1":"...","sha256":"..."}, ...]
        try:
            import json as _json
            data = _json.loads(text)
            hashes = [item["sha256"] for item in data if item.get("sha256")]
        except Exception:
            # Fallback: plain text, one hash per line
            hashes = [
                h.strip() for h in text.splitlines()
                if len(h.strip()) in (32, 64) and all(c in "0123456789abcdefABCDEF" for c in h.strip())
            ]
        log.info("Malshare: %d hashes in today's list", len(hashes))
    except Exception as e:
        log.warning("Malshare hash list failed: %s", e)
    return hashes[:target]


# ── theZoo offline source ─────────────────────────────────────────────────────

def collect_from_theZoo(theZoo_path: Path, target: int) -> int:
    """
    Extract PE malware samples from a locally-cloned theZoo repo.
    Clone it first:  git clone https://github.com/ytisf/theZoo
    Provides ~600 real labelled malware binaries with no API key required.
    """
    MALWARE_DIR.mkdir(parents=True, exist_ok=True)
    seen: set[str] = {f.name for f in MALWARE_DIR.iterdir()}
    collected = len(seen)
    if collected >= target:
        log.info("Already have %d malware samples — skipping theZoo extraction.", collected)
        return collected

    passwords = [b"infected", b"infected!", b"malware", b"virus", b"password", b"theZoo"]
    log.info("Extracting malware from theZoo at %s ...", theZoo_path)

    for zip_path in sorted(theZoo_path.rglob("*.zip")):
        if collected >= target:
            break
        try:
            with zipfile.ZipFile(zip_path) as zf:
                extracted = False
                for pwd in passwords:
                    if extracted:
                        break
                    for name in zf.namelist():
                        safe_name = Path(name).name  # strip any path component
                        if not safe_name or safe_name in seen:
                            continue
                        try:
                            data = zf.read(name, pwd=pwd)
                        except Exception:
                            continue
                        if len(data) < 512:
                            continue
                        # Accept PE (MZ header) or any binary that's not text
                        if data[:2] == b"MZ":
                            dest = MALWARE_DIR / safe_name
                            dest.write_bytes(data)
                            seen.add(safe_name)
                            collected += 1
                            extracted = True
                            if collected % 100 == 0:
                                log.info("  Extracted %d malware samples so far...", collected)
                            break  # one file per ZIP is fine
        except Exception:
            continue

    log.info("theZoo extraction complete: %d malware samples in %s", collected, MALWARE_DIR)
    return collected


def _download_one_malshare(sha256: str, api_key: str, dest_dir: Path) -> bool:
    """Download one sample from Malshare directly (no ZIP, no password). Returns True on success."""
    import requests
    dest = dest_dir / sha256[:24]
    if dest.exists() and dest.stat().st_size > 0:
        return True
    try:
        r = requests.get(
            MALSHARE_API,
            params={"api_key": api_key, "action": "getfile", "hash": sha256},
            timeout=60,
            stream=True,
        )
        if r.status_code != 200:
            return False
        ct = r.headers.get("content-type", "")
        if "text" in ct or "json" in ct or "html" in ct:
            return False
        raw = r.content
        if len(raw) < 512:
            return False
        dest.write_bytes(raw)
        return True
    except Exception:
        pass
    return False


def download_malware(per_family: int, threads: int, api_key: str = "", malshare_key: str = "") -> Path:
    MALWARE_DIR.mkdir(parents=True, exist_ok=True)
    existing = {f.name for f in MALWARE_DIR.iterdir()}
    log.info("Already have %d malware samples locally.", len(existing))

    if not api_key and not malshare_key:
        log.error(
            "\n"
            "  No download API key provided. You need one of:\n"
            "\n"
            "  Option A — Malshare (recommended, easiest):\n"
            "    1. Sign up free at malshare.com/register.php\n"
            "    2. Re-run: python scripts/train_real_model.py --malshare-key YOUR_KEY\n"
            "\n"
            "  Option B — MalwareBazaar:\n"
            "    1. Sign up free at bazaar.abuse.ch/signup/\n"
            "    2. Re-run: python scripts/train_real_model.py --mb-api-key YOUR_KEY\n"
        )
        sys.exit(1)

    if malshare_key:
        # Malshare path — simpler auth, raw binary download (no ZIP)
        # Malshare's own hashes: guaranteed downloadable from Malshare
        # MB CSV hashes: tried against MB auth methods only (not Malshare cross-ref)
        MALSHARE_DAILY_LIMIT = 2000
        ms_hashes = _get_hashes_malshare(malshare_key, target=MALSHARE_DAILY_LIMIT)
        mb_hashes = _get_hashes_bulk_csv(target=MALSHARE_DAILY_LIMIT * 5) if api_key else []
        # Malshare hashes first (high success rate), then MB hashes (tried via MB auth)
        combined = list(dict.fromkeys(ms_hashes + mb_hashes))
        log.info("Hash pool: %d (Malshare=%d, MB CSV=%d)", len(combined), len(ms_hashes), len(mb_hashes))

        already_have = {f.name for f in MALWARE_DIR.iterdir()}
        # Cap: Malshare daily limit applies only to Malshare downloads; MB downloads are separate
        ms_todo = [h for h in ms_hashes if h[:24] not in already_have][:MALSHARE_DAILY_LIMIT]
        mb_todo = [h for h in mb_hashes if h[:24] not in already_have and h not in ms_hashes]
        todo = ms_todo + mb_todo
        log.info("To download: %d Malshare + %d MB CSV = %d total", len(ms_todo), len(mb_todo), len(todo))

    else:
        # MB-only path: get hash list from CSV
        all_hashes: set[str] = set(_get_hashes_bulk_csv(target=per_family * len(MALWARE_TAGS)))
        if len(all_hashes) < 500:
            all_hashes.update(_get_hashes_recent(1000))
        already_have = {f.name for f in MALWARE_DIR.iterdir()}
        todo = [h for h in all_hashes if h[:24] not in already_have]
        log.info("Hashes to download: %d (via MalwareBazaar)", len(todo))

    if not todo:
        log.info("Nothing to download.")
        return MALWARE_DIR

    ok = errors = 0

    _MB_HEADERS = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0",
        "Accept": "application/zip, application/octet-stream, */*",
        "Referer": "https://bazaar.abuse.ch/",
    }

    def _dl(sha256: str) -> bool:
        """Try Malshare first, then MalwareBazaar (both endpoints). First win saves the file."""
        time.sleep(0.05)
        dest = MALWARE_DIR / sha256[:24]
        if dest.exists() and dest.stat().st_size > 0:
            return True
        import requests

        def _save(raw: bytes) -> bool:
            try:
                with zipfile.ZipFile(io.BytesIO(raw)) as zf:
                    for name in zf.namelist():
                        dest.write_bytes(zf.read(name, pwd=ZIP_PASS))
                        return True
            except Exception:
                pass
            if len(raw) > 512 and raw[:2] == b"MZ":
                dest.write_bytes(raw)
                return True
            return False

        # 1. Malshare (raw binary, no password)
        if malshare_key:
            try:
                r = requests.get(MALSHARE_API,
                                 params={"api_key": malshare_key, "action": "getfile", "hash": sha256},
                                 timeout=60)
                ct = r.headers.get("content-type", "")
                if r.status_code == 200 and "text" not in ct and "json" not in ct and "html" not in ct:
                    if len(r.content) > 512:
                        dest.write_bytes(r.content)
                        return True
            except Exception:
                pass

        # 2–5. MalwareBazaar — try every plausible auth method
        if api_key:
            mb_attempts = [
                # (method, url, extra_headers, post_data)
                ("POST", MB_API, {},
                 {"query": "get_file", "sha256_hash": sha256, "api_key": api_key}),
                ("POST", MB_API, {"Auth-Key": api_key},
                 {"query": "get_file", "sha256_hash": sha256}),
                ("POST", MB_API, {"Authorization": f"Token {api_key}"},
                 {"query": "get_file", "sha256_hash": sha256}),
                ("GET",  f"https://bazaar.abuse.ch/sample/{sha256}/",
                 {"Auth-Key": api_key, "Authorization": f"Token {api_key}"}, None),
            ]
            for method, url, extra_hdrs, post_data in mb_attempts:
                try:
                    hdrs = {**_MB_HEADERS, **extra_hdrs}
                    if method == "POST":
                        r = requests.post(url, data=post_data, headers=hdrs, timeout=60)
                    else:
                        r = requests.get(url, headers=hdrs, timeout=60, allow_redirects=True)
                    ct = r.headers.get("content-type", "")
                    if r.status_code == 200 and "html" not in ct:
                        if _save(r.content):
                            return True
                except Exception:
                    pass

        return False

    with ThreadPoolExecutor(max_workers=min(threads, 20)) as pool:
        futures = {pool.submit(_dl, h): h for h in todo}
        for i, fut in enumerate(as_completed(futures), 1):
            if fut.result():
                ok += 1
            else:
                errors += 1
            if i % 200 == 0:
                log.info("  %d / %d  (ok=%d err=%d)", i, len(todo), ok, errors)

    total = len(list(MALWARE_DIR.iterdir()))
    log.info("Download complete: %d ok, %d errors. Total on disk: %d", ok, errors, total)
    return MALWARE_DIR


# ── Benign samples ────────────────────────────────────────────────────────────

def collect_benign(target: int) -> Path:
    BENIGN_DIR.mkdir(parents=True, exist_ok=True)
    existing = len(list(BENIGN_DIR.iterdir()))
    if existing >= target:
        log.info("Already have %d benign samples.", existing)
        return BENIGN_DIR

    if sys.platform == "win32":
        source_dirs = [
            Path("C:/Windows/System32"),
            Path("C:/Windows/SysWOW64"),
            Path("C:/Windows/Microsoft.NET/Framework"),
            Path("C:/Windows/Microsoft.NET/Framework64"),
            Path("C:/Program Files/Windows NT"),
            Path("C:/Program Files/Common Files/Microsoft Shared"),
            Path("C:/Program Files/Internet Explorer"),
            Path("C:/Program Files (x86)/Common Files/Microsoft Shared"),
        ]
    elif sys.platform == "darwin":
        source_dirs = [Path("/usr/bin"), Path("/usr/lib"), Path("/System/Library")]
    else:
        source_dirs = [Path("/usr/bin"), Path("/usr/lib"), Path("/usr/sbin"), Path("/bin")]

    extensions = {".exe", ".dll", ".sys", ".drv"}
    copied = existing
    seen_names: set[str] = {f.name for f in BENIGN_DIR.iterdir()}
    log.info("Collecting benign PE files (target: %d)...", target)

    for src_dir in source_dirs:
        if not src_dir.exists():
            continue
        for fp in src_dir.rglob("*"):
            if copied >= target:
                break
            if not fp.is_file():
                continue
            if fp.suffix.lower() not in extensions:
                continue
            size = fp.stat().st_size
            if size < 1024 or size > 100 * 1024 * 1024:
                continue
            if fp.name in seen_names:
                continue
            try:
                dest = BENIGN_DIR / fp.name
                shutil.copy2(fp, dest)
                seen_names.add(fp.name)
                copied += 1
                if copied % 500 == 0:
                    log.info("  Collected %d benign samples...", copied)
            except Exception:
                pass
        if copied >= target:
            break

    log.info("Benign collection complete: %d samples.", copied)
    if copied < 500:
        log.warning(
            "Only %d benign samples — model may be unbalanced. "
            "Run on Windows with access to System32 for best results.",
            copied,
        )
    return BENIGN_DIR


# ── Training ──────────────────────────────────────────────────────────────────

def run_training(
    malware_dir: Path,
    benign_dir: Path,
    output: Path,
    estimators: int,
    use_gpu: bool = True,
    skip_features: bool = False,
):
    try:
        from engine.ml.trainer import train
    except ImportError:
        log.error(
            "Cannot import engine.ml.trainer.\n"
            "Run from sentinelcore/ directory:\n"
            "  cd sentinelcore && python scripts/train_real_model.py"
        )
        sys.exit(1)

    cache = FEATURES_CACHE if skip_features else FEATURES_CACHE
    # skip_features=True: must load from cache (error if missing)
    if skip_features and not cache.exists():
        log.error(
            "--skip-features specified but no cache found at %s\n"
            "Run without --skip-features first to build the cache.", cache
        )
        sys.exit(1)
    # skip_features=False: always re-extract and update cache
    if not skip_features:
        m_count = len(list(malware_dir.iterdir()))
        b_count = len(list(benign_dir.iterdir()))
        log.info("Extracting features: %d malware + %d benign files", m_count, b_count)

    return train(
        malware_dir=malware_dir,
        benign_dir=benign_dir,
        output=output,
        n_estimators=estimators,
        max_files=20000,
        use_gpu=use_gpu,
        feature_cache=cache,
    )


# ── Upload to server ──────────────────────────────────────────────────────────

def upload_model(pkl_path: Path, server: str, ssh_key: str | None):
    import subprocess, requests as req
    remote = "/opt/sentinelcore/sentinelcore/engine/ml/sentinel_rf.pkl"
    cmd = ["scp"]
    if ssh_key:
        cmd += ["-i", ssh_key]
    cmd += [str(pkl_path), f"root@{server}:{remote}"]
    log.info("Uploading model to %s ...", server)
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        log.error("SCP failed: %s", r.stderr)
        return
    log.info("Upload done. Reloading API...")
    try:
        resp = req.post(
            "https://api.redgaurd.com/api/v1/ml/reload",
            headers={"X-API-Key": os.environ.get("REDGUARD_API_KEY", "")},
            timeout=15,
        )
        log.info("Reload response: %d", resp.status_code)
    except Exception as e:
        log.warning("Could not trigger reload: %s — restart api+worker manually", e)


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description="Train real RedGuard ML model")
    ap.add_argument("--malware-count", type=int, default=1000,
                    help="Samples per malware family (default: 1000, × 15 families = ~15k)")
    ap.add_argument("--benign-count",  type=int, default=8000,
                    help="Benign samples to collect (default: 8000)")
    ap.add_argument("--threads",       type=int, default=50,
                    help="Parallel download workers (default: 50)")
    ap.add_argument("--estimators",    type=int, default=300,
                    help="RandomForest trees (default: 300)")
    ap.add_argument("--theZoo",          type=Path, default=None,
                    help="Path to a locally cloned theZoo repo (github.com/ytisf/theZoo) — no API key needed")
    ap.add_argument("--malshare-key",    default=os.environ.get("MALSHARE_KEY", ""),
                    help="Malshare API key — free at malshare.com/register.php  (or set MALSHARE_KEY env var)")
    ap.add_argument("--mb-api-key",      default=os.environ.get("MB_API_KEY", ""),
                    help="MalwareBazaar API key — free at bazaar.abuse.ch/signup/  (or set MB_API_KEY env var)")
    ap.add_argument("--skip-download",  action="store_true",
                    help="Use existing scripts/samples/ directory")
    ap.add_argument("--skip-features",  action="store_true",
                    help="Load cached feature vectors instead of re-running analyze_file on every sample")
    ap.add_argument("--no-gpu",         action="store_true",
                    help="Force CPU training (default: use CUDA if available)")
    ap.add_argument("--output",        type=Path, default=DEFAULT_OUT)
    ap.add_argument("--upload",        action="store_true",
                    help="SCP model to server after training")
    ap.add_argument("--server",        default="159.65.237.42")
    ap.add_argument("--ssh-key",       default=None)
    args = ap.parse_args()

    # Dependency check
    missing = []
    for pkg, imp in [("requests","requests"),("sklearn","sklearn"),("pefile","pefile"),("numpy","numpy")]:
        try: __import__(imp)
        except ImportError: missing.append(pkg)
    if missing:
        log.error("Missing: %s", ", ".join(missing))
        log.error("Run: pip install requests scikit-learn pefile numpy lief yara-python")
        sys.exit(1)

    # theZoo extraction always runs when --theZoo is set (not gated by --skip-download)
    if args.theZoo:
        collect_from_theZoo(args.theZoo, target=args.malware_count * len(MALWARE_TAGS))

    if not args.skip_download:
        download_malware(
            per_family=args.malware_count,
            threads=args.threads,
            api_key=args.mb_api_key,
            malshare_key=args.malshare_key,
        )
        collect_benign(target=args.benign_count)
    else:
        log.info("Skipping network download — using existing samples in %s", SAMPLES_DIR)

    model = run_training(
        MALWARE_DIR, BENIGN_DIR, args.output, args.estimators,
        use_gpu=not args.no_gpu,
        skip_features=args.skip_features,
    )

    log.info("")
    log.info("=" * 60)
    log.info("  Training complete!  Model: %s", args.output)
    log.info("")
    log.info("  To deploy:")
    log.info("  scp %s root@%s:/opt/sentinelcore/sentinelcore/engine/ml/sentinel_rf.pkl", args.output, args.server)
    log.info("  ssh root@%s 'cd /opt/sentinelcore/sentinelcore && docker compose -f infra/docker-compose.prod.yml restart api worker'", args.server)
    log.info("=" * 60)

    if args.upload:
        upload_model(args.output, args.server, args.ssh_key)


if __name__ == "__main__":
    main()
