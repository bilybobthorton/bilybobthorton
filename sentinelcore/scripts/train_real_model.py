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


# ── Module-level subprocess worker (must be picklable on Windows) ─────────────

def _subprocess_worker(fp_str: str, conn, repo_root: str):
    """
    Runs in a child process. Sends feature vector (or None) through a Pipe.
    Module-level so it survives Windows multiprocessing 'spawn' pickling.
    repo_root is passed explicitly because sys.path is not inherited on Windows spawn.
    """
    try:
        import sys as _sys
        if repo_root not in _sys.path:
            _sys.path.insert(0, repo_root)
        from pathlib import Path as _P
        from engine.ml.features import extract_features
        from engine.static.analyzer import analyze_file
        conn.send(extract_features(analyze_file(_P(fp_str))))
    except Exception:
        conn.send(None)
    finally:
        conn.close()

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

MB_BULK_CSV    = "https://bazaar.abuse.ch/export/csv/full/"
MB_DAILY_FEED  = "https://datalake.abuse.ch/malware-bazaar/daily/"
MB_HOURLY_FEED = "https://datalake.abuse.ch/malware-bazaar/hourly/"


def _mb_post(data: dict, timeout: int = 30) -> dict:
    import requests
    r = requests.post(MB_API, data=data, timeout=timeout)
    r.raise_for_status()
    return r.json()


def _extract_pe_from_zip_bytes(raw: bytes, dest_dir: Path, seen: set, prefix: str = "") -> int:
    """
    Extract PE files from a ZIP blob (password 'infected').
    Returns count of new PE files written to dest_dir.
    """
    count = 0
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as zf:
            for name in zf.namelist():
                safe = Path(name).name
                if not safe:
                    continue
                unique = f"{prefix}__{safe}" if prefix else safe
                if unique in seen:
                    continue
                try:
                    data = zf.read(name, pwd=ZIP_PASS)
                except Exception:
                    try:
                        data = zf.read(name)
                    except Exception:
                        continue
                if len(data) < 512 or data[:2] != b"MZ":
                    continue
                dest = dest_dir / unique
                dest.write_bytes(data)
                seen.add(unique)
                count += 1
    except Exception:
        pass
    return count


def _download_mb_daily_feeds(days_back: int = 30, parallel: int = 8) -> int:
    """
    Download MalwareBazaar daily batch ZIPs in parallel — NO auth, NO rate limit.
    Each daily ZIP contains every sample submitted that day, password 'infected'.
    Returns total new PE files written to MALWARE_DIR.
    """
    import requests
    import threading
    from datetime import date, timedelta

    MALWARE_DIR.mkdir(parents=True, exist_ok=True)
    seen: set[str] = {f.name for f in MALWARE_DIR.iterdir()}
    seen_lock = threading.Lock()
    total_new = 0
    total_lock = threading.Lock()

    log.info(
        "Downloading MalwareBazaar daily feeds (last %d days, %d parallel, no auth)...",
        days_back, parallel,
    )
    today = date.today()
    days = [today - timedelta(days=d) for d in range(1, days_back + 1)]

    def _fetch_day(day) -> int:
        day_str = day.strftime("%Y-%m-%d")
        url = f"{MB_DAILY_FEED}{day_str}.zip"
        try:
            r = requests.get(url, timeout=300, stream=True)
            if r.status_code == 404:
                log.debug("  %s — 404 (not published yet)", day_str)
                return 0
            r.raise_for_status()
            # Stream with progress so it's not silent
            chunks = []
            downloaded = 0
            for chunk in r.iter_content(chunk_size=1024 * 256):  # 256 KB chunks
                chunks.append(chunk)
                downloaded += len(chunk)
                if downloaded % (1024 * 1024 * 10) < 1024 * 256:  # log every ~10 MB
                    log.info("  %s downloading... %.1f MB", day_str, downloaded / 1024 / 1024)
            raw = b"".join(chunks)
            log.info("  %s download done (%.1f MB) — extracting...", day_str, len(raw) / 1024 / 1024)
            with seen_lock:
                new = _extract_pe_from_zip_bytes(raw, MALWARE_DIR, seen, prefix=day_str)
            log.info("  %s → %d PE samples", day_str, new)
            return new
        except Exception as e:
            log.warning("  Daily feed %s failed: %s", day_str, e)
            return 0

    with ThreadPoolExecutor(max_workers=parallel) as pool:
        futures = {pool.submit(_fetch_day, d): d for d in days}
        done = 0
        for fut in as_completed(futures):
            n = fut.result()
            with total_lock:
                total_new += n
            done += 1
            log.info("  Progress: %d / %d days done — %d PE samples total", done, len(days), total_new)

    return total_new


def _download_mb_hourly_feeds(hours_back: int = 24, parallel: int = 6) -> int:
    """
    Download MalwareBazaar hourly batch ZIPs in parallel — NO auth required.
    Fills in same-day samples before the daily ZIP is published.
    """
    import requests
    import threading
    from datetime import datetime, timedelta, timezone

    MALWARE_DIR.mkdir(parents=True, exist_ok=True)
    seen: set[str] = {f.name for f in MALWARE_DIR.iterdir()}
    seen_lock = threading.Lock()
    total_new = 0

    log.info("Downloading MalwareBazaar hourly feeds (last %d hours, %d parallel)...", hours_back, parallel)
    now = datetime.now(timezone.utc)
    hours = [now - timedelta(hours=h) for h in range(1, hours_back + 1)]

    def _fetch_hour(ts) -> int:
        for fmt in [
            ts.strftime("%Y-%m-%d_%H-00-00.zip"),
            ts.strftime("%Y-%m-%dT%H:00:00.zip"),
            ts.strftime("%Y%m%d%H.zip"),
        ]:
            url = f"{MB_HOURLY_FEED}{fmt}"
            try:
                r = requests.get(url, timeout=120)
                if r.status_code == 404:
                    continue
                r.raise_for_status()
                prefix = ts.strftime("h%Y%m%d%H")
                with seen_lock:
                    new = _extract_pe_from_zip_bytes(r.content, MALWARE_DIR, seen, prefix=prefix)
                if new:
                    log.info("  Hourly %s → %d PE samples", fmt, new)
                return new
            except Exception:
                continue
        return 0

    with ThreadPoolExecutor(max_workers=parallel) as pool:
        total_new = sum(fut.result() for fut in as_completed(
            pool.submit(_fetch_hour, ts) for ts in hours
        ))

    return total_new


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
                names = zf.namelist()
                working_pwd: bytes | None = None

                # Find the password that opens this ZIP
                for pwd in passwords:
                    try:
                        zf.read(names[0], pwd=pwd)
                        working_pwd = pwd
                        break
                    except Exception:
                        continue

                if working_pwd is None:
                    continue  # can't open this ZIP

                # Extract ALL PE files from the ZIP (collections have many)
                for name in names:
                    if collected >= target:
                        break
                    safe_name = Path(name).name
                    if not safe_name:
                        continue
                    # Deduplicate: prefix with zip stem to avoid collisions across ZIPs
                    unique_name = f"{zip_path.stem}__{safe_name}"
                    if unique_name in seen:
                        continue
                    try:
                        data = zf.read(name, pwd=working_pwd)
                    except Exception:
                        continue
                    if len(data) < 512:
                        continue
                    if data[:2] != b"MZ":
                        continue  # skip non-PE (Android APK, BAT, DOS COM, etc.)
                    dest = MALWARE_DIR / unique_name
                    dest.write_bytes(data)
                    seen.add(unique_name)
                    collected += 1
                    if collected % 50 == 0:
                        log.info("  Extracted %d PE malware samples so far...", collected)
        except Exception:
            continue

    log.info("theZoo extraction complete: %d PE malware samples in %s", collected, MALWARE_DIR)
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


def download_malware(
    per_family: int,
    threads: int,
    api_key: str = "",
    malshare_key: str = "",
    days_back: int = 30,
) -> Path:
    """
    Download malware samples using multiple sources in priority order:
      1. MalwareBazaar daily batch ZIPs — NO auth, NO rate limit (primary)
      2. MalwareBazaar hourly feeds    — NO auth (fills in current day)
      3. Malshare per-file API         — API key, 2000/day limit
    """
    import requests as _req

    MALWARE_DIR.mkdir(parents=True, exist_ok=True)
    before = len(list(MALWARE_DIR.iterdir()))
    log.info("Starting download. Already have %d malware samples.", before)

    # ── 1. MalwareBazaar daily feeds (no auth, highest yield) ────────────────
    daily_new = _download_mb_daily_feeds(days_back=days_back)
    log.info("Daily feeds: +%d new PE samples", daily_new)

    # ── 2. MalwareBazaar hourly feeds (no auth, fills current day) ───────────
    hourly_new = _download_mb_hourly_feeds(hours_back=24)
    log.info("Hourly feeds: +%d new PE samples", hourly_new)

    # ── 3. Malshare per-file API (rate-limited, good for fresh samples) ───────
    if malshare_key:
        ms_hashes = _get_hashes_malshare(malshare_key, target=2000)
        if ms_hashes:
            already = {f.name for f in MALWARE_DIR.iterdir()}
            todo_ms = [h for h in ms_hashes if h[:24] not in already][:2000]
            log.info("Malshare: %d hashes to download", len(todo_ms))
            ms_ok = ms_err = 0

            def _dl_malshare(sha256: str) -> bool:
                time.sleep(0.05)
                dest = MALWARE_DIR / sha256[:24]
                if dest.exists() and dest.stat().st_size > 0:
                    return True
                try:
                    r = _req.get(
                        MALSHARE_API,
                        params={"api_key": malshare_key, "action": "getfile", "hash": sha256},
                        timeout=60,
                    )
                    ct = r.headers.get("content-type", "")
                    if r.status_code == 200 and "text" not in ct and "json" not in ct and "html" not in ct:
                        raw = r.content
                        if len(raw) > 512:
                            if raw[:2] == b"MZ":
                                dest.write_bytes(raw)
                                return True
                            # might be ZIP
                            seen: set = set()
                            if _extract_pe_from_zip_bytes(raw, MALWARE_DIR, seen, prefix=sha256[:8]):
                                return True
                except Exception:
                    pass
                return False

            with ThreadPoolExecutor(max_workers=min(threads, 20)) as pool:
                futs = {pool.submit(_dl_malshare, h): h for h in todo_ms}
                for i, fut in enumerate(as_completed(futs), 1):
                    if fut.result():
                        ms_ok += 1
                    else:
                        ms_err += 1
                    if i % 200 == 0:
                        log.info("  Malshare: %d / %d  (ok=%d err=%d)", i, len(todo_ms), ms_ok, ms_err)
            log.info("Malshare download: %d ok, %d errors", ms_ok, ms_err)

    after = len(list(MALWARE_DIR.iterdir()))
    log.info("Download complete. Total on disk: %d (+%d from this run)", after, after - before)
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

BENIGN_CACHE  = SAMPLES_DIR / "benign_features.npz"   # benign-only cache (slow to re-extract)
MALWARE_CACHE = SAMPLES_DIR / "malware_features.npz"  # malware-only cache (fast, re-extract when stale)


def run_training(
    malware_dir: Path,
    benign_dir: Path,
    output: Path,
    estimators: int,
    use_gpu: bool = True,
    skip_features: bool = False,
):
    """
    Smart feature caching: benign features are expensive (6k+ Windows system files).
    Malware features are always re-extracted so new downloads are picked up.
    --skip-features loads benign from cache + re-extracts malware (best of both).
    """
    import numpy as np

    try:
        from engine.ml.trainer import train
        from engine.ml.features import extract_features
        from engine.static.analyzer import analyze_file
    except ImportError:
        log.error(
            "Cannot import engine modules.\n"
            "Run from sentinelcore/ directory:\n"
            "  cd sentinelcore && python scripts/train_real_model.py"
        )
        sys.exit(1)

    if skip_features:
        # Load benign from cache (saves ~20 min), re-extract malware (picks up new samples)
        if not BENIGN_CACHE.exists() and not FEATURES_CACHE.exists():
            log.error(
                "--skip-features: no benign cache found.\n"
                "Run without --skip-features once to build it."
            )
            sys.exit(1)

        # Load benign features
        if BENIGN_CACHE.exists():
            bd = np.load(BENIGN_CACHE)
            Xb = list(bd["Xb"])
            yb = list(bd["yb"].astype(int))
            log.info("Loaded %d benign features from cache.", len(Xb))
        else:
            # Fall back to old combined cache
            fd = np.load(FEATURES_CACHE)
            Xb = list(fd["Xb"])
            yb = list(fd["yb"].astype(int))
            log.info("Loaded %d benign features from combined cache.", len(Xb))

        # Always re-extract malware so new downloads are included
        # Skip files > 50 MB — oversized samples stall the PE parser and aren't useful
        MAX_SIZE = 50 * 1024 * 1024
        m_files = [
            f for f in malware_dir.rglob("*")
            if f.is_file() and f.stat().st_size <= MAX_SIZE
        ]
        skipped_large = sum(
            1 for f in malware_dir.rglob("*")
            if f.is_file() and f.stat().st_size > MAX_SIZE
        )
        log.info(
            "Extracting features from %d malware files (skipping %d oversized, benign from cache)...",
            len(m_files), skipped_large,
        )

        import multiprocessing as _mp
        import threading as _threading
        import os as _os

        # Use subprocesses so hung analyses can be hard-killed (threads can't be killed)
        TIMEOUT_S = 30
        workers = min(16, _os.cpu_count() or 4)
        Xm, ym = [], []
        total = len(m_files)

        _repo_root_str = str(_repo_root)

        def _feat_safe(fp: Path):
            """Analyze one file in a child process; terminate it if it hangs."""
            parent, child = _mp.Pipe(duplex=False)
            p = _mp.Process(target=_subprocess_worker, args=(str(fp), child, _repo_root_str))
            p.start()
            child.close()
            result = None
            if parent.poll(TIMEOUT_S):
                try:
                    result = parent.recv()
                except Exception:
                    pass
            p.terminate()
            p.join(timeout=3)
            if p.is_alive():
                p.kill()
                p.join()
            parent.close()
            return result

        # Live single-line progress bar driven by a background thread
        _done = [0]; _ok = [0]; _skip = [0]
        _lock = _threading.Lock()
        _stop = _threading.Event()

        def _show():
            while not _stop.wait(1.5):
                with _lock:
                    d, o, s = _done[0], _ok[0], _skip[0]
                filled = int(d / total * 35) if total else 0
                bar = "#" * filled + "-" * (35 - filled)
                print(f"\r  [{bar}] {d}/{total}  ok={o}  skip={s}  ", end="", flush=True)

        _pt = _threading.Thread(target=_show, daemon=True)
        _pt.start()

        # ThreadPoolExecutor runs _feat_safe concurrently; each call blocks for at
        # most TIMEOUT_S seconds before the subprocess is killed and None is returned.
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futs = {pool.submit(_feat_safe, f): f for f in m_files}
            for fut in as_completed(futs):
                r = fut.result()
                with _lock:
                    _done[0] += 1
                    if r is not None:
                        _ok[0] += 1
                    else:
                        _skip[0] += 1
                if r is not None:
                    Xm.append(r)
                    ym.append(1)

        _stop.set()
        print(f"\r  [{'#'*35}] {total}/{total}  ok={_ok[0]}  skip={_skip[0]}  ")
        log.info("Malware feature extraction complete: %d / %d.", _ok[0], total)

        # Save updated malware cache + combined cache
        SAMPLES_DIR.mkdir(parents=True, exist_ok=True)
        np.savez_compressed(MALWARE_CACHE, Xm=np.array(Xm, dtype=float), ym=np.array(ym, dtype=int))
        np.savez_compressed(
            FEATURES_CACHE,
            Xm=np.array(Xm, dtype=float), ym=np.array(ym, dtype=int),
            Xb=np.array(Xb, dtype=float), yb=np.array(yb, dtype=int),
        )

        return train(
            malware_dir=malware_dir,
            benign_dir=benign_dir,
            output=output,
            n_estimators=estimators,
            max_files=20000,
            use_gpu=use_gpu,
            feature_cache=FEATURES_CACHE,  # freshly written above
        )
    else:
        # Full re-extraction of both classes; save split caches afterward
        m_count = len(list(malware_dir.iterdir()))
        b_count = len(list(benign_dir.iterdir()))
        log.info("Full feature extraction: %d malware + %d benign files", m_count, b_count)

        result = train(
            malware_dir=malware_dir,
            benign_dir=benign_dir,
            output=output,
            n_estimators=estimators,
            max_files=20000,
            use_gpu=use_gpu,
            feature_cache=FEATURES_CACHE,
        )

        # Also save separate benign cache for future --skip-features runs
        if FEATURES_CACHE.exists():
            fd = np.load(FEATURES_CACHE)
            np.savez_compressed(BENIGN_CACHE, Xb=fd["Xb"], yb=fd["yb"])
            log.info("Benign cache saved → %s", BENIGN_CACHE)

        return result


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
    ap.add_argument("--days-back",     type=int, default=30,
                    help="How many days of MalwareBazaar daily feeds to pull (default: 30, no auth needed)")
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
            days_back=args.days_back,
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
    # Required on Windows: prevents spawned child processes from re-running main()
    import multiprocessing
    multiprocessing.freeze_support()
    main()
