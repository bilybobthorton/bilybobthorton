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

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("trainer")

# ── Paths ─────────────────────────────────────────────────────────────────────

SCRIPT_DIR  = Path(__file__).parent
REPO_ROOT   = SCRIPT_DIR.parent
SAMPLES_DIR = SCRIPT_DIR / "samples"
MALWARE_DIR = SAMPLES_DIR / "malware"
BENIGN_DIR  = SAMPLES_DIR / "benign"
DEFAULT_OUT = REPO_ROOT / "engine" / "ml" / "sentinel_rf.pkl"

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

def _mb_post(data: dict, timeout: int = 30) -> dict:
    import requests
    r = requests.post(MB_API, data=data, timeout=timeout)
    r.raise_for_status()
    return r.json()


def _get_hashes_for_tag(tag: str, limit: int = 1000) -> list[str]:
    try:
        res = _mb_post({"query": "get_taginfo", "tag": tag, "limit": str(limit)})
        if res.get("query_status") not in ("ok", "tag_info"):
            return []
        return [
            s["sha256_hash"]
            for s in res.get("data", [])
            if (s.get("file_type") or "").lower() in PE_TYPES
            and s.get("sha256_hash")
        ]
    except Exception as e:
        log.warning("Tag '%s' query failed: %s", tag, e)
        return []


def _download_one(sha256: str, dest_dir: Path) -> bool:
    """Download + extract one sample. Returns True on success."""
    import requests
    dest = dest_dir / sha256[:24]
    if dest.exists() and dest.stat().st_size > 0:
        return True
    try:
        r = requests.post(
            MB_API,
            data={"query": "get_file", "sha256_hash": sha256},
            timeout=60,
            stream=True,
        )
        if r.status_code != 200:
            return False
        if "json" in r.headers.get("content-type", ""):
            return False
        raw = r.content
        with zipfile.ZipFile(io.BytesIO(raw)) as zf:
            for name in zf.namelist():
                data = zf.read(name, pwd=ZIP_PASS)
                dest.write_bytes(data)
                return True
    except Exception:
        pass
    return False


def download_malware(per_family: int, threads: int) -> Path:
    MALWARE_DIR.mkdir(parents=True, exist_ok=True)
    existing = {f.name for f in MALWARE_DIR.iterdir()}
    log.info("Already have %d malware samples locally.", len(existing))

    # Collect hashes across all families
    all_hashes: set[str] = set()
    for tag in MALWARE_TAGS:
        hashes = _get_hashes_for_tag(tag, per_family)
        log.info("  %-15s → %d PE samples", tag, len(hashes))
        all_hashes.update(hashes)
        time.sleep(0.5)  # gentle on the API

    # Remove already-downloaded
    todo = [h for h in all_hashes if h[:24] not in existing]
    log.info("Need to download %d new samples (%d unique total).", len(todo), len(all_hashes))

    if not todo:
        return MALWARE_DIR

    ok = errors = 0

    def _dl(sha256: str):
        # Stagger slightly to avoid hammering the API
        time.sleep(0.1)
        return _download_one(sha256, MALWARE_DIR)

    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = {pool.submit(_dl, h): h for h in todo}
        for i, fut in enumerate(as_completed(futures), 1):
            if fut.result():
                ok += 1
            else:
                errors += 1
            if i % 200 == 0:
                log.info("  %d / %d  (ok=%d err=%d)", i, len(todo), ok, errors)

    log.info("Download complete: %d downloaded, %d errors. Total: %d",
             ok, errors, len(list(MALWARE_DIR.iterdir())))
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

def run_training(malware_dir: Path, benign_dir: Path, output: Path, estimators: int):
    try:
        from engine.ml.trainer import train
    except ImportError:
        log.error(
            "Cannot import engine.ml.trainer.\n"
            "Run from sentinelcore/ directory:\n"
            "  cd sentinelcore && python scripts/train_real_model.py"
        )
        sys.exit(1)

    m_count = len(list(malware_dir.iterdir()))
    b_count = len(list(benign_dir.iterdir()))
    log.info("Training on %d malware + %d benign = %d total samples", m_count, b_count, m_count + b_count)

    return train(
        malware_dir=malware_dir,
        benign_dir=benign_dir,
        output=output,
        n_estimators=estimators,
        max_files=20000,
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
    ap.add_argument("--threads",       type=int, default=20,
                    help="Parallel download workers (default: 20)")
    ap.add_argument("--estimators",    type=int, default=300,
                    help="RandomForest trees (default: 300)")
    ap.add_argument("--skip-download", action="store_true",
                    help="Use existing scripts/samples/ directory")
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

    if not args.skip_download:
        download_malware(per_family=args.malware_count, threads=args.threads)
        collect_benign(target=args.benign_count)
    else:
        log.info("Skipping download — using existing samples in %s", SAMPLES_DIR)

    model = run_training(MALWARE_DIR, BENIGN_DIR, args.output, args.estimators)

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
