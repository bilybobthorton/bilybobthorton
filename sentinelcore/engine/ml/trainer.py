"""
Offline trainer for the RedGuard ML classifier (XGBoost GPU-accelerated or RandomForest).

Run this script against a labeled dataset of malware/benign PE files:

    python -m engine.ml.trainer \\
        --malware  /path/to/malware_dir \\
        --benign   /path/to/benign_dir  \\
        --output   engine/ml/sentinel_rf.pkl

Dataset sources:
  - MalwareBazaar (https://bazaar.abuse.ch/export/) — recent malware
  - VirusShare  (https://virusshare.com/)            — large benign + malware
  - theZoo      (https://github.com/ytisf/theZoo)    — PoC malware
  - Windows system32/ or clean VM snapshot           — benign samples
"""
from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

import numpy as np

from engine.ml.features import FEATURE_NAMES, extract_features
from engine.ml.model import MalwareClassifier, _MODEL_PATH
from engine.static.analyzer import analyze_file

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
logger = logging.getLogger(__name__)


def _build_classifier(n_estimators: int, use_gpu: bool):
    """Return best available classifier: XGBoost/CUDA → XGBoost/CPU → RandomForest."""
    try:
        import xgboost as xgb
        xgb_params = dict(
            n_estimators=n_estimators,
            max_depth=8,
            learning_rate=0.05,
            subsample=0.8,
            colsample_bytree=0.8,
            scale_pos_weight=1,
            eval_metric="logloss",
            random_state=42,
            n_jobs=-1,
        )
        if use_gpu:
            try:
                # XGBoost >= 2.0 API
                clf = xgb.XGBClassifier(device="cuda", **xgb_params)
                # Quick smoke-test to verify CUDA is actually available
                import numpy as _np
                _X = _np.zeros((4, 2), dtype=float)
                _y = _np.array([0, 1, 0, 1])
                clf.fit(_X, _y)
                logger.info("Using XGBoost with CUDA (RTX 4070) ✓")
                return clf
            except Exception as e:
                logger.warning("CUDA init failed (%s) — trying XGBoost CPU", e)
                try:
                    clf = xgb.XGBClassifier(tree_method="hist", **xgb_params)
                    logger.info("Using XGBoost CPU (hist method)")
                    return clf
                except Exception as e2:
                    logger.warning("XGBoost CPU also failed (%s) — falling back to RandomForest", e2)
        else:
            clf = xgb.XGBClassifier(tree_method="hist", **xgb_params)
            logger.info("Using XGBoost CPU (--no-gpu flag)")
            return clf
    except ImportError:
        logger.warning("xgboost not installed — using RandomForest. Run: pip install xgboost")

    from sklearn.ensemble import RandomForestClassifier
    logger.info("Using RandomForest (n_estimators=%d, all CPU cores)", n_estimators)
    return RandomForestClassifier(
        n_estimators=n_estimators,
        max_depth=None,
        min_samples_split=5,
        min_samples_leaf=2,
        class_weight="balanced",
        n_jobs=-1,
        random_state=42,
    )


def _collect_features(directory: Path, label: int, max_files: int = 5000, workers: int = 0):
    from concurrent.futures import ThreadPoolExecutor, as_completed as _as_completed
    import os

    if workers <= 0:
        workers = min(32, (os.cpu_count() or 4))

    files = [f for f in directory.rglob("*") if f.is_file()][:max_files]
    logger.info(
        "Extracting features: %d files from %s (label=%d, workers=%d)",
        len(files), directory, label, workers,
    )

    X, y = [], []
    done = 0

    def _extract(fp: Path):
        try:
            return extract_features(analyze_file(fp))
        except Exception as e:
            logger.debug("Skip %s: %s", fp.name, e)
            return None

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_extract, f): f for f in files}
        for fut in _as_completed(futures):
            done += 1
            feats = fut.result()
            if feats is not None:
                X.append(feats)
                y.append(label)
            if done % 500 == 0:
                logger.info("  %d / %d extracted", done, len(files))

    return X, y


def train(
    malware_dir: Path,
    benign_dir: Path,
    output: Path = _MODEL_PATH,
    n_estimators: int = 200,
    max_files: int = 5000,
    threshold: float = 0.5,
    use_gpu: bool = True,
    workers: int = 0,
    feature_cache: Path | None = None,
) -> MalwareClassifier:
    from sklearn.metrics import classification_report, roc_auc_score
    from sklearn.model_selection import train_test_split

    # Load cached features if available (skips slow per-file extraction)
    if feature_cache and feature_cache.exists():
        logger.info("Loading cached features from %s", feature_cache)
        data = np.load(feature_cache)
        Xm, ym = list(data["Xm"]), list(data["ym"].astype(int))
        Xb, yb = list(data["Xb"]), list(data["yb"].astype(int))
        logger.info("Cache loaded: %d malware, %d benign", len(Xm), len(Xb))
    else:
        Xm, ym = _collect_features(malware_dir, label=1, max_files=max_files, workers=workers)
        Xb, yb = _collect_features(benign_dir,  label=0, max_files=max_files, workers=workers)
        if feature_cache:
            feature_cache.parent.mkdir(parents=True, exist_ok=True)
            np.savez_compressed(
                feature_cache,
                Xm=np.array(Xm, dtype=float), ym=np.array(ym, dtype=int),
                Xb=np.array(Xb, dtype=float), yb=np.array(yb, dtype=int),
            )
            logger.info("Features cached → %s  (use --skip-features to skip extraction next run)", feature_cache)

    if len(Xm) == 0:
        logger.error(
            "0 malware samples were successfully extracted.\n"
            "  → Make sure scripts/samples/malware/ has downloaded files.\n"
            "  → Re-run train_real_model.py without --skip-download."
        )
        sys.exit(1)
    if len(Xb) == 0:
        logger.error("0 benign samples — cannot train without both classes.")
        sys.exit(1)
    if len(Xm) < 10 or len(Xb) < 10:
        logger.error(
            "Too few samples (malware=%d, benign=%d) — need at least 10 per class.",
            len(Xm), len(Xb),
        )
        sys.exit(1)

    X = np.array(Xm + Xb, dtype=float)
    y = np.array(ym + yb, dtype=int)

    logger.info("Dataset: %d malware + %d benign = %d total", len(Xm), len(Xb), len(X))

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    clf = _build_classifier(n_estimators=n_estimators, use_gpu=use_gpu)
    clf_name = type(clf).__name__
    logger.info("Training %s on %d samples...", clf_name, len(X_train))
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    try:
        y_prob = clf.predict_proba(X_test)
        mal_idx = list(clf.classes_).index(1) if hasattr(clf, "classes_") and 1 in clf.classes_ else 1
        y_prob_mal = y_prob[:, mal_idx]
        logger.info("\n%s", classification_report(y_test, y_pred, target_names=["benign", "malicious"]))
        auc = roc_auc_score(y_test, y_prob_mal)
        logger.info("AUC-ROC: %.4f", auc)
    except Exception as e:
        logger.warning("Could not compute probabilities/AUC: %s", e)

    # Feature importance (XGBoost and RandomForest both expose feature_importances_)
    try:
        importances = sorted(
            zip(FEATURE_NAMES, clf.feature_importances_),
            key=lambda x: x[1], reverse=True,
        )
        logger.info("Top 10 features:")
        for name, imp in importances[:10]:
            logger.info("  %-35s %.4f", name, imp)
    except Exception:
        pass

    model = MalwareClassifier(clf=clf, threshold=threshold)
    model.save(output)
    logger.info("Model saved → %s", output)
    return model


def _generate_synthetic_model(output: Path) -> MalwareClassifier:
    """
    Creates a synthetic trained model using rule-based heuristics.
    Not for production — gives the system a working model for dev/testing
    until you train on a real dataset.
    """
    from sklearn.ensemble import RandomForestClassifier
    import random

    rng = random.Random(42)
    n_samples = 2000
    X, y = [], []

    for _ in range(n_samples):
        label = rng.randint(0, 1)
        # Malicious samples have higher entropy, more suspicious imports, YARA hits
        if label == 1:
            row = [
                rng.uniform(50, 5000),   # file_size_kb
                rng.uniform(10, 15),      # file_size_log
                1.0,                      # is_pe
                rng.choice([0.0, 1.0]),   # is_64bit
                rng.choices([0.0, 1.0], weights=[0.3, 0.7])[0],  # is_packed
                rng.choices([0.0, 1.0], weights=[0.5, 0.5])[0],  # has_overlay
                0.0,                      # is_signed
                0.0,                      # is_dotnet
                rng.uniform(3, 12),       # num_sections
                rng.uniform(5.5, 7.8),   # avg_section_entropy
                rng.uniform(6.5, 8.0),   # max_section_entropy
                rng.uniform(1, 5),        # high_entropy_section_count
                rng.choice([0.0, 1.0]),   # has_exec_writable_section
                rng.uniform(3, 15),       # num_import_dlls
                rng.uniform(20, 200),     # num_import_functions
                rng.uniform(2, 12),       # num_suspicious_imports
                1.0,                      # imports_kernel32
                rng.choice([0.0, 1.0]),   # imports_ntdll
                rng.choice([0.0, 1.0]),   # imports_wininet
                rng.choice([0.0, 1.0]),   # imports_crypt
                rng.choice([0.0, 1.0]),   # imports_ws2_32
                rng.uniform(0, 5),        # num_exports
                rng.uniform(0, 4),        # yara_match_count
                rng.uniform(0, 2),        # yara_critical_count
                rng.uniform(0, 2),        # yara_high_count
                rng.uniform(0, 10),       # num_urls
                rng.uniform(0, 5),        # num_ips
                rng.uniform(0, 8),        # num_suspicious_apis
                rng.uniform(0, 5),        # num_registry_keys
                rng.uniform(0, 200),      # overlay_size_kb
                rng.uniform(0, 12),       # overlay_size_log
            ]
        else:
            row = [
                rng.uniform(10, 10000),  # file_size_kb
                rng.uniform(9, 16),      # file_size_log
                rng.choice([0.0, 1.0]),  # is_pe
                rng.choice([0.0, 1.0]),  # is_64bit
                0.0,                     # is_packed
                0.0,                     # has_overlay
                rng.choices([0.0, 1.0], weights=[0.3, 0.7])[0],  # is_signed
                rng.choice([0.0, 1.0]),  # is_dotnet
                rng.uniform(3, 8),       # num_sections
                rng.uniform(2.0, 5.5),  # avg_section_entropy
                rng.uniform(3.0, 6.5),  # max_section_entropy
                rng.uniform(0, 1),       # high_entropy_section_count
                0.0,                     # has_exec_writable_section
                rng.uniform(2, 20),      # num_import_dlls
                rng.uniform(10, 300),    # num_import_functions
                rng.uniform(0, 2),       # num_suspicious_imports
                1.0,                     # imports_kernel32
                rng.choice([0.0, 1.0]),  # imports_ntdll
                0.0,                     # imports_wininet
                0.0,                     # imports_crypt
                0.0,                     # imports_ws2_32
                rng.uniform(0, 30),      # num_exports
                0.0,                     # yara_match_count
                0.0,                     # yara_critical_count
                0.0,                     # yara_high_count
                rng.uniform(0, 1),       # num_urls
                0.0,                     # num_ips
                rng.uniform(0, 1),       # num_suspicious_apis
                rng.uniform(0, 2),       # num_registry_keys
                0.0,                     # overlay_size_kb
                0.0,                     # overlay_size_log
            ]
        X.append(row)
        y.append(label)

    X_arr = np.array(X, dtype=float)
    y_arr = np.array(y, dtype=int)

    clf = RandomForestClassifier(
        n_estimators=100, class_weight="balanced", n_jobs=-1, random_state=42
    )
    clf.fit(X_arr, y_arr)

    model = MalwareClassifier(clf=clf, threshold=0.5)
    model.save(output)
    logger.info("Synthetic dev model saved → %s", output)
    return model


def main():
    parser = argparse.ArgumentParser(description="Train RedGuard ML model")
    parser.add_argument("--malware", type=Path, help="Directory of malware samples")
    parser.add_argument("--benign", type=Path, help="Directory of benign samples")
    parser.add_argument("--output", type=Path, default=_MODEL_PATH)
    parser.add_argument("--estimators", type=int, default=200)
    parser.add_argument("--max-files", type=int, default=5000)
    parser.add_argument("--threshold", type=float, default=0.5)
    parser.add_argument(
        "--synthetic",
        action="store_true",
        help="Generate synthetic dev model (no real dataset needed)",
    )
    parser.add_argument(
        "--no-gpu",
        action="store_true",
        help="Force CPU training even if CUDA is available",
    )
    args = parser.parse_args()

    if args.synthetic:
        _generate_synthetic_model(args.output)
    elif args.malware and args.benign:
        train(
            malware_dir=args.malware,
            benign_dir=args.benign,
            output=args.output,
            n_estimators=args.estimators,
            max_files=args.max_files,
            threshold=args.threshold,
            use_gpu=not args.no_gpu,
        )
    else:
        parser.print_help()
        print("\nTip: use --synthetic to generate a dev model without a real dataset.")
        sys.exit(1)


if __name__ == "__main__":
    main()
