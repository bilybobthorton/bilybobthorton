"""
RandomForest malware classifier.

Usage:
  from engine.ml.model import get_model
  model = get_model()          # loads from disk, falls back to untrained stub
  score = model.predict(features)   # returns float 0.0-1.0
"""
from __future__ import annotations

import logging
import os
import pickle
from pathlib import Path
from typing import Optional

from engine.ml.features import NUM_FEATURES

logger = logging.getLogger(__name__)

_MODEL_PATH = Path(__file__).parent / "sentinel_rf.pkl"

# Global singleton
_model_instance: Optional["MalwareClassifier"] = None


class MalwareClassifier:
    """Thin wrapper around a scikit-learn RandomForestClassifier."""

    def __init__(self, clf=None, threshold: float = 0.5):
        self._clf = clf
        self.threshold = threshold
        self.trained = clf is not None

    def predict(self, features: list[float]) -> float:
        """Return malice probability 0.0–1.0. Returns -1.0 if model not trained."""
        if not self.trained or self._clf is None:
            return -1.0
        import numpy as np
        X = np.array(features, dtype=float).reshape(1, -1)
        proba = self._clf.predict_proba(X)[0]
        # Class order: [benign=0, malicious=1]
        mal_idx = list(self._clf.classes_).index(1) if 1 in self._clf.classes_ else 1
        return float(proba[mal_idx])

    def is_malicious(self, features: list[float]) -> Optional[bool]:
        p = self.predict(features)
        if p < 0:
            return None
        return p >= self.threshold

    def save(self, path: Path = _MODEL_PATH) -> None:
        with open(path, "wb") as f:
            pickle.dump({"clf": self._clf, "threshold": self.threshold}, f)
        logger.info("Model saved to %s", path)

    @classmethod
    def load(cls, path: Path = _MODEL_PATH) -> "MalwareClassifier":
        if not path.exists():
            logger.warning("No trained model found at %s — ML scoring disabled", path)
            return cls(clf=None)
        with open(path, "rb") as f:
            data = pickle.load(f)
        logger.info("ML model loaded from %s", path)
        return cls(clf=data["clf"], threshold=data.get("threshold", 0.5))


def get_model() -> MalwareClassifier:
    """Load (or return cached) the global classifier instance."""
    global _model_instance
    if _model_instance is None:
        _model_instance = MalwareClassifier.load()
    return _model_instance


def reload_model() -> MalwareClassifier:
    """Force reload from disk (call after retraining)."""
    global _model_instance
    _model_instance = MalwareClassifier.load()
    return _model_instance
