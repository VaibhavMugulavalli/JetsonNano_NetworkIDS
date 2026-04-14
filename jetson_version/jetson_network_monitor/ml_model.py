"""Machine learning model utilities for anomaly detection.

Compatible with older sklearn versions (including 0.19.x) that may not expose
``score_samples`` on IsolationForest.
"""

import pickle
from typing import Iterable

import numpy as np

try:
    from sklearn.ensemble import IsolationForest
except ImportError:
    IsolationForest = None


class AnomalyDetector:
    """Wrapper around IsolationForest for anomaly detection."""

    def __init__(self, model_path=None):
        self.model_path = model_path
        self.model = None
        self.load_error = None
        if model_path:
            try:
                with open(model_path, "rb") as f:
                    self.model = pickle.load(f)
            except Exception as exc:
                self.model = None
                self.load_error = exc

    def fit(self, X, **kwargs):
        """Train an IsolationForest on the given feature matrix and save to disk."""
        if IsolationForest is None:
            raise ImportError("scikit-learn must be installed to train the anomaly detector")
        contamination = kwargs.pop("contamination", 0.05)
        random_state = kwargs.pop("random_state", 42)
        self.model = IsolationForest(contamination=contamination, random_state=random_state, **kwargs)
        self.model.fit(X)
        if self.model_path:
            with open(self.model_path, "wb") as f:
                pickle.dump(self.model, f)

    def predict(self, x: Iterable[float]) -> float:
        """Return anomaly score for one feature vector.

        Lower score means more anomalous.
        """
        if self.model is None:
            raise RuntimeError("Model not loaded. Call fit() or provide a trained model path.")

        x = np.array(x, dtype=float).reshape(1, -1)

        # Newer sklearn API.
        if hasattr(self.model, "score_samples"):
            return float(self.model.score_samples(x)[0])

        # Older sklearn API (0.19.x): use decision_function instead.
        if hasattr(self.model, "decision_function"):
            return float(self.model.decision_function(x)[0])

        raise AttributeError(
            "Loaded model does not expose score_samples or decision_function; "
            "cannot compute anomaly score."
        )
