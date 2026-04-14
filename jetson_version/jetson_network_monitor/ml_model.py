"""Machine learning model utilities for anomaly detection.

This module provides a simple wrapper around scikit‑learn’s unsupervised
anomaly detection algorithms.  It supports training an IsolationForest model
on extracted traffic features and predicting anomaly scores at runtime.

The model uses four features per host computed over a time window:

* packet_rate – packets per second
* connection_rate – distinct connection attempts per second
* avg_packet_size – mean packet size in bytes
* protocol_entropy – entropy of protocol distribution

These features can be extracted from the TrafficAnalyzer.  During training,
the model learns the normal distribution of these metrics.  At runtime,
negative anomaly scores (< 0) indicate outliers.

Usage:
    from jetson_network_monitor.ml_model import AnomalyDetector
    det = AnomalyDetector(model_path='model.pkl')
    det.fit(feature_matrix)
    score = det.predict(feature_vector)

Note: training and prediction require scikit‑learn to be installed.
"""

import pickle
from typing import Iterable, Any
import logging

import numpy as np

try:
    from sklearn.ensemble import IsolationForest
except ImportError:
    IsolationForest = None


class AnomalyDetector:
    """Wrapper around IsolationForest for anomaly detection."""

    def __init__(self, model_path: str = None):
        self.model_path = model_path
        self.model = None
        self.load_error = None
        if model_path:
            try:
                with open(model_path, 'rb') as f:
                    self.model = pickle.load(f)
            except Exception as exc:
                # model will be None until fit is called
                self.model = None
                self.load_error = exc

    def fit(self, X: np.ndarray, **kwargs) -> None:
        """Train an IsolationForest on the given feature matrix and save to disk."""
        if IsolationForest is None:
            raise ImportError("scikit-learn must be installed to train the anomaly detector")
        contamination = kwargs.pop("contamination", 0.05)
        random_state = kwargs.pop("random_state", 42)
        self.model = IsolationForest(contamination=contamination, random_state=random_state, **kwargs)
        self.model.fit(X)
        if self.model_path:
            with open(self.model_path, 'wb') as f:
                pickle.dump(self.model, f)

def predict(self, x: Iterable[float]) -> float:
    """Return anomaly score for one feature vector.
    Lower scores indicate more anomalous behavior.
    """
    if self.model is None:
        raise RuntimeError("Model not loaded. Call fit() or provide a trained model path.")
    x = np.array(x, dtype=float).reshape(1, -1)

    if hasattr(self.model, "score_samples"):
        return float(self.model.score_samples(x)[0])

    if hasattr(self.model, "decision_function"):
        return float(self.model.decision_function(x)[0])

    raise AttributeError(
        "Loaded model does not expose score_samples or decision_function; cannot compute anomaly score."
    )

