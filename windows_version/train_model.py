#!/usr/bin/env python3
"""Train an IsolationForest anomaly detection model for network traffic.

This script reads a CSV file of generic traffic features and trains an
IsolationForest model. The trained model is saved as a pickle file that can
be loaded by the monitor at runtime.

Usage:

    python3 train_model.py --input generic_training_data.csv --output model.pkl

The CSV file must contain the following columns:

    packet_rate,connection_rate,avg_packet_size,protocol_entropy

Additional columns are allowed and ignored by default.
"""

import argparse
import math
from pathlib import Path

import pandas as pd

from jetson_network_monitor.ml_model import AnomalyDetector

FEATURE_COLUMNS = [
    "packet_rate",
    "connection_rate",
    "avg_packet_size",
    "protocol_entropy",
]


def parse_args():
    parser = argparse.ArgumentParser(description="Train IsolationForest anomaly model")
    parser.add_argument('--input', required=True, help='Path to CSV training data')
    parser.add_argument('--output', required=True, help='Destination model path (pickle)')
    parser.add_argument('--contamination', type=float, default=0.05, help='Expected anomaly ratio used by IsolationForest')
    parser.add_argument('--label-column', default='label', help='Optional label column (e.g., normal/anomaly)')
    parser.add_argument('--normal-label', default='normal', help='Label value treated as normal when label column exists')
    return parser.parse_args()


def _validate_frame(df: pd.DataFrame) -> pd.DataFrame:
    missing = [c for c in FEATURE_COLUMNS if c not in df.columns]
    if missing:
        raise ValueError(f"Missing required feature columns: {missing}")
    frame = df.copy()
    frame[FEATURE_COLUMNS] = frame[FEATURE_COLUMNS].apply(pd.to_numeric, errors='coerce')
    frame = frame.dropna(subset=FEATURE_COLUMNS)
    if frame.empty:
        raise ValueError("No valid rows available after numeric conversion and NaN filtering.")
    return frame


def main():
    args = parse_args()
    input_path = Path(args.input)
    if not input_path.exists():
        raise FileNotFoundError(f"Input dataset not found: {input_path}")

    df = pd.read_csv(input_path)
    raw_count = len(df)

    # If a label column exists, default to training on normal samples only.
    if args.label_column in df.columns:
        normal_mask = df[args.label_column].astype(str).str.lower() == args.normal_label.lower()
        normal_count = int(normal_mask.sum())
        if normal_count == 0:
            raise ValueError(
                f"Label column '{args.label_column}' exists but contains no rows with label '{args.normal_label}'."
            )
        df = df[normal_mask]

    df = _validate_frame(df)
    X = df[FEATURE_COLUMNS].values
    det = AnomalyDetector(model_path=args.output)
    # Train the model with user-defined contamination ratio.
    det.fit(X, contamination=args.contamination)

    scores = det.model.score_samples(X)
    score_min = float(scores.min())
    score_mean = float(scores.mean())
    score_max = float(scores.max())
    score_p05 = float(pd.Series(scores).quantile(0.05))
    score_p95 = float(pd.Series(scores).quantile(0.95))

    print(f"Loaded rows: {raw_count}")
    print(f"Rows used for training: {len(df)}")
    print(f"Model trained and saved to {args.output}")
    print("Training score summary (higher is more normal):")
    print(f"  min={score_min:.4f} mean={score_mean:.4f} max={score_max:.4f}")
    print(f"  p05={score_p05:.4f} p95={score_p95:.4f}")
    suggested_threshold = score_p05
    if math.isnan(suggested_threshold):
        suggested_threshold = -0.5
    print(f"Suggested --anomaly-threshold starting point: {suggested_threshold:.4f}")


if __name__ == '__main__':
    main()
