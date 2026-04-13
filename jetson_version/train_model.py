#!/usr/bin/env python3
"""Train an IsolationForest model from feature CSV.

Colab-friendly: this script has no dependency on local project modules.

Required feature columns:
    packet_rate, connection_rate, avg_packet_size, protocol_entropy
"""

import argparse
import math
import pickle
from pathlib import Path
from typing import Iterable

import pandas as pd
from sklearn.ensemble import IsolationForest


FEATURE_COLUMNS = [
    "packet_rate",
    "connection_rate",
    "avg_packet_size",
    "protocol_entropy",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Train IsolationForest anomaly model")
    parser.add_argument("--input", help="Path to CSV training data (optional; auto-detected if omitted)")
    parser.add_argument("--output", default="model.pkl", help="Destination model path (pickle)")
    parser.add_argument("--contamination", type=float, default=0.05,
                        help="Expected anomaly ratio used by IsolationForest")
    parser.add_argument("--label-column", default="label", help="Optional label column (e.g., normal/anomaly)")
    parser.add_argument("--normal-label", default="normal",
                        help="Label value treated as normal when label column exists")
    parser.add_argument("--include-anomalies", action="store_true",
                        help="Include all rows even if label column exists (not recommended for IsolationForest)")
    parser.add_argument("--random-state", type=int, default=42, help="Random state for reproducibility")
    return parser.parse_args()


def _candidate_inputs(base_dir: Path) -> Iterable[Path]:
    names = [
        "large_synthetic_training_data.csv",
        "live_training_data.csv",
        "training_data.csv",
    ]
    for name in names:
        yield base_dir / name


def _resolve_input_path(input_arg: str | None) -> Path:
    if input_arg:
        path = Path(input_arg)
        if not path.exists():
            raise FileNotFoundError(f"Input dataset not found: {path}")
        return path

    script_dir = Path(__file__).resolve().parent
    for candidate in _candidate_inputs(script_dir):
        if candidate.exists():
            return candidate
    raise FileNotFoundError(
        "No default dataset found. Provide --input explicitly."
    )


def _validate_frame(df: pd.DataFrame) -> pd.DataFrame:
    missing = [c for c in FEATURE_COLUMNS if c not in df.columns]
    if missing:
        raise ValueError(f"Missing required feature columns: {missing}")
    frame = df.copy()
    frame[FEATURE_COLUMNS] = frame[FEATURE_COLUMNS].apply(pd.to_numeric, errors="coerce")
    frame = frame.dropna(subset=FEATURE_COLUMNS)
    if frame.empty:
        raise ValueError("No valid rows available after numeric conversion and NaN filtering.")
    return frame


def main() -> None:
    args = parse_args()
    input_path = _resolve_input_path(args.input)
    output_path = Path(args.output)

    df = pd.read_csv(input_path)
    raw_count = len(df)

    if args.label_column in df.columns and not args.include_anomalies:
        normal_mask = df[args.label_column].astype(str).str.lower() == args.normal_label.lower()
        normal_count = int(normal_mask.sum())
        if normal_count == 0:
            raise ValueError(
                f"Label column '{args.label_column}' exists but contains no rows with label '{args.normal_label}'."
            )
        df = df[normal_mask]

    df = _validate_frame(df)
    X = df[FEATURE_COLUMNS].values

    model = IsolationForest(
        contamination=args.contamination,
        random_state=args.random_state,
    )
    model.fit(X)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("wb") as f:
        pickle.dump(model, f)

    scores = model.score_samples(X)
    score_min = float(scores.min())
    score_mean = float(scores.mean())
    score_max = float(scores.max())
    score_p05 = float(pd.Series(scores).quantile(0.05))
    score_p95 = float(pd.Series(scores).quantile(0.95))

    print(f"Loaded rows: {raw_count}")
    print(f"Rows used for training: {len(df)}")
    print(f"Training dataset: {input_path}")
    print(f"Model trained and saved to {output_path}")
    print("Training score summary (higher is more normal):")
    print(f"  min={score_min:.4f} mean={score_mean:.4f} max={score_max:.4f}")
    print(f"  p05={score_p05:.4f} p95={score_p95:.4f}")
    suggested_threshold = score_p05
    if math.isnan(suggested_threshold):
        suggested_threshold = -0.5
    print(f"Suggested --anomaly-threshold starting point: {suggested_threshold:.4f}")


if __name__ == "__main__":
    main()
