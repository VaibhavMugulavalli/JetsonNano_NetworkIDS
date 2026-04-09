#!/usr/bin/env python3
"""Generate synthetic training/evaluation data from a captured seed dataset.

Input: CSV that contains model feature columns:
    packet_rate, connection_rate, avg_packet_size, protocol_entropy

Output: CSV with synthetic rows and labels:
    packet_rate,connection_rate,avg_packet_size,protocol_entropy,label,traffic_profile

The synthetic data is shaped using the observed baseline distribution from the
seed file, then expanded with realistic variations and injected threat patterns.
"""

import argparse
import random
from pathlib import Path
from typing import Dict, Tuple

import numpy as np
import pandas as pd


FEATURE_COLUMNS = [
    "packet_rate",
    "connection_rate",
    "avg_packet_size",
    "protocol_entropy",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate synthetic rows from captured seed features")
    parser.add_argument("--input", required=True, help="Seed CSV path")
    parser.add_argument("--output", default="seeded_synthetic_data.csv", help="Output CSV path")
    parser.add_argument("--rows", type=int, default=5000, help="Total synthetic rows to generate")
    parser.add_argument("--anomaly-ratio", type=float, default=0.10, help="Fraction of anomaly rows")
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    parser.add_argument("--drop-src-ip", action="append", default=["0.0.0.0"], help="Filter src_ip rows matching this value; can repeat")
    parser.add_argument("--normal-jitter", type=float, default=0.35, help="Noise scale for normal synthetic rows")
    return parser.parse_args()


def _bounded_uniform(lo: float, hi: float) -> float:
    if hi <= lo:
        hi = lo + 1e-6
    return random.uniform(lo, hi)


def _clamp(value: float, bounds: Tuple[float, float]) -> float:
    lo, hi = bounds
    return max(lo, min(hi, value))


def _feature_bounds(df: pd.DataFrame) -> Dict[str, Tuple[float, float]]:
    bounds: Dict[str, Tuple[float, float]] = {}
    for c in FEATURE_COLUMNS:
        q05 = float(df[c].quantile(0.05))
        q95 = float(df[c].quantile(0.95))
        spread = max(1e-6, q95 - q05)
        lo = q05 - (1.5 * spread)
        hi = q95 + (1.5 * spread)
        if c in ("packet_rate", "connection_rate", "avg_packet_size", "protocol_entropy"):
            lo = max(0.0, lo)
        if c == "avg_packet_size":
            lo = max(40.0, lo)
            hi = max(lo + 1.0, hi)
        if c == "protocol_entropy":
            hi = max(0.1, min(4.0, hi))
        bounds[c] = (lo, hi)
    return bounds


def _load_seed_frame(path: Path, drop_src_ips: set) -> pd.DataFrame:
    df = pd.read_csv(path)
    missing = [c for c in FEATURE_COLUMNS if c not in df.columns]
    if missing:
        raise ValueError(f"Input is missing required columns: {missing}")

    frame = df.copy()
    frame[FEATURE_COLUMNS] = frame[FEATURE_COLUMNS].apply(pd.to_numeric, errors="coerce")
    frame = frame.dropna(subset=FEATURE_COLUMNS)

    if "src_ip" in frame.columns and drop_src_ips:
        frame = frame[~frame["src_ip"].astype(str).isin(drop_src_ips)]

    # Prefer normal rows (if labels exist), fallback to all rows.
    if "label" in frame.columns:
        normal_rows = frame[frame["label"].astype(str).str.lower() == "normal"]
        if len(normal_rows) >= 10:
            frame = normal_rows

    if len(frame) < 10:
        raise ValueError("Not enough usable seed rows after filtering. Need at least 10.")
    return frame


def _normal_row(seed_row: pd.Series, stds: Dict[str, float], bounds: Dict[str, Tuple[float, float]], jitter: float) -> Dict[str, float]:
    row = {}
    for c in FEATURE_COLUMNS:
        base = float(seed_row[c])
        noise = np.random.normal(0.0, stds[c] * jitter)
        row[c] = _clamp(base + noise, bounds[c])
    return row


def _anomaly_row(q: Dict[str, float]) -> Dict[str, float]:
    scenario = random.choice(["port_scan", "flood", "beacon", "protocol_shift"])

    if scenario == "port_scan":
        row = {
            "packet_rate": _bounded_uniform(max(2.0, q["packet_rate_95"] * 1.4), max(8.0, q["packet_rate_95"] * 4.5)),
            "connection_rate": _bounded_uniform(max(1.0, q["connection_rate_95"] * 3.0), max(4.0, q["connection_rate_95"] * 10.0)),
            "avg_packet_size": _bounded_uniform(70.0, max(400.0, q["avg_packet_size_50"])),
            "protocol_entropy": _bounded_uniform(max(1.4, q["protocol_entropy_95"] + 0.8), 3.7),
        }
    elif scenario == "flood":
        row = {
            "packet_rate": _bounded_uniform(max(20.0, q["packet_rate_95"] * 6.0), max(120.0, q["packet_rate_95"] * 25.0)),
            "connection_rate": _bounded_uniform(0.05, max(2.0, q["connection_rate_50"] * 2.0)),
            "avg_packet_size": _bounded_uniform(max(100.0, q["avg_packet_size_50"]), min(1600.0, max(500.0, q["avg_packet_size_95"] * 1.5))),
            "protocol_entropy": _bounded_uniform(0.0, 0.9),
        }
    elif scenario == "beacon":
        row = {
            "packet_rate": _bounded_uniform(0.01, 0.4),
            "connection_rate": _bounded_uniform(0.01, 0.15),
            "avg_packet_size": _bounded_uniform(60.0, 220.0),
            "protocol_entropy": _bounded_uniform(0.0, 0.35),
        }
    else:
        row = {
            "packet_rate": _bounded_uniform(max(1.0, q["packet_rate_50"] * 0.8), max(12.0, q["packet_rate_95"] * 2.8)),
            "connection_rate": _bounded_uniform(max(0.2, q["connection_rate_50"]), max(2.5, q["connection_rate_95"] * 4.0)),
            "avg_packet_size": _bounded_uniform(80.0, 1000.0),
            "protocol_entropy": _bounded_uniform(2.2, 3.9),
        }

    row["label"] = "anomaly"
    row["traffic_profile"] = scenario
    return row


def main() -> None:
    args = parse_args()
    if args.rows < 100:
        raise ValueError("--rows must be at least 100")
    if not (0.0 <= args.anomaly_ratio < 0.5):
        raise ValueError("--anomaly-ratio must be in [0.0, 0.5)")

    random.seed(args.seed)
    np.random.seed(args.seed)

    input_path = Path(args.input)
    if not input_path.exists():
        raise FileNotFoundError(f"Input not found: {input_path}")

    seed_df = _load_seed_frame(input_path, set(args.drop_src_ip or []))
    bounds = _feature_bounds(seed_df)

    stds: Dict[str, float] = {}
    q: Dict[str, float] = {}
    for c in FEATURE_COLUMNS:
        std = float(seed_df[c].std(ddof=0))
        q05 = float(seed_df[c].quantile(0.05))
        q50 = float(seed_df[c].quantile(0.50))
        q95 = float(seed_df[c].quantile(0.95))
        robust = max(1e-6, (q95 - q05) / 3.0)
        stds[c] = max(std, robust)
        q[f"{c}_50"] = q50
        q[f"{c}_95"] = q95

    anomaly_rows = int(args.rows * args.anomaly_ratio)
    normal_rows = args.rows - anomaly_rows

    rows = []
    for _ in range(normal_rows):
        seed_row = seed_df.sample(n=1, replace=True).iloc[0]
        row = _normal_row(seed_row=seed_row, stds=stds, bounds=bounds, jitter=args.normal_jitter)
        row["label"] = "normal"
        row["traffic_profile"] = "seeded_normal"
        rows.append(row)

    for _ in range(anomaly_rows):
        rows.append(_anomaly_row(q))

    random.shuffle(rows)

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    out_df = pd.DataFrame(rows, columns=FEATURE_COLUMNS + ["label", "traffic_profile"])
    out_df.to_csv(output_path, index=False)

    print(f"Seed rows used: {len(seed_df)}")
    print(f"Wrote synthetic dataset: {output_path}")
    print(f"Rows: {len(out_df)} (normal={normal_rows}, anomaly={anomaly_rows})")
    print("Note: train_model.py uses only label=normal rows by default.")


if __name__ == "__main__":
    main()
