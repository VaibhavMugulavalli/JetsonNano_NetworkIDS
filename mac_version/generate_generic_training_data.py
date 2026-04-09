#!/usr/bin/env python3
"""Generate a generic network-feature dataset for anomaly model training.

The output schema matches the monitor feature vector:
    packet_rate, connection_rate, avg_packet_size, protocol_entropy

Extra columns:
    label: "normal" or "anomaly"
    traffic_profile: synthetic behavior archetype
"""

import argparse
import csv
import random
from pathlib import Path


FEATURE_COLUMNS = [
    "packet_rate",
    "connection_rate",
    "avg_packet_size",
    "protocol_entropy",
]


def parse_args():
    parser = argparse.ArgumentParser(description="Generate generic network training data")
    parser.add_argument("--output", default="generic_training_data.csv", help="Destination CSV path")
    parser.add_argument("--rows", type=int, default=3000, help="Total row count")
    parser.add_argument("--anomaly-ratio", type=float, default=0.08, help="Fraction of anomaly rows")
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    return parser.parse_args()


def clamp(value: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, value))


def normal_from_profile(profile: str) -> dict:
    profiles = {
        "interactive": (3.2, 1.2, 0.9, 0.45, 580, 140, 1.35, 0.22),
        "service_api": (8.5, 2.8, 0.55, 0.20, 460, 120, 0.95, 0.25),
        "iot_telemetry": (1.2, 0.45, 0.18, 0.09, 220, 70, 0.55, 0.20),
        "media_stream": (16.0, 4.5, 0.30, 0.12, 1080, 220, 0.40, 0.18),
        "bulk_transfer": (24.0, 6.5, 0.40, 0.15, 1320, 240, 0.50, 0.18),
        "device_sync": (5.5, 1.8, 0.35, 0.16, 700, 160, 0.85, 0.20),
    }
    mean = profiles[profile]
    packet_rate = random.gauss(mean[0], mean[1])
    connection_rate = random.gauss(mean[2], mean[3])
    avg_packet_size = random.gauss(mean[4], mean[5])
    protocol_entropy = random.gauss(mean[6], mean[7])
    return {
        "packet_rate": clamp(packet_rate, 0.05, 120.0),
        "connection_rate": clamp(connection_rate, 0.01, 18.0),
        "avg_packet_size": clamp(avg_packet_size, 60.0, 1600.0),
        "protocol_entropy": clamp(protocol_entropy, 0.0, 2.6),
        "label": "normal",
        "traffic_profile": profile,
    }


def anomaly_row() -> dict:
    scenario = random.choice([
        "port_scan",
        "flood",
        "beacon",
        "protocol_shift",
    ])
    if scenario == "port_scan":
        values = {
            "packet_rate": random.uniform(12, 55),
            "connection_rate": random.uniform(5, 20),
            "avg_packet_size": random.uniform(80, 360),
            "protocol_entropy": random.uniform(1.6, 2.8),
        }
    elif scenario == "flood":
        values = {
            "packet_rate": random.uniform(90, 500),
            "connection_rate": random.uniform(0.2, 3.5),
            "avg_packet_size": random.uniform(300, 1450),
            "protocol_entropy": random.uniform(0.0, 0.9),
        }
    elif scenario == "beacon":
        values = {
            "packet_rate": random.uniform(0.02, 0.8),
            "connection_rate": random.uniform(0.01, 0.08),
            "avg_packet_size": random.uniform(60, 170),
            "protocol_entropy": random.uniform(0.0, 0.25),
        }
    else:
        values = {
            "packet_rate": random.uniform(2, 30),
            "connection_rate": random.uniform(0.2, 4.0),
            "avg_packet_size": random.uniform(90, 900),
            "protocol_entropy": random.uniform(2.2, 3.8),
        }
    values["label"] = "anomaly"
    values["traffic_profile"] = scenario
    return values


def main():
    args = parse_args()
    if args.rows < 50:
        raise ValueError("--rows must be at least 50.")
    if not (0.0 <= args.anomaly_ratio < 0.5):
        raise ValueError("--anomaly-ratio must be in [0.0, 0.5).")

    random.seed(args.seed)
    output_path = Path(args.output)
    anomaly_rows = int(args.rows * args.anomaly_ratio)
    normal_rows = args.rows - anomaly_rows

    normal_profiles = [
        "interactive",
        "service_api",
        "iot_telemetry",
        "media_stream",
        "bulk_transfer",
        "device_sync",
    ]

    rows = []
    for _ in range(normal_rows):
        profile = random.choice(normal_profiles)
        rows.append(normal_from_profile(profile))
    for _ in range(anomaly_rows):
        rows.append(anomaly_row())
    random.shuffle(rows)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    fields = FEATURE_COLUMNS + ["label", "traffic_profile"]
    with output_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)

    print(f"Wrote dataset: {output_path}")
    print(f"Rows: {len(rows)} (normal={normal_rows}, anomaly={anomaly_rows})")


if __name__ == "__main__":
    main()
