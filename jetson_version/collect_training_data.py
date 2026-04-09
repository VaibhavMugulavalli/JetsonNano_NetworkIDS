#!/usr/bin/env python3
"""Collect live network feature rows for model training.

This script captures mirrored traffic on an interface, computes the same
feature vector used by runtime ML detection, and writes rows to CSV:

    packet_rate,connection_rate,avg_packet_size,protocol_entropy,label,src_ip,timestamp

Use this to build a real environment-specific training dataset on Jetson.
"""

import argparse
import csv
import logging
import time
from queue import Queue
from pathlib import Path

from jetson_network_monitor.capture import PacketCapture
from jetson_network_monitor.analysis import TrafficAnalyzer


FEATURE_COLUMNS = [
    "packet_rate",
    "connection_rate",
    "avg_packet_size",
    "protocol_entropy",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Collect live traffic features into CSV")
    parser.add_argument("--interface", "-i", required=True, help="Capture interface (for example: eth0)")
    parser.add_argument("--output", "-o", default="live_training_data.csv", help="Output CSV path")
    parser.add_argument("--duration", type=int, default=300, help="Collection duration in seconds")
    parser.add_argument("--sample-interval", type=float, default=2.0, help="Seconds between samples")
    parser.add_argument("--window", type=int, default=10, help="Feature window in seconds")
    parser.add_argument("--label", default="normal", help="Label value to write in CSV")
    parser.add_argument("--min-packet-rate", type=float, default=0.01, help="Skip rows below this packet_rate")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.duration <= 0:
        raise ValueError("--duration must be > 0")
    if args.sample_interval <= 0:
        raise ValueError("--sample-interval must be > 0")
    if args.window <= 0:
        raise ValueError("--window must be > 0")

    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    packet_queue: Queue = Queue(maxsize=10000)
    capture = PacketCapture(interface=args.interface, queue=packet_queue)
    analyzer = TrafficAnalyzer(queue=packet_queue, window_seconds=max(args.window, 60))

    fieldnames = FEATURE_COLUMNS + ["label", "src_ip", "timestamp"]
    rows_written = 0
    start = time.time()
    next_sample = start

    logging.info("Starting capture on interface: %s", args.interface)
    capture.start()
    analyzer.start()

    try:
        with output_path.open("w", newline="", encoding="utf-8") as csv_file:
            writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
            writer.writeheader()

            while True:
                now = time.time()
                if now - start >= args.duration:
                    break
                if now < next_sample:
                    time.sleep(min(0.2, next_sample - now))
                    continue
                next_sample = now + args.sample_interval

                host_stats = analyzer.host_stats
                for src_ip in host_stats.keys():
                    packet_rate = analyzer.packet_rate(src_ip, interval=args.window)
                    if packet_rate < args.min_packet_rate:
                        continue
                    row = {
                        "packet_rate": packet_rate,
                        "connection_rate": analyzer.unique_connections_count(src_ip, interval=args.window) / args.window,
                        "avg_packet_size": analyzer.average_packet_size(src_ip, interval=args.window),
                        "protocol_entropy": analyzer.protocol_entropy(src_ip, interval=args.window),
                        "label": args.label,
                        "src_ip": src_ip,
                        "timestamp": int(now),
                    }
                    writer.writerow(row)
                    rows_written += 1

                if int(now - start) % 30 == 0:
                    logging.info("Progress: %ds elapsed, rows written=%d", int(now - start), rows_written)
    finally:
        logging.info("Stopping capture/analyzer threads")
        capture.stop()
        analyzer.stop()
        capture.join(timeout=2.0)
        analyzer.join(timeout=2.0)

    logging.info("Collection complete. Output: %s", output_path)
    logging.info("Rows written: %d", rows_written)


if __name__ == "__main__":
    main()
