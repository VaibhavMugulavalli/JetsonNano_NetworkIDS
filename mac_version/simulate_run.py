#!/usr/bin/env python3
"""Simulator-runner for the mac_version monitor.

Starts the analyzer, detector and dashboard but replaces live capture with a
TrafficSimulator that injects synthetic packet metadata into the analyzer's
queue. This makes it possible to view alerts in the dashboard without sudo or
access to a real interface.

Usage:
    python3 simulate_run.py --dashboard-port 5001

"""
import argparse
import logging
import signal
import sys
import time
import threading
from queue import Queue
import os

# Ensure project root is on sys.path so `mac_version` can be imported when the
# script is executed directly from the `mac_version` directory.
proj_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if proj_root not in sys.path:
    sys.path.insert(0, proj_root)

from mac_version.jetson_network_monitor.analysis import TrafficAnalyzer
from mac_version.jetson_network_monitor.detect import ThreatDetector
from mac_version.jetson_network_monitor.dashboard import DashboardServer


logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")


class TrafficSimulator(threading.Thread):
    """Generate synthetic packet metadata to exercise detectors.

    The simulator produces three scenarios sequentially:
    1. Vertical scan: one source hits many ports on a single destination.
    2. Horizontal scan: one source hits the same port across many destinations.
    3. Data exfiltration: one source sends many bytes to external hosts.
    After the scenarios it emits low-volume background traffic so the dashboard
    stays populated.
    """

    def __init__(self, out_queue: Queue):
        super().__init__(daemon=True)
        self.out = out_queue
        self._stop = threading.Event()

    def stop(self):
        self._stop.set()

    def stopped(self):
        return self._stop.is_set()

    def _put(self, meta):
        try:
            self.out.put_nowait(meta)
        except Exception:
            pass

    def run(self):
        now = time.time()
        ts = lambda: time.time()

        # 1) Vertical scan: src -> single dst, many dst ports
        src_v = "192.0.2.10"
        dst_v = "198.51.100.5"
        for p in range(1000, 1060):
            if self.stopped():
                return
            meta = {
                "timestamp": ts(),
                "src_ip": src_v,
                "dst_ip": dst_v,
                "protocol": 6,
                "dst_port": p,
                "size": 60,
            }
            self._put(meta)
            time.sleep(0.05)

        # short pause
        time.sleep(1.0)

        # 2) Horizontal scan: src -> many dsts on same port
        src_h = "192.0.2.20"
        port_h = 22
        for i in range(40):
            if self.stopped():
                return
            dst = f"203.0.113.{i+1}"
            meta = {
                "timestamp": ts(),
                "src_ip": src_h,
                "dst_ip": dst,
                "protocol": 6,
                "dst_port": port_h,
                "size": 60,
            }
            self._put(meta)
            time.sleep(0.06)

        time.sleep(1.0)

        # 3) Data exfiltration: src sends many bytes to external IPs over 60s
        src_ex = "192.0.2.30"
        ext_dsts = ["8.8.8.8", "1.1.1.1"]
        # send ~1.2 MB in bursts
        bytes_sent = 0
        start = time.time()
        while not self.stopped() and (time.time() - start) < 12:
            for dst in ext_dsts:
                meta = {
                    "timestamp": ts(),
                    "src_ip": src_ex,
                    "dst_ip": dst,
                    "protocol": 6,
                    "dst_port": 443,
                    "size": 20000,  # 20 KB packets to reach threshold quickly
                }
                bytes_sent += meta["size"]
                self._put(meta)
                time.sleep(0.05)
            # small pause
            time.sleep(0.1)

        logger.info("Simulator sent approx %d bytes for exfil scenario", bytes_sent)

        # 4) Beaconing scenario: periodic connections to a single dst to trigger beacon detection
        # send 8 regular connections spaced by ~5s -> 7 intervals
        beacon_src = "192.0.2.40"
        beacon_dst = "198.51.100.200"
        for _ in range(8):
            if self.stopped():
                return
            meta = {
                "timestamp": ts(),
                "src_ip": beacon_src,
                "dst_ip": beacon_dst,
                "protocol": 6,
                "dst_port": 8080,
                "size": 200,
            }
            self._put(meta)
            time.sleep(5.0)

        # Background traffic: gentle noise
        background_srcs = ["192.0.2.101", "192.0.2.102"]
        while not self.stopped():
            for s in background_srcs:
                meta = {
                    "timestamp": ts(),
                    "src_ip": s,
                    "dst_ip": "198.51.100.100",
                    "protocol": 6,
                    "dst_port": 80,
                    "size": 500,
                }
                self._put(meta)
                time.sleep(0.2)


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="Run monitor with synthetic traffic simulator (mac_version)")
    parser.add_argument("--dashboard-port", type=int, default=5001, help="Port for the dashboard")
    parser.add_argument("--window", type=int, default=60, help="Analysis window seconds")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    packet_queue: Queue = Queue(maxsize=10000)
    alert_queue: Queue = Queue(maxsize=1000)

    analyzer = TrafficAnalyzer(queue=packet_queue, window_seconds=args.window)
    detector = ThreatDetector(analyzer=analyzer, alert_queue=alert_queue,
                              scan_port_threshold=50, flood_rate_threshold=100.0,
                              horizontal_scan_threshold=30, exfil_bytes_threshold=1_000_000,
                              beacon_min_intervals=3)
    dashboard = DashboardServer(analyzer=analyzer, alert_queue=alert_queue, port=args.dashboard_port)

    simulator = TrafficSimulator(out_queue=packet_queue)

    # start services
    analyzer.start()
    detector.start()
    dashboard.start()
    simulator.start()

    def shutdown(signum, frame):
        logger.info("Shutting down simulator run")
        simulator.stop()
        analyzer.stop()
        detector.stop()
        dashboard.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    # keep main thread alive
    while True:
        time.sleep(1.0)


if __name__ == '__main__':
    main()
