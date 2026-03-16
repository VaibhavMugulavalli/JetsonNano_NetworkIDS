"""Main entry point for the network monitoring system.

This script wires together the packet capture, traffic analysis, threat
detection and dashboard modules. It can be executed on a Jetson Nano to
start monitoring a mirrored network interface and serving a web interface.

Example usage:

    python3 -m jetson_network_monitor.run_monitor \
        --interface eth1 \
        --allowed-hosts allowed_hosts.txt \
        --scan-threshold 50 \
        --flood-threshold 100 \
        --dashboard-port 5000
"""

import argparse
import signal
import sys
import logging
from queue import Queue

from .capture import PacketCapture
from .analysis import TrafficAnalyzer
from .detect import ThreatDetector
from .dashboard import DashboardServer


logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Hardware‑assisted network monitoring system")
    parser.add_argument('--interface', '-i', default='eth0', help='Network interface to monitor (e.g., eth1)')
    parser.add_argument('--allowed-hosts', '-a', help='Path to file containing list of allowed IP addresses, one per line')
    parser.add_argument('--scan-threshold', type=int, default=50, help='Port scan detection threshold (unique ports in interval)')
    parser.add_argument('--flood-threshold', type=float, default=100.0, help='Traffic flood threshold (packets per second)')
    parser.add_argument('--dashboard-port', type=int, default=5000, help='Port for the web dashboard')
    parser.add_argument('--window', type=int, default=60, help='Time window in seconds for traffic analysis history')
    parser.add_argument('--ml-model', help='Path to a trained ML model for anomaly detection (IsolationForest pickle)')
    parser.add_argument('--anomaly-threshold', type=float, default=-0.5, help='Anomaly score threshold for ML detector (lower is more anomalous)')
    return parser.parse_args()


def load_allowed_hosts(path: str) -> list:
    if not path:
        return []
    try:
        with open(path, 'r') as f:
            return [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except Exception as exc:
        logging.error("Could not load allowed hosts from %s: %s", path, exc)
        return []


def main() -> None:
    args = parse_args()
    allowed_hosts = load_allowed_hosts(args.allowed_hosts)
    packet_queue: Queue = Queue(maxsize=10000)
    alert_queue: Queue = Queue(maxsize=100)
    # instantiate modules
    capture = PacketCapture(interface=args.interface, queue=packet_queue)
    analyzer = TrafficAnalyzer(queue=packet_queue, window_seconds=args.window)
    # load ML model if specified
    ml_detector = None
    if args.ml_model:
        try:
            from .ml_model import AnomalyDetector
            ml_detector = AnomalyDetector(model_path=args.ml_model)
            logging.info("Loaded ML model from %s", args.ml_model)
        except Exception as exc:
            logging.error("Failed to load ML model: %s", exc)

    detector = ThreatDetector(analyzer=analyzer, alert_queue=alert_queue, allowed_ips=allowed_hosts,
                              scan_port_threshold=args.scan_threshold, flood_rate_threshold=args.flood_threshold,
                              ml_detector=ml_detector, anomaly_threshold=args.anomaly_threshold)
    dashboard = DashboardServer(analyzer=analyzer, alert_queue=alert_queue, port=args.dashboard_port)
    # start threads
    logging.info("Starting packet capture on interface %s", args.interface)
    capture.start()
    analyzer.start()
    detector.start()
    logging.info("Starting dashboard on port %d", args.dashboard_port)
    dashboard.start()
    # handle signals
    def shutdown(signum, frame):
        logging.info("Shutting down")
        capture.stop()
        analyzer.stop()
        detector.stop()
        dashboard.stop()
        sys.exit(0)
    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)
    # keep main thread alive
    signal.pause()


if __name__ == '__main__':
    main()