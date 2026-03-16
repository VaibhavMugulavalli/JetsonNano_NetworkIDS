#!/usr/bin/env python3
"""Entry point for the Jetson version of the network monitor.

This script provides a convenient way to run the monitoring system on a Jetson
Nano in a lab environment.  It wraps the unified `run_monitor` module and
allows the user to specify interface, thresholds, allowed hosts, and a
trained ML model.  See README.md for details.
"""

import argparse
import sys

from jetson_network_monitor.run_monitor import main as core_main


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="Network monitor (Jetson version)")
    parser.add_argument('--interface', '-i', required=True, help='Name of the network interface connected to the mirror port')
    parser.add_argument('--allowed-hosts', '-a', help='Path to authorized hosts file (optional)')
    parser.add_argument('--scan-threshold', type=int, default=50, help='Unique destination ports threshold for port scan detection')
    parser.add_argument('--flood-threshold', type=float, default=100.0, help='Packets per second threshold for flood detection')
    parser.add_argument('--dashboard-port', type=int, default=5000, help='Port for the web dashboard')
    parser.add_argument('--ml-model', help='Path to trained ML model (pickle file)')
    parser.add_argument('--anomaly-threshold', type=float, default=-0.5, help='Anomaly score threshold for ML detector')
    parser.add_argument('--window', type=int, default=60, help='Time window in seconds for traffic analysis history')
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    # Build sys.argv for the core monitor.  Include all relevant parameters.
    sys.argv = [sys.argv[0],
                '--interface', args.interface,
                '--scan-threshold', str(args.scan_threshold),
                '--flood-threshold', str(args.flood_threshold),
                '--dashboard-port', str(args.dashboard_port),
                '--window', str(args.window)]
    if args.allowed_hosts:
        sys.argv += ['--allowed-hosts', args.allowed_hosts]
    if args.ml_model:
        sys.argv += ['--ml-model', args.ml_model, '--anomaly-threshold', str(args.anomaly_threshold)]
    # Call the core monitor
    core_main()


if __name__ == '__main__':
    main()