#!/usr/bin/env python3
"""Entry point for the Windows version of the network monitor.

This script acts as a thin wrapper around the core `jetson_network_monitor`
package.  It simply passes command‑line arguments through to the unified
`run_monitor` module.  Use it on Windows to capture traffic from your Wi‑Fi
or Ethernet interface.  See README.md for details.
"""

import argparse
from pathlib import Path

from jetson_network_monitor.run_monitor import main as core_main


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="Network monitor (Windows version)")
    parser.add_argument('--interface', '-i', required=True, help='Name of the Wi-Fi or Ethernet interface to capture from')
    parser.add_argument('--allowed-hosts', '-a', help='File with list of authorized IP addresses (optional)')
    parser.add_argument('--scan-threshold', type=int, default=50, help='Unique destination ports threshold for port scan detection')
    parser.add_argument('--flood-threshold', type=float, default=100.0, help='Packets per second threshold for flood detection')
    parser.add_argument('--dashboard-port', type=int, default=5000, help='HTTP port for the dashboard')
    # Accept but ignore Jetson‑specific arguments for compatibility
    parser.add_argument('--ml-model', help='Path to trained ML model (optional)')
    parser.add_argument('--anomaly-threshold', type=float, default=-0.5, help='Anomaly score threshold (optional)')
    parser.add_argument('--window', type=int, default=60, help='Time window for analysis history')
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    # Build argument list for core_main.
    core_argv = [
        '--interface', args.interface,
        '--dashboard-port', str(args.dashboard_port),
        '--scan-threshold', str(args.scan_threshold),
        '--flood-threshold', str(args.flood_threshold),
        '--window', str(args.window),
    ]
    # Resolve allowed hosts path from caller input or default file location.
    if args.allowed_hosts:
        allowed_hosts_path = Path(args.allowed_hosts).expanduser()
    else:
        default_path = Path(__file__).resolve().parent / "allowed_hosts.txt"
        allowed_hosts_path = default_path if default_path.exists() else None
    if allowed_hosts_path:
        core_argv += ['--allowed-hosts', str(allowed_hosts_path)]
    if args.ml_model:
        core_argv += ['--ml-model', args.ml_model, '--anomaly-threshold', str(args.anomaly_threshold)]
    # Call the core main function from jetson_network_monitor
    core_main(core_argv)


if __name__ == '__main__':
    main()
