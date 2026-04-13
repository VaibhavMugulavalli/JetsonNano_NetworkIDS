#!/usr/bin/env python3
"""PC-side traffic simulator for a direct Ethernet link to Jetson Nano.

This script generates normal and attack-like traffic patterns toward a Jetson
IP address so the Jetson monitor can capture/analyze data without switch SPAN.

Usage example (PowerShell):
    python simulate_traffic_to_jetson.py `
      --target-ip 192.168.50.2 `
      --profile mixed `
      --duration 900 `
      --rate 250 `
      --workers 4
"""

import argparse
import random
import socket
import threading
import time
from collections import Counter
from dataclasses import dataclass
from typing import Optional


def parse_ports(value: str) -> list[int]:
    ports: list[int] = []
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        port = int(part)
        if not (1 <= port <= 65535):
            raise ValueError(f"Invalid port: {port}")
        ports.append(port)
    if not ports:
        raise ValueError("At least one port is required.")
    return ports


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate network traffic from PC to Jetson over Ethernet")
    parser.add_argument("--target-ip", required=True, help="Jetson IP address on the direct Ethernet link")
    parser.add_argument("--duration", type=int, default=300, help="Total runtime in seconds")
    parser.add_argument("--profile", choices=["normal", "port_scan", "flood", "beacon", "protocol_shift", "mixed"],
                        default="mixed", help="Traffic behavior profile")
    parser.add_argument("--rate", type=float, default=120.0, help="Approximate actions per second (global)")
    parser.add_argument("--workers", type=int, default=4, help="Worker threads")
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    parser.add_argument("--bind-ip", help="Optional local source IP to bind sockets to")
    parser.add_argument("--tcp-timeout", type=float, default=0.25, help="TCP connect timeout (seconds)")
    parser.add_argument("--segment-seconds", type=int, default=60,
                        help="For mixed profile: duration of each sub-profile segment")
    parser.add_argument("--normal-ports", type=parse_ports, default=[53, 80, 123, 443, 5000],
                        help="Comma-separated ports used in normal profile")
    parser.add_argument("--flood-port", type=int, default=9999, help="UDP flood destination port")
    parser.add_argument("--beacon-port", type=int, default=19001, help="Beacon destination port")
    return parser.parse_args()


@dataclass
class Action:
    protocol: str
    port: int
    payload_size: int


class TrafficSimulator:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.stop_event = threading.Event()
        self.start_time = 0.0
        self.stats_lock = threading.Lock()
        self.stats = Counter()

    def run(self) -> None:
        random.seed(self.args.seed)
        self.start_time = time.time()
        threads = []
        for worker_id in range(self.args.workers):
            t = threading.Thread(target=self._worker, args=(worker_id,), daemon=True)
            t.start()
            threads.append(t)

        self._print_header()
        try:
            while True:
                elapsed = time.time() - self.start_time
                if elapsed >= self.args.duration:
                    break
                self._print_progress(elapsed)
                time.sleep(2.0)
        except KeyboardInterrupt:
            print("\nInterrupted by user, shutting down...")
        finally:
            self.stop_event.set()
            for t in threads:
                t.join(timeout=2.0)
            self._print_summary()

    def _worker(self, worker_id: int) -> None:
        # split configured rate across workers
        worker_rate = max(1e-6, self.args.rate / max(1, self.args.workers))
        interval = 1.0 / worker_rate
        next_tick = time.perf_counter()

        udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            if self.args.bind_ip:
                udp_sock.bind((self.args.bind_ip, 0))

            while not self.stop_event.is_set():
                elapsed = time.time() - self.start_time
                if elapsed >= self.args.duration:
                    break

                action = self._choose_action(elapsed)
                if action.protocol == "udp":
                    self._send_udp(udp_sock, action.port, action.payload_size)
                else:
                    self._send_tcp_probe(action.port)

                next_tick += interval
                sleep_for = next_tick - time.perf_counter()
                if sleep_for > 0:
                    time.sleep(sleep_for)
                else:
                    # if behind schedule, reset to avoid runaway lag
                    next_tick = time.perf_counter()
        finally:
            udp_sock.close()

    def _choose_action(self, elapsed: float) -> Action:
        profile = self.args.profile
        if profile == "mixed":
            segment = int(elapsed // max(1, self.args.segment_seconds)) % 5
            profile = ["normal", "protocol_shift", "port_scan", "beacon", "flood"][segment]

        if profile == "normal":
            # Mostly low-to-medium mixed traffic.
            r = random.random()
            if r < 0.70:
                return Action("tcp", random.choice(self.args.normal_ports), random.randint(80, 900))
            if r < 0.95:
                return Action("udp", random.choice(self.args.normal_ports), random.randint(70, 700))
            return Action("udp", random.choice(self.args.normal_ports), random.randint(900, 1300))

        if profile == "port_scan":
            return Action("tcp", random.randint(1, 65535), random.randint(40, 160))

        if profile == "flood":
            return Action("udp", self.args.flood_port, random.randint(500, 1400))

        if profile == "beacon":
            # Very small, periodic payloads.
            return Action("udp", self.args.beacon_port, random.randint(50, 120))

        # protocol_shift
        if random.random() < 0.5:
            return Action("tcp", random.randint(1, 65535), random.randint(70, 500))
        return Action("udp", random.randint(1, 65535), random.randint(80, 1000))

    def _send_udp(self, udp_sock: socket.socket, port: int, payload_size: int) -> None:
        payload = random.randbytes(payload_size) if hasattr(random, "randbytes") else bytes(
            random.getrandbits(8) for _ in range(payload_size)
        )
        try:
            udp_sock.sendto(payload, (self.args.target_ip, port))
            with self.stats_lock:
                self.stats["sent_udp"] += 1
                self.stats["bytes_udp"] += payload_size
        except Exception:
            with self.stats_lock:
                self.stats["udp_errors"] += 1

    def _send_tcp_probe(self, port: int) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.args.tcp_timeout)
        try:
            if self.args.bind_ip:
                sock.bind((self.args.bind_ip, 0))
            rc = sock.connect_ex((self.args.target_ip, port))
            with self.stats_lock:
                self.stats["sent_tcp"] += 1
                if rc == 0:
                    self.stats["tcp_connect_ok"] += 1
                else:
                    self.stats["tcp_connect_fail"] += 1
        except Exception:
            with self.stats_lock:
                self.stats["tcp_errors"] += 1
        finally:
            sock.close()

    def _print_header(self) -> None:
        print("=== PC -> Jetson Traffic Simulator ===")
        print(f"Target IP       : {self.args.target_ip}")
        print(f"Profile         : {self.args.profile}")
        print(f"Duration (sec)  : {self.args.duration}")
        print(f"Rate (global)   : {self.args.rate} actions/sec")
        print(f"Workers         : {self.args.workers}")
        print(f"Bind source IP  : {self.args.bind_ip or 'auto'}")
        print("Running...\n")

    def _print_progress(self, elapsed: float) -> None:
        with self.stats_lock:
            sent_udp = self.stats.get("sent_udp", 0)
            sent_tcp = self.stats.get("sent_tcp", 0)
            udp_errors = self.stats.get("udp_errors", 0)
            tcp_errors = self.stats.get("tcp_errors", 0)
        print(
            f"[{int(elapsed):4d}s] udp={sent_udp} tcp={sent_tcp} "
            f"udp_err={udp_errors} tcp_err={tcp_errors}"
        )

    def _print_summary(self) -> None:
        with self.stats_lock:
            total_actions = self.stats.get("sent_udp", 0) + self.stats.get("sent_tcp", 0)
            bytes_udp = self.stats.get("bytes_udp", 0)
            tcp_ok = self.stats.get("tcp_connect_ok", 0)
            tcp_fail = self.stats.get("tcp_connect_fail", 0)
            udp_err = self.stats.get("udp_errors", 0)
            tcp_err = self.stats.get("tcp_errors", 0)
        print("\n=== Simulation Summary ===")
        print(f"Total actions      : {total_actions}")
        print(f"UDP bytes sent     : {bytes_udp}")
        print(f"TCP connect ok/fail: {tcp_ok}/{tcp_fail}")
        print(f"UDP errors         : {udp_err}")
        print(f"TCP errors         : {tcp_err}")


def main() -> None:
    args = parse_args()
    if args.duration <= 0:
        raise ValueError("--duration must be > 0")
    if args.rate <= 0:
        raise ValueError("--rate must be > 0")
    if args.workers <= 0:
        raise ValueError("--workers must be > 0")
    if not (1 <= args.flood_port <= 65535):
        raise ValueError("--flood-port must be in [1, 65535]")
    if not (1 <= args.beacon_port <= 65535):
        raise ValueError("--beacon-port must be in [1, 65535]")

    sim = TrafficSimulator(args)
    sim.run()


if __name__ == "__main__":
    main()
