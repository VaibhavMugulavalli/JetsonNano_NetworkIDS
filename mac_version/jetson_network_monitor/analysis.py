"""Traffic analysis module.

This module defines a TrafficAnalyzer class responsible for consuming packet
metadata from a queue, maintaining aggregated statistics over time and
providing an interface for threat detection and dashboard display. It runs
in a dedicated thread and continuously processes incoming packet summaries.

The analyzer maintains per‑host statistics, such as packet counts, byte
counts, unique destination ports accessed, and sliding window rates. These
statistics are used by the detection module to identify suspicious patterns
like port scans or traffic flooding.
"""

import threading
import time
import logging
from collections import defaultdict, deque
from queue import Queue
from typing import Dict, Any, Deque, List
import ipaddress
import statistics


logger = logging.getLogger(__name__)


class TrafficAnalyzer(threading.Thread):
    """Threaded traffic analyzer.

    Consumes packet metadata dictionaries from a queue and aggregates
    statistics per source IP address. It maintains a rolling window of the
    most recent events for use in rate calculations. Aggregated statistics
    are exposed via properties for consumption by the detection and
    dashboard modules.
    """

    def __init__(self, queue: Queue, window_seconds: int = 60):
        super().__init__(daemon=True)
        self.queue = queue
        self.window_seconds = window_seconds
        # deques for storing packet metadata within time window
        self._history: Deque[Dict[str, Any]] = deque()
        # aggregated statistics keyed by src_ip
        self._host_stats: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
            "packets": 0,
            "bytes": 0,
            "ports": set(),
            "protocols": defaultdict(int),
            "last_seen": 0,
        })
        self._lock = threading.Lock()
        self._stop_event = threading.Event()

    def stop(self) -> None:
        self._stop_event.set()

    def stopped(self) -> bool:
        return self._stop_event.is_set()

    @property
    def host_stats(self) -> Dict[str, Dict[str, Any]]:
        with self._lock:
            # Return a copy to prevent race conditions
            return {host: {
                "packets": stats["packets"],
                "bytes": stats["bytes"],
                "ports": set(stats["ports"]),
                "protocols": dict(stats["protocols"]),
                "last_seen": stats["last_seen"],
            } for host, stats in self._host_stats.items()}

    @property
    def history(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._history)

    def run(self) -> None:
        while not self.stopped():
            try:
                meta = self.queue.get(timeout=1.0)
            except Exception:
                # periodically prune history even if no new packets
                self._prune_old()
                continue
            with self._lock:
                self._history.append(meta)
                # update per-host stats
                src = meta.get("src_ip")
                if src:
                    stats = self._host_stats[src]
                    stats["packets"] += 1
                    stats["bytes"] += meta.get("size", 0)
                    port = meta.get("dst_port")
                    if port:
                        stats["ports"].add(port)
                    proto = meta.get("protocol")
                    if proto is not None:
                        stats["protocols"][proto] += 1
                    stats["last_seen"] = meta.get("timestamp", time.time())
                # prune history outside window
                self._prune_old()

    def _prune_old(self) -> None:
        """Remove events older than the window."""
        cutoff = time.time() - self.window_seconds
        while self._history and self._history[0]["timestamp"] < cutoff:
            old = self._history.popleft()
            # we could decrement stats here, but for simplicity we let
            # host_stats be cumulative and use history for rate calculations.
            # This means the counters are lifetime counts.
            # Rate calculations should rely on history instead.

    def packet_rate(self, src_ip: str, interval: int = 10) -> float:
        """Compute packet rate (packets per second) for a host over the given interval."""
        cutoff = time.time() - interval
        with self._lock:
            count = sum(1 for meta in self._history if meta.get("src_ip") == src_ip and meta["timestamp"] >= cutoff)
        return count / interval

    def unique_ports_count(self, src_ip: str, interval: int = 10) -> int:
        """Compute number of distinct destination ports contacted by a host in the given interval."""
        cutoff = time.time() - interval
        ports = set()
        with self._lock:
            for meta in self._history:
                if meta.get("src_ip") == src_ip and meta["timestamp"] >= cutoff:
                    port = meta.get("dst_port")
                    if port:
                        ports.add(port)
        return len(ports)

    def unique_connections_count(self, src_ip: str, interval: int = 10) -> int:
        """Compute number of distinct destination IP/port pairs contacted by a host in the interval."""
        cutoff = time.time() - interval
        connections = set()
        with self._lock:
            for meta in self._history:
                if meta.get("src_ip") == src_ip and meta["timestamp"] >= cutoff:
                    dst_ip = meta.get("dst_ip")
                    dst_port = meta.get("dst_port")
                    if dst_ip:
                        connections.add((dst_ip, dst_port))
        return len(connections)

    def average_packet_size(self, src_ip: str, interval: int = 10) -> float:
        """Compute the average packet size in bytes for a host over the given interval."""
        cutoff = time.time() - interval
        total_size = 0
        count = 0
        with self._lock:
            for meta in self._history:
                if meta.get("src_ip") == src_ip and meta["timestamp"] >= cutoff:
                    total_size += meta.get("size", 0)
                    count += 1
        return (total_size / count) if count > 0 else 0.0

    def protocol_entropy(self, src_ip: str, interval: int = 10) -> float:
        """Compute the Shannon entropy of protocol distribution for a host in the interval."""
        import math
        cutoff = time.time() - interval
        counts = {}
        total = 0
        with self._lock:
            for meta in self._history:
                if meta.get("src_ip") == src_ip and meta["timestamp"] >= cutoff:
                    proto = meta.get("protocol")
                    counts[proto] = counts.get(proto, 0) + 1
                    total += 1
        if total == 0:
            return 0.0
        entropy = 0.0
        for c in counts.values():
            p = c / total
            entropy -= p * math.log2(p)
        return entropy

    def unique_ports_by_dst(self, src_ip: str, interval: int = 10) -> Dict[str, set]:
        """Return a mapping dst_ip -> set of dst_ports contacted by src_ip in interval."""
        cutoff = time.time() - interval
        mapping: Dict[str, set] = {}
        with self._lock:
            for meta in self._history:
                if meta.get("src_ip") == src_ip and meta["timestamp"] >= cutoff:
                    dst = meta.get("dst_ip")
                    port = meta.get("dst_port")
                    if not dst:
                        continue
                    mapping.setdefault(dst, set())
                    if port:
                        mapping[dst].add(port)
        return mapping

    def dst_ips_by_dst_port(self, src_ip: str, interval: int = 10) -> Dict[int, set]:
        """Return a mapping dst_port -> set of dst_ips contacted by src_ip in interval."""
        cutoff = time.time() - interval
        mapping: Dict[int, set] = {}
        with self._lock:
            for meta in self._history:
                if meta.get("src_ip") == src_ip and meta["timestamp"] >= cutoff:
                    dst = meta.get("dst_ip")
                    port = meta.get("dst_port")
                    if not dst or not port:
                        continue
                    mapping.setdefault(port, set()).add(dst)
        return mapping

    def bytes_to_external(self, src_ip: str, interval: int = 60) -> int:
        """Sum bytes sent from src_ip to external (non-private) destinations in interval."""
        cutoff = time.time() - interval
        total = 0
        with self._lock:
            for meta in self._history:
                if meta.get("src_ip") == src_ip and meta["timestamp"] >= cutoff:
                    dst = meta.get("dst_ip")
                    size = meta.get("size", 0) or 0
                    if not dst:
                        continue
                    try:
                        ip = ipaddress.ip_address(dst)
                        if ip.is_private:
                            continue
                    except Exception:
                        # non-IP or malformed, skip
                        continue
                    total += size
        return total

    def connection_interarrival_times(self, src_ip: str, dst_ip: str, interval: int = 300) -> List[float]:
        """Return list of inter-arrival times (seconds) for connections from src_ip to dst_ip within interval.

        The list is ordered by time and contains the differences between consecutive timestamps.
        """
        cutoff = time.time() - interval
        times: List[float] = []
        with self._lock:
            for meta in self._history:
                if meta.get("src_ip") == src_ip and meta.get("dst_ip") == dst_ip and meta["timestamp"] >= cutoff:
                    times.append(meta["timestamp"])
        if len(times) < 2:
            return []
        times.sort()
        inter = [t2 - t1 for t1, t2 in zip(times, times[1:])]
        return inter