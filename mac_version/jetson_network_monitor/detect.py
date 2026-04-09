"""Threat detection module.

This module defines a ThreatDetector class that consumes aggregated
statistics from the TrafficAnalyzer to identify suspicious network
behaviours. Detected threats are reported via an alerts queue.

Detection rules implemented:

* Port Scan Detection – triggers when a host contacts a large number of
  distinct destination ports on any host within a time window (e.g., more
  than 50 ports in 10 seconds).

* Traffic Flood Detection – triggers when a host generates traffic at a
  sustained high packet rate (e.g., more than 100 packets per second).

* Unknown Host Detection – triggers when a host not on the allowed list
  appears on the network for the first time.

Additional rules can easily be added by extending the ``_check_rules``
method.
"""

import threading
import queue
import time
import logging
import statistics
from typing import List, Dict, Any, Set

from .analysis import TrafficAnalyzer


logger = logging.getLogger(__name__)


class ThreatDetector(threading.Thread):
    """Threaded threat detector.

    Periodically inspects traffic statistics provided by a TrafficAnalyzer
    instance and generates alerts for suspicious conditions. Alerts are
    dictionaries placed on an alert queue. Each alert contains a timestamp,
    the source IP, the type of event, and a human‑readable description.
    """

    def __init__(self, analyzer: TrafficAnalyzer, alert_queue: "queue.Queue", allowed_ips: List[str] = None,
                 scan_port_threshold: int = 50, flood_rate_threshold: float = 100.0, check_interval: float = 1.0,
                 ml_detector: Any = None, anomaly_threshold: float = -0.5,
                 horizontal_scan_threshold: int = 30, exfil_bytes_threshold: int = 1_000_000,
                 beacon_min_intervals: int = 6):
        super().__init__(daemon=True)
        self.analyzer = analyzer
        self.alert_queue = alert_queue
        self.allowed_ips: Set[str] = set(allowed_ips or [])
        self.scan_port_threshold = scan_port_threshold
        self.flood_rate_threshold = flood_rate_threshold
        self.check_interval = check_interval
        self.ml_detector = ml_detector
        self.anomaly_threshold = anomaly_threshold
        # threshold: number of distinct destination IPs seen on same dst_port
        self.horizontal_scan_threshold = horizontal_scan_threshold
        # threshold: bytes sent to external IPs within window to consider exfiltration
        self.exfil_bytes_threshold = exfil_bytes_threshold
        # minimum number of inter-arrival intervals required to consider beaconing
        self.beacon_min_intervals = beacon_min_intervals
        self._known_hosts: Set[str] = set()  # hosts we have already seen
        # maintain last alert times to avoid spamming
        self._last_alert: Dict[str, Dict[str, float]] = {}
        self._stop_event = threading.Event()

    def stop(self) -> None:
        self._stop_event.set()

    def stopped(self) -> bool:
        return self._stop_event.is_set()

    def run(self) -> None:
        while not self.stopped():
            try:
                self._check_rules()
            except Exception as exc:
                logger.exception("Error in threat detector: %s", exc)
            time.sleep(self.check_interval)

    def _check_rules(self) -> None:
        now = time.time()
        stats = self.analyzer.host_stats
        for src_ip, host_info in stats.items():
            # unknown host detection
            if src_ip not in self._known_hosts:
                self._known_hosts.add(src_ip)
                if self.allowed_ips and src_ip not in self.allowed_ips:
                    self._raise_alert(src_ip, "unknown_host",
                                     f"New host detected: {src_ip}", now)
            # port scan detection (vertical/horizontal split)
            # vertical: many ports contacted on a single destination host
            ports_by_dst = self.analyzer.unique_ports_by_dst(src_ip, interval=10)
            vertical_flag = False
            for dst, ports in ports_by_dst.items():
                if len(ports) >= self.scan_port_threshold:
                    vertical_flag = True
                    self._raise_alert(src_ip, "scan_vertical",
                                      f"Vertical port scan detected against {dst}: {len(ports)} ports", now)
            # horizontal: same port across many destination IPs
            dsts_by_port = self.analyzer.dst_ips_by_dst_port(src_ip, interval=10)
            for port, dsts in dsts_by_port.items():
                if len(dsts) >= self.horizontal_scan_threshold:
                    # report horizontal scan
                    self._raise_alert(src_ip, "scan_horizontal",
                                      f"Horizontal scan detected on port {port}: contacted {len(dsts)} hosts", now)
            # generic port_scan fallback for compatibility (counts unique ports across all destinations)
            if not vertical_flag:
                ports_count = self.analyzer.unique_ports_count(src_ip, interval=10)
                if ports_count >= self.scan_port_threshold:
                    self._raise_alert(src_ip, "port_scan",
                                      f"Possible port scan detected: {ports_count} ports contacted", now)
            # flood detection
            rate = self.analyzer.packet_rate(src_ip, interval=1)
            if rate >= self.flood_rate_threshold:
                self._raise_alert(src_ip, "traffic_flood",
                                  f"High packet rate detected: {rate:.1f} pkt/s", now)

            # ML anomaly detection
            if self.ml_detector is not None:
                try:
                    features = self._extract_features(src_ip)
                    score = self.ml_detector.predict(features)
                    if score <= self.anomaly_threshold:
                        self._raise_alert(src_ip, "ml_anomaly",
                                          f"Anomalous traffic pattern detected (score={score:.3f})", now)
                except Exception as exc:
                    logger.exception("ML anomaly detection failed: %s", exc)

            # Data exfiltration detection: bytes sent to external IPs in window
            try:
                exfil_bytes = self.analyzer.bytes_to_external(src_ip, interval=60)
                if exfil_bytes >= self.exfil_bytes_threshold:
                    self._raise_alert(src_ip, "data_exfiltration",
                                      f"Large outbound transfer detected: {exfil_bytes} bytes to external hosts in last 60s", now)
            except Exception:
                # be conservative and ignore failures here
                pass

            # Suspicious beaconing / periodic connections detection
            # For each destination contacted by src_ip, compute inter-arrival times and flag low-variance periodic patterns.
            try:
                # gather destinations seen recently
                ports_by_dst = self.analyzer.unique_ports_by_dst(src_ip, interval=300)
                for dst in ports_by_dst.keys():
                    inter = self.analyzer.connection_interarrival_times(src_ip, dst, interval=300)
                    # require minimum samples (at least 6 intervals -> 7 connections)
                    if len(inter) < 6:
                        continue
                    mean = statistics.mean(inter)
                    stdev = statistics.pstdev(inter) if mean > 0 else 0.0
                    cv = (stdev / mean) if mean > 0 else 1.0
                    # sensible bounds: ignore extremely rapid (<1s) or extremely sparse (>3600s) periodicity
                    if mean < 1.0 or mean > 3600.0:
                        continue
                    # if coefficient of variation is low, we likely have periodic beaconing
                    if cv <= 0.25:
                        self._raise_alert(src_ip, "suspicious_beaconing",
                                          f"Periodic connections to {dst}: period~{mean:.1f}s (cv={cv:.2f}, samples={len(inter)+1})", now)
            except Exception:
                # ignore detection failures to avoid crashing the detector
                pass

    def _raise_alert(self, src_ip: str, alert_type: str, description: str, timestamp: float) -> None:
        # avoid generating repeated alerts of the same type for a host within a cooldown period
        cooldown = 30  # seconds before raising same alert again
        last = self._last_alert.get(src_ip, {}).get(alert_type)
        if last and (timestamp - last) < cooldown:
            return
        self._last_alert.setdefault(src_ip, {})[alert_type] = timestamp
        alert = {
            "timestamp": timestamp,
            "src_ip": src_ip,
            "type": alert_type,
            "description": description,
        }
        # log the alert so it appears in stdout for simulator runs
        try:
            logger.info("Alert raised: %s %s", alert_type, alert)
        except Exception:
            pass
        try:
            self.alert_queue.put_nowait(alert)
        except Exception as exc:
            logger.error("Failed to enqueue alert: %s", exc)

    def _extract_features(self, src_ip: str) -> list:
        """Compute feature vector for a host: [packet_rate, connection_rate, avg_packet_size, protocol_entropy]."""
        # use 10s interval for features
        interval = 10
        packet_rate = self.analyzer.packet_rate(src_ip, interval)
        connection_rate = self.analyzer.unique_connections_count(src_ip, interval) / interval
        avg_size = self.analyzer.average_packet_size(src_ip, interval)
        entropy = self.analyzer.protocol_entropy(src_ip, interval)
        return [packet_rate, connection_rate, avg_size, entropy]