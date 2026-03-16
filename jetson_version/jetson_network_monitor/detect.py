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
import time
import logging
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
                 ml_detector: Any = None, anomaly_threshold: float = -0.5):
        super().__init__(daemon=True)
        self.analyzer = analyzer
        self.alert_queue = alert_queue
        self.allowed_ips: Set[str] = set(allowed_ips or [])
        self.scan_port_threshold = scan_port_threshold
        self.flood_rate_threshold = flood_rate_threshold
        self.check_interval = check_interval
        self.ml_detector = ml_detector
        self.anomaly_threshold = anomaly_threshold
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
            # port scan detection
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