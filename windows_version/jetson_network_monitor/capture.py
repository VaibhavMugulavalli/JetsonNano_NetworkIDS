"""Packet capture module.

This module defines a PacketCapture class which can sniff packets on a network
interface and push high‑level metadata into a shared queue for further
processing. It attempts to use scapy for packet sniffing because scapy
provides robust parsing of a wide variety of protocols. If scapy is not
available, it falls back to using a raw socket, which may be limited to
Ethernet frames and requires root privileges.

Usage:
    from jetson_network_monitor.capture import PacketCapture
    from queue import Queue
    q = Queue()
    capturer = PacketCapture(interface='eth0', queue=q)
    capturer.start()
    # consumption of q by analysis module

Note: capturing packets requires the process to run with sufficient
privileges (CAP_NET_RAW or root). When running on Jetson Nano, ensure the
script is executed with sudo or capabilities are assigned appropriately.
"""

import threading
import time
import logging
import platform
from queue import Queue

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP
    _SCAPY_AVAILABLE = True
except ImportError:
    _SCAPY_AVAILABLE = False

import socket


logger = logging.getLogger(__name__)


class PacketCapture(threading.Thread):
    """Threaded packet capture.

    This class encapsulates packet sniffing on a given network interface. It
    continuously captures packets and extracts summary metadata which is
    placed into a Queue for downstream analysis. Capturing can be stopped
    gracefully by calling the ``stop`` method.
    """

    def __init__(self, interface: str, queue: Queue, promisc: bool = True):
        super().__init__(daemon=True)
        self.interface = interface
        self.queue = queue
        self.promisc = promisc
        self._stop_event = threading.Event()

    def stop(self) -> None:
        """Signal the capture thread to stop."""
        self._stop_event.set()

    def stopped(self) -> bool:
        return self._stop_event.is_set()

    def run(self) -> None:
        if _SCAPY_AVAILABLE:
            self._run_scapy()
        else:
            logger.warning("Scapy not available, falling back to raw socket capture")
            self._run_raw_socket()

    def _run_scapy(self) -> None:
        """Capture packets using scapy sniff. Runs until stop is signaled."""

        def process_packet(pkt) -> None:
            if self.stopped():
                return True  # stop sniffing
            # Extract timestamp and layer info
            ts = time.time()
            # default values
            src_ip = dst_ip = ""
            protocol = None
            src_port = dst_port = None
            size = len(pkt)
            # Determine IP layer
            if IP in pkt:
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                protocol = pkt[IP].proto
                if TCP in pkt:
                    protocol = 6
                    src_port = pkt[TCP].sport
                    dst_port = pkt[TCP].dport
                elif UDP in pkt:
                    protocol = 17
                    src_port = pkt[UDP].sport
                    dst_port = pkt[UDP].dport
                elif ICMP in pkt:
                    protocol = 1
            # Put summary into queue
            meta = {
                "timestamp": ts,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "protocol": protocol,
                "src_port": src_port,
                "dst_port": dst_port,
                "size": size,
            }
            try:
                self.queue.put_nowait(meta)
            except Exception as exc:
                logger.exception("Failed to enqueue packet metadata: %s", exc)

        # Start sniffing; scapy will run in this thread.
        # Common Windows failures are bad interface names or missing Npcap.
        try:
            sniff(iface=self.interface, prn=process_packet, store=False, stop_filter=lambda x: self.stopped(), promisc=self.promisc)
        except Exception as exc:
            logger.error(
                "Packet capture failed on interface '%s': %s. "
                "On Windows, verify Npcap is installed and the interface name is exact.",
                self.interface,
                exc,
            )

    def _run_raw_socket(self) -> None:
        """Capture packets using raw socket if scapy is unavailable.

        This method listens on a raw socket and extracts Ethernet/IP/TCP/UDP
        metadata manually. It is limited compared to scapy but sufficient for
        this project. Running this requires root privileges.
        """
        if not hasattr(socket, "AF_PACKET"):
            logger.error(
                "Raw socket fallback is not supported on %s. "
                "Install scapy + Npcap to capture packets on Windows.",
                platform.system(),
            )
            return
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
            sock.bind((self.interface, 0))
        except Exception as exc:
            logger.error("Could not open raw socket on %s: %s", self.interface, exc)
            return
        sock.settimeout(1.0)
        while not self.stopped():
            try:
                raw_data, addr = sock.recvfrom(65535)
                ts = time.time()
                size = len(raw_data)
                # Extract Ethernet frame
                if size < 14:
                    continue
                eth_proto = int.from_bytes(raw_data[12:14], 'big')
                if eth_proto != 0x0800:  # IPv4
                    continue
                # Extract IP header
                ip_header = raw_data[14:34]
                ver_ihl = ip_header[0]
                ihl = (ver_ihl & 0x0F) * 4
                protocol = ip_header[9]
                src_ip = socket.inet_ntoa(ip_header[12:16])
                dst_ip = socket.inet_ntoa(ip_header[16:20])
                src_port = dst_port = None
                # Extract ports for TCP/UDP
                if protocol in (6, 17):
                    # start of transport header
                    start = 14 + ihl
                    if start + 4 <= len(raw_data):
                        src_port = int.from_bytes(raw_data[start:start+2], 'big')
                        dst_port = int.from_bytes(raw_data[start+2:start+4], 'big')
                meta = {
                    "timestamp": ts,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "protocol": protocol,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "size": size,
                }
                try:
                    self.queue.put_nowait(meta)
                except Exception:
                    pass
            except socket.timeout:
                continue
            except Exception as exc:
                logger.exception("Raw socket capture error: %s", exc)
                break
