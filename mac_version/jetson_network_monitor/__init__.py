"""Network monitoring package for the Jetson Nano threat detection project.

This package contains modules for capturing packets from a mirrored switch port,
analyzing traffic patterns, detecting suspicious behaviour, and serving a
dashboard over HTTP. The software is designed to run on a Jetson Nano but can
run on any Linux host with an appropriate network interface and permissions.

See individual modules for details.
"""

__all__ = [
    "capture",
    "analysis",
    "detect",
    "dashboard",
    "run_monitor",
]