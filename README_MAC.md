# macOS — setup & run notes for Network Monitor

This document explains how to run the network monitor on macOS, what to install,
how to find the correct interface name, and troubleshooting tips. It also lists
suggested additional detection features you can add beyond the current alerts
(`port_scan`, `traffic_flood`, `unknown_host`, `ml_anomaly`) with short
implementation notes and priorities.

## Quick compatibility summary

- The core Python code (analysis, ML model wrapper, dashboard) is cross-platform.
- Packet capture uses `scapy` as the primary backend — scapy works on macOS
  (it uses libpcap). If `scapy` is installed and the process has capture
  privileges, live capture should work on macOS.
- The project has a Linux-only raw-socket fallback (uses `socket.AF_PACKET`) —
  that fallback will not work on macOS. Make sure `scapy` is available.

## Prerequisites (macOS)

- Python 3.8+ (system Python may be older; prefer Homebrew Python or pyenv).
- Xcode command-line tools:

```bash
xcode-select --install
```

- Homebrew (optional, but useful): https://brew.sh/
- Python virtual environment (recommended).

## Minimal Python dependencies

Create and activate a venv, then install packages. This list covers the common
imports observed in the project (scapy, ML and dashboard libs).

```bash
python3 -m venv venv
source venv/bin/activate
python -m pip install --upgrade pip
pip install scapy numpy scikit-learn flask pandas
```

If `scapy` fails to build or function, you can try installing/updating libpcap
via Homebrew or consult scapy install docs.

## Find the correct interface name on macOS

Use `ifconfig` or the `networksetup` helper to map a device name to a human
friendly name:

```bash
ifconfig
# or to map Hardware Port -> Device name
networksetup -listallhardwareports
```

Typical interface names on macOS are `en0`, `en1`, etc. Use whichever is
connected to the network you want to mirror/capture.

## Running the monitor on macOS

The project includes thin wrappers. Use the wrapper that exists in
the repository root (the `windows_version` wrapper is portable):

```bash
sudo python3 run_windows_monitor.py \
  --interface en0 \
  --dashboard-port 5000 \
  --allowed-hosts windows_version/allowed_hosts.txt
```

Notes:
- Capture usually requires elevated privileges on macOS — use `sudo`.
- Provide the correct path to `--allowed-hosts` and to any `--ml-model`.
- If you see permission prompts from macOS about network capture or
  accessibility, follow the system dialogs and grant the permissions.

## Troubleshooting common errors

- scapy import fails: ensure virtualenv activated and `pip install scapy` ran
  successfully. Check pip output for wheel build failures and install any
  missing build tools.
- scapy runs but sniffing on the chosen interface yields no packets:
  - confirm interface with `ifconfig` and that traffic exists on that interface.
  - ensure process has privileges (run with `sudo`).
- If code falls back to raw socket and prints an error about `AF_PACKET` or
  "Raw socket fallback is not supported on Darwin", that's expected — install
  scapy instead of relying on the raw fallback.

## Quick security & operational notes

- Run the monitor from a dedicated user or drop privileges after opening a
  capture handle if you add that code (open socket as root then drop privileges).
- Be careful with `pickle` model files from untrusted sources — they can
  deserialize arbitrary code. Prefer joblib or signed model artifacts for
  production.

