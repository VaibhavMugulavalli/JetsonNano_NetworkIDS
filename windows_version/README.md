# Windows Utilities

This folder is now focused on PC-side traffic generation for Jetson testing.

## Files

- `simulate_traffic_to_jetson.py` - send simulated traffic to Jetson over Ethernet
- `run_windows_monitor.py` - optional: run monitor locally on Windows
- `jetson_network_monitor/` - shared core package

## Install

```powershell
pip install scapy flask pandas scikit-learn numpy
```

## Simulate traffic to Jetson

```powershell
cd windows_version
python simulate_traffic_to_jetson.py `
  --target-ip 192.168.50.2 `
  --profile mixed `
  --duration 900 `
  --rate 250 `
  --workers 4
```

Profiles:
- `normal`
- `port_scan`
- `flood`
- `beacon`
- `protocol_shift`
- `mixed`
