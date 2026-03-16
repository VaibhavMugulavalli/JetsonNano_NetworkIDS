# Windows Version

This directory contains the Windows deployment of the network monitor. It captures traffic, computes host-level metrics, detects suspicious behavior, and serves a local dashboard.

## Contents

* `jetson_network_monitor/` - core package (capture, analysis, detection, dashboard, ML model wrapper)
* `run_windows_monitor.py` - monitor launcher for Windows
* `allowed_hosts.txt` - optional allowlist for known hosts
* `train_model.py` - trains an IsolationForest model from CSV features
* `generate_generic_training_data.py` - creates generic synthetic feature data
* `generic_training_data.csv` - baseline generic dataset for quick training

## Prerequisites

1. Python 3.8+.
2. Npcap installed (WinPcap compatibility enabled).
3. Install dependencies (PowerShell as Administrator recommended):

```powershell
pip install scapy flask pandas scikit-learn numpy
```

## Run the monitor

```powershell
cd windows_version
python run_windows_monitor.py `
  --interface "Wi-Fi" `
  --allowed-hosts allowed_hosts.txt `
  --scan-threshold 50 `
  --flood-threshold 100 `
  --dashboard-port 5000
```

If testing ML detection, include:

```powershell
--ml-model model.pkl --anomaly-threshold -0.45
```

Open `http://localhost:5000`.

## Dashboard features

* Summary cards: active hosts, total packets, total bytes, and alerts in the last 15 minutes.
* Top talkers: busiest source hosts by packet count.
* Host inventory: sortable table (packets, bytes, unique ports, protocol mix, last seen).
* Alert stream: severity-styled alerts with filter by type and source IP.

## Train ML model on Windows

Feature columns used:

* `packet_rate`
* `connection_rate`
* `avg_packet_size`
* `protocol_entropy`

### Option A: use included dataset

```powershell
python train_model.py `
  --input generic_training_data.csv `
  --output model.pkl
```

### Option B: generate a fresh generic dataset

```powershell
python generate_generic_training_data.py `
  --output generic_training_data.csv `
  --rows 5000 `
  --anomaly-ratio 0.08 `
  --seed 42
```

Then train:

```powershell
python train_model.py `
  --input generic_training_data.csv `
  --output model.pkl
```

`train_model.py` filters to `label=normal` rows when a `label` column exists and prints a suggested anomaly threshold.

## Alert types

* `port_scan` - many unique destination ports in a short interval
* `traffic_flood` - very high packet rate
* `unknown_host` - host not present in allowlist
* `ml_anomaly` - model score below threshold
