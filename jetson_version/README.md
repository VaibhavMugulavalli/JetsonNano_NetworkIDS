# Jetson Version

This directory contains the Linux/Jetson deployment of the network monitor. It captures traffic, computes host-level metrics, detects suspicious patterns, and serves a web dashboard.

For a full beginner-friendly, hardware-to-dashboard walkthrough (including Ruckus ICX 7150 switch commands), see:
`BEGINNER_ICX7150_DEPLOYMENT_GUIDE.md`

## Contents

* `jetson_network_monitor/` - core package (capture, analysis, detection, dashboard, ML model wrapper)
* `run_jetson_monitor.py` - convenience launcher for Jetson/Linux
* `allowed_hosts.txt` - optional allowlist for known hosts
* `train_model.py` - trains an IsolationForest model from feature CSV data
* `collect_training_data.py` - captures live traffic features to CSV for model training
* `generate_generic_training_data.py` - generates synthetic, environment-agnostic training data
* `generic_training_data.csv` - ready-to-use generic baseline dataset
* `sample_training_data.csv` - original sample feature dataset

## Prerequisites

1. Python 3.8+ on Jetson/Linux.
2. Root or equivalent capture privileges.
3. Python dependencies:

```bash
sudo apt update
sudo apt install -y python3 python3-pip
sudo pip3 install scapy flask pandas scikit-learn numpy
```

## Run the monitor

```bash
cd jetson_version
sudo python3 run_jetson_monitor.py \
  --interface eth0 \
  --allowed-hosts allowed_hosts.txt \
  --scan-threshold 50 \
  --flood-threshold 100 \
  --dashboard-port 5000
```

If you have a trained model, include:

```bash
--ml-model model.pkl --anomaly-threshold -0.45
```

Open `http://<jetson-ip>:5000`.

## What the dashboard shows

* Summary cards: active hosts, cumulative packet count, total bytes, and alerts in the last 15 minutes.
* Top talkers: the five busiest source hosts by packet count.
* Host inventory table: per-source packets, bytes, unique ports, protocol mix, and last-seen time.
* Alert stream: live alerts with severity styling and filters (by type and source IP).

Dashboard data is pulled from:
* `/data/host_stats` for aggregated host metrics
* `/data/alerts` for recent alerts

## Training a generic ML model

The model uses these features:

* `packet_rate`
* `connection_rate`
* `avg_packet_size`
* `protocol_entropy`

### Option A: use included generic dataset

```bash
python3 train_model.py \
  --input generic_training_data.csv \
  --output model.pkl
```

### Option B: generate a new generic dataset

```bash
python3 generate_generic_training_data.py \
  --output generic_training_data.csv \
  --rows 5000 \
  --anomaly-ratio 0.08 \
  --seed 42
```

Then train:

```bash
python3 train_model.py \
  --input generic_training_data.csv \
  --output model.pkl
```

`train_model.py` automatically filters to `label=normal` rows when a `label` column is present and prints a suggested starting value for `--anomaly-threshold`.

## Collecting live training data (from mirrored traffic)

You can build your own environment-specific CSV on Jetson:

```bash
sudo python3 collect_training_data.py \
  --interface eth0 \
  --output live_training_data.csv \
  --duration 900 \
  --sample-interval 2 \
  --window 10 \
  --label normal
```

Then train:

```bash
python3 train_model.py \
  --input live_training_data.csv \
  --output model.pkl
```

## Alert types

* `port_scan` - many unique destination ports in a short interval
* `traffic_flood` - very high packet rate
* `unknown_host` - source not in allowlist appears for first time
* `ml_anomaly` - model score below configured threshold
