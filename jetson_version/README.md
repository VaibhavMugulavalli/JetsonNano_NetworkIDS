# Jetson Version

Minimal runtime for Jetson Nano network monitoring.

## Core files you need

- `jetson_network_monitor/` - capture, analysis, detection, dashboard, ML wrapper
- `run_jetson_monitor.py` - main launcher
- `allowed_hosts.txt` - optional allowlist
- `train_model.py` - standalone trainer (works in Jetson or Colab)
- `DIRECT_CABLE_SIMULATION_GUIDE.md` - no-switch testing from PC over Ethernet
- `COLAB_TRAINING_GUIDE.md` - train in Google Colab and drop `model.pkl` into this folder

## Install dependencies (Jetson/Linux)

```bash
sudo apt update
sudo apt install -y python3 python3-pip
sudo pip3 install scapy flask pandas scikit-learn numpy
```

## Run monitor

```bash
cd jetson_version
sudo python3 run_jetson_monitor.py \
  --interface eth0 \
  --allowed-hosts allowed_hosts.txt \
  --dashboard-port 5000
```

Open:
- `http://<jetson-ip>:5000`

## Drop-in model behavior

If `jetson_version/model.pkl` exists, `run_jetson_monitor.py` auto-loads it.

You can still pass a custom model explicitly:

```bash
sudo python3 run_jetson_monitor.py --interface eth0 --ml-model model.pkl --anomaly-threshold -0.55
```

## Local training quick command

```bash
python3 train_model.py --input large_synthetic_training_data.csv --output model.pkl
```

## Alert types

- `port_scan`
- `traffic_flood`
- `unknown_host`
- `ml_anomaly`
