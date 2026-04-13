# Complete Network Monitoring Project

This repository has two folders:

- `jetson_version` - deploy monitor on Jetson Nano (recommended runtime path)
- `windows_version` - Windows utilities, including traffic simulation toward Jetson

## Recommended workflow

1. Simulate traffic from PC to Jetson using:
   - `windows_version/simulate_traffic_to_jetson.py`
2. Train model in Google Colab using:
   - `jetson_version/train_model.py`
   - `jetson_version/COLAB_TRAINING_GUIDE.md`
3. Drop `model.pkl` into `jetson_version/`.
4. Start Jetson monitor:

```bash
cd jetson_version
sudo python3 run_jetson_monitor.py --interface eth0 --dashboard-port 5000
```

If `model.pkl` exists in `jetson_version/`, it is auto-loaded.
