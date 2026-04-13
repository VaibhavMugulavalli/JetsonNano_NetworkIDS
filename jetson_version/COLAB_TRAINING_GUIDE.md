# Google Colab Training Guide (Drop-In `model.pkl`)

This workflow trains in Colab, then you copy `model.pkl` into `jetson_version/`.

## 1. Open Colab and install libs

In a Colab cell:

```python
!pip -q install pandas scikit-learn numpy
```

## 2. Upload files

Upload:
- `train_model.py` (from this `jetson_version` folder)
- your dataset CSV (for example `large_synthetic_training_data.csv` or your own `training_data.csv`)

Colab file upload cell:

```python
from google.colab import files
uploaded = files.upload()
print(uploaded.keys())
```

## 3. Train model in Colab

Run:

```python
!python train_model.py --input large_synthetic_training_data.csv --output model.pkl --contamination 0.05
```

If your filename is different, replace `--input` value.

The script prints a suggested anomaly threshold (p05 score).

## 4. Download trained pickle

```python
from google.colab import files
files.download("model.pkl")
```

## 5. Drop model into Jetson project

Copy downloaded `model.pkl` to:

`jetson_version/model.pkl`

## 6. Run on Jetson

Because launcher auto-loads `model.pkl`, run:

```bash
cd jetson_version
sudo python3 run_jetson_monitor.py --interface eth0 --dashboard-port 5000 --allowed-hosts allowed_hosts.txt
```

Optional explicit threshold:

```bash
sudo python3 run_jetson_monitor.py --interface eth0 --dashboard-port 5000 --ml-model model.pkl --anomaly-threshold -0.55
```
