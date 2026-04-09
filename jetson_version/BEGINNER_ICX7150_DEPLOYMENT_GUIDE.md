# Beginner Deployment Guide: Jetson Nano + Ruckus ICX 7150

This guide is for absolute beginners. Follow it top to bottom and copy/paste commands.

It covers:
- Hardware wiring and topology
- Ruckus ICX 7150 port mirroring (SPAN)
- Optional VLAN setup (for management segmentation)
- Jetson setup and dependency install
- Running this project
- Accessing and validating the dashboard
- Optional ML model training
- Optional auto-start on boot

## 1. What You Need

Hardware:
- 1 x Jetson Nano (with Linux installed)
- 1 x Ruckus ICX 7150 switch
- 2+ Ethernet cables
- 1 x laptop/PC for browser access
- Optional: Jetson Wi-Fi adapter or second NIC for easier management

Software:
- This repository on Jetson
- Switch admin access (console, SSH, or web-managed CLI)

## 2. Final Network Design (Simple and Recommended)

Use this as your base layout:

1. `ICX source port(s)` = ports where traffic originates (hosts/uplink/etc.).
2. `ICX destination mirror port` = port connected to Jetson `eth0`.
3. `Jetson management path` = either Wi-Fi (`wlan0`) or separate Ethernet/NIC.

Why this is recommended:
- SPAN destination ports are for mirrored traffic capture.
- Management traffic is more stable on a separate interface/path.

## 3. Choose Your Ports and Values First

Before typing commands, write these down:

- `MIRROR_DEST_PORT` (example: `1/1/24`)
- `SOURCE_PORT_1` (example: `1/1/1`)
- `SOURCE_PORT_2` (optional, example: `1/1/2`)
- `JETSON_CAPTURE_IFACE` (usually `eth0`)
- `DASHBOARD_PORT` (default `5000`)

Optional management VLAN values:
- `MGMT_VLAN_ID` (example `99`)
- `MGMT_GW` (example `192.168.99.1`)
- `SWITCH_MGMT_IP` (example `192.168.99.2/24`)
- `JETSON_MGMT_IP` (optional static, example `192.168.99.20/24`)

## 4. ICX 7150: Pre-Check and Backup

Log into the switch and run:

```bash
enable
show version
show interfaces brief
show vlan brief
show mirror
show monitor
show running-config
```

Save a backup copy of current config:

```bash
copy running-config startup-config
```

## 5. ICX 7150: Configure Port Mirroring (SPAN)

Replace ports with your real ports.

Example:
- Destination mirror port: `1/1/24`
- Source ports: `1/1/1` and `1/1/2`

Commands:

```bash
enable
configure terminal

mirror-port ethernet 1/1/24

interface ethernet 1/1/1
 monitor ethernet 1/1/24 both
 exit

interface ethernet 1/1/2
 monitor ethernet 1/1/24 both
 exit

end
write memory
```

Verify:

```bash
show mirror
show monitor
show running-config | include mirror
show running-config | include monitor
```

Important rules:
- Do not use the same port as both source and mirror destination.
- Avoid using a trunk port as the mirror destination.
- If source bandwidth is very high, some mirrored packets may drop at destination.

## 6. Optional: Management VLAN Setup (Only If You Need It)

You do not need VLAN configuration to run SPAN itself.

Use this section only if you want a dedicated management segment.

Example creates VLAN 99 and assigns:
- Uplink/trunk port tagged: `1/1/48`
- Local management access port untagged: `1/1/10`

```bash
enable
configure terminal

vlan 99 name MGMT by port
 tagged ethernet 1/1/48
 untagged ethernet 1/1/10
 router-interface ve 99
 exit

interface ve 99
 ip address 192.168.99.2 255.255.255.0
 exit

ip route 0.0.0.0/0 192.168.99.1

end
write memory
```

Verify VLAN:

```bash
show vlan brief
show ip interface brief
show running-config vlan 99
```

If your network already has management configured, do not duplicate this blindly. Match your existing design.

## 7. Jetson: System Setup

Open terminal on Jetson and run:

```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv git tcpdump
sudo pip3 install scapy flask pandas scikit-learn numpy
```

Confirm network interfaces:

```bash
ip -br link
ip -4 addr
```

Confirm which interface is connected to mirror destination port (usually `eth0`):

```bash
sudo ethtool eth0
```

If `ethtool` is missing:

```bash
sudo apt install -y ethtool
sudo ethtool eth0
```

## 8. Put This Project on Jetson

If cloning from Git:

```bash
cd ~
git clone <YOUR_REPO_URL> complete_project
cd complete_project/jetson_version
```

If already copied manually, just go to the folder:

```bash
cd ~/complete_project/jetson_version
```

Confirm files exist:

```bash
ls -la
```

You should see:
- `run_jetson_monitor.py`
- `allowed_hosts.txt`
- `train_model.py`
- `jetson_network_monitor/`

## 9. Validate Mirrored Traffic Before Running App

Run a short packet capture test:

```bash
sudo tcpdump -ni eth0 -c 30
```

Expected result:
- You should see packets from mirrored source ports.
- If you see nothing, fix switch mirror config and cabling before continuing.

## 10. Configure Allowed Hosts File (Optional but Recommended)

Edit:

```bash
cd ~/complete_project/jetson_version
nano allowed_hosts.txt
```

Format: one trusted IP per line.

Example:

```text
10.0.0.1
10.0.0.2
10.0.0.3
```

Save and exit (`Ctrl+O`, `Enter`, `Ctrl+X`).

## 11. Run the Monitor (No ML First)

From `jetson_version`:

```bash
sudo python3 run_jetson_monitor.py \
  --interface eth0 \
  --allowed-hosts allowed_hosts.txt \
  --scan-threshold 50 \
  --flood-threshold 100 \
  --dashboard-port 5000 \
  --window 60
```

What this runs internally:
- Packet capture thread
- Traffic analyzer thread
- Threat detector thread
- Flask dashboard server

## 12. Open Dashboard

Find Jetson IP on management interface:

```bash
ip -4 addr
```

From your laptop browser:

```text
http://<JETSON_IP>:5000
```

Also available locally on Jetson:

```text
http://127.0.0.1:5000
```

## 13. Test End-to-End Alerts

Generate test traffic from a mirrored source host.

Examples:
- Open many different ports quickly to trigger `port_scan`.
- Send very high packet rate to trigger `traffic_flood`.
- Send traffic from non-allowlisted IP to trigger `unknown_host`.

Watch alert stream in dashboard.

## 14. Optional ML Setup

### 14.1 Train model from included generic dataset

```bash
cd ~/complete_project/jetson_version
python3 train_model.py \
  --input generic_training_data.csv \
  --output model.pkl \
  --contamination 0.05
```

The script prints a suggested `--anomaly-threshold`.

### 14.2 Optional: generate new synthetic dataset and retrain

```bash
cd ~/complete_project/jetson_version
python3 generate_generic_training_data.py \
  --output generic_training_data.csv \
  --rows 5000 \
  --anomaly-ratio 0.08 \
  --seed 42

python3 train_model.py \
  --input generic_training_data.csv \
  --output model.pkl \
  --contamination 0.05
```

### 14.3 Run monitor with ML enabled

```bash
cd ~/complete_project/jetson_version
sudo python3 run_jetson_monitor.py \
  --interface eth0 \
  --allowed-hosts allowed_hosts.txt \
  --scan-threshold 50 \
  --flood-threshold 100 \
  --dashboard-port 5000 \
  --window 60 \
  --ml-model model.pkl \
  --anomaly-threshold -0.45
```

### 14.4 Build training CSV from your real mirrored traffic (recommended)

Collect feature rows directly on Jetson:

```bash
cd ~/complete_project/jetson_version
sudo python3 collect_training_data.py \
  --interface eth0 \
  --output live_training_data.csv \
  --duration 1800 \
  --sample-interval 2 \
  --window 10 \
  --label normal
```

Then train model from that CSV:

```bash
cd ~/complete_project/jetson_version
python3 train_model.py \
  --input live_training_data.csv \
  --output model.pkl \
  --contamination 0.05
```

Then run deployment with the trained model:

```bash
cd ~/complete_project/jetson_version
sudo python3 run_jetson_monitor.py \
  --interface eth0 \
  --allowed-hosts allowed_hosts.txt \
  --scan-threshold 50 \
  --flood-threshold 100 \
  --dashboard-port 5000 \
  --window 60 \
  --ml-model model.pkl \
  --anomaly-threshold -0.45
```

### 14.5 Expand a small real sample into synthetic normal + threats

If your real capture is repetitive (for example many near-identical rows), use:

```bash
cd ~/complete_project/jetson_version
python3 generate_seeded_synthetic_data.py \
  --input live_training_data.csv \
  --output seeded_synthetic_data.csv \
  --rows 6000 \
  --anomaly-ratio 0.12 \
  --seed 42
```

Then train:

```bash
cd ~/complete_project/jetson_version
python3 train_model.py \
  --input seeded_synthetic_data.csv \
  --output model.pkl \
  --contamination 0.05
```

Deploy:

```bash
cd ~/complete_project/jetson_version
sudo python3 run_jetson_monitor.py \
  --interface eth0 \
  --allowed-hosts allowed_hosts.txt \
  --scan-threshold 50 \
  --flood-threshold 100 \
  --dashboard-port 5000 \
  --window 60 \
  --ml-model model.pkl \
  --anomaly-threshold -0.45
```

## 15. Optional Auto-Start On Boot (systemd)

Create service file:

```bash
sudo nano /etc/systemd/system/jetson-monitor.service
```

Paste:

```ini
[Unit]
Description=Jetson Network Monitor
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/home/<YOUR_USER>/complete_project/jetson_version
ExecStart=/usr/bin/python3 /home/<YOUR_USER>/complete_project/jetson_version/run_jetson_monitor.py --interface eth0 --allowed-hosts allowed_hosts.txt --scan-threshold 50 --flood-threshold 100 --dashboard-port 5000 --window 60
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable jetson-monitor
sudo systemctl start jetson-monitor
sudo systemctl status jetson-monitor
```

View live logs:

```bash
sudo journalctl -u jetson-monitor -f
```

## 16. Troubleshooting Commands (Copy/Paste)

Switch-side:

```bash
show mirror
show monitor
show interfaces brief
show vlan brief
```

Jetson-side:

```bash
ip -br link
ip -4 addr
sudo tcpdump -ni eth0 -c 20
sudo ss -lntp | grep 5000
```

If app is running but dashboard unreachable:

```bash
sudo ufw status
sudo iptables -L -n
```

## 17. Files in This Repo You Actually Run

Primary runtime:
- `jetson_version/run_jetson_monitor.py`
- `jetson_version/jetson_network_monitor/run_monitor.py`

Optional ML:
- `jetson_version/train_model.py`
- `jetson_version/generate_generic_training_data.py`
- `jetson_version/jetson_network_monitor/ml_model.py`

Config file:
- `jetson_version/allowed_hosts.txt`

## 18. Safe Rollback (If Mirror Config Causes Issues)

On ICX, remove monitor from source interfaces and remove mirror destination:

```bash
enable
configure terminal

interface ethernet 1/1/1
 no monitor ethernet 1/1/24 both
 exit

interface ethernet 1/1/2
 no monitor ethernet 1/1/24 both
 exit

no mirror-port ethernet 1/1/24

end
write memory
```

Adjust ports to your actual values.

## 19. One-Command Quick Start (After Everything Is Configured)

```bash
cd ~/complete_project/jetson_version && sudo python3 run_jetson_monitor.py --interface eth0 --allowed-hosts allowed_hosts.txt --scan-threshold 50 --flood-threshold 100 --dashboard-port 5000 --window 60
```
