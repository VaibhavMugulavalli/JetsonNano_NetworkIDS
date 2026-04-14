# Direct Cable Simulation Guide (No Switch Needed)

This guide lets you skip switch/SPAN configuration entirely.

You will:
1. Connect a Windows PC directly to Jetson Nano via Ethernet.
2. Generate realistic traffic from the PC using Python.
3. Capture/analyze that traffic on Jetson.
4. Train a model in Colab and drop `model.pkl` into Jetson project.

## 1. Physical Setup

1. Connect `PC Ethernet` <-> `Jetson eth0` with one Ethernet cable.
2. Keep Jetson internet (if needed) on Wi-Fi or another interface.

## 2. Configure IP Addresses (Same Subnet)

Pick these example IPs:
- Windows PC Ethernet: `192.168.50.10/24`
- Jetson eth0: `192.168.50.2/24`

### 2.1 Windows (PowerShell as Administrator)

Find interface name:

```powershell
Get-NetAdapter
```

Set static IP (replace `"Ethernet"` if your adapter name differs):

```powershell
New-NetIPAddress -InterfaceAlias "Ethernet" -IPAddress 192.168.50.10 -PrefixLength 24
```

If IP already exists and command fails, remove old one then retry:

```powershell
Get-NetIPAddress -InterfaceAlias "Ethernet" -AddressFamily IPv4
Remove-NetIPAddress -InterfaceAlias "Ethernet" -IPAddress <OLD_IP> -Confirm:$false
New-NetIPAddress -InterfaceAlias "Ethernet" -IPAddress 192.168.50.10 -PrefixLength 24
```

### 2.2 Jetson (Linux)

Set temporary IP on eth0:

```bash
sudo ip addr flush dev eth0
sudo ip addr add 192.168.50.2/24 dev eth0
sudo ip link set eth0 up
ip -4 addr show eth0
```

## 3. Verify Link Connectivity

From Windows:

```powershell
ping 192.168.50.2
```

From Jetson:

```bash
ping -c 4 192.168.50.10
```

If ping fails, check cable, interface name, and IP assignment.

## 4. Run Jetson Monitor

On Jetson:

```bash
cd ~/complete_project/jetson_version
sudo python3 run_jetson_monitor.py \
  --interface eth0 \
  --allowed-hosts allowed_hosts.txt \
  --scan-threshold 50 \
  --flood-threshold 100 \
  --dashboard-port 5000 \
  --window 60
```

Open dashboard:
- Local on Jetson: `http://127.0.0.1:5000`
- Remote from same network (if reachable): `http://<jetson-management-ip>:5000`

## 5. Run PC Traffic Simulator

On Windows:

```powershell
cd <path-to-repo>\windows_version
python simulate_traffic_to_jetson.py `
  --target-ip 192.168.50.2 `
  --profile mixed `
  --duration 900 `
  --rate 250 `
  --workers 4
```

Profile examples:

```powershell
# Normal-like traffic
python simulate_traffic_to_jetson.py --target-ip 192.168.50.2 --profile normal --duration 300 --rate 80 --workers 2

# Port scan-heavy traffic
python simulate_traffic_to_jetson.py --target-ip 192.168.50.2 --profile port_scan --duration 180 --rate 300 --workers 4

# Flood-heavy traffic
python simulate_traffic_to_jetson.py --target-ip 192.168.50.2 --profile flood --duration 120 --rate 800 --workers 6
#ML Anomaly
python simulate_traffic_to_jetson.py --target-ip 192.168.50.2 --profile protocol_shift --duration 240 --rate 350 --workers 4

python simulate_traffic_to_jetson.py --target-ip 192.168.50.2 --profile beacon --duration 300 --rate 60 --workers 2
```

## 6. Collect Real Feature CSV on Jetson

Run while simulator is generating traffic:

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

## 7. Train Model in Colab

Follow:

`jetson_version/COLAB_TRAINING_GUIDE.md`

Result should be:

- `model.pkl` downloaded from Colab and copied to `jetson_version/model.pkl`

## 8. Deploy Trained Model on Jetson Monitor

Drop-in mode (auto-loads `model.pkl` if present):

```bash
cd ~/complete_project/jetson_version
sudo python3 run_jetson_monitor.py \
  --interface eth0 \
  --allowed-hosts allowed_hosts.txt \
  --dashboard-port 5000 \
  --window 60
```

Or explicit:

```bash
sudo python3 run_jetson_monitor.py --interface eth0 --ml-model model.pkl --anomaly-threshold -0.55
```

## 9. Optional: Restore Windows Ethernet to DHCP

When done testing:

```powershell
Get-NetIPAddress -InterfaceAlias "Ethernet" -AddressFamily IPv4
Remove-NetIPAddress -InterfaceAlias "Ethernet" -IPAddress 192.168.50.10 -Confirm:$false
Set-NetIPInterface -InterfaceAlias "Ethernet" -Dhcp Enabled
ipconfig /renew
```

## 10. Quick Troubleshooting

Jetson sees no traffic:

```bash
sudo tcpdump -ni eth0 -c 20
```

Dashboard up?

```bash
sudo ss -lntp | grep 5000
```

Windows route check:

```powershell
route print
```
