# Complete Network Monitoring Project

This repository contains two separate versions of the network monitoring system:

- **windows_version** – for testing the concept on a Windows laptop using Wi‑Fi or Ethernet.  This version uses Scapy with Npcap to capture packets and provides a minimal wrapper to run the core monitoring engine.
- **jetson_version** – designed for deployment on the Jetson Nano in a lab environment with a managed switch configured for port mirroring.  It includes the optional machine‑learning model and training script.

Each version contains the full `jetson_network_monitor` package required to run the system and one or more convenience scripts.  See the individual `README.md` files in each subdirectory for platform‑specific setup and execution instructions.