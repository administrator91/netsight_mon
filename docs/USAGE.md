# Usage Guide

## 1. Start the Application

Linux/Kali/Ubuntu:

```bash
sudo python3 netsight_mon.py
```

Windows:

Run PowerShell or Command Prompt as Administrator:

```powershell
python netsight_mon.py
```

Npcap must be installed on Windows for packet capture support.

## 2. Select Network Interface

- `lo`: localhost/loopback traffic from the same system.
- `eth0`: Ethernet/local network traffic visible to the selected adapter.
- Wi-Fi interface names may vary depending on the system.

## 3. Capture Packets

Click **START CAPTURE** to begin live packet monitoring. The packet table shows source IP, destination IP, ports, protocol, application protocol, and packet length.

## 4. Filter Packets

Examples:

```text
app==http
proto==tcp
port==443
ip==192.168.1.5
src==192.168.1.4 && app==http
domain contains google
```

## 5. Export PDF Report

Click **EXPORT PDF REPORT** after capturing packets. Reports are saved in:

```text
exported_reports/
```

The generated filename uses a timestamp to avoid overwriting previous reports.
