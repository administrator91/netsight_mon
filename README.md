<div align="center">

# 🌐 NetSight Monitor

### A Real-Time Network Monitoring and Traffic Analysis Tool

**Final Year B.Tech CSE Project**  
Developed by **Rajarshi Sarkar**

![Python](https://img.shields.io/badge/Python-3.x-blue?style=for-the-badge&logo=python)
![PyQt6](https://img.shields.io/badge/GUI-PyQt6-green?style=for-the-badge)
![Scapy](https://img.shields.io/badge/Packet%20Capture-Scapy-orange?style=for-the-badge)
![PDF](https://img.shields.io/badge/Report-FPDF-red?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-purple?style=for-the-badge)

</div>

---

## 📌 Project Overview

**NetSight Monitor** is a Python-based real-time network monitoring and traffic analysis tool developed as a final-year B.Tech Computer Science & Engineering project. The tool provides a graphical dashboard for capturing live packets, identifying protocols, monitoring visible plaintext HTTP/Form events, discovering connected devices, viewing live statistics, applying packet filters, and generating professional PDF reports.

The project is designed for **academic learning, authorized lab testing, network visibility, and security awareness**. It helps users understand how devices communicate over a network and how packet metadata can be analyzed in a structured and readable format.

> ⚠️ This tool is for authorized monitoring only. Do not use it on networks or systems without permission.

---

## ✨ Key Features

- ✅ Real-time packet capture from selected network interface
- ✅ PyQt6-based professional desktop GUI
- ✅ Live packet table with date, time, IP, port, protocol, application and length
- ✅ Detailed packet inspection panel
- ✅ Payload preview and raw hex view
- ✅ Protocol identification using packet layers and port mapping
- ✅ HTTP/Form Event monitoring for plaintext HTTP traffic in authorized environments
- ✅ Connected device discovery using ARP scanning
- ✅ Live statistics dashboard
- ✅ Packet filtering by IP, protocol, application, port and domain
- ✅ Professional PDF report generation
- ✅ Ethical-use documentation for safe academic publishing

---

## 🖥️ GUI Sections

| Section | Purpose |
|---|---|
| **Live Packet Inspector** | Captures and displays live packet metadata in table format. |
| **HTTP / Form Events** | Shows visible plaintext HTTP request/form events during authorized testing. |
| **Network Devices** | Discovers active local network devices using ARP scan. |
| **Live Statistics** | Displays total packets, protocol counts, application counts and top sources. |
| **Export PDF Report** | Generates a professional PDF report from captured session data. |

---

## 🧱 Technology Stack

| Component | Technology Used |
|---|---|
| Programming Language | Python 3.x |
| GUI Framework | PyQt6 |
| Packet Capture & Analysis | Scapy |
| PDF Report Generation | fpdf2 / FPDF |
| Network Helpers | socket, ipaddress, urllib, re |
| Data Counting | collections.Counter |
| Threading | QThread / threading |

---

## 📂 Repository Structure

```text
NetSight-Monitor/
├── netsight_mon.py                 # Main application source code
├── requirements.txt                # Python dependencies
├── README.md                       # GitHub project documentation
├── LICENSE                         # MIT license
├── SECURITY.md                     # Security and responsible use notes
├── .gitignore                      # Git ignore rules
├── docs/
│   ├── USAGE.md                    # Usage instructions
│   ├── ETHICAL_USE.md              # Ethical-use guidelines
│   └── PROJECT_REPORT_NOTES.md     # Academic report notes
└── assets/
    └── screenshots/
        └── README.md               # Screenshot placement guide
```

---

## ⚙️ Installation

### 1. Clone the Repository

```bash
git clone https://github.com/YOUR_USERNAME/NetSight-Monitor.git
cd NetSight-Monitor
```

Replace `YOUR_USERNAME` with your GitHub username.

### 2. Create a Virtual Environment

Linux / Kali / Ubuntu:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Windows:

```powershell
python -m venv .venv
.venv\Scripts\activate
```

### 3. Install Requirements

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

---

## ▶️ How to Run

### Linux / Kali / Ubuntu

Packet capture requires root privileges:

```bash
sudo python3 netsight_mon.py
```

### Windows

1. Install **Npcap**.
2. Run PowerShell/CMD as Administrator.
3. Start the application:

```powershell
python netsight_mon.py
```

> Linux/Kali is recommended for smoother packet capture and interface handling.

---

## 🌐 Network Interface Selection

Before starting packet capture, select an interface from the dropdown.

| Interface | Use Case |
|---|---|
| `lo` | Localhost/loopback traffic from the same machine, useful for local testing and debugging. |
| `eth0` | Ethernet/local network interface, useful for real network monitoring in authorized LAN environments. |
| Wi-Fi interface | Depends on adapter and driver support. Some systems may show limited visibility. |

---

## 🔎 Packet Filter Examples

```text
app==http
proto==tcp
port==443
ip==192.168.1.5
src==192.168.1.4 && app==http
domain contains google
```

---

## 📊 PDF Report Output

After capturing packets, click **EXPORT PDF REPORT**. Reports are saved automatically in:

```text
exported_reports/
```

Generated report filenames use timestamps:

```text
Professional_Network_Report_YYYYMMDD_HHMMSS.pdf
```

The PDF report includes:

- Tool overview
- Executive summary
- Field dictionary
- Protocol statistics
- Application protocol summary
- Top source IPs
- Top destination IPs
- Connected devices
- HTTP/Form event summary
- Packet flow table
- Professional interpretation

---

## 🧪 Testing Environment

Recommended testing setup:

| Requirement | Recommended Setup |
|---|---|
| OS | Kali Linux / Ubuntu |
| Network Mode | Bridged Adapter if using VM |
| Permission | Root/Admin access |
| Interface | eth0 for LAN testing, lo for localhost testing |
| Test Data | Demo/test traffic only |

---

## 🛡️ Responsible Use Notice

NetSight Monitor may display plaintext HTTP/Form data when such traffic is visible in an authorized lab environment. This behavior is intended for **security education and awareness**.

Do not capture, store, publish, or share real credentials or sensitive network data. Use only demo websites, test accounts, and authorized lab networks.

Encrypted traffic such as HTTPS and SSH is not decrypted by the tool. Only metadata such as IP addresses, ports, protocol names, packet counts, and available domain information may be shown.

---

## 📸 Screenshots

Place screenshots inside:

```text
assets/screenshots/
```

Suggested screenshot names:

```text
main-dashboard.png
packet-capture-testing.png
http-form-events.png
device-discovery.png
live-statistics.png
pdf-report-output.png
```

Before uploading screenshots, blur:

- Real credentials
- Private IPs if needed
- Personal data
- Sensitive domains or packet details

---

## 🚀 GitHub Upload Checklist

Upload these files:

- `netsight_mon.py`
- `README.md`
- `requirements.txt`
- `.gitignore`
- `LICENSE`
- `SECURITY.md`
- `docs/`
- `assets/screenshots/`

Do not upload:

- `.venv/` or `venv/`
- `__pycache__/`
- Generated reports containing sensitive data
- Real packet captures
- Private credentials

---

## 🧭 Future Improvements

- Improved DNS/domain resolution
- More advanced alerting features
- Database support for past sessions
- Better graphical charts in the GUI
- More detailed protocol analysis
- Cross-platform packaging as executable
- Custom report templates

---

## 👨‍💻 Author

**Rajarshi Sarkar**  
Final Year B.Tech CSE Project  
Modern Institute of Engineering & Technology

---

## 📄 License

This project is released under the **MIT License**. See the `LICENSE` file for details.

---

<div align="center">

### ⭐ If this project helps you, consider starring the repository.

</div>
