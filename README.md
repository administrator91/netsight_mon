# 🌐 NetSight Monitor

## A Real-Time Network Monitoring and Traffic Analysis Tool

**NetSight Monitor** is a Python-based real-time network monitoring and traffic analysis tool developed as a final-year B.Tech Computer Science & Engineering project.

Developed by **Rajarshi Sarkar**

![Python](https://img.shields.io/badge/Python-3.x-blue)
![PyQt6](https://img.shields.io/badge/GUI-PyQt6-green)
![Scapy](https://img.shields.io/badge/Packet%20Analysis-Scapy-orange)
![PDF](https://img.shields.io/badge/Report-PDF-red)
![License](https://img.shields.io/badge/License-MIT-lightgrey)

---

## 📌 Project Overview

**NetSight Monitor** is a real-time network monitoring and traffic analysis tool built using Python. It provides a graphical dashboard for capturing live network packets, identifying network and application protocols, monitoring visible plaintext HTTP/Form events, discovering connected devices, viewing live traffic statistics, applying packet filters, and generating professional PDF reports.

The project is designed for academic learning, authorized lab testing, network visibility, and cybersecurity awareness. It helps users understand how devices communicate inside a network and how packet metadata can be analyzed in a structured and readable format.

> ⚠️ **Important:** This tool is intended only for authorized monitoring, academic demonstration, and controlled lab environments. Do not use it on networks or systems without permission.

---

## ✨ Key Features

- Real-time packet capture from selected network interface
- PyQt6-based graphical desktop dashboard
- Live packet table with date, time, source IP, destination IP, ports, protocol, application protocol, and packet length
- Detailed packet inspection panel
- Payload preview and raw hexadecimal view
- Protocol detection using packet layers and well-known port mapping
- Plaintext HTTP/Form event monitoring in authorized environments
- Connected device discovery using ARP scanning
- Live statistics dashboard
- Packet filtering by IP, protocol, application, port, and domain
- Professional PDF report generation
- Ethical-use documentation for academic and responsible publishing

---

## 🖥️ Interface Overview

NetSight Monitor provides a clean graphical interface divided into multiple working sections.

| Section | Purpose |
|---|---|
| **Live Packet Inspector** | Captures and displays live packet metadata in a structured table format. |
| **HTTP / Form Events** | Shows visible plaintext HTTP request and form events during authorized testing. |
| **Network Devices** | Discovers active local network devices using ARP scanning. |
| **Live Statistics** | Displays total packets, protocol counts, application counts, HTTP/Form events, and top sources. |
| **Packet Filter** | Allows filtering packets by IP, protocol, application, port, and domain. |
| **Export PDF Report** | Generates a professional PDF report from the captured monitoring session. |

---

## 🧱 Technology Stack

| Component | Technology Used |
|---|---|
| Programming Language | Python 3.x |
| GUI Framework | PyQt6 |
| Packet Capture and Analysis | Scapy |
| PDF Report Generation | FPDF / fpdf2 |
| Network Utilities | socket, ipaddress, urllib, re |
| Data Counting | collections.Counter |
| Background Processing | QThread / threading |
| Report Format | PDF |

---

## 📂 Repository Structure

```text
netsight_mon/
├── netsight_mon.py
├── requirements.txt
├── README.md
├── LICENSE
├── SECURITY.md
├── .gitignore
└── docs/
    ├── USAGE.md
    ├── ETHICAL_USE.md
    └── PROJECT_REPORT_NOTES.md
