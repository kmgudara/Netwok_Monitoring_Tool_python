# 🧠 Network Monitoring and Device Discovery Tool

A user-friendly, Python-based tool that provides real-time traffic monitoring, device discovery, packet capturing, and network visualization — designed especially for **non-technical users**, small businesses, and educators.

---

## 📌 Project Overview

In today’s hyper-connected digital world, understanding network activity is essential — but tools like Wireshark and Nmap are too complex for non-technical users. This project addresses this gap by offering an **intuitive Python-based tool** with a clean GUI that allows users to:

- Monitor real-time network activity
- Detect unknown or unauthorized devices
- Capture and inspect network packets
- Visualize traffic using interactive charts

> ✅ Developed as the Final Year Project for the BSc (Hons) in Computer Network  
> 🏫 University: Plymouth University  
> 🧑‍💻 Developer: Kahadugoda Udara  
> 🎓 Supervisor: Mr. Chamara Dissanayake  
> 📅 Submitted: May 2025

---

## 🎯 Project Objectives

- Simplify network monitoring for non-technical users
- Design an accessible and visual GUI using Tkinter
- Integrate packet capture, device discovery, and traffic analysis
- Ensure cross-platform compatibility (Windows, macOS, Linux)
- Reduce reliance on command-line tools and technical expertise

---

## 🖥 Features

| Feature                     | Description                                                                 |
|----------------------------|-----------------------------------------------------------------------------|
| 🌐 Real-Time Monitoring     | Monitor bandwidth usage and live network traffic                            |
| 🧭 Device Discovery         | Scan the local network and list connected devices (IP & MAC)                 |
| 📦 Packet Capturing         | Capture packets using Scapy and inspect protocol-level data                  |
| 📊 Data Visualization       | View usage graphs, trends, and statistics using `matplotlib`                 |
| ⚠️ Alerts & Notifications   | Identify suspicious activity and alert the user                              |
| 🪟 GUI Interface             | Built with Tkinter for ease of use                                           |
| 🔄 Cross-Platform Support   | Compatible with Windows, macOS, and Linux                                    |


---

## 🧰 Tools & Technologies

- **Python 3.13**
- [`Scapy`](https://scapy.readthedocs.io/en/latest/) – Packet sniffing and manipulation
- [`psutil`](https://psutil.readthedocs.io/en/latest/) – System and network stats
- [`Tkinter`](https://tkdocs.com/) – Graphical User Interface
- [`matplotlib`](https://matplotlib.org/) – Data visualization
- [`reportlab`](https://www.reportlab.com/) – PDF report generation
- `ipaddress` – Built-in Python IP address management

---

## 📦 Installation Guide

### ✅ Prerequisites

- Python 3.7 or above (Recommended: Python 3.13)
- `pip` installed

### 🔧 Setup Instructions

```bash
git clone https://github.com/kmgudara/Netwok_Monitoring_Tool_python.git
cd Netwok_Monitoring_Tool_python
pip install -r requirements.txt
python main.py
