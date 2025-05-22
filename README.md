# 🧠 Network Monitoring and Device Discovery Tool

A **user-friendly, Python-based** cross-platform application for real-time network monitoring, packet capturing, and device discovery — designed especially for **non-technical users** like home users, educators, and small business owners.

---

## 📘 Table of Contents

- [Overview](#-overview)
- [Project Objectives](#-project-objectives)
- [Key Features](#-key-features)
- [System Architecture](#-system-architecture)
- [Tools & Technologies](#-tools--technologies)
- [Installation Guide](#-installation-guide)
- [Usage Guide](#-usage-guide)
- [Functional & Non-Functional Requirements](#-requirements)
- [Prototype & Testing](#-prototype--testing)
- [Challenges Faced](#-challenges-faced)
- [Future Enhancements](#-future-enhancements)
- [Contributors](#-contributors)
- [License](#-license)
- [Repository](#-repository)

---

## 📄 Overview

This project addresses the gap between highly technical tools (e.g., Wireshark, Nmap) and the needs of everyday users. Most existing tools are command-line based and require deep understanding of networking. Our tool empowers users with:

- Real-time bandwidth monitoring  
- Detection of unauthorized devices  
- Packet-level network inspection  
- Visual traffic analysis  
- Alerting system for suspicious behavior  

> Developed as part of the **PUSL3190 Computing Project** at Plymouth University.

---

## 🎯 Project Objectives

- Develop a **simplified, cross-platform tool** for network monitoring and device discovery.
- **Empower non-technical users** to independently manage and secure their networks.
- Provide an **intuitive GUI** with graphs, alerts, and interactive dashboards.
- Replace dependency on command-line tools like Wireshark and Nmap.
- Address **cybersecurity threats** like spoofing, packet sniffing, and bandwidth theft.

---

## 🖥️ Key Features

| Module                    | Description                                                                 |
|--------------------------|-----------------------------------------------------------------------------|
| 🌐 Real-Time Traffic      | Monitors live bandwidth usage and packet flow.                              |
| 🧭 Device Discovery       | Scans local network for active devices and displays IP/MAC addresses.       |
| 📦 Packet Capturing       | Captures packets for deep inspection using Scapy.                           |
| 📊 Visual Analytics       | Shows bandwidth and device usage in real-time graphs (matplotlib).         |
| ⚠️ Alerts & Security       | Detects unusual traffic patterns or unauthorized connections.               |
| 💡 GUI Interface           | Tkinter-powered UI optimized for usability by all levels of users.          |
| 🪟 Cross-Platform Support | Compatible with Windows, macOS, and Linux.                                 |
| 📄 PDF Reports            | Generate summaries and vulnerability reports via `reportlab`.              |

---

## 🧱 System Architecture

### 🔹 Architecture Layers:
- **GUI Layer:** Tkinter-based interface with tabs for monitoring, scanning, alerts.
- **Logic Layer:** Python core managing device discovery, capture, and alerting.
- **Data Layer:** Stores logs, exports, and configurations locally in JSON/PDF.

### 🖼️ Diagrams Included:
- High-Level Architecture  
- Networking Layer Diagram  
- Use Case & ER Diagrams  
*(See `/docs/architecture`)*
  
---

## 🛠️ Tools & Technologies

| Tool         | Purpose                                          |
|--------------|--------------------------------------------------|
| Python 3.13  | Programming language                             |
| Scapy        | Packet sniffing and analysis                     |
| psutil       | System and network performance metrics           |
| Tkinter      | GUI development                                  |
| matplotlib   | Real-time graph plotting                         |
| reportlab    | PDF report generation                            |
| ipaddress    | IP data handling and validation                  |
| Agile Model  | Iterative development and user feedback loop     |

---

## 🔧 Installation Guide

### 1. Prerequisites
- Python 3.7 or later (Recommended: Python 3.13)
- pip package manager

### 2. Clone & Install

```bash
git clone https://github.com/kmgudara/Netwok_Monitoring_Tool_python.git
cd Netwok_Monitoring_Tool_python
pip install -r requirements.txt
