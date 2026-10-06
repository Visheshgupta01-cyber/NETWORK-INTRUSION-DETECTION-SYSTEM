# Network Intrusion Detection System (NIDS)

## 1. Project Overview

Network Intrusion Detection System (NIDS) is a Python-based cybersecurity application that monitors network traffic and detects suspicious activities.

The system captures network packets using Scapy, analyzes traffic patterns, detects possible security threats, stores alerts in SQLite, and displays security information through a graphical dashboard.

## 2. Objectives

- Monitor network traffic in real time
- Identify TCP, UDP and ICMP traffic
- Detect suspicious network behavior
- Generate security alerts
- Store alerts in a database
- Display live security statistics
- Generate security reports

## 3. Technologies Used

- Python
- Scapy
- Tkinter
- SQLite
- HTML
- CSS
- Windows
- Npcap

## 4. Main Features

### Packet Monitoring
Captures network packets and displays:

- Source IP
- Destination IP
- Protocol
- Port
- Timestamp

### Intrusion Detection

The system detects:

- Possible Port Scan
- TCP Connection Burst
- ICMP Traffic Burst

### Alert Management

Detected threats are:

- Displayed to the user
- Stored in SQLite
- Available through Alert History

### Security Dashboard

The dashboard displays:

- Total packets
- TCP packets
- UDP packets
- ICMP packets
- Total alerts
- High-risk alerts
- Medium-risk alerts
- Low-risk alerts
- Security event statistics

### Report Generation

The system generates an HTML security report containing alert statistics and detected events.

## 5. Project Structure

NetworkIDS/

├── main.py
├── packet_monitor.py
├── detector.py
├── database.py
├── alerts.py
├── config.py
├── report.py
├── dashboard.py
├── test_sniffer.py
├── database/
├── logs/
├── reports/
└── venv/

## 6. How to Run

Open PowerShell in the project directory.

Activate the virtual environment:

.\venv\Scripts\Activate.ps1

Run the application:

python main.py

## 7. Detection Rules

### Possible Port Scan

15 or more different TCP destination ports from the same source within 10 seconds.

Risk Level: HIGH

### TCP Connection Burst

50 or more TCP packets from the same source within 10 seconds.

Risk Level: MEDIUM

### ICMP Traffic Burst

30 or more ICMP packets from the same source within 10 seconds.

Risk Level: MEDIUM

## 8. Database

SQLite is used to store security alerts.

Database location:

database/nids_alerts.db

## 9. Reports

Generated reports are stored in:

reports/

## 10. Purpose

This project is developed for educational cybersecurity purposes and demonstrates the basic concepts of network monitoring, intrusion detection, security alerting and incident reporting.

## 11. Future Improvements

- Machine learning based detection
- Email notifications
- IP reputation checking
- Advanced packet analysis
- Graphical charts
- User authentication
- Cloud-based monitoring
- SIEM integration