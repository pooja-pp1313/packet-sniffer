# Network Packet Sniffer with Alerts

## Overview

This project is a real-time network packet sniffer built in Python. It captures live network traffic, detects anomalies like port scanning and flooding, logs packets to a SQLite database, and alerts on suspicious activity. The GUI displays live protocol distribution and supports exporting captured data to CSV.

## Features

- Selectable network interface for sniffing  
- Real-time packet capture (TCP, UDP)  
- Basic anomaly detection (port scans and flooding)  
- SQLite database logging  
- GUI with live pie chart visualization  
- Export captured packets to CSV  

## Tools & Libraries

- Python 3  
- Scapy  
- SQLite3  
- Tkinter  
- Matplotlib  

## Usage

1. Run the program with administrator privileges (required for packet sniffing).  
2. Select the network interface from the dropdown menu.  
3. Click **Start Sniffing** to begin capturing packets.  
4. View live protocol distribution in the pie chart.  
5. Click **Stop Sniffing** to end capture.  
6. Click **Export to CSV** to save captured packets.

## Installation

1. Install Python 3.  
2. Install required packages:

```bash
pip install scapy matplotlib
