import tkinter as tk
from tkinter import ttk
import sqlite3
import threading
import time
import logging
from datetime import datetime
from collections import defaultdict
from scapy.all import sniff, IP, TCP, UDP, get_if_list
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import csv

# --- GLOBAL FLAGS ---
sniffing = False
sniffer_thread = None
selected_iface = None

# --- DATABASE SETUP ---
conn = sqlite3.connect("packets.db", check_same_thread=False)
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS packets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT,
    src_ip TEXT,
    dst_ip TEXT,
    src_port INTEGER,
    dst_port INTEGER,
    protocol TEXT,
    length INTEGER,
    flags TEXT
)
""")
conn.commit()

# --- ALERT SYSTEM SETUP ---
logging.basicConfig(filename="alerts.log", level=logging.INFO, format="%(asctime)s - %(message)s")

def alert(message):
    print("[ALERT]", message)
    logging.info(message)

# --- ANOMALY DETECTION ---
port_scan_tracker = defaultdict(set)
flood_tracker = defaultdict(list)

def detect_anomalies(src_ip, dst_port):
    now = time.time()
    port_scan_tracker[src_ip].add(dst_port)
    if len(port_scan_tracker[src_ip]) > 20:
        alert(f"[Port Scan] {src_ip} accessed {len(port_scan_tracker[src_ip])} ports.")
        port_scan_tracker[src_ip].clear()

    flood_tracker[src_ip].append(now)
    flood_tracker[src_ip] = [t for t in flood_tracker[src_ip] if now - t < 10]
    if len(flood_tracker[src_ip]) > 100:
        alert(f"[Flooding] {src_ip} sent {len(flood_tracker[src_ip])} packets in 10s.")
        flood_tracker[src_ip].clear()

# --- PACKET PROCESSOR ---
def start_sniffing():
    global sniffing, selected_iface
    sniffing = True

    def process_packet(packet):
        if not sniffing:
            return

        conn_thread = sqlite3.connect("packets.db")
        cursor_thread = conn_thread.cursor()

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            proto = "TCP" if TCP in packet else "UDP" if UDP in packet else "Other"
            length = len(packet)
            flags = None
            src_port = None
            dst_port = None

            if TCP in packet:
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                flags = str(packet[TCP].flags)
            elif UDP in packet:
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport

            cursor_thread.execute('''
                INSERT INTO packets (timestamp, src_ip, dst_ip, src_port, dst_port, protocol, length, flags)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (timestamp, src_ip, dst_ip, src_port, dst_port, proto, length, flags))
            conn_thread.commit()
            conn_thread.close()

            if dst_port:
                detect_anomalies(src_ip, dst_port)

    sniff(prn=process_packet, store=False, stop_filter=lambda _: not sniffing, iface=selected_iface)

# --- GUI CHART UPDATE ---
def get_protocol_data():
    cursor.execute("SELECT protocol, COUNT(*) FROM packets GROUP BY protocol")
    data = cursor.fetchall()
    labels = [row[0] for row in data]
    sizes = [row[1] for row in data]
    return labels, sizes

def update_chart():
    labels, sizes = get_protocol_data()
    ax.clear()
    if sizes:
        ax.pie(sizes, labels=labels, autopct='%1.1f%%')
    else:
        ax.text(0.5, 0.5, "Waiting for packets...", ha='center', va='center', fontsize=12)
    ax.set_title("Live Protocol Usage")
    canvas.draw()
    root.after(5000, update_chart)

# --- GUI EVENT HANDLERS ---
def on_start():
    global sniffer_thread, sniffing, selected_iface
    if not sniffing:
        selected_iface = iface_combo.get()
        if not selected_iface:
            status_var.set("Select an interface first!")
            return
        sniffing = True
        sniffer_thread = threading.Thread(target=start_sniffing, daemon=True)
        sniffer_thread.start()
        status_var.set(f"Sniffing on {selected_iface}...")

def on_stop():
    global sniffing
    sniffing = False
    status_var.set("Stopped.")

def export_to_csv():
    try:
        conn_export = sqlite3.connect("packets.db")
        cursor_export = conn_export.cursor()
        cursor_export.execute("SELECT timestamp, src_ip, dst_ip, src_port, dst_port, protocol, length, flags FROM packets")
        rows = cursor_export.fetchall()
        conn_export.close()

        with open("packets_export.csv", "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["timestamp", "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "length", "flags"])
            writer.writerows(rows)

        status_var.set("Exported packets_export.csv ✅")
    except Exception as e:
        status_var.set(f"Export failed: {e}")

# --- GUI SETUP ---
root = tk.Tk()
root.title("Packet Sniffer with Alerts")
root.geometry("650x600")

# Interface selection dropdown
iface_label = tk.Label(root, text="Select Network Interface:")
iface_label.pack(pady=(10, 0))

interfaces = get_if_list()
iface_combo = ttk.Combobox(root, values=interfaces, width=60)
iface_combo.pack(pady=(0, 10))
iface_combo.set(interfaces[0])  # default select first interface

# Matplotlib pie chart
fig, ax = plt.subplots(figsize=(5, 4))
canvas = FigureCanvasTkAgg(fig, master=root)
canvas.get_tk_widget().pack()

# Buttons frame
btn_frame = tk.Frame(root)
btn_frame.pack(pady=10)

start_btn = tk.Button(btn_frame, text="Start Sniffing", command=on_start, bg="green", fg="white", width=15)
start_btn.grid(row=0, column=0, padx=10)

stop_btn = tk.Button(btn_frame, text="Stop Sniffing", command=on_stop, bg="red", fg="white", width=15)
stop_btn.grid(row=0, column=1, padx=10)

export_btn = tk.Button(btn_frame, text="Export to CSV", command=export_to_csv, bg="blue", fg="white", width=15)
export_btn.grid(row=0, column=2, padx=10)

status_var = tk.StringVar()
status_var.set("Select interface and start.")
status_label = tk.Label(root, textvariable=status_var, font=("Arial", 12, "bold"))
status_label.pack(pady=5)

# Start updating chart
update_chart()
root.mainloop()
