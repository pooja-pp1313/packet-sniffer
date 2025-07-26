from scapy.all import sniff, IP, TCP, UDP
import sqlite3
import logging
from datetime import datetime
import time
from collections import defaultdict

# --- ALERT SYSTEM SETUP ---
logging.basicConfig(filename="alerts.log", level=logging.INFO, format="%(asctime)s - %(message)s")

def alert(message):
    print("[ALERT]", message)
    logging.info(message)

# --- DATABASE SETUP ---
conn = sqlite3.connect("packets.db")
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

# --- DETECTION STORAGE ---
port_scan_tracker = defaultdict(set)      # src_ip: set of dst_ports
flood_tracker = defaultdict(list)         # src_ip: list of timestamps

# --- DETECTION LOGIC ---
def detect_anomalies(src_ip, dst_port):
    now = time.time()

    # Port scan detection
    port_scan_tracker[src_ip].add(dst_port)
    if len(port_scan_tracker[src_ip]) > 20:
        alert(f"[Port Scan] {src_ip} accessed {len(port_scan_tracker[src_ip])} different ports.")
        port_scan_tracker[src_ip].clear()

    # Flood detection
    flood_tracker[src_ip].append(now)
    flood_tracker[src_ip] = [t for t in flood_tracker[src_ip] if now - t < 10]  # keep last 10s
    if len(flood_tracker[src_ip]) > 100:
        alert(f"[Flood Attack] {src_ip} sent {len(flood_tracker[src_ip])} packets in 10 seconds.")
        flood_tracker[src_ip].clear()

# --- PACKET HANDLER ---
def process_packet(packet):
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

        # Log to terminal
        print(f"[{timestamp}] {proto} {src_ip}:{src_port} -> {dst_ip}:{dst_port} | Len: {length} | Flags: {flags}")

        # Store in DB
        cursor.execute('''
            INSERT INTO packets (timestamp, src_ip, dst_ip, src_port, dst_port, protocol, length, flags)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (timestamp, src_ip, dst_ip, src_port, dst_port, proto, length, flags))
        conn.commit()

        # Check for anomalies
        if dst_port:
            detect_anomalies(src_ip, dst_port)

# --- MAIN ---
print("Starting packet capture... (Press Ctrl+C to stop)")
try:
    sniff(prn=process_packet, store=False)
except KeyboardInterrupt:
    print("Sniffing stopped.")
    conn.close()
