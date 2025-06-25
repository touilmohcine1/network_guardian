from scapy.all import sniff, TCP, IP
import sqlite3
from datetime import datetime
from collections import defaultdict
import time

DB_PATH = 'database.db'
scan_tracker = defaultdict(set)
threshold_ports = 15
time_window = 10

def insert_alert(attack_type, description, source_ip):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("INSERT INTO alerts (timestamp, attack_type, description, source_ip) VALUES (?, ?, ?, ?)",
                   (timestamp, attack_type, description, source_ip))
    conn.commit()
    conn.close()

def monitor():
    while True:
        time.sleep(time_window)
        for ip, ports in list(scan_tracker.items()):
            if len(ports) > threshold_ports:
                desc = f"Scan de ports détecté : {len(ports)} ports ciblés"
                insert_alert("Scan de Ports", desc, ip)
        scan_tracker.clear()

def detect(pkt):
    if pkt.haslayer(TCP) and pkt[TCP].flags == 'S':
        src_ip = pkt[IP].src
        dst_port = pkt[TCP].dport
        scan_tracker[src_ip].add(dst_port)

def start_scan_detection():
    from threading import Thread
    Thread(target=monitor, daemon=True).start()
    sniff(filter="tcp", store=False, prn=detect)
