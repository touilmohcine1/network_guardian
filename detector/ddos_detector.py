from scapy.all import sniff, IP
import sqlite3
from datetime import datetime
from collections import defaultdict
import time
import logging

# Configure logging to be silent by default
logger = logging.getLogger(__name__)
logger.setLevel(logging.WARNING)  # Only show warnings and errors

DB_PATH = 'database.db'
ip_counter = defaultdict(int)
window_time = 10
threshold = 100

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
        time.sleep(window_time)
        for ip, count in list(ip_counter.items()):
            if count > threshold:
                desc = f"Possible attaque DDoS : {count} paquets en {window_time}s"
                insert_alert("DDoS", desc, ip)
        ip_counter.clear()

def detect(pkt):
    if pkt.haslayer(IP):
        ip = pkt[IP].src
        ip_counter[ip] += 1

def start_ddos_detection():
    from threading import Thread
    Thread(target=monitor, daemon=True).start()
    sniff(filter="ip", store=False, prn=detect)
