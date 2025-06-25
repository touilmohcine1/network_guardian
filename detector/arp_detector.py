from scapy.all import sniff, ARP
import sqlite3
from datetime import datetime

DB_PATH = 'database.db'
arp_table = {}

def insert_alert(attack_type, description, source_ip):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("INSERT INTO alerts (timestamp, attack_type, description, source_ip) VALUES (?, ?, ?, ?)",
                   (timestamp, attack_type, description, source_ip))
    conn.commit()
    conn.close()

def detect(pkt):
    if pkt.haslayer(ARP) and pkt[ARP].op == 2:
        ip = pkt[ARP].psrc
        mac = pkt[ARP].hwsrc
        if ip in arp_table and arp_table[ip] != mac:
            desc = f"ARP spoofing détecté : {ip} change de {arp_table[ip]} à {mac}"
            insert_alert("ARP Spoofing", desc, ip)
        else:
            arp_table[ip] = mac

def start_arp_detection():
    sniff(filter="arp", store=False, prn=detect)
