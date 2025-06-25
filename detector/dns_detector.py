from scapy.all import sniff, DNS, DNSQR, DNSRR
import sqlite3
from datetime import datetime

DB_PATH = 'database.db'
dns_cache = {}

def insert_alert(attack_type, description, source_ip):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("INSERT INTO alerts (timestamp, attack_type, description, source_ip) VALUES (?, ?, ?, ?)",
                   (timestamp, attack_type, description, source_ip))
    conn.commit()
    conn.close()

def detect(pkt):
    if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 1:
        try:
            domain = pkt[DNSQR].qname.decode()
            ip = pkt[DNSRR].rdata
            source_ip = pkt[1].src
            if domain in dns_cache and dns_cache[domain] != ip:
                desc = f"DNS spoofing détecté : {domain} -> IP changée de {dns_cache[domain]} à {ip}"
                insert_alert("DNS Spoofing", desc, source_ip)
            else:
                dns_cache[domain] = ip
        except:
            pass

def start_dns_detection():
    sniff(filter="udp port 53", store=False, prn=detect)
