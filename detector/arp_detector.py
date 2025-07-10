from scapy.all import sniff, ARP, get_if_hwaddr, get_if_addr, IP
import sqlite3
from datetime import datetime
import time
from collections import defaultdict
import threading
import logging
from app import broadcast_arp_alert

# Configure logging to be silent by default
logger = logging.getLogger(__name__)
logger.setLevel(logging.WARNING)  # Only show warnings and errors

DB_PATH = 'database.db'

class ARPSpoofingDetector:
    def __init__(self):
        self.arp_table = {}  # IP -> MAC mapping
        self.suspicious_ips = defaultdict(int)  # IP -> suspicious activity count
        self.legitimate_ips = set()  # Known legitimate IPs
        self.alert_cooldown = {}  # IP -> last alert time
        self.cooldown_period = 60  # seconds between alerts for same IP
        self.suspicious_threshold = 3  # suspicious activities before alert
        self.interface = None
        self.gateway_ip = None
        self.gateway_mac = None
        
        # Initialize interface and gateway info
        self._init_network_info()
        
    def _init_network_info(self):
        """Initialize network interface and gateway information"""
        try:
            # Get default interface (you can modify this for specific interface)
            import subprocess
            result = subprocess.run(['ip', 'route', 'show', 'default'], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                interface = result.stdout.split()[4]  # Extract interface name
                self.interface = interface
                logger.info(f"Using interface: {interface}")
                
                # Get gateway IP
                gateway_line = result.stdout.strip()
                self.gateway_ip = gateway_line.split()[2]
                logger.info(f"Gateway IP: {self.gateway_ip}")
                
                # Get interface MAC
                self.interface_mac = get_if_hwaddr(interface)
                logger.info(f"Interface MAC: {self.interface_mac}")
                
        except Exception as e:
            logger.warning(f"Could not auto-detect network info: {e}")
            self.interface = None
            self.gateway_ip = None
    
    def insert_alert(self, attack_type, description, source_ip, severity="HIGH"):
        """Insert alert into database with enhanced information and broadcast via WebSocket"""
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            enhanced_desc = f"{description} | Severity: {severity} | Interface: {self.interface or 'Unknown'}"
            cursor.execute(
                "INSERT INTO alerts (timestamp, attack_type, description, source_ip) VALUES (?, ?, ?, ?)",
                (timestamp, attack_type, enhanced_desc, source_ip)
            )
            conn.commit()
            conn.close()
            logger.warning(f"ARP Alert: {enhanced_desc}")
            # Broadcast only ARP-related alerts
            if attack_type.lower().startswith("arp") or "spoofing" in attack_type.lower() or "mac flooding" in attack_type.lower() or "gateway spoofing" in attack_type.lower():
                broadcast_arp_alert((timestamp, attack_type, enhanced_desc, source_ip))
        except Exception as e:
            logger.error(f"Error inserting alert: {e}")
    
    def is_legitimate_arp(self, pkt):
        """Check if ARP packet is legitimate"""
        try:
            # Check if it's a gratuitous ARP (common in legitimate scenarios)
            if pkt[ARP].psrc == pkt[ARP].pdst:
                return True
            
            # Check if it's from our own interface
            if pkt[ARP].hwsrc == self.interface_mac:
                return True
            
            # Check if it's a response to our own request
            if pkt[ARP].op == 2:  # ARP reply
                return False  # We'll handle this in main detection logic
            
            return True
            
        except Exception as e:
            logger.debug(f"Error checking legitimate ARP: {e}")
            return True
    
    def detect_arp_spoofing(self, pkt):
        """Enhanced ARP spoofing detection"""
        try:
            if not pkt.haslayer(ARP):
                return
            
            arp_layer = pkt[ARP]
            
            # Only process ARP replies
            if arp_layer.op != 2:  # 2 = ARP reply
                return
            
            ip = arp_layer.psrc
            mac = arp_layer.hwsrc
            source_ip = pkt[IP].src if pkt.haslayer(IP) else "Unknown"
            
            # Skip if it's a legitimate ARP
            if self.is_legitimate_arp(pkt):
                return
            
            # Check for MAC address spoofing
            if ip in self.arp_table:
                if self.arp_table[ip] != mac:
                    # Potential ARP spoofing detected
                    self.suspicious_ips[ip] += 1
                    
                    # Check if we should alert
                    if self.suspicious_ips[ip] >= self.suspicious_threshold:
                        current_time = time.time()
                        
                        # Check cooldown
                        if ip not in self.alert_cooldown or \
                           current_time - self.alert_cooldown[ip] > self.cooldown_period:
                            
                            desc = f"ARP Spoofing detected: {ip} MAC changed from {self.arp_table[ip]} to {mac}"
                            severity = "CRITICAL" if ip == self.gateway_ip else "HIGH"
                            
                            self.insert_alert("ARP Spoofing", desc, source_ip, severity)
                            self.alert_cooldown[ip] = current_time
                            
                            # Reset suspicious count after alert
                            self.suspicious_ips[ip] = 0
                else:
                    # Legitimate update, reduce suspicious count
                    if self.suspicious_ips[ip] > 0:
                        self.suspicious_ips[ip] -= 1
            
            # Update ARP table
            self.arp_table[ip] = mac
            
            # Check for suspicious patterns
            self._check_suspicious_patterns(ip, mac, source_ip)
            
        except Exception as e:
            logger.error(f"Error in ARP detection: {e}")
    
    def _check_suspicious_patterns(self, ip, mac, source_ip):
        """Check for additional suspicious patterns"""
        try:
            # Check for rapid ARP updates
            current_time = time.time()
            
            # Check if this IP is sending too many ARP replies
            if ip not in self.arp_table:
                # First time seeing this IP
                return
            
            # Check for MAC flooding (same MAC with multiple IPs)
            mac_ips = [k for k, v in self.arp_table.items() if v == mac]
            if len(mac_ips) > 5:  # More than 5 IPs for same MAC
                desc = f"MAC flooding detected: MAC {mac} claiming {len(mac_ips)} IPs"
                self.insert_alert("MAC Flooding", desc, source_ip, "MEDIUM")
            
            # Check for gateway spoofing
            if ip == self.gateway_ip and mac != self.gateway_mac:
                desc = f"Gateway spoofing detected: {ip} MAC {mac} (expected: {self.gateway_mac})"
                self.insert_alert("Gateway Spoofing", desc, source_ip, "CRITICAL")
                
        except Exception as e:
            logger.debug(f"Error in pattern checking: {e}")
    
    def cleanup_old_entries(self):
        """Periodically cleanup old ARP table entries"""
        while True:
            try:
                time.sleep(300)  # Cleanup every 5 minutes
                current_time = time.time()
                
                # Remove old suspicious entries
                for ip in list(self.suspicious_ips.keys()):
                    if self.suspicious_ips[ip] <= 0:
                        del self.suspicious_ips[ip]
                
                # Remove old cooldown entries
                for ip in list(self.alert_cooldown.keys()):
                    if current_time - self.alert_cooldown[ip] > self.cooldown_period * 2:
                        del self.alert_cooldown[ip]
                
                logger.debug("ARP detector cleanup completed")
                
            except Exception as e:
                logger.error(f"Error in cleanup: {e}")
    
    def start_detection(self):
        """Start ARP spoofing detection"""
        logger.info("Starting ARP spoofing detection...")
        
        # Start cleanup thread
        cleanup_thread = threading.Thread(target=self.cleanup_old_entries, daemon=True)
        cleanup_thread.start()
        
        # Start sniffing
        try:
            sniff(filter="arp", store=False, prn=self.detect_arp_spoofing)
        except Exception as e:
            logger.error(f"Error in ARP sniffing: {e}")

# Global detector instance
detector = ARPSpoofingDetector()

def start_arp_detection():
    """Start ARP detection (legacy function for compatibility)"""
    detector.start_detection()
