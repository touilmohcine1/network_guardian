from scapy.all import sniff, TCP, IP, UDP, ICMP
import sqlite3
from datetime import datetime
import time
from collections import defaultdict
import threading
import logging
import ipaddress

# Configure logging to be silent by default
logger = logging.getLogger(__name__)
logger.setLevel(logging.WARNING)  # Only show warnings and errors

DB_PATH = 'database.db'

class PortScanDetector:
    def __init__(self):
        self.scan_tracker = defaultdict(lambda: {
            'ports': set(),
            'syn_count': 0,
            'fin_count': 0,
            'rst_count': 0,
            'udp_count': 0,
            'icmp_count': 0,
            'first_seen': time.time(),
            'last_seen': time.time()
        })
        self.legitimate_ips = set()  # Known legitimate IPs
        self.alert_cooldown = {}  # IP -> last alert time
        self.cooldown_period = 300  # 5 minutes between alerts for same IP
        self.cleanup_interval = 60  # Cleanup every minute
        
        # Thresholds for different scan types
        self.thresholds = {
            'port_scan': 10,      # Number of ports to trigger port scan alert
            'syn_scan': 5,        # Number of SYN packets to trigger SYN scan alert
            'fin_scan': 3,        # Number of FIN packets to trigger FIN scan alert
            'udp_scan': 8,        # Number of UDP packets to trigger UDP scan alert
            'icmp_scan': 5,       # Number of ICMP packets to trigger ICMP scan alert
            'time_window': 30     # Time window in seconds for scan detection
        }
        
        # Common ports that are often scanned
        self.common_scan_ports = {
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995, 1723, 3306, 3389, 5900, 8080
        }
        
        # Initialize legitimate IPs
        self._init_legitimate_ips()
        
    def _init_legitimate_ips(self):
        """Initialize list of legitimate IPs"""
        try:
            # Add local network IPs
            import subprocess
            result = subprocess.run(['ip', 'route', 'show'], capture_output=True, text=True)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if 'default' in line:
                        parts = line.split()
                        if len(parts) >= 3:
                            gateway = parts[2]
                            self.legitimate_ips.add(gateway)
                            logger.info(f"Added gateway: {gateway}")
        except Exception as e:
            logger.warning(f"Could not detect gateway: {e}")
    
    def insert_alert(self, attack_type, description, source_ip, severity="HIGH"):
        """Insert alert into database with enhanced information"""
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            # Enhanced description with more details
            enhanced_desc = f"{description} | Severity: {severity}"
            
            cursor.execute(
                "INSERT INTO alerts (timestamp, attack_type, description, source_ip) VALUES (?, ?, ?, ?)",
                (timestamp, attack_type, enhanced_desc, source_ip)
            )
            conn.commit()
            conn.close()
            
            logger.warning(f"Scan Alert: {enhanced_desc}")
            
        except Exception as e:
            logger.error(f"Error inserting alert: {e}")
    
    def is_legitimate_traffic(self, src_ip, dst_ip, dst_port):
        """Check if traffic is legitimate"""
        try:
            # Skip if source is legitimate
            if src_ip in self.legitimate_ips:
                return True
            
            # Skip common legitimate ports
            if dst_port in {80, 443, 53, 22, 21, 25, 110, 143, 993, 995}:
                return True
            
            # Skip if it's internal communication
            src_network = ipaddress.ip_network(src_ip + '/24', strict=False)
            dst_network = ipaddress.ip_network(dst_ip + '/24', strict=False)
            if src_network == dst_network:
                return True
            
            return False
            
        except Exception as e:
            logger.debug(f"Error checking legitimate traffic: {e}")
            return True
    
    def detect_scan(self, pkt):
        """Enhanced port scan detection"""
        try:
            src_ip = None
            dst_ip = None
            dst_port = None
            scan_type = None
            
            # Extract packet information based on protocol
            if pkt.haslayer(TCP):
                tcp_layer = pkt[TCP]
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                dst_port = tcp_layer.dport
                
                # Determine scan type based on TCP flags
                if tcp_layer.flags == 2:  # SYN
                    scan_type = 'syn'
                elif tcp_layer.flags == 1:  # FIN
                    scan_type = 'fin'
                elif tcp_layer.flags == 4:  # RST
                    scan_type = 'rst'
                elif tcp_layer.flags == 0:  # NULL
                    scan_type = 'null'
                elif tcp_layer.flags == 1:  # FIN
                    scan_type = 'fin'
                elif tcp_layer.flags == 3:  # FIN-ACK
                    scan_type = 'fin_ack'
                elif tcp_layer.flags == 5:  # SYN-FIN
                    scan_type = 'syn_fin'
                else:
                    return  # Skip other TCP packets
                    
            elif pkt.haslayer(UDP):
                udp_layer = pkt[UDP]
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                dst_port = udp_layer.dport
                scan_type = 'udp'
                
            elif pkt.haslayer(ICMP):
                icmp_layer = pkt[ICMP]
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                scan_type = 'icmp'
                
            else:
                return  # Skip other protocols
            
            if not src_ip or not dst_ip:
                return
            
            # Skip legitimate traffic
            if self.is_legitimate_traffic(src_ip, dst_ip, dst_port):
                return
            
            # Update scan tracker
            current_time = time.time()
            tracker = self.scan_tracker[src_ip]
            
            if dst_port:
                tracker['ports'].add(dst_port)
            
            if scan_type == 'syn':
                tracker['syn_count'] += 1
            elif scan_type == 'fin':
                tracker['fin_count'] += 1
            elif scan_type == 'rst':
                tracker['rst_count'] += 1
            elif scan_type == 'udp':
                tracker['udp_count'] += 1
            elif scan_type == 'icmp':
                tracker['icmp_count'] += 1
            
            tracker['last_seen'] = current_time
            
            # Check for scan patterns
            self._check_scan_patterns(src_ip, tracker)
            
        except Exception as e:
            logger.error(f"Error in scan detection: {e}")
    
    def _check_scan_patterns(self, src_ip, tracker):
        """Check for various scan patterns"""
        try:
            current_time = time.time()
            time_diff = current_time - tracker['first_seen']
            
            # Skip if within time window
            if time_diff < self.thresholds['time_window']:
                return
            
            # Check cooldown
            if src_ip in self.alert_cooldown:
                if current_time - self.alert_cooldown[src_ip] < self.cooldown_period:
                    return
            
            # Port scan detection
            if len(tracker['ports']) >= self.thresholds['port_scan']:
                desc = f"Port scan detected: {len(tracker['ports'])} ports scanned in {time_diff:.1f}s"
                self.insert_alert("Port Scan", desc, src_ip, "HIGH")
                self.alert_cooldown[src_ip] = current_time
                self._reset_tracker(src_ip)
                return
            
            # SYN scan detection
            if tracker['syn_count'] >= self.thresholds['syn_scan']:
                desc = f"SYN scan detected: {tracker['syn_count']} SYN packets in {time_diff:.1f}s"
                self.insert_alert("SYN Scan", desc, src_ip, "HIGH")
                self.alert_cooldown[src_ip] = current_time
                self._reset_tracker(src_ip)
                return
            
            # FIN scan detection
            if tracker['fin_count'] >= self.thresholds['fin_scan']:
                desc = f"FIN scan detected: {tracker['fin_count']} FIN packets in {time_diff:.1f}s"
                self.insert_alert("FIN Scan", desc, src_ip, "MEDIUM")
                self.alert_cooldown[src_ip] = current_time
                self._reset_tracker(src_ip)
                return
            
            # UDP scan detection
            if tracker['udp_count'] >= self.thresholds['udp_scan']:
                desc = f"UDP scan detected: {tracker['udp_count']} UDP packets in {time_diff:.1f}s"
                self.insert_alert("UDP Scan", desc, src_ip, "MEDIUM")
                self.alert_cooldown[src_ip] = current_time
                self._reset_tracker(src_ip)
                return
            
            # ICMP scan detection
            if tracker['icmp_count'] >= self.thresholds['icmp_scan']:
                desc = f"ICMP scan detected: {tracker['icmp_count']} ICMP packets in {time_diff:.1f}s"
                self.insert_alert("ICMP Scan", desc, src_ip, "LOW")
                self.alert_cooldown[src_ip] = current_time
                self._reset_tracker(src_ip)
                return
            
            # Check for stealth scan patterns
            self._check_stealth_patterns(src_ip, tracker)
            
        except Exception as e:
            logger.error(f"Error in pattern checking: {e}")
    
    def _check_stealth_patterns(self, src_ip, tracker):
        """Check for stealth scan patterns"""
        try:
            # Check for slow scan (many ports over long time)
            time_diff = time.time() - tracker['first_seen']
            if len(tracker['ports']) >= 5 and time_diff > 300:  # 5+ ports over 5 minutes
                desc = f"Slow scan detected: {len(tracker['ports'])} ports over {time_diff/60:.1f} minutes"
                self.insert_alert("Slow Scan", desc, src_ip, "LOW")
                self.alert_cooldown[src_ip] = time.time()
                self._reset_tracker(src_ip)
                return
            
            # Check for common port scan
            common_ports_scanned = len(tracker['ports'].intersection(self.common_scan_ports))
            if common_ports_scanned >= 3:
                desc = f"Common port scan detected: {common_ports_scanned} common ports"
                self.insert_alert("Common Port Scan", desc, src_ip, "MEDIUM")
                self.alert_cooldown[src_ip] = time.time()
                self._reset_tracker(src_ip)
                return
            
            # Check for mixed scan types
            scan_types = sum([
                1 if tracker['syn_count'] > 0 else 0,
                1 if tracker['fin_count'] > 0 else 0,
                1 if tracker['udp_count'] > 0 else 0,
                1 if tracker['icmp_count'] > 0 else 0
            ])
            
            if scan_types >= 2:
                desc = f"Mixed scan detected: {scan_types} different scan types"
                self.insert_alert("Mixed Scan", desc, src_ip, "HIGH")
                self.alert_cooldown[src_ip] = time.time()
                self._reset_tracker(src_ip)
                return
                
        except Exception as e:
            logger.debug(f"Error in stealth pattern checking: {e}")
    
    def _reset_tracker(self, src_ip):
        """Reset tracker for an IP after alert"""
        if src_ip in self.scan_tracker:
            del self.scan_tracker[src_ip]
    
    def cleanup_old_entries(self):
        """Periodically cleanup old scan tracker entries"""
        while True:
            try:
                time.sleep(self.cleanup_interval)
                current_time = time.time()
                
                # Remove old tracker entries
                for ip in list(self.scan_tracker.keys()):
                    tracker = self.scan_tracker[ip]
                    if current_time - tracker['last_seen'] > self.thresholds['time_window'] * 2:
                        del self.scan_tracker[ip]
                
                # Remove old cooldown entries
                for ip in list(self.alert_cooldown.keys()):
                    if current_time - self.alert_cooldown[ip] > self.cooldown_period * 2:
                        del self.alert_cooldown[ip]
                
                logger.debug("Scan detector cleanup completed")
                
            except Exception as e:
                logger.error(f"Error in cleanup: {e}")
    
    def start_detection(self):
        """Start port scan detection"""
        logger.info("Starting port scan detection...")
        
        # Start cleanup thread
        cleanup_thread = threading.Thread(target=self.cleanup_old_entries, daemon=True)
        cleanup_thread.start()
        
        # Start sniffing
        try:
            # Sniff TCP, UDP, and ICMP packets
            sniff(filter="tcp or udp or icmp", store=False, prn=self.detect_scan)
        except Exception as e:
            logger.error(f"Error in scan sniffing: {e}")

# Global detector instance
detector = PortScanDetector()

def start_scan_detection():
    """Start scan detection (legacy function for compatibility)"""
    detector.start_detection()
