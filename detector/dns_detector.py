from scapy.all import sniff, DNS, DNSQR, DNSRR, IP, UDP
import sqlite3
from datetime import datetime
import time
from collections import defaultdict
import threading
import logging
import socket
import dns.resolver
import dns.reversename

# Configure logging to be silent by default
logger = logging.getLogger(__name__)
logger.setLevel(logging.WARNING)  # Only show warnings and errors

DB_PATH = 'database.db'

class DNSSpoofingDetector:
    def __init__(self):
        self.dns_cache = {}  # domain -> {ip, timestamp, count}
        self.suspicious_ips = defaultdict(int)  # IP -> suspicious activity count
        self.legitimate_dns_servers = set()  # Known legitimate DNS servers
        self.alert_cooldown = {}  # domain -> last alert time
        self.cooldown_period = 120  # seconds between alerts for same domain
        self.suspicious_threshold = 2  # suspicious activities before alert
        self.cache_timeout = 3600  # 1 hour cache timeout
        self.trusted_dns_servers = [
            '8.8.8.8', '8.8.4.4',  # Google DNS
            '1.1.1.1', '1.0.0.1',  # Cloudflare DNS
            '208.67.222.222', '208.67.220.220',  # OpenDNS
        ]
        
        # Initialize legitimate DNS servers
        self._init_dns_servers()
        
    def _init_dns_servers(self):
        """Initialize legitimate DNS servers list"""
        try:
            # Get system DNS servers
            with open('/etc/resolv.conf', 'r') as f:
                for line in f:
                    if line.startswith('nameserver'):
                        server = line.split()[1]
                        self.legitimate_dns_servers.add(server)
                        logger.info(f"Added DNS server: {server}")
        except Exception as e:
            logger.warning(f"Could not read resolv.conf: {e}")
        
        # Add trusted DNS servers
        for server in self.trusted_dns_servers:
            self.legitimate_dns_servers.add(server)
    
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
            
            logger.warning(f"DNS Alert: {enhanced_desc}")
            
        except Exception as e:
            logger.error(f"Error inserting alert: {e}")
    
    def is_legitimate_dns_server(self, ip):
        """Check if DNS server is legitimate"""
        return ip in self.legitimate_dns_servers
    
    def validate_dns_response(self, domain, ip, dns_server):
        """Validate DNS response using external DNS servers"""
        try:
            # Skip validation for known legitimate servers
            if self.is_legitimate_dns_server(dns_server):
                return True
            
            # Query multiple trusted DNS servers
            trusted_ips = set()
            for trusted_server in self.trusted_dns_servers[:2]:  # Use first 2 trusted servers
                try:
                    resolver = dns.resolver.Resolver()
                    resolver.nameservers = [trusted_server]
                    resolver.timeout = 2
                    resolver.lifetime = 2
                    
                    answers = resolver.resolve(domain, 'A')
                    for answer in answers:
                        trusted_ips.add(str(answer))
                        
                except Exception as e:
                    logger.debug(f"Error querying {trusted_server}: {e}")
                    continue
            
            # If we got responses from trusted servers
            if trusted_ips:
                return ip in trusted_ips
            
            return True  # If we can't validate, assume legitimate
            
        except Exception as e:
            logger.debug(f"Error in DNS validation: {e}")
            return True
    
    def detect_dns_spoofing(self, pkt):
        """Enhanced DNS spoofing detection"""
        try:
            if not pkt.haslayer(DNS):
                return
            
            dns_layer = pkt[DNS]
            
            # Only process DNS responses
            if dns_layer.qr != 1:  # 1 = response
                return
            
            # Get source IP
            if pkt.haslayer(IP):
                source_ip = pkt[IP].src
            else:
                return
            
            # Extract DNS query and response
            try:
                # Get query
                if dns_layer.haslayer(DNSQR):
                    query = dns_layer[DNSQR]
                    domain = query.qname.decode().rstrip('.')
                else:
                    return
                
                # Get response
                if dns_layer.haslayer(DNSRR):
                    response = dns_layer[DNSRR]
                    if response.type == 1:  # A record
                        ip = response.rdata
                    else:
                        return  # Skip non-A records
                else:
                    return
                
            except Exception as e:
                logger.debug(f"Error parsing DNS packet: {e}")
                return
            
            # Skip if it's a legitimate DNS server
            if self.is_legitimate_dns_server(source_ip):
                return
            
            # Check for DNS cache poisoning
            current_time = time.time()
            
            if domain in self.dns_cache:
                cached_data = self.dns_cache[domain]
                
                # Check if IP has changed
                if cached_data['ip'] != ip:
                    self.suspicious_ips[source_ip] += 1
                    
                    # Validate the response
                    is_valid = self.validate_dns_response(domain, ip, source_ip)
                    
                    if not is_valid:
                        self.suspicious_ips[source_ip] += 1  # Extra penalty for invalid response
                    
                    # Check if we should alert
                    if self.suspicious_ips[source_ip] >= self.suspicious_threshold:
                        # Check cooldown
                        if domain not in self.alert_cooldown or \
                           current_time - self.alert_cooldown[domain] > self.cooldown_period:
                            
                            desc = f"DNS Spoofing detected: {domain} -> IP changed from {cached_data['ip']} to {ip}"
                            severity = "CRITICAL" if not is_valid else "HIGH"
                            
                            self.insert_alert("DNS Spoofing", desc, source_ip, severity)
                            self.alert_cooldown[domain] = current_time
                            
                            # Reset suspicious count after alert
                            self.suspicious_ips[source_ip] = 0
                else:
                    # Same IP, reduce suspicious count
                    if self.suspicious_ips[source_ip] > 0:
                        self.suspicious_ips[source_ip] -= 1
            
            # Update DNS cache
            self.dns_cache[domain] = {
                'ip': ip,
                'timestamp': current_time,
                'count': self.dns_cache.get(domain, {}).get('count', 0) + 1
            }
            
            # Check for additional suspicious patterns
            self._check_suspicious_patterns(domain, ip, source_ip)
            
        except Exception as e:
            logger.error(f"Error in DNS detection: {e}")
    
    def _check_suspicious_patterns(self, domain, ip, source_ip):
        """Check for additional suspicious DNS patterns"""
        try:
            current_time = time.time()
            
            # Check for DNS amplification attack
            if domain in self.dns_cache:
                cache_data = self.dns_cache[domain]
                if cache_data['count'] > 10:  # Too many queries for same domain
                    desc = f"DNS amplification attack detected: {domain} queried {cache_data['count']} times"
                    self.insert_alert("DNS Amplification", desc, source_ip, "MEDIUM")
            
            # Check for suspicious domains
            suspicious_keywords = ['bank', 'paypal', 'amazon', 'google', 'facebook', 'twitter']
            if any(keyword in domain.lower() for keyword in suspicious_keywords):
                # Extra scrutiny for financial/popular domains
                if not self.validate_dns_response(domain, ip, source_ip):
                    desc = f"Suspicious DNS response for {domain} -> {ip}"
                    self.insert_alert("Suspicious DNS", desc, source_ip, "HIGH")
            
            # Check for local network spoofing
            if ip.startswith(('192.168.', '10.', '172.')):
                # Internal IP being returned for external domain
                if not domain.endswith(('.local', '.home', '.lan')):
                    desc = f"Internal IP spoofing: {domain} -> {ip}"
                    self.insert_alert("Internal IP Spoofing", desc, source_ip, "HIGH")
                    
        except Exception as e:
            logger.debug(f"Error in pattern checking: {e}")
    
    def cleanup_old_entries(self):
        """Periodically cleanup old DNS cache entries"""
        while True:
            try:
                time.sleep(300)  # Cleanup every 5 minutes
                current_time = time.time()
                
                # Remove old cache entries
                for domain in list(self.dns_cache.keys()):
                    if current_time - self.dns_cache[domain]['timestamp'] > self.cache_timeout:
                        del self.dns_cache[domain]
                
                # Remove old suspicious entries
                for ip in list(self.suspicious_ips.keys()):
                    if self.suspicious_ips[ip] <= 0:
                        del self.suspicious_ips[ip]
                
                # Remove old cooldown entries
                for domain in list(self.alert_cooldown.keys()):
                    if current_time - self.alert_cooldown[domain] > self.cooldown_period * 2:
                        del self.alert_cooldown[domain]
                
                logger.debug("DNS detector cleanup completed")
                
            except Exception as e:
                logger.error(f"Error in cleanup: {e}")
    
    def start_detection(self):
        """Start DNS spoofing detection"""
        logger.info("Starting DNS spoofing detection...")
        
        # Start cleanup thread
        cleanup_thread = threading.Thread(target=self.cleanup_old_entries, daemon=True)
        cleanup_thread.start()
        
        # Start sniffing
        try:
            sniff(filter="udp port 53", store=False, prn=self.detect_dns_spoofing)
        except Exception as e:
            logger.error(f"Error in DNS sniffing: {e}")

# Global detector instance
detector = DNSSpoofingDetector()

def start_dns_detection():
    """Start DNS detection (legacy function for compatibility)"""
    detector.start_detection()
