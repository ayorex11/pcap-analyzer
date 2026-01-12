import re
import math
from collections import defaultdict, Counter
from typing import Dict, List, Tuple, Set, Any
from datetime import datetime


class SecurityDetector:
    """Comprehensive network security threat detector"""
    
    # Known malicious ports
    MALICIOUS_PORTS = {
        4444, 31337, 1337, 12345, 54321, 9999, 666, 999, 1338, 1339,
        9998, 9997, 6667, 6668, 6669, 7000, 12346, 27374, 6711, 6712,
        20034, 27665, 27444, 27573, 1234, 4321, 5555, 6666, 7777, 8888
    }
    
    # Common exploit/attack patterns
    EXPLOIT_PATTERNS = {
        'sql_injection': [
            r'union.*select',
            r'select.*from',
            r'insert.*into',
            r'update.*set',
            r'delete.*from',
            r'drop.*table',
            r'--',
            r'/\*.*\*/'
        ],
        'xss': [
            r'<script',
            r'javascript:',
            r'onload=',
            r'onerror=',
            r'onclick=',
            r'alert\(',
            r'document\.cookie'
        ],
        'directory_traversal': [
            r'\.\./',
            r'\.\.\\',
            r'/etc/passwd',
            r'/etc/shadow',
            r'c:\\windows',
            r'../../'
        ],
        'command_injection': [
            r';ls',
            r';cat',
            r';id',
            r';whoami',
            r'\|\s*sh',
            r'\|\s*bash',
            r'&&\s*',
            r'\|\|'
        ]
    }
    
    def __init__(self):
        self.ip_connections = defaultdict(lambda: defaultdict(set))
        self.syn_counts = defaultdict(int)
        self.icmp_counts = defaultdict(int)
        self.packet_sizes = defaultdict(list)
        self.http_requests = []
        self.dns_queries = []
        self.arp_requests = []
        self.threats = defaultdict(list)
        
    def analyze_packet(self, packet):
        """Analyze packet for security threats"""
        if packet.haslayer('IP'):
            self._analyze_ip_packet(packet)
        
        if packet.haslayer('ARP'):
            self._analyze_arp_packet(packet)
    
    def _analyze_ip_packet(self, packet):
        """Analyze IP layer threats"""
        src_ip = packet['IP'].src
        dst_ip = packet['IP'].dst
        
        # Track connections for port scan detection
        if packet.haslayer('TCP'):
            tcp = packet['TCP']
            dst_port = tcp.dport
            src_port = tcp.sport
            
            self.ip_connections[src_ip]['tcp'].add((dst_ip, dst_port))
            
            # SYN flood detection
            flags = str(tcp.flags)
            if 'S' in flags and 'A' not in flags:  # SYN without ACK
                self.syn_counts[src_ip] += 1
            
            # Suspicious port detection
            if dst_port in self.MALICIOUS_PORTS:
                self.threats['malicious_ports'].append({
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'port': dst_port,
                    'protocol': 'TCP',
                    'timestamp': datetime.fromtimestamp(float(packet.time))
                })
            
            # Packet size analysis (data exfiltration)
            packet_size = len(packet)
            self.packet_sizes[src_ip].append(packet_size)
            
            # Large outbound packets
            if packet_size > 1400 and self._is_external_ip(dst_ip):
                self.threats['large_outbound'].append({
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'size': packet_size,
                    'timestamp': datetime.fromtimestamp(float(packet.time))
                })
        
        elif packet.haslayer('UDP'):
            udp = packet['UDP']
            dst_port = udp.dport
            
            self.ip_connections[src_ip]['udp'].add((dst_ip, dst_port))
            
            if dst_port in self.MALICIOUS_PORTS:
                self.threats['malicious_ports'].append({
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'port': dst_port,
                    'protocol': 'UDP',
                    'timestamp': datetime.fromtimestamp(float(packet.time))
                })
        
        elif packet.haslayer('ICMP'):
            self.icmp_counts[src_ip] += 1
            
            # ICMP flood detection
            if self.icmp_counts[src_ip] > 500:
                self.threats['icmp_flood'].append({
                    'src_ip': src_ip,
                    'count': self.icmp_counts[src_ip],
                    'timestamp': datetime.fromtimestamp(float(packet.time))
                })
        
        # DNS analysis
        if packet.haslayer('DNS'):
            self._analyze_dns_packet(packet)
        
        # HTTP analysis
        if packet.haslayer('HTTPRequest'):
            self._analyze_http_packet(packet)
    
    def _analyze_arp_packet(self, packet):
        """Analyze ARP packets for spoofing"""
        arp = packet['ARP']
        
        arp_info = {
            'src_mac': arp.hwsrc,
            'src_ip': arp.psrc,
            'dst_ip': arp.pdst,
            'op': 'request' if arp.op == 1 else 'reply',
            'timestamp': datetime.fromtimestamp(float(packet.time))
        }
        
        self.arp_requests.append(arp_info)
        
        # Detect ARP spoofing
        self._detect_arp_spoofing()
    
    def _analyze_dns_packet(self, packet):
        """Analyze DNS packets for threats"""
        try:
            dns = packet['DNS']
            
            if dns.qr == 0 and hasattr(dns, 'qd') and dns.qd is not None:  # Query
                qname = str(dns.qd.qname, 'utf-8', errors='ignore').rstrip('.')
                
                dns_query = {
                    'domain': qname,
                    'src_ip': packet['IP'].src if packet.haslayer('IP') else 'Unknown',
                    'timestamp': datetime.fromtimestamp(float(packet.time))
                }
                
                self.dns_queries.append(dns_query)
                
                # Check for suspicious DNS patterns
                self._check_dns_threats(qname, dns_query)
                
        except Exception:
            pass
    
    def _analyze_http_packet(self, packet):
        """Analyze HTTP packets for attacks"""
        try:
            http = packet['HTTPRequest']
            
            host = str(http.Host, 'utf-8', errors='ignore') if http.Host else ''
            path = str(http.Path, 'utf-8', errors='ignore') if http.Path else ''
            method = str(http.Method, 'utf-8', errors='ignore') if hasattr(http, 'Method') else ''
            
            http_request = {
                'src_ip': packet['IP'].src if packet.haslayer('IP') else 'Unknown',
                'host': host,
                'method': method,
                'path': path,
                'timestamp': datetime.fromtimestamp(float(packet.time))
            }
            
            self.http_requests.append(http_request)
            
            # Check for HTTP attacks
            self._check_http_threats(http_request)
            
            # Check for credentials in plaintext
            if packet.haslayer('Raw'):
                raw = packet['Raw']
                try:
                    payload = raw.load.decode('utf-8', errors='ignore')
                    self._check_credentials(payload, http_request)
                except:
                    pass
                    
        except Exception:
            pass
    
    def _check_dns_threats(self, domain: str, query_info: dict):
        """Check DNS queries for threats"""
        # Long domain names (possible tunneling)
        if len(domain) > 60:
            self.threats['dns_tunneling_suspect'].append({
                **query_info,
                'reason': f'Long domain name: {len(domain)} characters'
            })
        
        # High entropy domains (DGA)
        entropy = self._calculate_entropy(domain)
        if entropy > 4.5:
            self.threats['dga_suspect'].append({
                **query_info,
                'reason': f'High entropy: {entropy:.2f}'
            })
        
        # Suspicious TLDs
        if '.' in domain:
            tld = domain.split('.')[-1].lower()
            suspicious_tlds = {'tk', 'ml', 'ga', 'cf', 'gq', 'pw'}
            if tld in suspicious_tlds:
                self.threats['suspicious_tld'].append({
                    **query_info,
                    'reason': f'Suspicious TLD: .{tld}'
                })
    
    def _check_http_threats(self, request: dict):
        """Check HTTP requests for attacks"""
        full_request = f"{request['method']} {request['path']}"
        
        for attack_type, patterns in self.EXPLOIT_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, full_request, re.IGNORECASE):
                    self.threats['http_attack'].append({
                        **request,
                        'attack_type': attack_type,
                        'pattern': pattern
                    })
                    break
    
    def _check_credentials(self, payload: str, request: dict):
        """Check for plaintext credentials"""
        credential_patterns = [
            (r'password[=:]\s*["\']?([^"\'\s&]+)', 'password'),
            (r'passwd[=:]\s*["\']?([^"\'\s&]+)', 'password'),
            (r'pwd[=:]\s*["\']?([^"\'\s&]+)', 'password'),
            (r'username[=:]\s*["\']?([^"\'\s&]+)', 'username'),
            (r'user[=:]\s*["\']?([^"\'\s&]+)', 'username'),
            (r'email[=:]\s*["\']?([^"\'\s&]+)', 'email'),
            (r'api[_-]?key[=:]\s*["\']?([^"\'\s&]+)', 'api_key'),
            (r'token[=:]\s*["\']?([^"\'\s&]+)', 'token'),
            (r'secret[=:]\s*["\']?([^"\'\s&]+)', 'secret'),
            (r'authorization:\s*(basic|bearer)\s+([^\s]+)', 'auth_token')
        ]
        
        for pattern, cred_type in credential_patterns:
            matches = re.findall(pattern, payload, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    value = match[-1]
                else:
                    value = match
                
                # Don't capture empty values
                if value and len(value) > 3:
                    self.threats['credential_exposure'].append({
                        **request,
                        'credential_type': cred_type,
                        'value_preview': value[:20] + '...' if len(value) > 20 else value
                    })
    
    def _detect_arp_spoofing(self):
        """Detect ARP spoofing attacks"""
        if len(self.arp_requests) < 10:
            return
        
        mac_to_ips = defaultdict(set)
        ip_to_macs = defaultdict(set)
        
        for arp in self.arp_requests[-100:]:  # Check last 100 ARP requests
            mac_to_ips[arp['src_mac']].add(arp['src_ip'])
            ip_to_macs[arp['src_ip']].add(arp['src_mac'])
        
        # Multiple IPs for one MAC
        for mac, ips in mac_to_ips.items():
            if len(ips) > 1:
                self.threats['arp_spoofing'].append({
                    'type': 'MAC claiming multiple IPs',
                    'mac': mac,
                    'ips': list(ips),
                    'timestamp': datetime.now()
                })
        
        # Multiple MACs for one IP
        for ip, macs in ip_to_macs.items():
            if len(macs) > 1:
                self.threats['arp_spoofing'].append({
                    'type': 'IP claimed by multiple MACs',
                    'ip': ip,
                    'macs': list(macs),
                    'timestamp': datetime.now()
                })
    
    def detect_port_scans(self, threshold: int = 50) -> List[Dict]:
        """Detect port scanning activity"""
        scans = []
        
        for src_ip, protocols in self.ip_connections.items():
            total_targets = 0
            
            for proto, connections in protocols.items():
                unique_targets = len(connections)
                total_targets += unique_targets
                
                if unique_targets > threshold:
                    scans.append({
                        'src_ip': src_ip,
                        'protocol': proto,
                        'unique_targets': unique_targets,
                        'targets_sample': list(connections)[:10],
                        'severity': 'HIGH' if unique_targets > 100 else 'MEDIUM'
                    })
        
        return scans
    
    def detect_syn_floods(self, threshold: int = 1000) -> List[Dict]:
        """Detect SYN flood attacks"""
        floods = []
        
        for src_ip, count in self.syn_counts.items():
            if count > threshold:
                floods.append({
                    'src_ip': src_ip,
                    'syn_count': count,
                    'severity': 'HIGH' if count > 5000 else 'MEDIUM'
                })
        
        return floods
    
    def detect_data_exfiltration(self, size_threshold: int = 1000000) -> List[Dict]:
        """Detect potential data exfiltration"""
        exfil = []
        
        for src_ip, sizes in self.packet_sizes.items():
            total_size = sum(sizes)
            avg_size = total_size / len(sizes) if sizes else 0
            
            if total_size > size_threshold and avg_size > 1000:
                exfil.append({
                    'src_ip': src_ip,
                    'total_size': total_size,
                    'avg_size': avg_size,
                    'packet_count': len(sizes),
                    'severity': 'HIGH' if total_size > 5000000 else 'MEDIUM'
                })
        
        return exfil
    
    def get_all_threats(self) -> Dict[str, List]:
        """Get all detected threats"""
        all_threats = dict(self.threats)
        
        # Add dynamic detections
        all_threats['port_scans'] = self.detect_port_scans()
        all_threats['syn_floods'] = self.detect_syn_floods()
        all_threats['data_exfiltration'] = self.detect_data_exfiltration()
        
        # Summary statistics
        summary = {
            'total_threats': sum(len(threats) for threats in all_threats.values()),
            'threat_categories': len(all_threats),
            'high_severity': self._count_severity(all_threats, 'HIGH'),
            'medium_severity': self._count_severity(all_threats, 'MEDIUM')
        }
        
        all_threats['summary'] = summary
        return all_threats
    
    def _count_severity(self, threats: Dict[str, List], severity: str) -> int:
        """Count threats by severity"""
        count = 0
        for threat_list in threats.values():
            for threat in threat_list:
                if threat.get('severity') == severity:
                    count += 1
        return count
    
    @staticmethod
    def _calculate_entropy(string: str) -> float:
        """Calculate Shannon entropy"""
        if not string:
            return 0.0
        
        entropy = 0.0
        for char in set(string):
            freq = string.count(char) / len(string)
            entropy -= freq * math.log2(freq)
        
        return entropy
    
    @staticmethod
    def _is_external_ip(ip: str) -> bool:
        """Check if IP is external"""
        try:
            parts = list(map(int, ip.split('.')))
            
            if parts[0] == 10:
                return False
            if parts[0] == 172 and 16 <= parts[1] <= 31:
                return False
            if parts[0] == 192 and parts[1] == 168:
                return False
            if parts[0] == 127:
                return False
            if parts[0] == 169 and parts[1] == 254:
                return False
            
            return True
        except Exception:
            return False