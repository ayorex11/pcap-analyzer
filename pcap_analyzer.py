"""
Enhanced Advanced PCAP File Analyzer
Analyzes network packet capture files with comprehensive statistics, 
security detection, and export capabilities

Installation:
    pip install scapy requests matplotlib ipwhois
"""

import argparse
import re
import json
import csv
import sys
import os
from collections import Counter, defaultdict
from datetime import datetime
from typing import Dict, List, Tuple, Any, Optional
import requests
from scapy.all import rdpcap, IP, TCP, UDP, ICMP, ARP, DNS, DNSQR, Raw
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
from scapy.layers.dhcp import DHCP
from scapy.layers.ntp import NTP
from scapy.error import Scapy_Exception
import warnings
import math
from urllib.parse import parse_qs, urlparse

warnings.filterwarnings('ignore')

# Try to import optional dependencies
try:
    from ipwhois import IPWhois
    IPWHOIS_AVAILABLE = True
except ImportError:
    IPWHOIS_AVAILABLE = False

try:
    import matplotlib.pyplot as plt
    import matplotlib
    matplotlib.use('Agg')  # Non-interactive backend
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False


class PCAPAnalyzer:
    """Main analyzer class for PCAP files"""
    
    def __init__(self, filename: str, verbose: bool = False, quick_mode: bool = False):
        self.filename = filename
        self.verbose = verbose
        self.quick_mode = quick_mode
        self.packets = None
        self.stats = None
        
    def load_packets(self) -> bool:
        """Load packets from PCAP file with error handling"""
        try:
            if self.verbose:
                print(f"📂 Loading packets from {self.filename}...")
            
            self.packets = rdpcap(self.filename)
            
            if self.verbose:
                print(f"✅ Loaded {len(self.packets)} packets successfully")
            
            return True
        except FileNotFoundError:
            print(f"❌ Error: File '{self.filename}' not found")
            return False
        except Scapy_Exception as e:
            print(f"❌ Scapy error reading file: {e}")
            return False
        except Exception as e:
            print(f"❌ Unexpected error reading file: {e}")
            return False
    
    def analyze(self) -> Dict[str, Any]:
        """
        Perform comprehensive analysis of loaded packets
        """
        if not self.packets:
            return {}
        
        self.stats = {
            'total_packets': len(self.packets),
            'protocols': Counter(),
            'ip_sources': Counter(),
            'ip_destinations': Counter(),
            'ports': {'tcp': Counter(), 'udp': Counter()},
            'conversations': defaultdict(int),
            'packet_sizes': [],
            'dns_queries': [],
            'timeline': {},
            'suspicious_activities': {},
            'http_analysis': {},
            'ip_enrichment': {},
            'tcp_flags': Counter(),
            'payload_analysis': {}
        }
        
        # Analyze packets
        for idx, packet in enumerate(self.packets):
            if self.verbose and idx % 10000 == 0 and idx > 0:
                print(f"  Processing packet {idx}/{len(self.packets)}...")
            
            self._analyze_packet(packet)
        
        # Enhanced analysis
        if self.verbose:
            print("📊 Performing timeline analysis...")
        self.stats['timeline'] = self._analyze_timeline()
        
        if not self.quick_mode:
            if self.verbose:
                print("🔍 Detecting suspicious patterns...")
            self.stats['suspicious_activities'] = self._detect_suspicious_patterns()
            
            if self.verbose:
                print("🌐 Analyzing HTTP traffic...")
            self.stats['http_analysis'] = self._analyze_http_traffic()
            
            if self.verbose:
                print("🔐 Analyzing payloads...")
            self.stats['payload_analysis'] = self._analyze_payloads()
            
            if self.verbose:
                print("🌍 Enriching IP information...")
            top_ips = set(
                list(dict(self.stats['ip_sources'].most_common(10)).keys()) + 
                list(dict(self.stats['ip_destinations'].most_common(10)).keys())
            )
            self.stats['ip_enrichment'] = self._enrich_ip_information(top_ips)
        
        return self.stats
    
    def _analyze_packet(self, packet) -> None:
        """Analyze individual packet"""
        # Protocol statistics
        if packet.haslayer(TCP):
            self.stats['protocols']['TCP'] += 1
            tcp_layer = packet[TCP]
            if tcp_layer.dport:
                self.stats['ports']['tcp'][tcp_layer.dport] += 1
            # TCP flags analysis
            flags = tcp_layer.sprintf('%TCP.flags%')
            self.stats['tcp_flags'][flags] += 1
            
        if packet.haslayer(UDP):
            self.stats['protocols']['UDP'] += 1
            if packet[UDP].dport:
                self.stats['ports']['udp'][packet[UDP].dport] += 1
                
        if packet.haslayer(ICMP):
            self.stats['protocols']['ICMP'] += 1
            
        if packet.haslayer(ARP):
            self.stats['protocols']['ARP'] += 1
            
        if packet.haslayer(DNS):
            self.stats['protocols']['DNS'] += 1
        
        # IP layer analysis
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            self.stats['ip_sources'][src_ip] += 1
            self.stats['ip_destinations'][dst_ip] += 1
            
            # Track conversations (bidirectional communication)
            conversation = tuple(sorted([src_ip, dst_ip]))
            self.stats['conversations'][conversation] += 1
            
            # Packet size
            self.stats['packet_sizes'].append(len(packet))
        
        # DNS queries extraction
        if packet.haslayer(DNS) and packet.haslayer(DNSQR):
            try:
                qr_flag = packet[DNS].qr  # 0 = query, 1 = response
                if qr_flag == 0:  # Only queries
                    qname = packet[DNSQR].qname
                    if qname:
                        query = qname.decode('utf-8', errors='ignore').rstrip('.')
                        if query:
                            self.stats['dns_queries'].append(query)
            except Exception:
                pass
    
    def _analyze_timeline(self) -> Dict[str, Any]:
        """Analyze packet timing and detect traffic bursts"""
        if not self.packets:
            return {}
        
        try:
            timestamps = [float(packet.time) for packet in self.packets]
        except Exception:
            return {}
        
        if not timestamps:
            return {}
        
        min_time = min(timestamps)
        max_time = max(timestamps)
        duration = max_time - min_time
        
        timeline = {
            'start_time': datetime.fromtimestamp(min_time),
            'end_time': datetime.fromtimestamp(max_time),
            'duration_seconds': duration,
            'packets_per_second': len(self.packets) / duration if duration > 0 else 0,
            'time_buckets': defaultdict(int),
            'bursts': []
        }
        
        # Group packets into 1-minute intervals
        interval = 60  # seconds
        for timestamp in timestamps:
            bucket = int((timestamp - min_time) / interval)
            timeline['time_buckets'][bucket] += 1
        
        # Detect traffic bursts (>100 packets in 10 seconds)
        if len(timestamps) > 1 and not self.quick_mode:
            burst_window = 10  # seconds
            burst_threshold = 100
            
            window_start = 0
            for i in range(len(timestamps)):
                # Move window forward
                while window_start < i and timestamps[i] - timestamps[window_start] > burst_window:
                    window_start += 1
                
                packets_in_window = i - window_start + 1
                
                if packets_in_window > burst_threshold:
                    # Check if this is a new burst
                    if not timeline['bursts'] or timestamps[i] - timeline['bursts'][-1]['end_time'] > burst_window:
                        timeline['bursts'].append({
                            'start': datetime.fromtimestamp(timestamps[window_start]),
                            'end_time': timestamps[i],
                            'duration': timestamps[i] - timestamps[window_start],
                            'packet_count': packets_in_window
                        })
        
        return timeline
    
    def _detect_suspicious_patterns(self) -> Dict[str, List]:
        """Detect potentially malicious network activity"""
        suspicious = {
            'port_scan': [],
            'syn_flood': [],
            'dns_tunneling': [],
            'unusual_ports': [],
            'data_exfiltration': [],
            'high_frequency_ips': [],
            'icmp_flood': [],
            'arp_spoofing': []
        }
        
        # Suspicious ports commonly used by malware
        suspicious_ports = {
            4444, 31337, 1337, 12345, 54321, 9999, 666, 999, 1338, 1339,
            9998, 9997, 6667, 6668, 6669, 7000, 12346, 27374, 6711, 6712
        }
        
        # Tracking dictionaries
        src_dst_ports = defaultdict(set)  # Track unique ports per source
        syn_packets = defaultdict(int)
        icmp_packets = defaultdict(int)
        arp_requests = []
        packet_counts_per_ip = defaultdict(int)
        
        for packet in self.packets:
            if packet.haslayer(IP):
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                packet_counts_per_ip[src_ip] += 1
                
                # Port scanning detection
                if packet.haslayer(TCP):
                    dst_port = packet[TCP].dport
                    src_dst_ports[src_ip].add((dst_ip, dst_port))
                    
                    # SYN flood detection
                    flags = packet[TCP].sprintf('%TCP.flags%')
                    if 'S' in flags and 'A' not in flags:
                        syn_packets[src_ip] += 1
                    
                    # Unusual port detection
                    if dst_port in suspicious_ports:
                        suspicious['unusual_ports'].append({
                            'source': src_ip,
                            'destination': dst_ip,
                            'port': dst_port,
                            'protocol': 'TCP',
                            'timestamp': datetime.fromtimestamp(float(packet.time))
                        })
                
                # DNS tunneling detection (unusually large DNS packets)
                if packet.haslayer(DNS) and len(packet) > 512:
                    suspicious['dns_tunneling'].append({
                        'source': src_ip,
                        'destination': dst_ip,
                        'packet_size': len(packet),
                        'timestamp': datetime.fromtimestamp(float(packet.time))
                    })
                
                # Data exfiltration detection
                if len(packet) > 1400 and self._is_external_ip(dst_ip):
                    suspicious['data_exfiltration'].append({
                        'source': src_ip,
                        'destination': dst_ip,
                        'size': len(packet),
                        'timestamp': datetime.fromtimestamp(float(packet.time))
                    })
                
                # ICMP flood detection
                if packet.haslayer(ICMP):
                    icmp_packets[src_ip] += 1
            
            # ARP spoofing detection
            if packet.haslayer(ARP):
                arp_requests.append({
                    'src_mac': packet[ARP].hwsrc,
                    'src_ip': packet[ARP].psrc,
                    'dst_ip': packet[ARP].pdst,
                    'op': packet[ARP].op  # 1=request, 2=reply
                })
        
        # Analyze collected data
        # Port scan detection (>50 unique destination ports from single source)
        for src_ip, dst_ports in src_dst_ports.items():
            if len(dst_ports) > 50:
                suspicious['port_scan'].append({
                    'ip': src_ip,
                    'unique_targets': len(dst_ports),
                    'severity': 'HIGH' if len(dst_ports) > 100 else 'MEDIUM'
                })
        
        # SYN flood detection (>1000 SYN packets from single source)
        for src_ip, count in syn_packets.items():
            if count > 1000:
                suspicious['syn_flood'].append({
                    'ip': src_ip,
                    'syn_count': count,
                    'severity': 'HIGH'
                })
        
        # High frequency IP detection
        if packet_counts_per_ip:
            avg_packets = sum(packet_counts_per_ip.values()) / len(packet_counts_per_ip)
            for ip, count in packet_counts_per_ip.items():
                if count > avg_packets * 10 and count > 1000:
                    suspicious['high_frequency_ips'].append({
                        'ip': ip,
                        'packet_count': count,
                        'average': int(avg_packets),
                        'ratio': f"{count/avg_packets:.1f}x"
                    })
        
        # ICMP flood detection (>500 ICMP packets from single source)
        for src_ip, count in icmp_packets.items():
            if count > 500:
                suspicious['icmp_flood'].append({
                    'ip': src_ip,
                    'icmp_count': count
                })
        
        # ARP spoofing detection (multiple IPs claiming same MAC or same IP with different MACs)
        if arp_requests:
            mac_to_ips = defaultdict(set)
            ip_to_macs = defaultdict(set)
            
            for arp in arp_requests:
                mac_to_ips[arp['src_mac']].add(arp['src_ip'])
                ip_to_macs[arp['src_ip']].add(arp['src_mac'])
            
            for mac, ips in mac_to_ips.items():
                if len(ips) > 1:
                    suspicious['arp_spoofing'].append({
                        'mac': mac,
                        'claimed_ips': list(ips),
                        'type': 'Multiple IPs for one MAC'
                    })
            
            for ip, macs in ip_to_macs.items():
                if len(macs) > 1:
                    suspicious['arp_spoofing'].append({
                        'ip': ip,
                        'macs': list(macs),
                        'type': 'Multiple MACs for one IP'
                    })
        
        return suspicious
    
    def _analyze_http_traffic(self) -> Dict[str, Any]:
        """Extract and analyze HTTP traffic"""
        http_data = {
            'requests': [],
            'responses': [],
            'hosts': Counter(),
            'user_agents': Counter(),
            'status_codes': Counter(),
            'methods': Counter(),
            'suspicious_requests': []
        }
        
        # Patterns for detecting suspicious HTTP activity
        suspicious_patterns = [
            r'\.\./',  # Directory traversal
            r'<script',  # XSS attempts
            r'union.*select',  # SQL injection
            r'exec\(',  # Command injection
            r'eval\(',  # Code injection
        ]
        
        for packet in self.packets:
            try:
                # HTTP Requests
                if packet.haslayer(HTTPRequest):
                    http_layer = packet[HTTPRequest]
                    
                    host = http_layer.Host.decode('utf-8', errors='ignore') if http_layer.Host else 'Unknown'
                    path = http_layer.Path.decode('utf-8', errors='ignore') if http_layer.Path else '/'
                    method = http_layer.Method.decode('utf-8', errors='ignore') if hasattr(http_layer, 'Method') else 'Unknown'
                    
                    http_data['hosts'][host] += 1
                    http_data['methods'][method] += 1
                    
                    # Extract User-Agent
                    user_agent = 'Unknown'
                    if hasattr(http_layer, 'User_Agent'):
                        user_agent = http_layer.User_Agent.decode('utf-8', errors='ignore')
                    
                    http_data['user_agents'][user_agent] += 1
                    
                    # Check for suspicious patterns
                    full_request = f"{method} {path}"
                    if packet.haslayer(Raw):
                        full_request += packet[Raw].load.decode('utf-8', errors='ignore')
                    
                    for pattern in suspicious_patterns:
                        if re.search(pattern, full_request, re.IGNORECASE):
                            http_data['suspicious_requests'].append({
                                'src_ip': packet[IP].src if packet.haslayer(IP) else 'Unknown',
                                'host': host,
                                'method': method,
                                'path': path,
                                'pattern_matched': pattern,
                                'timestamp': datetime.fromtimestamp(float(packet.time))
                            })
                            break
                    
                    http_data['requests'].append({
                        'src_ip': packet[IP].src if packet.haslayer(IP) else 'Unknown',
                        'host': host,
                        'method': method,
                        'path': path,
                        'user_agent': user_agent,
                        'timestamp': datetime.fromtimestamp(float(packet.time))
                    })
                
                # HTTP Responses
                if packet.haslayer(HTTPResponse):
                    http_layer = packet[HTTPResponse]
                    
                    status = 'Unknown'
                    if hasattr(http_layer, 'Status_Code'):
                        status = http_layer.Status_Code.decode('utf-8', errors='ignore')
                    
                    http_data['status_codes'][status] += 1
                    
                    http_data['responses'].append({
                        'dst_ip': packet[IP].dst if packet.haslayer(IP) else 'Unknown',
                        'status': status,
                        'timestamp': datetime.fromtimestamp(float(packet.time))
                    })
            except Exception:
                continue
        
        return http_data
    
    def _analyze_payloads(self) -> Dict[str, Any]:
        """Analyze packet payloads for interesting patterns"""
        payload_info = {
            'encrypted_traffic': 0,
            'plaintext_credentials': [],
            'interesting_strings': [],
            'file_transfers': []
        }
        
        # Patterns for credentials
        credential_patterns = [
            (r'password[=:]\s*(\S+)', 'password'),
            (r'user(?:name)?[=:]\s*(\S+)', 'username'),
            (r'api[_-]?key[=:]\s*(\S+)', 'api_key'),
            (r'token[=:]\s*(\S+)', 'token'),
        ]
        
        for packet in self.packets[:10000]:  # Limit for performance
            try:
                if packet.haslayer(Raw):
                    payload = packet[Raw].load
                    
                    # Check for encrypted traffic (high entropy)
                    if len(payload) > 100:
                        # Simple entropy check - count unique bytes
                        unique_bytes = len(set(payload))
                        if unique_bytes > len(payload) * 0.7:  # High randomness
                            payload_info['encrypted_traffic'] += 1
                    
                    # Look for credentials in plaintext
                    try:
                        text_payload = payload.decode('utf-8', errors='ignore')
                        
                        for pattern, cred_type in credential_patterns:
                            matches = re.findall(pattern, text_payload, re.IGNORECASE)
                            for match in matches:
                                payload_info['plaintext_credentials'].append({
                                    'type': cred_type,
                                    'value': match[:20] + '...' if len(match) > 20 else match,
                                    'src_ip': packet[IP].src if packet.haslayer(IP) else 'Unknown',
                                    'timestamp': datetime.fromtimestamp(float(packet.time))
                                })
                    except Exception:
                        pass
            except Exception:
                continue
        
        return payload_info
    
    def _enrich_ip_information(self, ip_list: set) -> Dict[str, Dict]:
        """Add geolocation and ASN information for IPs"""
        enriched_ips = {}
        
        for ip in list(ip_list)[:15]:  # Limit API calls
            # Skip private IPs
            if not self._is_external_ip(ip):
                enriched_ips[ip] = {
                    'country': 'Private',
                    'city': 'Private',
                    'isp': 'Private Network',
                    'asn': 'N/A',
                    'org': 'Private'
                }
                continue
            
            try:
                # Use free geolocation API with rate limiting
                response = requests.get(
                    f'http://ip-api.com/json/{ip}',
                    timeout=3,
                    headers={'User-Agent': 'PCAP-Analyzer/1.0'}
                )
                
                if response.status_code == 200:
                    data = response.json()
                    if data.get('status') == 'success':
                        enriched_ips[ip] = {
                            'country': data.get('country', 'Unknown'),
                            'city': data.get('city', 'Unknown'),
                            'isp': data.get('isp', 'Unknown'),
                            'asn': data.get('as', 'Unknown'),
                            'org': data.get('org', 'Unknown'),
                            'lat': data.get('lat'),
                            'lon': data.get('lon')
                        }
                        continue
            except requests.RequestException:
                pass
            except Exception:
                pass
            
            # Fallback for failed lookups
            enriched_ips[ip] = {
                'country': 'Unknown',
                'city': 'Unknown',
                'isp': 'Unknown',
                'asn': 'Unknown',
                'org': 'Unknown'
            }
        
        return enriched_ips
    
    @staticmethod
    def _is_external_ip(ip: str) -> bool:
        """Check if IP is external (not private/loopback)"""
        try:
            parts = list(map(int, ip.split('.')))
            
            # Check private ranges
            if parts[0] == 10:
                return False
            if parts[0] == 172 and 16 <= parts[1] <= 31:
                return False
            if parts[0] == 192 and parts[1] == 168:
                return False
            if parts[0] == 127:  # Loopback
                return False
            if parts[0] == 169 and parts[1] == 254:  # Link-local
                return False
            
            return True
        except Exception:
            return False


class ReportGenerator:
    """Generate various report formats"""
    
    def __init__(self, stats: Dict[str, Any], filename: str):
        self.stats = stats
        self.filename = filename
        self.base_name = os.path.splitext(filename)[0]
    
    def print_statistics(self) -> None:
        """Print formatted statistics to console"""
        print("\n" + "=" * 80)
        print("ADVANCED PCAP ANALYSIS REPORT")
        print("=" * 80)
        
        # Summary
        print(f"\n📊 SUMMARY")
        print(f"Total Packets: {self.stats['total_packets']:,}")
        if self.stats.get('timeline'):
            print(f"Capture Duration: {self.stats['timeline'].get('duration_seconds', 0):.2f} seconds")
            print(f"Packets/Second: {self.stats['timeline'].get('packets_per_second', 0):.2f}")
            print(f"Start Time: {self.stats['timeline'].get('start_time', 'Unknown')}")
            print(f"End Time: {self.stats['timeline'].get('end_time', 'Unknown')}")
        
        # Protocol distribution
        print(f"\n📡 PROTOCOL DISTRIBUTION")
        for protocol, count in self.stats['protocols'].most_common():
            percentage = (count / self.stats['total_packets']) * 100
            bar = "█" * int(percentage / 2)
            print(f"  {protocol:8s}: {count:8,} ({percentage:5.2f}%) {bar}")
        
        # TCP Flags
        if self.stats.get('tcp_flags'):
            print(f"\n🚩 TCP FLAGS DISTRIBUTION")
            for flags, count in self.stats['tcp_flags'].most_common(10):
                print(f"  {flags:8s}: {count:,}")
        
        # Top source IPs
        print(f"\n🌐 TOP 10 SOURCE IP ADDRESSES")
        for ip, count in self.stats['ip_sources'].most_common(10):
            enrichment = self.stats.get('ip_enrichment', {}).get(ip, {})
            country = enrichment.get('country', 'Unknown')
            isp = enrichment.get('isp', 'Unknown')
            print(f"  {ip:15s}: {count:8,} packets | {country:15s} | {isp[:30]}")
        
        # Top destination IPs
        print(f"\n🎯 TOP 10 DESTINATION IP ADDRESSES")
        for ip, count in self.stats['ip_destinations'].most_common(10):
            enrichment = self.stats.get('ip_enrichment', {}).get(ip, {})
            country = enrichment.get('country', 'Unknown')
            isp = enrichment.get('isp', 'Unknown')
            print(f"  {ip:15s}: {count:8,} packets | {country:15s} | {isp[:30]}")
        
        # Top TCP ports
        if self.stats['ports']['tcp']:
            print(f"\n🔌 TOP 10 TCP DESTINATION PORTS")
            for port, count in self.stats['ports']['tcp'].most_common(10):
                service = self._get_service_name(port)
                print(f"  Port {port:5d} ({service:10s}): {count:,} packets")
        
        # Top UDP ports
        if self.stats['ports']['udp']:
            print(f"\n🔌 TOP 10 UDP DESTINATION PORTS")
            for port, count in self.stats['ports']['udp'].most_common(10):
                service = self._get_service_name(port)
                print(f"  Port {port:5d} ({service:10s}): {count:,} packets")
        
        # Top conversations
        print(f"\n💬 TOP 10 CONVERSATIONS")
        sorted_convs = sorted(
            self.stats['conversations'].items(),
            key=lambda x: x[1],
            reverse=True
        )[:10]
        for conversation, count in sorted_convs:
            print(f"  {conversation[0]:15s} <-> {conversation[1]:15s}: {count:,} packets")
        
        # Packet size statistics
        if self.stats['packet_sizes']:
            sizes = self.stats['packet_sizes']
            print(f"\n📦 PACKET SIZE STATISTICS")
            print(f"  Average: {sum(sizes) / len(sizes):.2f} bytes")
            print(f"  Minimum: {min(sizes):,} bytes")
            print(f"  Maximum: {max(sizes):,} bytes")
            print(f"  Total Data: {sum(sizes):,} bytes ({sum(sizes)/(1024*1024):.2f} MB)")
        
        # DNS queries
        if self.stats['dns_queries']:
            print(f"\n🔍 TOP 10 DNS QUERIES")
            dns_counter = Counter(self.stats['dns_queries'])
            for query, count in dns_counter.most_common(10):
                print(f"  {query[:60]:60s}: {count:,} queries")
        
        # HTTP Analysis
        if self.stats.get('http_analysis', {}).get('requests'):
            http = self.stats['http_analysis']
            print(f"\n🌐 HTTP TRAFFIC ANALYSIS")
            print(f"  Total HTTP Requests: {len(http['requests']):,}")
            print(f"  Unique Hosts: {len(http['hosts']):,}")
            
            if http['methods']:
                print(f"  HTTP Methods:")
                for method, count in http['methods'].most_common():
                    print(f"    {method}: {count:,}")
            
            if http['status_codes']:
                print(f"  HTTP Status Codes:")
                for code, count in http['status_codes'].most_common(5):
                    print(f"    {code}: {count:,}")
            
            if http.get('suspicious_requests'):
                print(f"  ⚠️  Suspicious HTTP Requests: {len(http['suspicious_requests'])}")
        
        # Traffic bursts
        if self.stats.get('timeline', {}).get('bursts'):
            bursts = self.stats['timeline']['bursts']
            print(f"\n⚡ TRAFFIC BURSTS DETECTED ({len(bursts)} total)")
            for burst in bursts[:5]:
                print(f"  {burst['start']}: {burst['packet_count']:,} packets in {burst['duration']:.2f}s")
        
        # Payload analysis
        if self.stats.get('payload_analysis'):
            payload = self.stats['payload_analysis']
            print(f"\n🔐 PAYLOAD ANALYSIS")
            print(f"  Encrypted Traffic Packets: {payload['encrypted_traffic']:,}")
            if payload['plaintext_credentials']:
                print(f"  ⚠️  Plaintext Credentials Found: {len(payload['plaintext_credentials'])}")
        
        print("\n" + "=" * 80)
    
    def print_security_findings(self) -> None:
        """Print security-related findings"""
        suspicious = self.stats.get('suspicious_activities', {})
        
        print("\n" + "!" * 80)
        print("🔒 SECURITY FINDINGS")
        print("!" * 80)
        
        findings_count = 0
        
        # Port scans
        if suspicious.get('port_scan'):
            findings_count += len(suspicious['port_scan'])
            print(f"\n🚨 PORT SCANNING DETECTED:")
            for finding in suspicious['port_scan'][:5]:
                severity = finding.get('severity', 'MEDIUM')
                emoji = "🔴" if severity == "HIGH" else "🟡"
                print(f"  {emoji} IP: {finding['ip']} | Unique targets: {finding['unique_targets']} | Severity: {severity}")
        
        # SYN floods
        if suspicious.get('syn_flood'):
            findings_count += len(suspicious['syn_flood'])
            print(f"\n🚨 SYN FLOOD ATTACKS:")
            for finding in suspicious['syn_flood'][:5]:
                print(f"  🔴 IP: {finding['ip']} | SYN packets: {finding['syn_count']:,}")
        
        # DNS tunneling
        if suspicious.get('dns_tunneling'):
            findings_count += len(suspicious['dns_tunneling'])
            print(f"\n🚨 POTENTIAL DNS TUNNELING:")
            for finding in suspicious['dns_tunneling'][:5]:
                print(f"  ⚠️  {finding['source']} -> {finding['destination']} | Size: {finding['packet_size']} bytes")
        
        # Unusual ports
        if suspicious.get('unusual_ports'):
            findings_count += len(suspicious['unusual_ports'])
            print(f"\n🚨 SUSPICIOUS PORT USAGE:")
            unique_ports = {}
            for finding in suspicious['unusual_ports']:
                port = finding['port']
                if port not in unique_ports:
                    unique_ports[port] = []
                unique_ports[port].append(finding['source'])
            
            for port, sources in list(unique_ports.items())[:5]:
                print(f"  ⚠️  Port {port}: {len(sources)} unique sources")
        
        # Data exfiltration
        if suspicious.get('data_exfiltration'):
            findings_count += len(suspicious['data_exfiltration'])
            print(f"\n🚨 POTENTIAL DATA EXFILTRATION:")
            total_size = sum(f['size'] for f in suspicious['data_exfiltration'])
            print(f"  ⚠️  {len(suspicious['data_exfiltration'])} large outbound transfers | Total: {total_size:,} bytes")
        
        # High frequency IPs
        if suspicious.get('high_frequency_ips'):
            findings_count += len(suspicious['high_frequency_ips'])
            print(f"\n🚨 HIGH FREQUENCY IP ADDRESSES:")
            for finding in suspicious['high_frequency_ips'][:5]:
                print(f"  ⚠️  IP: {finding['ip']} | Packets: {finding['packet_count']:,} ({finding['ratio']} avg)")
        
        # ICMP floods
        if suspicious.get('icmp_flood'):
            findings_count += len(suspicious['icmp_flood'])
            print(f"\n🚨 ICMP FLOOD DETECTED:")
            for finding in suspicious['icmp_flood'][:5]:
                print(f"  ⚠️  IP: {finding['ip']} | ICMP packets: {finding['icmp_count']:,}")
        
        # ARP spoofing
        if suspicious.get('arp_spoofing'):
            findings_count += len(suspicious['arp_spoofing'])
            print(f"\n🚨 POTENTIAL ARP SPOOFING:")
            for finding in suspicious['arp_spoofing'][:5]:
                print(f"  ⚠️  {finding['type']}")
                if 'mac' in finding:
                    print(f"     MAC: {finding['mac']} | IPs: {finding['claimed_ips']}")
                else:
                    print(f"     IP: {finding['ip']} | MACs: {finding['macs']}")
        
        if findings_count == 0:
            print(f"\n✅ No suspicious activities detected.")
        else:
            print(f"\n🔍 Total security findings: {findings_count}")
            print("⚠️  Note: These are potential threats. Manual verification recommended.")
        
        print("!" * 80)
    
    def export_json(self) -> str:
        """Export statistics to JSON format"""
        output_file = f"{self.base_name}_analysis.json"
        
        # Convert Counter and defaultdict objects for JSON serialization
        serializable_stats = self._make_serializable(self.stats)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(serializable_stats, f, indent=2, default=str)
        
        print(f"📁 Exported JSON to: {output_file}")
        return output_file
    
    def export_csv(self) -> str:
        """Export IP statistics to CSV format"""
        output_file = f"{self.base_name}_ip_stats.csv"
        
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['IP Address', 'Packet Count', 'Type', 'Country', 'City', 'ISP', 'ASN'])
            
            # Source IPs
            for ip, count in self.stats['ip_sources'].most_common(100):
                enrichment = self.stats.get('ip_enrichment', {}).get(ip, {})
                writer.writerow([
                    ip, count, 'Source',
                    enrichment.get('country', 'Unknown'),
                    enrichment.get('city', 'Unknown'),
                    enrichment.get('isp', 'Unknown'),
                    enrichment.get('asn', 'Unknown')
                ])
            
            # Destination IPs
            for ip, count in self.stats['ip_destinations'].most_common(100):
                enrichment = self.stats.get('ip_enrichment', {}).get(ip, {})
                writer.writerow([
                    ip, count, 'Destination',
                    enrichment.get('country', 'Unknown'),
                    enrichment.get('city', 'Unknown'),
                    enrichment.get('isp', 'Unknown'),
                    enrichment.get('asn', 'Unknown')
                ])
        
        print(f"📁 Exported CSV to: {output_file}")
        return output_file
    
    def export_html(self) -> str:
        """Generate comprehensive HTML report"""
        output_file = f"{self.base_name}_report.html"
        
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PCAP Analysis Report - {os.path.basename(self.filename)}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f5f5;
            padding: 20px;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; margin-bottom: 30px; }}
        h2 {{ color: #34495e; margin-top: 30px; margin-bottom: 15px; padding: 10px; background: #ecf0f1; border-left: 4px solid #3498db; }}
        h3 {{ color: #555; margin-top: 20px; margin-bottom: 10px; }}
        .summary {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 8px; margin-bottom: 30px; }}
        .summary p {{ margin: 8px 0; font-size: 1.1em; }}
        .summary strong {{ color: #fff; }}
        table {{ width: 100%; border-collapse: collapse; margin: 15px 0; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }}
        th {{ background: #3498db; color: white; padding: 12px; text-align: left; font-weight: 600; }}
        td {{ padding: 10px; border-bottom: 1px solid #ddd; }}
        tr:hover {{ background: #f8f9fa; }}
        .warning {{ color: #e67e22; font-weight: bold; }}
        .critical {{ color: #e74c3c; font-weight: bold; }}
        .safe {{ color: #27ae60; font-weight: bold; }}
        .badge {{ display: inline-block; padding: 4px 8px; border-radius: 3px; font-size: 0.85em; font-weight: bold; }}
        .badge-high {{ background: #e74c3c; color: white; }}
        .badge-medium {{ background: #f39c12; color: white; }}
        .badge-low {{ background: #27ae60; color: white; }}
        .metric {{ display: inline-block; margin: 10px 20px 10px 0; }}
        .metric-label {{ font-weight: bold; color: #555; }}
        .metric-value {{ color: #3498db; font-size: 1.2em; }}
        .chart-container {{ margin: 20px 0; padding: 15px; background: #f8f9fa; border-radius: 5px; }}
        footer {{ margin-top: 40px; padding-top: 20px; border-top: 2px solid #ecf0f1; text-align: center; color: #7f8c8d; }}
        .alert {{ padding: 15px; margin: 15px 0; border-radius: 5px; border-left: 4px solid; }}
        .alert-danger {{ background: #fee; border-color: #e74c3c; }}
        .alert-warning {{ background: #fef3cd; border-color: #f39c12; }}
        .alert-info {{ background: #d1ecf1; border-color: #3498db; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>📊 PCAP Analysis Report</h1>
        
        <div class="summary">
            <h2 style="color: white; background: transparent; border: none; padding: 0; margin-bottom: 15px;">📋 Executive Summary</h2>
            <p><strong>File:</strong> {os.path.basename(self.filename)}</p>
            <p><strong>Total Packets:</strong> {self.stats['total_packets']:,}</p>
            <p><strong>Capture Duration:</strong> {self.stats.get('timeline', {}).get('duration_seconds', 0):.2f} seconds</p>
            <p><strong>Analysis Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p><strong>Packets/Second:</strong> {self.stats.get('timeline', {}).get('packets_per_second', 0):.2f}</p>
        </div>
"""
        
        # Protocol Distribution
        html_content += """
        <h2>📡 Protocol Distribution</h2>
        <table>
            <tr><th>Protocol</th><th>Packet Count</th><th>Percentage</th></tr>
"""
        for protocol, count in self.stats['protocols'].most_common():
            percentage = (count / self.stats['total_packets']) * 100
            html_content += f"<tr><td>{protocol}</td><td>{count:,}</td><td>{percentage:.2f}%</td></tr>\n"
        
        html_content += "</table>\n"
        
        # Top Source IPs
        html_content += """
        <h2>🌐 Top Source IP Addresses</h2>
        <table>
            <tr><th>IP Address</th><th>Packets</th><th>Country</th><th>ISP</th></tr>
"""
        for ip, count in self.stats['ip_sources'].most_common(20):
            enrichment = self.stats.get('ip_enrichment', {}).get(ip, {})
            html_content += f"""<tr>
                <td>{ip}</td>
                <td>{count:,}</td>
                <td>{enrichment.get('country', 'Unknown')}</td>
                <td>{enrichment.get('isp', 'Unknown')}</td>
            </tr>\n"""
        
        html_content += "</table>\n"
        
        # Security Findings
        suspicious = self.stats.get('suspicious_activities', {})
        findings_count = sum(len(v) for v in suspicious.values() if isinstance(v, list))
        
        if findings_count > 0:
            html_content += f"""
        <h2>🔒 Security Findings</h2>
        <div class="alert alert-danger">
            <strong>⚠️ {findings_count} potential security issues detected</strong>
        </div>
"""
            
            for category, findings in suspicious.items():
                if findings and isinstance(findings, list):
                    html_content += f"<h3>{category.replace('_', ' ').title()}</h3>\n"
                    html_content += "<table>\n<tr><th>Details</th><th>Severity</th></tr>\n"
                    
                    for finding in findings[:10]:
                        if isinstance(finding, dict):
                            details = " | ".join([f"<strong>{k}:</strong> {v}" for k, v in list(finding.items())[:4]])
                            severity = finding.get('severity', 'MEDIUM')
                            badge_class = f"badge-{severity.lower()}" if severity in ['HIGH', 'MEDIUM', 'LOW'] else 'badge-medium'
                            html_content += f"""<tr>
                                <td>{details}</td>
                                <td><span class="badge {badge_class}">{severity}</span></td>
                            </tr>\n"""
                    
                    html_content += "</table>\n"
        else:
            html_content += """
        <h2>🔒 Security Findings</h2>
        <div class="alert alert-info">
            <strong>✅ No suspicious activities detected</strong>
        </div>
"""
        
        # Footer
        html_content += f"""
        <footer>
            <p>Generated by Enhanced PCAP Analyzer | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </footer>
    </div>
</body>
</html>
"""
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"📁 Exported HTML report to: {output_file}")
        return output_file
    
    def generate_plots(self) -> Optional[str]:
        """Generate visual plots for the analysis"""
        if not MATPLOTLIB_AVAILABLE:
            print("⚠️  matplotlib not available. Skipping plot generation.")
            return None
        
        output_file = f"{self.base_name}_plots.png"
        
        fig, axes = plt.subplots(2, 2, figsize=(16, 12))
        fig.suptitle('PCAP Analysis Visualization', fontsize=16, fontweight='bold')
        
        # Protocol distribution pie chart
        if self.stats['protocols']:
            protocols = list(self.stats['protocols'].keys())
            counts = list(self.stats['protocols'].values())
            colors = plt.cm.Set3(range(len(protocols)))
            
            axes[0, 0].pie(counts, labels=protocols, autopct='%1.1f%%', colors=colors, startangle=90)
            axes[0, 0].set_title('Protocol Distribution', fontweight='bold')
        
        # Top source IPs bar chart
        if self.stats['ip_sources']:
            top_sources = dict(self.stats['ip_sources'].most_common(10))
            axes[0, 1].barh(range(len(top_sources)), list(top_sources.values()), color='steelblue')
            axes[0, 1].set_yticks(range(len(top_sources)))
            axes[0, 1].set_yticklabels(list(top_sources.keys()), fontsize=8)
            axes[0, 1].set_xlabel('Packet Count')
            axes[0, 1].set_title('Top 10 Source IPs', fontweight='bold')
            axes[0, 1].grid(axis='x', alpha=0.3)
        
        # Top TCP ports
        if self.stats['ports']['tcp']:
            top_tcp = dict(self.stats['ports']['tcp'].most_common(10))
            axes[1, 0].bar(range(len(top_tcp)), list(top_tcp.values()), color='coral')
            axes[1, 0].set_xticks(range(len(top_tcp)))
            axes[1, 0].set_xticklabels(list(top_tcp.keys()), rotation=45)
            axes[1, 0].set_ylabel('Packet Count')
            axes[1, 0].set_title('Top 10 TCP Ports', fontweight='bold')
            axes[1, 0].grid(axis='y', alpha=0.3)
        
        # Packet size distribution
        if self.stats['packet_sizes']:
            axes[1, 1].hist(self.stats['packet_sizes'], bins=50, color='mediumseagreen', edgecolor='black', alpha=0.7)
            axes[1, 1].set_xlabel('Packet Size (bytes)')
            axes[1, 1].set_ylabel('Frequency')
            axes[1, 1].set_title('Packet Size Distribution', fontweight='bold')
            axes[1, 1].grid(axis='y', alpha=0.3)
        
        plt.tight_layout()
        plt.savefig(output_file, dpi=300, bbox_inches='tight')
        plt.close()
        
        print(f"📊 Generated plots: {output_file}")
        return output_file
    
    @staticmethod
    def _get_service_name(port: int) -> str:
        """Get common service name for port number"""
        services = {
            20: 'FTP-Data', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
            53: 'DNS', 67: 'DHCP', 68: 'DHCP', 80: 'HTTP', 110: 'POP3',
            143: 'IMAP', 443: 'HTTPS', 445: 'SMB', 3389: 'RDP', 3306: 'MySQL',
            5432: 'PostgreSQL', 6379: 'Redis', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt',
            27017: 'MongoDB'
        }
        return services.get(port, 'Unknown')
    
    @staticmethod
    def _make_serializable(obj):
        """Convert Counter and defaultdict to regular dict for JSON serialization"""
        if isinstance(obj, (Counter, defaultdict)):
            # Recursively convert the dict after converting Counter/defaultdict
            return ReportGenerator._make_serializable(dict(obj))
        elif isinstance(obj, dict):
            # Handle tuple keys by converting them to strings
            new_dict = {}
            for k, v in obj.items():
                if isinstance(k, tuple):
                    # Convert tuple to string representation
                    new_key = " <-> ".join(str(x) for x in k)
                    new_dict[new_key] = ReportGenerator._make_serializable(v)
                else:
                    new_dict[str(k)] = ReportGenerator._make_serializable(v)  # Ensure key is string
            return new_dict
        elif isinstance(obj, list):
            return [ReportGenerator._make_serializable(item) for item in obj]
        elif isinstance(obj, tuple):
            return [ReportGenerator._make_serializable(item) for item in obj]  # Convert to list
        elif isinstance(obj, (datetime,)):
            return obj.isoformat()  # Convert datetime to string
        else:
            return obj


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Enhanced Advanced PCAP file analyzer with security detection',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Basic analysis
  python %(prog)s capture.pcap
  
  # Verbose output with security scan
  python %(prog)s capture.pcap -v --security-scan
  
  # Export to JSON and generate plots
  python %(prog)s capture.pcap --export json --generate-plots
  
  # Complete analysis with all outputs
  python %(prog)s capture.pcap --export all --security-scan --generate-plots -v
  
  # Quick mode (faster, less detailed)
  python %(prog)s capture.pcap --quick
        '''
    )
    
    parser.add_argument(
        'pcap_file',
        help='Path to the PCAP file to analyze'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output with progress indicators'
    )
    parser.add_argument(
        '--export',
        choices=['json', 'csv', 'html', 'all'],
        help='Export analysis results to specified format(s)'
    )
    parser.add_argument(
        '--security-scan',
        action='store_true',
        help='Enable comprehensive security pattern detection and display findings'
    )
    parser.add_argument(
        '--generate-plots',
        action='store_true',
        help='Generate visual plots and charts (requires matplotlib)'
    )
    parser.add_argument(
        '--quick',
        action='store_true',
        help='Quick mode - faster analysis with basic statistics only'
    )
    
    args = parser.parse_args()
    
    # Validate file exists
    if not os.path.exists(args.pcap_file):
        print(f"❌ Error: File '{args.pcap_file}' not found")
        sys.exit(1)
    
    # Display file info
    file_size = os.path.getsize(args.pcap_file) / (1024 * 1024)
    if args.verbose:
        print(f"\n{'=' * 80}")
        print(f"🔍 Starting PCAP Analysis")
        print(f"{'=' * 80}")
        print(f"📁 File: {args.pcap_file}")
        print(f"📊 Size: {file_size:.2f} MB")
        if args.quick:
            print(f"⚡ Mode: Quick (basic statistics only)")
        print(f"{'=' * 80}\n")
    
    # Initialize analyzer
    analyzer = PCAPAnalyzer(args.pcap_file, verbose=args.verbose, quick_mode=args.quick)
    
    # Load packets
    if not analyzer.load_packets():
        sys.exit(1)
    
    # Analyze
    if args.verbose:
        print("\n🔬 Analyzing packets...")
    stats = analyzer.analyze()
    
    if not stats:
        print("❌ Error: Analysis failed")
        sys.exit(1)
    
    # Generate reports
    reporter = ReportGenerator(stats, args.pcap_file)
    
    # Print statistics
    reporter.print_statistics()
    
    # Security findings
    if args.security_scan:
        reporter.print_security_findings()
    
    # Export functionality
    if args.export:
        print(f"\n📤 Exporting results...")
        if args.export == 'all':
            reporter.export_json()
            reporter.export_csv()
            reporter.export_html()
        elif args.export == 'json':
            reporter.export_json()
        elif args.export == 'csv':
            reporter.export_csv()
        elif args.export == 'html':
            reporter.export_html()
    
    # Generate plots
    if args.generate_plots:
        print(f"\n📊 Generating visualizations...")
        reporter.generate_plots()
    
    if args.verbose:
        print(f"\n{'=' * 80}")
        print(f"✅ Analysis completed successfully!")
        print(f"{'=' * 80}\n")


if __name__ == "__main__":
    main()