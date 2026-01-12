import json
import math
import re
import sys
import os
import warnings
from collections import Counter, defaultdict
from datetime import datetime
from typing import Dict, List, Tuple, Any, Optional
import requests
from scapy.all import rdpcap, IP, TCP, UDP, ICMP, ARP, DNS, DNSQR, DNSRR, Raw
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.dhcp import DHCP
from scapy.layers.ntp import NTP
from scapy.error import Scapy_Exception
import warnings
from urllib.parse import parse_qs, urlparse

warnings.filterwarnings('ignore')

# Import optional dependencies
try:
    import matplotlib.pyplot as plt
    import matplotlib
    matplotlib.use('Agg')
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False

try:
    import tldextract
    TLDEXTRACT_AVAILABLE = True
except ImportError:
    TLDEXTRACT_AVAILABLE = False

try:
    from ipwhois import IPWhois
    IPWHOIS_AVAILABLE = True
except ImportError:
    IPWHOIS_AVAILABLE = False


class AdvancedDNSAnalyzer:
    """Advanced DNS traffic analyzer with all original features"""
    
    # Known malicious/suspicious TLDs
    SUSPICIOUS_TLDS = {
        'tk', 'ml', 'ga', 'cf', 'gq', 'pw', 'cc', 'ws', 'top', 'work',
        'click', 'link', 'xyz', 'date', 'racing', 'stream'
    }
    
    # Common legitimate domains for whitelist
    WHITELIST_DOMAINS = {
        'google.com', 'googleapis.com', 'gstatic.com', 'amazon.com',
        'microsoft.com', 'apple.com', 'facebook.com', 'cloudfront.net',
        'akamai.net', 'cloudflare.com', 'windows.com', 'live.com'
    }
    
    def __init__(self):
        self.queries = []
        self.responses = []
        self.query_types = Counter()
        self.response_codes = Counter()
        self.tld_stats = Counter()
        self.domain_to_ips = defaultdict(list)
        self.ip_to_domains = defaultdict(list)
        self.query_lengths = []
        self.suspicious_queries = []
        
    def analyze_packet(self, packet):
        """Analyze DNS packet"""
        if not packet.haslayer(DNS):
            return
        
        try:
            dns_layer = packet[DNS]
            
            # Query analysis
            if dns_layer.qr == 0 and packet.haslayer(DNSQR):
                self._analyze_query(packet, dns_layer)
            
            # Response analysis
            elif dns_layer.qr == 1:
                self._analyze_response(packet, dns_layer)
        except Exception:
            pass
    
    def _analyze_query(self, packet, dns_layer):
        """Analyze DNS query"""
        try:
            qname = packet[DNSQR].qname.decode('utf-8', errors='ignore').rstrip('.')
            qtype = packet[DNSQR].qtype
            
            if not qname:
                return
            
            # Record query
            query_info = {
                'domain': qname,
                'type': self._get_query_type_name(qtype),
                'type_code': qtype,
                'timestamp': datetime.fromtimestamp(float(packet.time)),
                'src_ip': packet[IP].src if packet.haslayer(IP) else 'Unknown'
            }
            
            self.queries.append(query_info)
            self.query_types[query_info['type']] += 1
            self.query_lengths.append(len(qname))
            
            # TLD analysis
            if TLDEXTRACT_AVAILABLE:
                extracted = tldextract.extract(qname)
                if extracted.suffix:
                    self.tld_stats[extracted.suffix] += 1
            else:
                # Fallback TLD extraction
                parts = qname.split('.')
                if len(parts) >= 2:
                    self.tld_stats[parts[-1]] += 1
            
            # Suspicious domain detection
            self._check_suspicious_domain(qname, query_info)
            
        except Exception:
            pass
    
    def _analyze_response(self, packet, dns_layer):
        """Analyze DNS response"""
        try:
            rcode = dns_layer.rcode
            self.response_codes[self._get_rcode_name(rcode)] += 1
            
            # Extract resolved IPs
            if packet.haslayer(DNSRR):
                qname = None
                if packet.haslayer(DNSQR):
                    qname = packet[DNSQR].qname.decode('utf-8', errors='ignore').rstrip('.')
                
                # Process all answer records
                for i in range(dns_layer.ancount):
                    try:
                        dnsrr = packet[DNSRR][i] if dns_layer.ancount > 1 else packet[DNSRR]
                        
                        if dnsrr.type == 1:  # A record
                            ip = dnsrr.rdata
                            if qname:
                                self.domain_to_ips[qname].append(ip)
                                self.ip_to_domains[ip].append(qname)
                    except Exception:
                        continue
                
                response_info = {
                    'domain': qname,
                    'rcode': self._get_rcode_name(rcode),
                    'timestamp': datetime.fromtimestamp(float(packet.time)),
                    'ttl': packet[DNSRR].ttl if hasattr(packet[DNSRR], 'ttl') else 0
                }
                
                self.responses.append(response_info)
                
        except Exception:
            pass
    
    def _check_suspicious_domain(self, domain: str, query_info: dict):
        """Check if domain exhibits suspicious characteristics"""
        suspicious_reasons = []
        
        # Skip whitelisted domains
        if any(domain.endswith(whitelist) for whitelist in self.WHITELIST_DOMAINS):
            return
        
        # 1. Check TLD
        if TLDEXTRACT_AVAILABLE:
            extracted = tldextract.extract(domain)
            if extracted.suffix in self.SUSPICIOUS_TLDS:
                suspicious_reasons.append(f"Suspicious TLD: {extracted.suffix}")
        
        # 2. Length check (unusually long domains can indicate tunneling)
        if len(domain) > 50:
            suspicious_reasons.append(f"Unusually long domain: {len(domain)} chars")
        
        # 3. Entropy check (DGA detection)
        entropy = self._calculate_entropy(domain)
        if entropy > 4.5:  # High randomness
            suspicious_reasons.append(f"High entropy: {entropy:.2f} (possible DGA)")
        
        # 4. Subdomain depth
        subdomain_count = domain.count('.')
        if subdomain_count > 4:
            suspicious_reasons.append(f"Deep subdomain nesting: {subdomain_count} levels")
        
        # 5. Numeric domain check
        if re.search(r'\d{8,}', domain):
            suspicious_reasons.append("Contains long numeric sequence")
        
        # 6. Character patterns (consonant clusters)
        consonant_clusters = re.findall(r'[bcdfghjklmnpqrstvwxyz]{5,}', domain.lower())
        if consonant_clusters:
            suspicious_reasons.append(f"Unusual consonant clusters: {consonant_clusters[:2]}")
        
        # 7. Hex-like patterns
        if re.match(r'^[a-f0-9]{20,}\.', domain):
            suspicious_reasons.append("Hex-like subdomain pattern")
        
        # 8. Base64-like patterns
        if re.search(r'[A-Za-z0-9+/]{30,}', domain):
            suspicious_reasons.append("Base64-like encoding detected")
        
        if suspicious_reasons:
            self.suspicious_queries.append({
                **query_info,
                'reasons': suspicious_reasons,
                'entropy': entropy,
                'length': len(domain)
            })
    
    def detect_dns_tunneling(self) -> List[Dict]:
        """Detect potential DNS tunneling based on query patterns"""
        tunneling_suspects = []
        
        # Group queries by domain
        domain_queries = defaultdict(list)
        for query in self.queries:
            base_domain = self._get_base_domain(query['domain'])
            domain_queries[base_domain].append(query)
        
        for base_domain, queries in domain_queries.items():
            if len(queries) < 10:  # Need sufficient samples
                continue
            
            # Calculate average subdomain length
            avg_length = sum(len(q['domain']) for q in queries) / len(queries)
            
            # Calculate entropy variance
            entropies = [self._calculate_entropy(q['domain']) for q in queries]
            avg_entropy = sum(entropies) / len(entropies)
            
            # Check for TXT queries (common in DNS tunneling)
            txt_queries = sum(1 for q in queries if q['type'] == 'TXT')
            txt_ratio = txt_queries / len(queries)
            
            # Tunneling indicators
            indicators = []
            score = 0
            
            if avg_length > 40:
                indicators.append(f"Long average query length: {avg_length:.1f}")
                score += 2
            
            if avg_entropy > 4.0:
                indicators.append(f"High average entropy: {avg_entropy:.2f}")
                score += 2
            
            if txt_ratio > 0.3:
                indicators.append(f"High TXT query ratio: {txt_ratio:.1%}")
                score += 2
            
            if len(queries) > 100:
                indicators.append(f"High query volume: {len(queries)}")
                score += 1
            
            # Check for regular intervals (beaconing)
            if len(queries) > 20:
                timestamps = [q['timestamp'] for q in queries]
                intervals = [(timestamps[i+1] - timestamps[i]).total_seconds() 
                            for i in range(len(timestamps)-1)]
                if intervals:
                    avg_interval = sum(intervals) / len(intervals)
                    variance = sum((x - avg_interval)**2 for x in intervals) / len(intervals)
                    if variance < 100 and avg_interval < 60:  # Regular, frequent queries
                        indicators.append(f"Regular beaconing: ~{avg_interval:.1f}s intervals")
                        score += 3
            
            if score >= 4:  # Threshold for suspicion
                tunneling_suspects.append({
                    'domain': base_domain,
                    'query_count': len(queries),
                    'avg_length': avg_length,
                    'avg_entropy': avg_entropy,
                    'txt_ratio': txt_ratio,
                    'indicators': indicators,
                    'severity': 'HIGH' if score >= 6 else 'MEDIUM',
                    'score': score
                })
        
        return sorted(tunneling_suspects, key=lambda x: x['score'], reverse=True)
    
    def detect_fast_flux(self) -> List[Dict]:
        """Detect fast-flux DNS patterns"""
        fast_flux_suspects = []
        
        for domain, ips in self.domain_to_ips.items():
            unique_ips = len(set(ips))
            
            # Fast-flux typically involves many IPs
            if unique_ips > 10:
                # Check TTL values from responses
                domain_responses = [r for r in self.responses if r.get('domain') == domain]
                low_ttl_count = sum(1 for r in domain_responses if r.get('ttl', 3600) < 300)
                
                fast_flux_suspects.append({
                    'domain': domain,
                    'unique_ips': unique_ips,
                    'total_resolutions': len(ips),
                    'low_ttl_responses': low_ttl_count,
                    'ips_sample': list(set(ips))[:10],
                    'severity': 'HIGH' if unique_ips > 50 else 'MEDIUM'
                })
        
        return sorted(fast_flux_suspects, key=lambda x: x['unique_ips'], reverse=True)
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get comprehensive DNS statistics"""
        stats = {
            'total_queries': len(self.queries),
            'total_responses': len(self.responses),
            'query_types': dict(self.query_types.most_common()),
            'response_codes': dict(self.response_codes.most_common()),
            'tld_distribution': dict(self.tld_stats.most_common(20)),
            'suspicious_queries': self.suspicious_queries,
            'top_queried_domains': self._get_top_domains(),
            'dns_tunneling_suspects': self.detect_dns_tunneling(),
            'fast_flux_suspects': self.detect_fast_flux(),
            'query_length_stats': self._get_length_stats(),
            'unique_domains': len(set(q['domain'] for q in self.queries)),
            'domains_with_multiple_ips': self._get_multi_ip_domains()
        }
        
        return stats
    
    def _get_top_domains(self, limit: int = 20) -> List[Tuple[str, int]]:
        """Get most queried domains"""
        domain_counts = Counter(q['domain'] for q in self.queries)
        return domain_counts.most_common(limit)
    
    def _get_multi_ip_domains(self) -> List[Dict]:
        """Get domains resolving to multiple IPs"""
        multi_ip = []
        for domain, ips in self.domain_to_ips.items():
            unique_ips = list(set(ips))
            if len(unique_ips) > 1:
                multi_ip.append({
                    'domain': domain,
                    'ip_count': len(unique_ips),
                    'ips': unique_ips[:10]  # Limit for display
                })
        
        return sorted(multi_ip, key=lambda x: x['ip_count'], reverse=True)[:20]
    
    def _get_length_stats(self) -> Dict[str, float]:
        """Get query length statistics"""
        if not self.query_lengths:
            return {}
        
        return {
            'min': min(self.query_lengths),
            'max': max(self.query_lengths),
            'avg': sum(self.query_lengths) / len(self.query_lengths),
            'median': sorted(self.query_lengths)[len(self.query_lengths) // 2]
        }
    
    @staticmethod
    def _calculate_entropy(string: str) -> float:
        """Calculate Shannon entropy of a string"""
        if not string:
            return 0.0
        
        # Remove common TLD to focus on domain name
        string = re.sub(r'\.(com|net|org|edu|gov|mil)$', '', string.lower())
        
        entropy = 0.0
        for char in set(string):
            freq = string.count(char) / len(string)
            entropy -= freq * math.log2(freq)
        
        return entropy
    
    @staticmethod
    def _get_base_domain(domain: str) -> str:
        """Extract base domain from full domain"""
        if TLDEXTRACT_AVAILABLE:
            extracted = tldextract.extract(domain)
            return f"{extracted.domain}.{extracted.suffix}"
        else:
            parts = domain.split('.')
            if len(parts) >= 2:
                return '.'.join(parts[-2:])
            return domain
    
    @staticmethod
    def _get_query_type_name(qtype: int) -> str:
        """Convert DNS query type code to name"""
        types = {
            1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR',
            15: 'MX', 16: 'TXT', 28: 'AAAA', 33: 'SRV', 255: 'ANY'
        }
        return types.get(qtype, f'TYPE{qtype}')
    
    @staticmethod
    def _get_rcode_name(rcode: int) -> str:
        """Convert DNS response code to name"""
        rcodes = {
            0: 'NOERROR', 1: 'FORMERR', 2: 'SERVFAIL', 3: 'NXDOMAIN',
            4: 'NOTIMP', 5: 'REFUSED'
        }
        return rcodes.get(rcode, f'RCODE{rcode}')


class BeaconDetector:
    """Detect C2 beaconing patterns"""
    
    def __init__(self, threshold_variance: float = 0.1):
        self.threshold_variance = threshold_variance
        self.ip_connections = defaultdict(list)
    
    def add_packet(self, packet):
        """Track packet for beacon detection"""
        if packet.haslayer(IP) and packet.haslayer(TCP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            dst_port = packet[TCP].dport
            timestamp = float(packet.time)
            
            key = (src_ip, dst_ip, dst_port)
            self.ip_connections[key].append(timestamp)
    
    def detect_beacons(self) -> List[Dict]:
        """Detect beaconing behavior"""
        beacons = []
        
        for (src_ip, dst_ip, dst_port), timestamps in self.ip_connections.items():
            if len(timestamps) < 10:  # Need enough samples
                continue
            
            # Calculate intervals
            timestamps = sorted(timestamps)
            intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
            
            if not intervals:
                continue
            
            avg_interval = sum(intervals) / len(intervals)
            
            # Skip very short intervals (likely bulk transfer)
            if avg_interval < 1:
                continue
            
            # Calculate coefficient of variation
            variance = sum((x - avg_interval)**2 for x in intervals) / len(intervals)
            std_dev = math.sqrt(variance)
            cv = std_dev / avg_interval if avg_interval > 0 else 0
            
            # Low variance indicates regular beaconing
            if cv < self.threshold_variance and avg_interval < 3600:
                beacons.append({
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'dst_port': dst_port,
                    'connection_count': len(timestamps),
                    'avg_interval_sec': avg_interval,
                    'coefficient_variation': cv,
                    'duration_sec': timestamps[-1] - timestamps[0],
                    'severity': 'HIGH' if cv < 0.05 and avg_interval < 60 else 'MEDIUM'
                })
        
        return sorted(beacons, key=lambda x: x['coefficient_variation'])


class PCAPAnalyzer:
    """Main PCAP analyzer with GUI support and all original features"""
    
    def __init__(self, filename: str = None, verbose: bool = False, quick_mode: bool = False):
        self.filename = filename
        self.verbose = verbose
        self.quick_mode = quick_mode
        self.packets = None
        self.stats = None
        self.dns_analyzer = AdvancedDNSAnalyzer()
        self.beacon_detector = BeaconDetector()
        self.progress_callback = None
        
    def set_progress_callback(self, callback):
        """Set callback for progress updates"""
        self.progress_callback = callback
    
    def load_packets(self, filename: str = None) -> bool:
        """Load packets from PCAP file with error handling"""
        if filename:
            self.filename = filename
            
        try:
            if self.verbose and self.progress_callback:
                self.progress_callback("Loading packets...", 0)
            
            self.packets = rdpcap(self.filename)
            
            if self.verbose and self.progress_callback:
                self.progress_callback(f"Loaded {len(self.packets)} packets", 100)
            
            return True
        except FileNotFoundError:
            if self.progress_callback:
                self.progress_callback(f"Error: File '{self.filename}' not found", 0, is_error=True)
            return False
        except Scapy_Exception as e:
            if self.progress_callback:
                self.progress_callback(f"Scapy error reading file: {e}", 0, is_error=True)
            return False
        except Exception as e:
            if self.progress_callback:
                self.progress_callback(f"Unexpected error reading file: {e}", 0, is_error=True)
            return False
    
    def analyze(self, filename: str = None) -> Dict[str, Any]:
        """Perform comprehensive analysis of loaded packets"""
        if filename:
            self.filename = filename
            
        if not self.load_packets():
            return {}
        
        self.stats = {
            'filename': os.path.basename(self.filename),
            'total_packets': len(self.packets),
            'protocols': Counter(),
            'ip_sources': Counter(),
            'ip_destinations': Counter(),
            'ports': {'tcp': Counter(), 'udp': Counter()},
            'conversations': defaultdict(int),
            'packet_sizes': [],
            'timeline': {},
            'suspicious_activities': {},
            'http_analysis': {},
            'ip_enrichment': {},
            'tcp_flags': Counter(),
            'payload_analysis': {},
            'dns_analysis': {},
            'beacon_analysis': []
        }
        
        total_packets = len(self.packets)
        
        # Analyze packets
        for idx, packet in enumerate(self.packets):
            # Update progress
            if self.progress_callback and idx % 1000 == 0:
                progress = int((idx / total_packets) * 100)
                self.progress_callback(f"Analyzing packets... {idx}/{total_packets}", progress)
            
            self._analyze_packet(packet)
            
            # DNS analysis
            if packet.haslayer(DNS):
                self.dns_analyzer.analyze_packet(packet)
            
            # Beacon detection
            if not self.quick_mode:
                self.beacon_detector.add_packet(packet)
        
        # Get DNS statistics
        if self.progress_callback:
            self.progress_callback("Analyzing DNS traffic...", 85)
        self.stats['dns_analysis'] = self.dns_analyzer.get_statistics()
        
        # Enhanced analysis
        if self.progress_callback:
            self.progress_callback("Performing timeline analysis...", 88)
        self.stats['timeline'] = self._analyze_timeline()
        
        if not self.quick_mode:
            if self.progress_callback:
                self.progress_callback("Detecting suspicious patterns...", 90)
            self.stats['suspicious_activities'] = self._detect_suspicious_patterns()
            
            if self.progress_callback:
                self.progress_callback("Analyzing HTTP traffic...", 92)
            self.stats['http_analysis'] = self._analyze_http_traffic()
            
            if self.progress_callback:
                self.progress_callback("Analyzing payloads...", 94)
            self.stats['payload_analysis'] = self._analyze_payloads()
            
            if self.progress_callback:
                self.progress_callback("Detecting beacons...", 96)
            self.stats['beacon_analysis'] = self.beacon_detector.detect_beacons()
            
            if self.progress_callback:
                self.progress_callback("Enriching IP information...", 98)
            top_ips = set(
                list(dict(self.stats['ip_sources'].most_common(10)).keys()) + 
                list(dict(self.stats['ip_destinations'].most_common(10)).keys())
            )
            enriched = {}
            total_ips = len(top_ips)
            for idx, ip in enumerate(top_ips, 1):
                if self.progress_callback and idx % 3 == 0:
                    progress = 98 + int((idx / total_ips) * 2)
                    self.progress_callback(f"Enriching IP information... {idx}/{total_ips}...", min(progress, 99))
                ip_info = self._enrich_single_ip(ip)
                enriched[ip] = ip_info


            self.stats['ip_enrichment'] = enriched
        
        if self.progress_callback:
            self.progress_callback("Analysis complete!", 100)
        
        return self.stats

    def _enrich_single_ip(self, ip: str) -> Dict[str, str]:
        """Enrich a single IP address with timeout protection"""
        if not self._is_external_ip(ip):
            return {
                'country': 'Private',
                'city': 'Private',
                'isp': 'Private Network',
                'asn': 'N/A',
                'org': 'Private'
            }
        
        try:
            response = requests.get(
                f'http://ip-api.com/json/{ip}',
                timeout=2,
                headers={'User-Agent': 'PCAP-Analyzer/3.0'}
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    return {
                        'country': data.get('country', 'Unknown'),
                        'city': data.get('city', 'Unknown'),
                        'isp': data.get('isp', 'Unknown'),
                        'asn': data.get('as', 'Unknown'),
                        'org': data.get('org', 'Unknown')
                    }
        except:
            pass
        
        return {
            'country': 'Unknown',
            'city': 'Unknown',
            'isp': 'Unknown',
            'asn': 'Unknown',
            'org': 'Unknown'
        }
    
    def _analyze_packet(self, packet) -> None:
        """Analyze individual packet"""
        # Protocol statistics
        if packet.haslayer(TCP):
            self.stats['protocols']['TCP'] += 1
            tcp_layer = packet[TCP]
            if tcp_layer.dport:
                self.stats['ports']['tcp'][tcp_layer.dport] += 1
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
            
            conversation = tuple(sorted([src_ip, dst_ip]))
            self.stats['conversations'][conversation] += 1
            
            self.stats['packet_sizes'].append(len(packet))
    
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
        interval = 60
        for timestamp in timestamps:
            bucket = int((timestamp - min_time) / interval)
            timeline['time_buckets'][bucket] += 1
        
        return timeline
    
    def _detect_suspicious_patterns(self) -> Dict[str, List]:
        """Detect potentially malicious network activity"""
        suspicious = {
            'port_scan': [],
            'syn_flood': [],
            'unusual_ports': [],
            'data_exfiltration': [],
            'high_frequency_ips': [],
            'icmp_flood': [],
            'arp_spoofing': []
        }
        
        suspicious_ports = {
            4444, 31337, 1337, 12345, 54321, 9999, 666, 999, 1338, 1339,
            9998, 9997, 6667, 6668, 6669, 7000, 12346, 27374, 6711, 6712
        }
        
        src_dst_ports = defaultdict(set)
        syn_packets = defaultdict(int)
        icmp_packets = defaultdict(int)
        arp_requests = []
        packet_counts_per_ip = defaultdict(int)
        
        for packet in self.packets:
            if packet.haslayer(IP):
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                packet_counts_per_ip[src_ip] += 1
                
                if packet.haslayer(TCP):
                    dst_port = packet[TCP].dport
                    src_dst_ports[src_ip].add((dst_ip, dst_port))
                    
                    flags = packet[TCP].sprintf('%TCP.flags%')
                    if 'S' in flags and 'A' not in flags:
                        syn_packets[src_ip] += 1
                    
                    if dst_port in suspicious_ports:
                        suspicious['unusual_ports'].append({
                            'source': src_ip,
                            'destination': dst_ip,
                            'port': dst_port,
                            'protocol': 'TCP',
                            'timestamp': datetime.fromtimestamp(float(packet.time))
                        })
                
                if len(packet) > 1400 and self._is_external_ip(dst_ip):
                    suspicious['data_exfiltration'].append({
                        'source': src_ip,
                        'destination': dst_ip,
                        'size': len(packet),
                        'timestamp': datetime.fromtimestamp(float(packet.time))
                    })
                
                if packet.haslayer(ICMP):
                    icmp_packets[src_ip] += 1
            
            if packet.haslayer(ARP):
                arp_requests.append({
                    'src_mac': packet[ARP].hwsrc,
                    'src_ip': packet[ARP].psrc,
                    'dst_ip': packet[ARP].pdst,
                    'op': packet[ARP].op
                })
        
        # Port scan detection
        for src_ip, dst_ports in src_dst_ports.items():
            if len(dst_ports) > 50:
                suspicious['port_scan'].append({
                    'ip': src_ip,
                    'unique_targets': len(dst_ports),
                    'severity': 'HIGH' if len(dst_ports) > 100 else 'MEDIUM'
                })
        
        # SYN flood detection
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
        
        # ICMP flood detection
        for src_ip, count in icmp_packets.items():
            if count > 500:
                suspicious['icmp_flood'].append({
                    'ip': src_ip,
                    'icmp_count': count
                })
        
        # ARP spoofing detection
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
        
        suspicious_patterns = [
            r'\.\./',
            r'<script',
            r'union.*select',
            r'exec\(',
            r'eval\(',
        ]
        
        for packet in self.packets:
            try:
                if packet.haslayer(HTTPRequest):
                    http_layer = packet[HTTPRequest]
                    
                    host = http_layer.Host.decode('utf-8', errors='ignore') if http_layer.Host else 'Unknown'
                    path = http_layer.Path.decode('utf-8', errors='ignore') if http_layer.Path else '/'
                    method = http_layer.Method.decode('utf-8', errors='ignore') if hasattr(http_layer, 'Method') else 'Unknown'
                    
                    http_data['hosts'][host] += 1
                    http_data['methods'][method] += 1
                    
                    user_agent = 'Unknown'
                    if hasattr(http_layer, 'User_Agent'):
                        user_agent = http_layer.User_Agent.decode('utf-8', errors='ignore')
                    
                    http_data['user_agents'][user_agent] += 1
                    
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
        
        credential_patterns = [
            (r'password[=:]\s*(\S+)', 'password'),
            (r'user(?:name)?[=:]\s*(\S+)', 'username'),
            (r'api[_-]?key[=:]\s*(\S+)', 'api_key'),
            (r'token[=:]\s*(\S+)', 'token'),
        ]
        
        for packet in self.packets[:10000]:
            try:
                if packet.haslayer(Raw):
                    payload = packet[Raw].load
                    
                    if len(payload) > 100:
                        unique_bytes = len(set(payload))
                        if unique_bytes > len(payload) * 0.7:
                            payload_info['encrypted_traffic'] += 1
                    
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
        
        for ip in list(ip_list)[:15]:
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
                if IPWHOIS_AVAILABLE:
                    # Try ipwhois first
                    obj = IPWhois(ip, timeout=3)
                    results = obj.lookup_rdap(depth=1)
                    enriched_ips[ip] = {
                        'country': results.get('asn_country_code', 'Unknown'),
                        'city': results.get('city', 'Unknown'),
                        'isp': results.get('asn_description', 'Unknown'),
                        'asn': results.get('asn', 'Unknown'),
                        'org': results.get('network', {}).get('name', 'Unknown')
                    }
                else:
                    # Fallback to ip-api.com
                    response = requests.get(
                        f'http://ip-api.com/json/{ip}',
                        timeout=2,
                        headers={'User-Agent': 'PCAP-Analyzer/3.0'}
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
            except requests.Timeout:
                if self.progress_callback:
                    self.progress_callback(f"Timeout enriching {ip}, skipping...", 98)
            except Exception as e:
                pass
            
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
    
    def print_statistics(self) -> None:
        """Print formatted statistics to console (for CLI mode)"""
        if not self.stats:
            print("No analysis results available. Run analyze() first.")
            return
        
        print("\n" + "=" * 80)
        print("ADVANCED PCAP ANALYSIS REPORT v3.0")
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
        
        # DNS Analysis Section
        if self.stats.get('dns_analysis'):
            dns = self.stats['dns_analysis']
            print(f"\n🔍 DNS ANALYSIS")
            print(f"  Total DNS Queries: {dns.get('total_queries', 0):,}")
            print(f"  Unique Domains Queried: {dns.get('unique_domains', 0):,}")
            
            # Query types
            if dns.get('query_types'):
                print(f"\n  DNS Query Types:")
                for qtype, count in list(dns['query_types'].items())[:10]:
                    print(f"    {qtype:8s}: {count:,}")
            
            # Response codes
            if dns.get('response_codes'):
                print(f"\n  DNS Response Codes:")
                for rcode, count in dns['response_codes'].items():
                    print(f"    {rcode:12s}: {count:,}")
            
            # TLD distribution
            if dns.get('tld_distribution'):
                print(f"\n  Top 15 TLDs:")
                for tld, count in list(dns['tld_distribution'].items())[:15]:
                    print(f"    .{tld:12s}: {count:,} queries")
            
            # Top queried domains
            if dns.get('top_queried_domains'):
                print(f"\n  Top 15 Queried Domains:")
                for domain, count in dns['top_queried_domains'][:15]:
                    print(f"    {domain[:60]:60s}: {count:,}")
            
            # Query length stats
            if dns.get('query_length_stats'):
                ql = dns['query_length_stats']
                print(f"\n  Query Length Statistics:")
                print(f"    Min: {ql.get('min', 0)} | Max: {ql.get('max', 0)} | Avg: {ql.get('avg', 0):.1f} | Median: {ql.get('median', 0)}")
            
            # Suspicious DNS queries
            if dns.get('suspicious_queries'):
                print(f"\n  ⚠️  Suspicious DNS Queries: {len(dns['suspicious_queries'])}")
                for sq in dns['suspicious_queries'][:5]:
                    print(f"    🚨 {sq['domain'][:60]}")
                    print(f"       Entropy: {sq.get('entropy', 0):.2f} | Length: {sq.get('length', 0)}")
                    print(f"       Reasons: {', '.join(sq.get('reasons', [])[:2])}")
            
            # DNS Tunneling
            if dns.get('dns_tunneling_suspects'):
                tunneling = dns['dns_tunneling_suspects']
                if tunneling:
                    print(f"\n  🚨 DNS TUNNELING SUSPECTS: {len(tunneling)}")
                    for tunnel in tunneling[:5]:
                        print(f"    Severity: {tunnel['severity']} | Domain: {tunnel['domain']}")
                        print(f"    Queries: {tunnel['query_count']} | Avg Length: {tunnel['avg_length']:.1f}")
                        print(f"    Indicators: {', '.join(tunnel['indicators'][:2])}")
            
            # Fast-Flux Detection
            if dns.get('fast_flux_suspects'):
                fast_flux = dns['fast_flux_suspects']
                if fast_flux:
                    print(f"\n  🚨 FAST-FLUX SUSPECTS: {len(fast_flux)}")
                    for ff in fast_flux[:5]:
                        print(f"    Domain: {ff['domain']}")
                        print(f"    Unique IPs: {ff['unique_ips']} | Total Resolutions: {ff['total_resolutions']}")
            
            # Domains with multiple IPs
            if dns.get('domains_with_multiple_ips'):
                print(f"\n  Domains Resolving to Multiple IPs (Top 10):")
                for item in dns['domains_with_multiple_ips'][:10]:
                    print(f"    {item['domain'][:50]:50s}: {item['ip_count']} IPs")
        
        # Beacon Detection
        if self.stats.get('beacon_analysis'):
            beacons = self.stats['beacon_analysis']
            if beacons:
                print(f"\n📡 C2 BEACONING DETECTED: {len(beacons)}")
                for beacon in beacons[:5]:
                    print(f"  {beacon['src_ip']} -> {beacon['dst_ip']}:{beacon['dst_port']}")
                    print(f"  Connections: {beacon['connection_count']} | Interval: {beacon['avg_interval_sec']:.1f}s")
                    print(f"  CV: {beacon['coefficient_variation']:.3f} | Severity: {beacon['severity']}")
        
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
        
        # Packet size statistics
        if self.stats['packet_sizes']:
            sizes = self.stats['packet_sizes']
            print(f"\n📦 PACKET SIZE STATISTICS")
            print(f"  Average: {sum(sizes) / len(sizes):.2f} bytes")
            print(f"  Minimum: {min(sizes):,} bytes")
            print(f"  Maximum: {max(sizes):,} bytes")
            print(f"  Total Data: {sum(sizes):,} bytes ({sum(sizes)/(1024*1024):.2f} MB)")
        
        print("\n" + "=" * 80)
    
    def print_security_findings(self) -> None:
        """Print security-related findings"""
        if not self.stats:
            return
        
        suspicious = self.stats.get('suspicious_activities', {})
        dns = self.stats.get('dns_analysis', {})
        beacons = self.stats.get('beacon_analysis', [])
        
        print("\n" + "!" * 80)
        print("🔒 SECURITY FINDINGS")
        print("!" * 80)
        
        findings_count = 0
        
        # DNS-based threats
        if dns.get('suspicious_queries'):
            findings_count += len(dns['suspicious_queries'])
            print(f"\n🚨 SUSPICIOUS DNS QUERIES: {len(dns['suspicious_queries'])}")
            for finding in dns['suspicious_queries'][:10]:
                print(f"  ⚠️  {finding['domain']}")
                print(f"     Reasons: {', '.join(finding['reasons'][:3])}")
        
        if dns.get('dns_tunneling_suspects'):
            findings_count += len(dns['dns_tunneling_suspects'])
            print(f"\n🚨 DNS TUNNELING SUSPECTS: {len(dns['dns_tunneling_suspects'])}")
            for finding in dns['dns_tunneling_suspects'][:5]:
                severity = finding['severity']
                emoji = "🔴" if severity == "HIGH" else "🟡"
                print(f"  {emoji} Domain: {finding['domain']} | Severity: {severity}")
                print(f"     Score: {finding['score']} | Queries: {finding['query_count']}")
        
        if dns.get('fast_flux_suspects'):
            findings_count += len(dns['fast_flux_suspects'])
            print(f"\n🚨 FAST-FLUX DNS: {len(dns['fast_flux_suspects'])}")
            for finding in dns['fast_flux_suspects'][:5]:
                print(f"  ⚠️  {finding['domain']}: {finding['unique_ips']} unique IPs")
        
        # Beaconing
        if beacons:
            findings_count += len(beacons)
            print(f"\n🚨 C2 BEACONING DETECTED: {len(beacons)}")
            for beacon in beacons[:5]:
                severity = beacon['severity']
                emoji = "🔴" if severity == "HIGH" else "🟡"
                print(f"  {emoji} {beacon['src_ip']} -> {beacon['dst_ip']}:{beacon['dst_port']}")
                print(f"     Interval: {beacon['avg_interval_sec']:.1f}s | CV: {beacon['coefficient_variation']:.3f}")
        
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
        
        if findings_count == 0:
            print(f"\n✅ No suspicious activities detected.")
        else:
            print(f"\n🔍 Total security findings: {findings_count}")
            print("⚠️  Note: These are potential threats. Manual verification recommended.")
        
        print("!" * 80)
    
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