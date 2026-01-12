import math
import re
from collections import Counter, defaultdict
from typing import Dict, List, Any, Set
from datetime import datetime

try:
    import tldextract
    TLDEXTRACT_AVAILABLE = True
except ImportError:
    TLDEXTRACT_AVAILABLE = False


class AdvancedDNSAnalyzer:
    """Comprehensive DNS traffic analyzer with threat detection"""
    
    # Known malicious/suspicious TLDs
    SUSPICIOUS_TLDS = {
        'tk', 'ml', 'ga', 'cf', 'gq', 'pw', 'cc', 'ws', 'top', 'work',
        'click', 'link', 'xyz', 'date', 'racing', 'stream', 'online',
        'shop', 'club', 'site', 'win', 'bid', 'download', 'webcam'
    }
    
    # DGA-like patterns
    DGA_PATTERNS = [
        r'^[a-f0-9]{16,}\.',
        r'^[0-9]{8,}\.',
        r'[a-z]{10,}[0-9]{5,}',
        r'[0-9]{5,}[a-z]{10,}'
    ]
    
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
        self.failed_responses = []
        self.domain_frequencies = Counter()
        
    def analyze_packet(self, packet):
        """Analyze DNS packet"""
        if not packet.haslayer('DNS'):
            return
        
        try:
            dns = packet['DNS']
            
            # Query analysis
            if dns.qr == 0:  # Query
                self._analyze_query(packet, dns)
            
            # Response analysis
            elif dns.qr == 1:  # Response
                self._analyze_response(packet, dns)
                
        except Exception as e:
            pass  # Skip malformed packets
    
    def _analyze_query(self, packet, dns):
        """Analyze DNS query packet"""
        try:
            if not hasattr(dns, 'qd') or dns.qd is None:
                return
            
            qname = str(dns.qd.qname, 'utf-8', errors='ignore').rstrip('.')
            if not qname:
                return
            
            qtype = dns.qd.qtype
            
            query_info = {
                'domain': qname,
                'type': self._get_query_type_name(qtype),
                'type_code': qtype,
                'timestamp': datetime.fromtimestamp(float(packet.time)),
                'src_ip': packet['IP'].src if packet.haslayer('IP') else 'Unknown',
                'packet_size': len(packet)
            }
            
            self.queries.append(query_info)
            self.query_types[query_info['type']] += 1
            self.query_lengths.append(len(qname))
            self.domain_frequencies[qname] += 1
            
            # TLD analysis
            self._analyze_tld(qname)
            
            # Threat analysis
            threat_score = self._analyze_domain_threat(qname, query_info)
            if threat_score > 0.3:
                self.suspicious_queries.append({
                    **query_info,
                    'threat_score': threat_score,
                    'indicators': self._get_threat_indicators(qname)
                })
                
        except Exception as e:
            pass
    
    def _analyze_response(self, packet, dns):
        """Analyze DNS response packet"""
        try:
            rcode = dns.rcode
            rcode_name = self._get_rcode_name(rcode)
            self.response_codes[rcode_name] += 1
            
            # Track failed responses
            if rcode != 0:  # Non-zero response codes indicate errors
                self.failed_responses.append({
                    'rcode': rcode_name,
                    'timestamp': datetime.fromtimestamp(float(packet.time)),
                    'src_ip': packet['IP'].src if packet.haslayer('IP') else 'Unknown'
                })
            
            # Process answer records
            if hasattr(dns, 'an') and dns.an is not None:
                qname = None
                if hasattr(dns, 'qd') and dns.qd is not None:
                    qname = str(dns.qd.qname, 'utf-8', errors='ignore').rstrip('.')
                
                self._process_dns_records(dns.an, qname)
                
        except Exception as e:
            pass
    
    def _analyze_tld(self, domain: str):
        """Analyze TLD of domain"""
        if TLDEXTRACT_AVAILABLE:
            extracted = tldextract.extract(domain)
            if extracted.suffix:
                self.tld_stats[extracted.suffix] += 1
        else:
            parts = domain.split('.')
            if len(parts) >= 2:
                self.tld_stats[parts[-1]] += 1
    
    def _analyze_domain_threat(self, domain: str, query_info: dict) -> float:
        """Calculate threat score for domain"""
        score = 0.0
        indicators = []
        
        # 1. Check TLD
        if TLDEXTRACT_AVAILABLE:
            extracted = tldextract.extract(domain)
            if extracted.suffix in self.SUSPICIOUS_TLDS:
                score += 0.3
                indicators.append(f"Suspicious TLD: {extracted.suffix}")
        
        # 2. Check length (DGA indicator)
        if len(domain) > 60:
            score += 0.2
            indicators.append(f"Very long domain: {len(domain)} chars")
        elif len(domain) > 40:
            score += 0.1
        
        # 3. Check entropy (DGA detection)
        entropy = self._calculate_entropy(domain)
        if entropy > 4.5:
            score += 0.3
            indicators.append(f"High entropy: {entropy:.2f}")
        elif entropy > 3.5:
            score += 0.1
        
        # 4. Check for DGA patterns
        for pattern in self.DGA_PATTERNS:
            if re.search(pattern, domain, re.IGNORECASE):
                score += 0.4
                indicators.append("DGA-like pattern detected")
                break
        
        # 5. Check subdomain depth
        subdomain_count = domain.count('.')
        if subdomain_count > 6:
            score += 0.3
            indicators.append(f"Deep nesting: {subdomain_count} levels")
        elif subdomain_count > 4:
            score += 0.1
        
        # 6. Check for hex patterns
        if re.match(r'^[a-f0-9]{20,}\.', domain.lower()):
            score += 0.3
            indicators.append("Hex-like subdomain")
        
        return min(score, 1.0)
    
    def _process_dns_records(self, records, qname: str = None):
        """Process DNS resource records"""
        if records is None:
            return
        
        try:
            # Handle single record or list
            record_list = [records] if not isinstance(records, list) else records
            
            for record in record_list:
                if hasattr(record, 'type'):
                    if record.type == 1:  # A record
                        ip = record.rdata
                        if isinstance(ip, str) and qname:
                            self.domain_to_ips[qname].append(ip)
                            self.ip_to_domains[ip].append(qname)
                    elif record.type == 28:  # AAAA record
                        ipv6 = record.rdata
                        if qname:
                            self.domain_to_ips[qname].append(ipv6)
                            
        except Exception as e:
            pass
    
    def detect_dns_tunneling(self, threshold: float = 0.6) -> List[Dict]:
        """Detect potential DNS tunneling"""
        suspects = []
        
        # Group queries by source IP and domain pattern
        src_domain_map = defaultdict(lambda: defaultdict(list))
        
        for query in self.queries:
            src_ip = query['src_ip']
            domain = query['domain']
            src_domain_map[src_ip][self._get_base_domain(domain)].append(query)
        
        for src_ip, domains in src_domain_map.items():
            for base_domain, queries in domains.items():
                if len(queries) < 15:  # Need sufficient queries
                    continue
                
                # Calculate tunneling indicators
                indicators = []
                tunnel_score = 0
                
                # 1. High query volume
                if len(queries) > 100:
                    indicators.append(f"High volume: {len(queries)} queries")
                    tunnel_score += 0.2
                
                # 2. High TXT query ratio
                txt_count = sum(1 for q in queries if q['type'] == 'TXT')
                txt_ratio = txt_count / len(queries)
                if txt_ratio > 0.3:
                    indicators.append(f"High TXT ratio: {txt_ratio:.1%}")
                    tunnel_score += 0.3
                
                # 3. High entropy domains
                avg_entropy = sum(self._calculate_entropy(q['domain']) for q in queries) / len(queries)
                if avg_entropy > 4.0:
                    indicators.append(f"High avg entropy: {avg_entropy:.2f}")
                    tunnel_score += 0.3
                
                # 4. Regular timing patterns (beaconing)
                if len(queries) > 20:
                    timestamps = [q['timestamp'] for q in queries]
                    intervals = [(timestamps[i+1] - timestamps[i]).total_seconds() 
                                for i in range(len(timestamps)-1)]
                    
                    if intervals:
                        avg_interval = sum(intervals) / len(intervals)
                        variance = sum((x - avg_interval)**2 for x in intervals) / len(intervals)
                        
                        if variance < 10 and 5 < avg_interval < 300:  # Regular intervals
                            indicators.append(f"Regular intervals: ~{avg_interval:.1f}s")
                            tunnel_score += 0.4
                
                if tunnel_score >= threshold:
                    suspects.append({
                        'source_ip': src_ip,
                        'domain': base_domain,
                        'query_count': len(queries),
                        'tunnel_score': tunnel_score,
                        'indicators': indicators,
                        'severity': 'HIGH' if tunnel_score > 0.8 else 'MEDIUM',
                        'sample_queries': [q['domain'] for q in queries[:3]]
                    })
        
        return sorted(suspects, key=lambda x: x['tunnel_score'], reverse=True)
    
    def detect_fast_flux(self, min_ips: int = 10, max_ttl: int = 300) -> List[Dict]:
        """Detect fast-flux DNS networks"""
        flux_domains = []
        
        for domain, ips in self.domain_to_ips.items():
            unique_ips = set(ips)
            
            if len(unique_ips) >= min_ips:
                flux_domains.append({
                    'domain': domain,
                    'unique_ips': len(unique_ips),
                    'total_resolutions': len(ips),
                    'ip_sample': list(unique_ips)[:10],
                    'severity': 'HIGH' if len(unique_ips) > 50 else 'MEDIUM'
                })
        
        return sorted(flux_domains, key=lambda x: x['unique_ips'], reverse=True)
    
    def detect_domain_generation(self) -> List[Dict]:
        """Detect Domain Generation Algorithms (DGA)"""
        dga_candidates = []
        
        for domain, freq in self.domain_frequencies.most_common():
            if freq > 5:  # Multiple queries for same domain
                continue
            
            entropy = self._calculate_entropy(domain)
            length = len(domain)
            
            dga_score = 0
            indicators = []
            
            # Scoring criteria
            if entropy > 4.5:
                dga_score += 0.4
                indicators.append(f"High entropy: {entropy:.2f}")
            
            if length > 40:
                dga_score += 0.3
                indicators.append(f"Long domain: {length} chars")
            
            # Check patterns
            if re.search(r'\d{8,}', domain):
                dga_score += 0.3
                indicators.append("Long numeric sequence")
            
            if re.search(r'[bcdfghjklmnpqrstvwxyz]{6,}', domain.lower()):
                dga_score += 0.2
                indicators.append("Consonant cluster")
            
            if dga_score > 0.6:
                dga_candidates.append({
                    'domain': domain,
                    'dga_score': dga_score,
                    'entropy': entropy,
                    'length': length,
                    'query_count': freq,
                    'indicators': indicators
                })
        
        return sorted(dga_candidates, key=lambda x: x['dga_score'], reverse=True)
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get comprehensive DNS statistics"""
        return {
            'summary': {
                'total_queries': len(self.queries),
                'total_responses': len(self.responses),
                'unique_domains': len(self.domain_frequencies),
                'failed_responses': len(self.failed_responses)
            },
            'query_types': dict(self.query_types.most_common(15)),
            'response_codes': dict(self.response_codes.most_common()),
            'tld_distribution': dict(self.tld_stats.most_common(20)),
            'top_domains': self.domain_frequencies.most_common(20),
            'query_length_stats': self._get_length_stats(),
            'threats': {
                'suspicious_queries': self.suspicious_queries[:50],
                'dns_tunneling': self.detect_dns_tunneling(),
                'fast_flux': self.detect_fast_flux(),
                'dga_candidates': self.detect_domain_generation()
            },
            'resolution_mapping': {
                'domains_multiple_ips': self._get_domains_with_multiple_ips(),
                'ips_multiple_domains': self._get_ips_with_multiple_domains()
            }
        }
    
    def _get_length_stats(self) -> Dict[str, float]:
        """Get query length statistics"""
        if not self.query_lengths:
            return {}
        
        lengths = self.query_lengths
        return {
            'min': min(lengths),
            'max': max(lengths),
            'mean': sum(lengths) / len(lengths),
            'median': sorted(lengths)[len(lengths) // 2],
            'std_dev': math.sqrt(sum((x - sum(lengths)/len(lengths))**2 for x in lengths) / len(lengths))
        }
    
    def _get_domains_with_multiple_ips(self, min_ips: int = 2) -> List[Dict]:
        """Get domains that resolve to multiple IPs"""
        multi_ip = []
        for domain, ips in self.domain_to_ips.items():
            unique_ips = set(ips)
            if len(unique_ips) >= min_ips:
                multi_ip.append({
                    'domain': domain,
                    'ip_count': len(unique_ips),
                    'ips': list(unique_ips)[:10]
                })
        return sorted(multi_ip, key=lambda x: x['ip_count'], reverse=True)[:20]
    
    def _get_ips_with_multiple_domains(self, min_domains: int = 5) -> List[Dict]:
        """Get IPs associated with multiple domains"""
        multi_domain = []
        for ip, domains in self.ip_to_domains.items():
            unique_domains = set(domains)
            if len(unique_domains) >= min_domains:
                multi_domain.append({
                    'ip': ip,
                    'domain_count': len(unique_domains),
                    'domains': list(unique_domains)[:10]
                })
        return sorted(multi_domain, key=lambda x: x['domain_count'], reverse=True)[:20]
    
    def _get_threat_indicators(self, domain: str) -> List[str]:
        """Get specific threat indicators for a domain"""
        indicators = []
        
        # TLD check
        if TLDEXTRACT_AVAILABLE:
            extracted = tldextract.extract(domain)
            if extracted.suffix in self.SUSPICIOUS_TLDS:
                indicators.append(f"TLD: {extracted.suffix}")
        
        # Pattern checks
        if re.search(r'\d{8,}', domain):
            indicators.append("Long numeric sequence")
        
        if re.search(r'[bcdfghjklmnpqrstvwxyz]{6,}', domain.lower()):
            indicators.append("Consonant cluster")
        
        # Length
        if len(domain) > 50:
            indicators.append(f"Length: {len(domain)} chars")
        
        return indicators
    
    @staticmethod
    def _calculate_entropy(string: str) -> float:
        """Calculate Shannon entropy"""
        if not string:
            return 0.0
        
        # Remove common TLDs for better entropy calculation
        string = re.sub(r'\.(com|net|org|edu|gov|io)$', '', string.lower())
        
        entropy = 0.0
        char_count = len(string)
        
        for char in set(string):
            freq = string.count(char) / char_count
            entropy -= freq * math.log2(freq)
        
        return entropy
    
    @staticmethod
    def _get_base_domain(domain: str) -> str:
        """Extract base domain"""
        if TLDEXTRACT_AVAILABLE:
            extracted = tldextract.extract(domain)
            if extracted.suffix:
                return f"{extracted.domain}.{extracted.suffix}"
        return domain
    
    @staticmethod
    def _get_query_type_name(qtype: int) -> str:
        """Convert DNS type code to name"""
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
            4: 'NOTIMP', 5: 'REFUSED', 6: 'YXDOMAIN', 7: 'YXRRSET',
            8: 'NXRRSET', 9: 'NOTAUTH', 10: 'NOTZONE'
        }
        return rcodes.get(rcode, f'RCODE{rcode}')