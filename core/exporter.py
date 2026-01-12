import json
import csv
import os
import base64
import io
from datetime import datetime
from typing import Dict, List, Any
import matplotlib.pyplot as plt
import matplotlib
matplotlib.use('Agg')


class ReportExporter:
    """Export analysis results to various formats with matplotlib plots"""
    
    def __init__(self, base_filename: str):
        self.base_filename = base_filename
        self.export_dir = "exports"
        os.makedirs(self.export_dir, exist_ok=True)
    def _santize_filename(self, name: str) -> str:
        """ Remove path separators from filename """
        filename = filename.replace('/', '_').replace('\\', '_')
        # Remove other potentially problematic characters
        filename = filename.replace(':', '_').replace('*', '_').replace('?', '_')
        filename = filename.replace('"', '_').replace('<', '_').replace('>', '_')
        filename = filename.replace('|', '_')
        return filename
    def export_json(self, data: Dict[str, Any]) -> str:
        """Export data to JSON format"""
        filename = os.path.join(self.export_dir, f"{self.base_filename}_analysis.json")
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(self._make_serializable(data), f, indent=2, default=str)
        
        return filename
    
    def export_csv(self, data: Dict[str, Any]) -> List[str]:
        """Export data to multiple CSV files"""
        files = []
        
        # 1. IP Statistics CSV
        if 'ip_sources' in data or 'ip_destinations' in data:
            ip_file = os.path.join(self.export_dir, f"{self.base_filename}_ip_stats.csv")
            with open(ip_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['IP Address', 'Packet Count', 'Type', 'Country', 'City', 'ISP', 'ASN', 'Organization'])
                
                # Sources with enrichment
                for ip, count in data.get('ip_sources', {}).most_common(100):
                    enrichment = data.get('ip_enrichment', {}).get(ip, {})
                    writer.writerow([
                        ip, count, 'Source',
                        enrichment.get('country', 'Unknown'),
                        enrichment.get('city', 'Unknown'),
                        enrichment.get('isp', 'Unknown'),
                        enrichment.get('asn', 'Unknown'),
                        enrichment.get('org', 'Unknown')
                    ])
                
                # Destinations with enrichment
                for ip, count in data.get('ip_destinations', {}).most_common(100):
                    enrichment = data.get('ip_enrichment', {}).get(ip, {})
                    writer.writerow([
                        ip, count, 'Destination',
                        enrichment.get('country', 'Unknown'),
                        enrichment.get('city', 'Unknown'),
                        enrichment.get('isp', 'Unknown'),
                        enrichment.get('asn', 'Unknown'),
                        enrichment.get('org', 'Unknown')
                    ])
            
            files.append(ip_file)
        
        # 2. Protocol Statistics CSV
        if 'protocols' in data:
            proto_file = os.path.join(self.export_dir, f"{self.base_filename}_protocols.csv")
            with open(proto_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['Protocol', 'Packet Count', 'Percentage'])
                
                total = data['total_packets']
                for proto, count in data['protocols'].items():
                    percentage = (count / total) * 100
                    writer.writerow([proto, count, f"{percentage:.2f}%"])
            
            files.append(proto_file)
        
        # 3. Port Statistics CSV
        if 'ports' in data:
            ports_file = os.path.join(self.export_dir, f"{self.base_filename}_ports.csv")
            with open(ports_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['Port', 'Protocol', 'Packet Count', 'Service'])
                
                # TCP ports
                for port, count in data['ports'].get('tcp', {}).most_common(50):
                    service = self._get_service_name(port)
                    writer.writerow([port, 'TCP', count, service])
                
                # UDP ports
                for port, count in data['ports'].get('udp', {}).most_common(50):
                    service = self._get_service_name(port)
                    writer.writerow([port, 'UDP', count, service])
            
            files.append(ports_file)
        
        # 4. Security Findings CSV
        if 'suspicious_activities' in data:
            sec_file = os.path.join(self.export_dir, f"{self.base_filename}_security.csv")
            self._export_security_csv(data['suspicious_activities'], sec_file)
            files.append(sec_file)
        
        # 5. DNS Statistics CSV
        if 'dns_analysis' in data:
            dns_file = os.path.join(self.export_dir, f"{self.base_filename}_dns.csv")
            self._export_dns_csv(data['dns_analysis'], dns_file)
            files.append(dns_file)
        
        # 6. HTTP Statistics CSV
        if 'http_analysis' in data:
            http_file = os.path.join(self.export_dir, f"{self.base_filename}_http.csv")
            self._export_http_csv(data['http_analysis'], http_file)
            files.append(http_file)
        
        return files
    
    def _export_security_csv(self, findings: Dict[str, List], filename: str):
        """Export security findings to CSV"""
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['Category', 'Source IP', 'Destination IP', 'Port', 'Protocol', 'Description', 'Severity', 'Timestamp'])
            
            for category, threats in findings.items():
                for threat in threats:
                    writer.writerow([
                        category,
                        threat.get('source', threat.get('src_ip', threat.get('ip', ''))),
                        threat.get('destination', threat.get('dst_ip', '')),
                        threat.get('port', ''),
                        threat.get('protocol', ''),
                        threat.get('reason', threat.get('description', '')),
                        threat.get('severity', 'MEDIUM'),
                        threat.get('timestamp', '')
                    ])
    
    def _export_dns_csv(self, dns_data: Dict[str, Any], filename: str):
        """Export DNS analysis to CSV"""
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['Domain', 'Query Count', 'Type', 'Source IP', 'Timestamp', 'Threat Level', 'Indicators'])
            
            # Top domains
            for domain, count in dns_data.get('top_queried_domains', []):
                writer.writerow([domain, count, 'Query', '', '', 'Normal', ''])
            
            # Suspicious queries
            for query in dns_data.get('suspicious_queries', []):
                indicators = ', '.join(query.get('reasons', [])[:3])
                writer.writerow([
                    query.get('domain', ''),
                    query.get('query_count', 1),
                    query.get('type', ''),
                    query.get('src_ip', ''),
                    query.get('timestamp', ''),
                    'High' if query.get('entropy', 0) > 4.5 else 'Medium',
                    indicators[:100]
                ])
            
            # DNS tunneling suspects
            for tunnel in dns_data.get('dns_tunneling_suspects', []):
                indicators = ', '.join(tunnel.get('indicators', [])[:3])
                writer.writerow([
                    tunnel.get('domain', ''),
                    tunnel.get('query_count', 0),
                    'TUNNELING',
                    '',
                    '',
                    tunnel.get('severity', 'HIGH'),
                    indicators[:100]
                ])
    
    def _export_http_csv(self, http_data: Dict[str, Any], filename: str):
        """Export HTTP analysis to CSV"""
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['Source IP', 'Host', 'Method', 'Path', 'User Agent', 'Timestamp', 'Suspicious'])
            
            for request in http_data.get('requests', [])[:1000]:
                is_suspicious = 'Yes' if any(r.get('src_ip') == request.get('src_ip') and 
                                           r.get('host') == request.get('host') 
                                           for r in http_data.get('suspicious_requests', [])) else 'No'
                writer.writerow([
                    request.get('src_ip', ''),
                    request.get('host', ''),
                    request.get('method', ''),
                    request.get('path', ''),
                    request.get('user_agent', '')[:100],
                    request.get('timestamp', ''),
                    is_suspicious
                ])
    
    def export_html(self, data: Dict[str, Any]) -> str:
        """Export data to HTML report with matplotlib plots"""
        filename = os.path.join(self.export_dir, f"{self.base_filename}_report.html")
        
        # Generate plots
        plot_images = self._generate_plot_images(data)
        
        html_content = self._generate_html_report(data, plot_images)
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return filename
    
    def _generate_plot_images(self, data: Dict[str, Any]) -> Dict[str, str]:
        """Generate matplotlib plots and return as base64 images"""
        plot_images = {}
        
        try:
            # 1. Protocol Distribution Pie Chart
            if data.get('protocols'):
                fig, ax = plt.subplots(figsize=(8, 6))
                protocols = list(data['protocols'].keys())
                counts = list(data['protocols'].values())
                colors = plt.cm.Set3(range(len(protocols)))
                explode = [0.1 if count/sum(counts) < 0.05 else 0 for count in counts]
                ax.pie(counts, labels=protocols, autopct='%1.1f%%', colors=colors, startangle=90, explode=explode)
                ax.set_title('Protocol Distribution', fontweight='bold')
                plt.tight_layout()
                
                # Save to base64
                buf = io.BytesIO()
                plt.savefig(buf, format='png', dpi=100, bbox_inches='tight')
                buf.seek(0)
                plot_images['protocols'] = base64.b64encode(buf.read()).decode('utf-8')
                plt.close(fig)
            
            # 2. Top Source IPs Bar Chart
            if data.get('ip_sources'):
                fig, ax = plt.subplots(figsize=(10, 6))
                top_sources = dict(data['ip_sources'].most_common(10))
                
                ax.barh(range(len(top_sources)), list(top_sources.values()), color='steelblue')
                ax.set_yticks(range(len(top_sources)))
                ax.set_yticklabels(list(top_sources.keys()), fontsize=9)
                ax.set_xlabel('Packet Count')
                ax.set_title('Top 10 Source IP Addresses', fontweight='bold')
                ax.grid(axis='x', alpha=0.3)
                plt.tight_layout()
                
                buf = io.BytesIO()
                plt.savefig(buf, format='png', dpi=100, bbox_inches='tight')
                buf.seek(0)
                plot_images['source_ips'] = base64.b64encode(buf.read()).decode('utf-8')
                plt.close(fig)
            
            # 3. Top TCP Ports Bar Chart
            if data.get('ports', {}).get('tcp'):
                fig, ax = plt.subplots(figsize=(10, 6))
                top_tcp = dict(data['ports']['tcp'].most_common(10))
                
                ax.bar(range(len(top_tcp)), list(top_tcp.values()), color='coral')
                ax.set_xticks(range(len(top_tcp)))
                ax.set_xticklabels([f"{port}\n({self._get_service_name(port)})" for port in top_tcp.keys()], 
                                  rotation=45, fontsize=9)
                ax.set_ylabel('Packet Count')
                ax.set_title('Top 10 TCP Ports', fontweight='bold')
                ax.grid(axis='y', alpha=0.3)
                plt.tight_layout()
                
                buf = io.BytesIO()
                plt.savefig(buf, format='png', dpi=100, bbox_inches='tight')
                buf.seek(0)
                plot_images['tcp_ports'] = base64.b64encode(buf.read()).decode('utf-8')
                plt.close(fig)
            
            # 4. DNS TLD Distribution
            if data.get('dns_analysis', {}).get('tld_distribution'):
                fig, ax = plt.subplots(figsize=(10, 6))
                dns = data['dns_analysis']
                top_tlds = dict(list(dns['tld_distribution'].items())[:10])
                
                ax.bar(range(len(top_tlds)), list(top_tlds.values()), color='mediumseagreen')
                ax.set_xticks(range(len(top_tlds)))
                ax.set_xticklabels([f".{tld}" for tld in top_tlds.keys()], rotation=45, fontsize=9)
                ax.set_ylabel('Query Count')
                ax.set_title('Top 10 TLDs in DNS Queries', fontweight='bold')
                ax.grid(axis='y', alpha=0.3)
                plt.tight_layout()
                
                buf = io.BytesIO()
                plt.savefig(buf, format='png', dpi=100, bbox_inches='tight')
                buf.seek(0)
                plot_images['dns_tlds'] = base64.b64encode(buf.read()).decode('utf-8')
                plt.close(fig)
            
            # 5. Packet Size Distribution Histogram
            if data.get('packet_sizes'):
                fig, ax = plt.subplots(figsize=(10, 6))
                sizes = data['packet_sizes'][:10000]  # Limit for performance
                
                ax.hist(sizes, bins=50, color='purple', alpha=0.7, edgecolor='black')
                ax.set_xlabel('Packet Size (bytes)')
                ax.set_ylabel('Frequency')
                ax.set_title('Packet Size Distribution', fontweight='bold')
                ax.grid(alpha=0.3)
                plt.tight_layout()
                
                buf = io.BytesIO()
                plt.savefig(buf, format='png', dpi=100, bbox_inches='tight')
                buf.seek(0)
                plot_images['packet_sizes'] = base64.b64encode(buf.read()).decode('utf-8')
                plt.close(fig)
                
        except Exception as e:
            print(f"Warning: Failed to generate plots: {e}")
        
        return plot_images
    
    def _generate_html_report(self, data: Dict[str, Any], plot_images: Dict[str, str]) -> str:
        """Generate comprehensive HTML report with plots"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        filename = data.get('filename', self.base_filename)
        
        # Build HTML in parts
        html_parts = []
        
        # Header and CSS
        html_parts.append(f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PCAP Analysis Report v3.0 - {filename}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f5f5;
            padding: 20px;
        }}
        .container {{ max-width: 1400px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
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
        .alert {{ padding: 15px; margin: 15px 0; border-radius: 5px; border-left: 4px solid; }}
        .alert-danger {{ background: #fee; border-color: #e74c3c; }}
        .alert-warning {{ background: #fef3cd; border-color: #f39c12; }}
        .alert-info {{ background: #d1ecf1; border-color: #3498db; }}
        .alert-success {{ background: #d4edda; border-color: #27ae60; }}
        footer {{ margin-top: 40px; padding-top: 20px; border-top: 2px solid #ecf0f1; text-align: center; color: #7f8c8d; }}
        .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin: 20px 0; }}
        .card {{ background: #f8f9fa; padding: 15px; border-radius: 5px; border-left: 4px solid #3498db; }}
        .card h4 {{ color: #2c3e50; margin-bottom: 10px; }}
        .plot-container {{ margin: 20px 0; text-align: center; }}
        .plot {{ max-width: 100%; height: auto; border: 1px solid #ddd; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }}
        .plot-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(500px, 1fr)); gap: 20px; margin: 30px 0; }}
        .code {{ background: #2c3e50; color: #ecf0f1; padding: 10px; border-radius: 4px; font-family: monospace; margin: 10px 0; overflow-x: auto; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>📊 PCAP Analysis Report v3.0</h1>
        
        <div class="summary">
            <h2 style="color: white; background: transparent; border: none; padding: 0; margin-bottom: 15px;">📋 Executive Summary</h2>
            <p><strong>File:</strong> {filename}</p>
            <p><strong>Total Packets:</strong> {data.get('total_packets', 0):,}</p>
            <p><strong>Capture Duration:</strong> {data.get('timeline', {}).get('duration_seconds', 0):.2f} seconds</p>
            <p><strong>Analysis Date:</strong> {timestamp}</p>
            <p><strong>Packets/Second:</strong> {data.get('timeline', {}).get('packets_per_second', 0):.2f}</p>
            <p><strong>Start Time:</strong> {data.get('timeline', {}).get('start_time', 'Unknown')}</p>
            <p><strong>End Time:</strong> {data.get('timeline', {}).get('end_time', 'Unknown')}</p>
        </div>
""")
        
        # Visualizations Section
        if plot_images:
            html_parts.append("""
        <div class="section">
            <h2>📈 Visual Analysis</h2>
            <div class="plot-grid">
""")
            
            if 'protocols' in plot_images:
                html_parts.append(f"""
                <div class="plot-container">
                    <h3>Protocol Distribution</h3>
                    <img src="data:image/png;base64,{plot_images['protocols']}" alt="Protocol Distribution" class="plot">
                </div>
""")
            
            if 'source_ips' in plot_images:
                html_parts.append(f"""
                <div class="plot-container">
                    <h3>Top Source IPs</h3>
                    <img src="data:image/png;base64,{plot_images['source_ips']}" alt="Top Source IPs" class="plot">
                </div>
""")
            
            if 'tcp_ports' in plot_images:
                html_parts.append(f"""
                <div class="plot-container">
                    <h3>Top TCP Ports</h3>
                    <img src="data:image/png;base64,{plot_images['tcp_ports']}" alt="Top TCP Ports" class="plot">
                </div>
""")
            
            if 'dns_tlds' in plot_images:
                html_parts.append(f"""
                <div class="plot-container">
                    <h3>DNS TLD Distribution</h3>
                    <img src="data:image/png;base64,{plot_images['dns_tlds']}" alt="DNS TLD Distribution" class="plot">
                </div>
""")
            
            html_parts.append("""
            </div>
        </div>
""")
        
        # Protocol Distribution
        html_parts.append("""
        <div class="section">
            <h2>📡 Protocol Distribution</h2>
            <table>
                <tr><th>Protocol</th><th>Packet Count</th><th>Percentage</th></tr>
""")
        
        total = data.get('total_packets', 1)
        for protocol, count in data.get('protocols', {}).most_common():
            percentage = (count / total) * 100
            html_parts.append(f"<tr><td>{protocol}</td><td>{count:,}</td><td>{percentage:.2f}%</td></tr>\n")
        
        html_parts.append("""            </table>
        </div>
        
        <div class="section">
            <h2>🌐 IP Address Analysis</h2>
            <div class="grid">
                <div class="card">
                    <h4>Top Source IPs</h4>
                    <table>
                        <tr><th>IP Address</th><th>Packets</th><th>Country</th><th>ISP</th></tr>
""")
        
        # Top Source IPs
        for ip, count in list(data.get('ip_sources', {}).most_common(10)):
            enrichment = data.get('ip_enrichment', {}).get(ip, {})
            html_parts.append(f"""<tr>
                <td>{ip}</td>
                <td>{count:,}</td>
                <td>{enrichment.get('country', 'Unknown')}</td>
                <td>{enrichment.get('isp', 'Unknown')[:30]}</td>
            </tr>\n""")
        
        html_parts.append("""                    </table>
                </div>
                
                <div class="card">
                    <h4>Top Destination IPs</h4>
                    <table>
                        <tr><th>IP Address</th><th>Packets</th><th>Country</th><th>ISP</th></tr>
""")
        
        # Top Destination IPs
        for ip, count in list(data.get('ip_destinations', {}).most_common(10)):
            enrichment = data.get('ip_enrichment', {}).get(ip, {})
            html_parts.append(f"""<tr>
                <td>{ip}</td>
                <td>{count:,}</td>
                <td>{enrichment.get('country', 'Unknown')}</td>
                <td>{enrichment.get('isp', 'Unknown')[:30]}</td>
            </tr>\n""")
        
        html_parts.append("""                    </table>
                </div>
            </div>
        </div>
        
        <div class="section">
            <h2>🔌 Port Analysis</h2>
            <div class="grid">
                <div class="card">
                    <h4>Top TCP Ports</h4>
                    <table>
                        <tr><th>Port</th><th>Service</th><th>Packet Count</th></tr>
""")
        
        # Top TCP Ports
        for port, count in list(data.get('ports', {}).get('tcp', {}).most_common(10)):
            service = self._get_service_name(port)
            html_parts.append(f"<tr><td>{port}</td><td>{service}</td><td>{count:,}</td></tr>\n")
        
        html_parts.append("""                    </table>
                </div>
                
                <div class="card">
                    <h4>Top UDP Ports</h4>
                    <table>
                        <tr><th>Port</th><th>Service</th><th>Packet Count</th></tr>
""")
        
        # Top UDP Ports
        for port, count in list(data.get('ports', {}).get('udp', {}).most_common(10)):
            service = self._get_service_name(port)
            html_parts.append(f"<tr><td>{port}</td><td>{service}</td><td>{count:,}</td></tr>\n")
        
        html_parts.append("""                    </table>
                </div>
            </div>
        </div>
""")
        
        # DNS Analysis
        if data.get('dns_analysis'):
            dns = data['dns_analysis']
            html_parts.append("""
        <div class="section">
            <h2>🔍 DNS Analysis</h2>
            <div class="grid">
                <div class="card">
                    <h4>DNS Overview</h4>
""")
            html_parts.append(f"<p><strong>Total Queries:</strong> {dns.get('total_queries', 0):,}</p>\n")
            html_parts.append(f"<p><strong>Total Responses:</strong> {dns.get('total_responses', 0):,}</p>\n")
            html_parts.append(f"<p><strong>Unique Domains:</strong> {dns.get('unique_domains', 0):,}</p>\n")
            html_parts.append("""</div>
                
                <div class="card">
                    <h4>Query Types</h4>
                    <table>
                        <tr><th>Type</th><th>Count</th></tr>
""")
            
            for qtype, count in list(dns.get('query_types', {}).items())[:10]:
                html_parts.append(f"<tr><td>{qtype}</td><td>{count:,}</td></tr>\n")
            
            html_parts.append("""                    </table>
                </div>
                
                <div class="card">
                    <h4>Top TLDs</h4>
                    <table>
                        <tr><th>TLD</th><th>Query Count</th></tr>
""")
            
            for tld, count in list(dns.get('tld_distribution', {}).items())[:10]:
                html_parts.append(f"<tr><td>.{tld}</td><td>{count:,}</td></tr>\n")
            
            html_parts.append("""                    </table>
                </div>
            </div>
""")
            
            # DNS Threats
            if dns.get('suspicious_queries') or dns.get('dns_tunneling_suspects') or dns.get('fast_flux_suspects'):
                html_parts.append("""
            <h3>🚨 DNS Security Findings</h3>
""")
                
                if dns.get('suspicious_queries'):
                    html_parts.append(f"""
            <div class="alert alert-warning">
                <strong>⚠️ {len(dns['suspicious_queries'])} Suspicious DNS Queries Detected</strong>
                <p>These domains exhibit characteristics of DGA, phishing, or other malicious activity.</p>
            </div>
            <table>
                <tr><th>Domain</th><th>Type</th><th>Entropy</th><th>Length</th><th>Reasons</th></tr>
""")
                    for sq in dns['suspicious_queries'][:10]:
                        reasons = '<br>'.join(sq.get('reasons', [])[:2])
                        html_parts.append(f"""<tr>
                            <td>{sq.get('domain', '')[:50]}</td>
                            <td>{sq.get('type', '')}</td>
                            <td>{sq.get('entropy', 0):.2f}</td>
                            <td>{sq.get('length', 0)}</td>
                            <td>{reasons}</td>
                        </tr>\n""")
                    html_parts.append("</table>\n")
                
                if dns.get('dns_tunneling_suspects'):
                    html_parts.append(f"""
            <div class="alert alert-danger">
                <strong>🚨 {len(dns['dns_tunneling_suspects'])} DNS Tunneling Suspects</strong>
                <p>These domains show patterns consistent with data exfiltration via DNS.</p>
            </div>
            <table>
                <tr><th>Domain</th><th>Queries</th><th>Avg Length</th><th>Avg Entropy</th><th>Severity</th><th>Indicators</th></tr>
""")
                    for tunnel in dns['dns_tunneling_suspects'][:5]:
                        indicators = '<br>'.join(tunnel.get('indicators', [])[:2])
                        severity_class = f"badge-{tunnel['severity'].lower()}"
                        html_parts.append(f"""<tr>
                            <td>{tunnel.get('domain', '')}</td>
                            <td>{tunnel.get('query_count', 0)}</td>
                            <td>{tunnel.get('avg_length', 0):.1f}</td>
                            <td>{tunnel.get('avg_entropy', 0):.2f}</td>
                            <td><span class="badge {severity_class}">{tunnel.get('severity', '')}</span></td>
                            <td>{indicators}</td>
                        </tr>\n""")
                    html_parts.append("</table>\n")
            
            html_parts.append("</div>\n")
        
        # Security Findings
        suspicious = data.get('suspicious_activities', {})
        beacons = data.get('beacon_analysis', [])
        
        findings_count = sum(len(v) for v in suspicious.values() if isinstance(v, list))
        findings_count += len(beacons)
        
        if data.get('dns_analysis'):
            dns = data['dns_analysis']
            findings_count += len(dns.get('suspicious_queries', []))
            findings_count += len(dns.get('dns_tunneling_suspects', []))
            findings_count += len(dns.get('fast_flux_suspects', []))
        
        html_parts.append("""
        <div class="section">
            <h2>🛡️ Security Assessment</h2>
""")
        
        if findings_count > 0:
            html_parts.append(f"""
            <div class="alert alert-danger">
                <strong>⚠️ {findings_count} Security Findings Detected</strong>
                <p>This capture contains potential security threats that require investigation.</p>
            </div>
            
            <div class="grid">
                <div class="card">
                    <h4>Threat Categories</h4>
                    <table>
                        <tr><th>Category</th><th>Count</th><th>Severity</th></tr>
""")
            
            # Count threats by category
            threat_categories = []
            
            if suspicious.get('port_scan'):
                threat_categories.append(('Port Scanning', len(suspicious['port_scan']), 'HIGH'))
            if suspicious.get('syn_flood'):
                threat_categories.append(('SYN Flood', len(suspicious['syn_flood']), 'HIGH'))
            if suspicious.get('unusual_ports'):
                threat_categories.append(('Suspicious Ports', len(suspicious['unusual_ports']), 'MEDIUM'))
            if suspicious.get('data_exfiltration'):
                threat_categories.append(('Data Exfiltration', len(suspicious['data_exfiltration']), 'HIGH'))
            if beacons:
                threat_categories.append(('C2 Beaconing', len(beacons), 'HIGH'))
            if data.get('dns_analysis', {}).get('dns_tunneling_suspects'):
                threat_categories.append(('DNS Tunneling', len(data['dns_analysis']['dns_tunneling_suspects']), 'HIGH'))
            if data.get('dns_analysis', {}).get('suspicious_queries'):
                threat_categories.append(('Suspicious DNS', len(data['dns_analysis']['suspicious_queries']), 'MEDIUM'))
            
            for category, count, severity in threat_categories:
                severity_class = f"badge-{severity.lower()}"
                html_parts.append(f"""<tr>
                    <td>{category}</td>
                    <td>{count}</td>
                    <td><span class="badge {severity_class}">{severity}</span></td>
                </tr>\n""")
            
            html_parts.append("""                    </table>
                </div>
                
                <div class="card">
                    <h4>Top Threats</h4>
""")
            
            # Show top threats
            if suspicious.get('port_scan'):
                html_parts.append("<p><strong>🔴 Port Scanning:</strong>")
                for scan in suspicious['port_scan'][:3]:
                    html_parts.append(f"<br>{scan.get('ip', '')} - {scan.get('unique_targets', 0)} targets")
                html_parts.append("</p>")
            
            if beacons:
                html_parts.append("<p><strong>🔴 C2 Beaconing:</strong>")
                for beacon in beacons[:3]:
                    html_parts.append(f"<br>{beacon.get('src_ip', '')} → {beacon.get('dst_ip', '')}:{beacon.get('dst_port', '')}")
                html_parts.append("</p>")
            
            if data.get('dns_analysis', {}).get('dns_tunneling_suspects'):
                html_parts.append("<p><strong>🔴 DNS Tunneling:</strong>")
                for tunnel in data['dns_analysis']['dns_tunneling_suspects'][:3]:
                    html_parts.append(f"<br>{tunnel.get('domain', '')} (score: {tunnel.get('score', 0)})")
                html_parts.append("</p>")
            
            html_parts.append("""                </div>
            </div>
""")
        else:
            html_parts.append("""
            <div class="alert alert-success">
                <strong>✅ No Security Threats Detected</strong>
                <p>No suspicious activities were found in this network capture.</p>
            </div>
""")
        
        # HTTP Analysis
        if data.get('http_analysis'):
            http = data['http_analysis']
            html_parts.append("""
        <div class="section">
            <h2>🌍 HTTP Analysis</h2>
            <div class="grid">
                <div class="card">
                    <h4>Top Hosts</h4>
                    <table>
                        <tr><th>Host</th><th>Requests</th></tr>
""")
            
            for host, count in list(http.get('hosts', {}).most_common(10)):
                html_parts.append(f"<tr><td>{host[:50]}</td><td>{count:,}</td></tr>\n")
            
            html_parts.append("""                    </table>
                </div>
                
                <div class="card">
                    <h4>HTTP Methods</h4>
                    <table>
                        <tr><th>Method</th><th>Count</th></tr>
""")
            
            for method, count in list(http.get('methods', {}).most_common()):
                html_parts.append(f"<tr><td>{method}</td><td>{count:,}</td></tr>\n")
            
            html_parts.append("""                    </table>
                </div>
            </div>
""")
            
            if http.get('suspicious_requests'):
                html_parts.append(f"""
            <div class="alert alert-warning">
                <strong>⚠️ {len(http['suspicious_requests'])} Suspicious HTTP Requests</strong>
                <p>These requests contain patterns associated with web attacks.</p>
            </div>
            <table>
                <tr><th>Source IP</th><th>Host</th><th>Method</th><th>Path</th><th>Pattern</th></tr>
""")
                
                for req in http['suspicious_requests'][:10]:
                    html_parts.append(f"""<tr>
                        <td>{req.get('src_ip', '')}</td>
                        <td>{req.get('host', '')[:30]}</td>
                        <td>{req.get('method', '')}</td>
                        <td>{req.get('path', '')[:50]}</td>
                        <td>{req.get('pattern_matched', '')}</td>
                    </tr>\n""")
                
                html_parts.append("</table>\n")
            
            html_parts.append("</div>\n")
        
        # Footer
        html_parts.append(f"""
        <div class="section">
            <h2>📋 Report Information</h2>
            <div class="grid">
                <div class="card">
                    <h4>Packet Statistics</h4>
""")
        
        if data.get('packet_sizes'):
            sizes = data['packet_sizes']
            html_parts.append(f"""
                    <p><strong>Total Data:</strong> {sum(sizes):,} bytes ({sum(sizes)/(1024*1024):.2f} MB)</p>
                    <p><strong>Average Size:</strong> {sum(sizes)/len(sizes):.2f} bytes</p>
                    <p><strong>Min Size:</strong> {min(sizes):,} bytes</p>
                    <p><strong>Max Size:</strong> {max(sizes):,} bytes</p>
""")
        
        html_parts.append(f"""                </div>
                
                <div class="card">
                    <h4>Export Information</h4>
                    <p><strong>JSON Export:</strong> {self.base_filename}_analysis.json</p>
                    <p><strong>CSV Exports:</strong> Multiple CSV files generated</p>
                    <p><strong>HTML Report:</strong> {self.base_filename}_report.html</p>
                    <p><strong>Generated:</strong> {timestamp}</p>
                </div>
            </div>
        </div>
        
        <footer>
            <p>Generated by Enhanced Advanced PCAP Analyzer v3.0</p>
            <p>⚠️ This report is for informational purposes only. Manual verification of findings is recommended.</p>
            <p>Always ensure proper authorization before analyzing network traffic.</p>
        </footer>
    </div>
</body>
</html>""")
        
        return ''.join(html_parts)
    
    def export_all(self, data: Dict[str, Any]) -> Dict[str, str]:
        """Export to all formats"""
        results = {}
        
        # JSON export
        results['json'] = self.export_json(data)
        
        # CSV exports
        csv_files = self.export_csv(data)
        results['csv'] = csv_files
        
        # HTML export
        results['html'] = self.export_html(data)
        
        return results
    
    def generate_plots(self, data: Dict[str, Any]) -> str:
        """Generate visual plots as a separate image file"""
        output_file = os.path.join(self.export_dir, f"{self.base_filename}_plots.png")
        
        try:
            fig, axes = plt.subplots(2, 2, figsize=(16, 12))
            fig.suptitle('PCAP Analysis Visualization', fontsize=16, fontweight='bold')
            
            # Protocol distribution pie chart
            if data.get('protocols'):
                protocols = list(data['protocols'].keys())
                counts = list(data['protocols'].values())
                colors = plt.cm.Set3(range(len(protocols)))
                
                axes[0, 0].pie(counts, labels=protocols, autopct='%1.1f%%', colors=colors, startangle=90)
                axes[0, 0].set_title('Protocol Distribution', fontweight='bold')
            
            # Top source IPs bar chart
            if data.get('ip_sources'):
                top_sources = dict(data['ip_sources'].most_common(10))
                axes[0, 1].barh(range(len(top_sources)), list(top_sources.values()), color='steelblue')
                axes[0, 1].set_yticks(range(len(top_sources)))
                axes[0, 1].set_yticklabels(list(top_sources.keys()), fontsize=8)
                axes[0, 1].set_xlabel('Packet Count')
                axes[0, 1].set_title('Top 10 Source IPs', fontweight='bold')
                axes[0, 1].grid(axis='x', alpha=0.3)
            
            # Top TCP ports
            if data.get('ports', {}).get('tcp'):
                top_tcp = dict(data['ports']['tcp'].most_common(10))
                axes[1, 0].bar(range(len(top_tcp)), list(top_tcp.values()), color='coral')
                axes[1, 0].set_xticks(range(len(top_tcp)))
                axes[1, 0].set_xticklabels(list(top_tcp.keys()), rotation=45)
                axes[1, 0].set_ylabel('Packet Count')
                axes[1, 0].set_title('Top 10 TCP Ports', fontweight='bold')
                axes[1, 0].grid(axis='y', alpha=0.3)
            
            # DNS TLD distribution
            dns = data.get('dns_analysis', {})
            if dns.get('tld_distribution'):
                top_tlds = dict(list(dns['tld_distribution'].items())[:10])
                axes[1, 1].bar(range(len(top_tlds)), list(top_tlds.values()), color='mediumseagreen')
                axes[1, 1].set_xticks(range(len(top_tlds)))
                axes[1, 1].set_xticklabels([f".{tld}" for tld in top_tlds.keys()], rotation=45)
                axes[1, 1].set_ylabel('Query Count')
                axes[1, 1].set_title('Top 10 TLDs', fontweight='bold')
                axes[1, 1].grid(axis='y', alpha=0.3)
            
            plt.tight_layout()
            plt.savefig(output_file, dpi=300, bbox_inches='tight')
            plt.close()
            
            return output_file
            
        except Exception as e:
            print(f"Warning: Failed to generate plots: {e}")
            return ""
    
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
        return services.get(port, '')
    
    @staticmethod
    def _make_serializable(obj):
        """Convert objects to JSON-serializable format"""
        if isinstance(obj, dict):
            return {str(k): ReportExporter._make_serializable(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [ReportExporter._make_serializable(item) for item in obj]
        elif hasattr(obj, '__dict__'):
            return ReportExporter._make_serializable(obj.__dict__)
        elif isinstance(obj, (set, tuple)):
            return list(obj)
        elif hasattr(obj, 'isoformat'):  # datetime objects
            return obj.isoformat()
        else:
            try:
                return str(obj)
            except:
                return None