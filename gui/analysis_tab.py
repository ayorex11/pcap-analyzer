from PyQt6.QtWidgets import (
    QTabWidget, QWidget, QVBoxLayout, QHBoxLayout, 
    QTableWidget, QTableWidgetItem, QTreeWidget,
    QTreeWidgetItem, QTextEdit, QPushButton, QLabel,
    QHeaderView, QSplitter, QGroupBox, QProgressBar
)
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QFont, QColor
import json
import csv
import os
from datetime import datetime

try:
    import matplotlib.pyplot as plt
    import matplotlib
    matplotlib.use('Agg')
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False


class AnalysisTabs(QTabWidget):
    """Tab widget for displaying analysis results"""
    
    def __init__(self):
        super().__init__()
        self.init_tabs()
    
    def init_tabs(self):
        """Initialize all analysis tabs"""
        # Overview tab
        self.overview_tab = OverviewTab()
        self.addTab(self.overview_tab, "📊 Overview")
        
        # Protocols tab
        self.protocols_tab = ProtocolsTab()
        self.addTab(self.protocols_tab, "📡 Protocols")
        
        # IP Analysis tab
        self.ip_tab = IPAnalysisTab()
        self.addTab(self.ip_tab, "🌐 IP Analysis")
        
        # DNS Analysis tab
        self.dns_tab = DNSAnalysisTab()
        self.addTab(self.dns_tab, "🔍 DNS Analysis")
        
        # Security tab
        self.security_tab = SecurityTab()
        self.addTab(self.security_tab, "🛡️ Security")
        
        # HTTP Analysis tab
        self.http_tab = HTTPAnalysisTab()
        self.addTab(self.http_tab, "🌍 HTTP Analysis")
    
    def update_all_tabs(self, results):
        """Update all tabs with analysis results"""
        self.overview_tab.update(results)
        self.protocols_tab.update(results)
        self.ip_tab.update(results)
        self.dns_tab.update(results.get('dns_analysis', {}))
        self.security_tab.update(results.get('security_findings', {}), results.get('dns_analysis', {}))
        self.http_tab.update(results.get('http_analysis', {}))
    
    def clear_all(self):
        """Clear all tab contents"""
        for i in range(self.count()):
            widget = self.widget(i)
            if hasattr(widget, 'clear'):
                widget.clear()
    
    def export_results(self, results, export_format, filename):
        """Export analysis results"""
        base_name = os.path.splitext(filename)[0]
        
        try:
            if export_format == "JSON" or export_format == "All":
                json_file = f"{base_name}_analysis.json"
                with open(json_file, 'w', encoding='utf-8') as f:
                    json.dump(self._make_serializable(results), f, indent=2, default=str)
                print(f"✅ Exported JSON: {json_file}")
            
            if export_format == "CSV" or export_format == "All":
                self._export_csv(results, base_name)
            
            if export_format == "HTML" or export_format == "All":
                self._export_html(results, base_name)
                
        except Exception as e:
            print(f"❌ Export error: {e}")
    
    def _export_csv(self, results, base_name):
        """Export IP statistics to CSV"""
        csv_file = f"{base_name}_ip_stats.csv"
        
        with open(csv_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['IP Address', 'Packet Count', 'Type'])
            
            for ip, count in results['ip_sources'].most_common():
                writer.writerow([ip, count, 'Source'])
            
            for ip, count in results['ip_destinations'].most_common():
                writer.writerow([ip, count, 'Destination'])
        
        print(f"✅ Exported CSV: {csv_file}")
    
    def _export_html(self, results, base_name):
        """Export HTML report"""
        html_file = f"{base_name}_report.html"
        
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>PCAP Analysis Report - {base_name}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1 {{ color: #2c3e50; }}
        .section {{ margin: 20px 0; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #4da6ff; color: white; }}
        .warning {{ color: #e67e22; }}
        .critical {{ color: #e74c3c; }}
    </style>
</head>
<body>
    <h1>📊 PCAP Analysis Report</h1>
    <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    
    <div class="section">
        <h2>Summary</h2>
        <p>Total Packets: {results['total_packets']:,}</p>
    </div>
</body>
</html>"""
        
        with open(html_file, 'w', encoding='utf-8') as f:
            f.write(html)
        
        print(f"✅ Exported HTML: {html_file}")
    
    @staticmethod
    def _make_serializable(obj):
        """Make object JSON serializable"""
        if isinstance(obj, dict):
            return {str(k): AnalysisTabs._make_serializable(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [AnalysisTabs._make_serializable(item) for item in obj]
        elif hasattr(obj, '__dict__'):
            return AnalysisTabs._make_serializable(obj.__dict__)
        elif isinstance(obj, (datetime,)):
            return obj.isoformat()
        else:
            return obj


class OverviewTab(QWidget):
    """Overview tab showing summary statistics"""
    
    def __init__(self):
        super().__init__()
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout(self)
        
        # Summary text
        self.summary_text = QTextEdit()
        self.summary_text.setReadOnly(True)
        self.summary_text.setFont(QFont("Consolas", 10))
        
        layout.addWidget(self.summary_text)
    
    def update(self, results):
        """Update with analysis results"""
        summary = f"""
{'='*80}
ADVANCED PCAP ANALYZER v3.0 - ANALYSIS REPORT
{'='*80}

📋 FILE INFORMATION
{'='*80}
File: {results.get('filename', 'Unknown')}
Total Packets: {results.get('total_packets', 0):,}

{'='*80}
📊 PROTOCOL OVERVIEW
{'='*80}"""
        
        if 'protocols' in results:
            for proto, count in results['protocols'].most_common():
                percent = (count / results['total_packets']) * 100
                bar = "█" * int(percent / 2)
                summary += f"\n{proto:8s}: {count:8,} ({percent:5.1f}%) {bar}"
        
        if 'timeline' in results:
            timeline = results['timeline']
            summary += f"\n\n⏰ TIMELINE"
            summary += f"\nStart: {timeline.get('start_time', 'Unknown')}"
            summary += f"\nEnd:   {timeline.get('end_time', 'Unknown')}"
            summary += f"\nDuration: {timeline.get('duration_seconds', 0):.2f} seconds"
            summary += f"\nRate: {timeline.get('packets_per_second', 0):.1f} packets/second"
        
        if 'dns_analysis' in results:
            dns = results['dns_analysis']
            summary += f"\n\n🔍 DNS SUMMARY"
            summary += f"\nTotal Queries: {dns.get('total_queries', 0):,}"
            summary += f"\nUnique Domains: {dns.get('unique_domains', 0):,}"
            
            if 'suspicious_queries' in dns:
                summary += f"\nSuspicious Queries: {len(dns['suspicious_queries'])}"
        
        summary += f"\n\n{'='*80}"
        summary += "\n⚠️  Analysis complete. Check other tabs for detailed information."
        
        self.summary_text.setText(summary)
    
    def clear(self):
        """Clear the tab content"""
        self.summary_text.clear()


class ProtocolsTab(QWidget):
    """Protocol analysis tab"""
    
    def __init__(self):
        super().__init__()
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout(self)
        
        # Split view
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left: Protocol table
        self.protocol_table = QTableWidget()
        self.protocol_table.setColumnCount(3)
        self.protocol_table.setHorizontalHeaderLabels(["Protocol", "Count", "Percentage"])
        self.protocol_table.horizontalHeader().setStretchLastSection(True)
        
        # Right: Port tables
        port_widget = QWidget()
        port_layout = QVBoxLayout(port_widget)
        
        self.tcp_table = QTableWidget()
        self.tcp_table.setColumnCount(2)
        self.tcp_table.setHorizontalHeaderLabels(["Port", "Count"])
        self.tcp_table.horizontalHeader().setStretchLastSection(True)
        
        self.udp_table = QTableWidget()
        self.udp_table.setColumnCount(2)
        self.udp_table.setHorizontalHeaderLabels(["Port", "Count"])
        self.udp_table.horizontalHeader().setStretchLastSection(True)
        
        port_layout.addWidget(QLabel("TCP Ports:"))
        port_layout.addWidget(self.tcp_table)
        port_layout.addWidget(QLabel("UDP Ports:"))
        port_layout.addWidget(self.udp_table)
        
        splitter.addWidget(self.protocol_table)
        splitter.addWidget(port_widget)
        splitter.setSizes([300, 700])
        
        layout.addWidget(splitter)
    
    def update(self, results):
        """Update protocol tables"""
        # Update protocol table
        protocols = results.get('protocols', {})
        total = results.get('total_packets', 1)
        
        self.protocol_table.setRowCount(len(protocols))
        for i, (proto, count) in enumerate(protocols.most_common()):
            percent = (count / total) * 100
            
            self.protocol_table.setItem(i, 0, QTableWidgetItem(proto))
            self.protocol_table.setItem(i, 1, QTableWidgetItem(f"{count:,}"))
            self.protocol_table.setItem(i, 2, QTableWidgetItem(f"{percent:.2f}%"))
        
        # Update TCP ports
        tcp_ports = results.get('ports', {}).get('tcp', {})
        self.tcp_table.setRowCount(len(tcp_ports))
        for i, (port, count) in enumerate(tcp_ports.most_common(20)):
            service = self._get_service_name(port)
            self.tcp_table.setItem(i, 0, QTableWidgetItem(f"{port} ({service})"))
            self.tcp_table.setItem(i, 1, QTableWidgetItem(f"{count:,}"))
        
        # Update UDP ports
        udp_ports = results.get('ports', {}).get('udp', {})
        self.udp_table.setRowCount(len(udp_ports))
        for i, (port, count) in enumerate(udp_ports.most_common(20)):
            service = self._get_service_name(port)
            self.udp_table.setItem(i, 0, QTableWidgetItem(f"{port} ({service})"))
            self.udp_table.setItem(i, 1, QTableWidgetItem(f"{count:,}"))
    
    @staticmethod
    def _get_service_name(port: int) -> str:
        services = {
            80: 'HTTP', 443: 'HTTPS', 53: 'DNS', 22: 'SSH', 25: 'SMTP',
            110: 'POP3', 143: 'IMAP', 3389: 'RDP', 445: 'SMB', 3306: 'MySQL'
        }
        return services.get(port, '')
    
    def clear(self):
        """Clear tables"""
        self.protocol_table.setRowCount(0)
        self.tcp_table.setRowCount(0)
        self.udp_table.setRowCount(0)


class IPAnalysisTab(QWidget):
    """IP analysis tab"""
    
    def __init__(self):
        super().__init__()
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout(self)
        
        # Split view
        splitter = QSplitter(Qt.Orientation.Vertical)
        
        # Top: Source IPs
        source_widget = QWidget()
        source_layout = QVBoxLayout(source_widget)
        source_layout.addWidget(QLabel("🔝 Top Source IP Addresses"))
        self.source_table = QTableWidget()
        self.source_table.setColumnCount(3)
        self.source_table.setHorizontalHeaderLabels(["IP Address", "Packet Count", "Percentage"])
        source_layout.addWidget(self.source_table)
        
        # Bottom: Destination IPs
        dest_widget = QWidget()
        dest_layout = QVBoxLayout(dest_widget)
        dest_layout.addWidget(QLabel("🎯 Top Destination IP Addresses"))
        self.dest_table = QTableWidget()
        self.dest_table.setColumnCount(3)
        self.dest_table.setHorizontalHeaderLabels(["IP Address", "Packet Count", "Percentage"])
        dest_layout.addWidget(self.dest_table)
        
        splitter.addWidget(source_widget)
        splitter.addWidget(dest_widget)
        splitter.setSizes([400, 400])
        
        layout.addWidget(splitter)
    
    def update(self, results):
        """Update IP tables"""
        total = results.get('total_packets', 1)
        
        # Update source IPs
        sources = results.get('ip_sources', {})
        self.source_table.setRowCount(len(sources))
        for i, (ip, count) in enumerate(sources.most_common(20)):
            percent = (count / total) * 100
            
            self.source_table.setItem(i, 0, QTableWidgetItem(ip))
            self.source_table.setItem(i, 1, QTableWidgetItem(f"{count:,}"))
            self.source_table.setItem(i, 2, QTableWidgetItem(f"{percent:.2f}%"))
        
        # Update destination IPs
        dests = results.get('ip_destinations', {})
        self.dest_table.setRowCount(len(dests))
        for i, (ip, count) in enumerate(dests.most_common(20)):
            percent = (count / total) * 100
            
            self.dest_table.setItem(i, 0, QTableWidgetItem(ip))
            self.dest_table.setItem(i, 1, QTableWidgetItem(f"{count:,}"))
            self.dest_table.setItem(i, 2, QTableWidgetItem(f"{percent:.2f}%"))
    
    def clear(self):
        """Clear tables"""
        self.source_table.setRowCount(0)
        self.dest_table.setRowCount(0)


class DNSAnalysisTab(QWidget):
    """DNS analysis tab"""
    
    def __init__(self):
        super().__init__()
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout(self)
        
        # Tab widget for DNS sections
        self.dns_tabs = QTabWidget()
        
        # Queries tab
        self.queries_tab = QWidget()
        queries_layout = QVBoxLayout(self.queries_tab)
        self.queries_table = QTableWidget()
        self.queries_table.setColumnCount(4)
        self.queries_table.setHorizontalHeaderLabels(["Domain", "Type", "Source IP", "Time"])
        queries_layout.addWidget(self.queries_table)
        
        # Statistics tab
        self.stats_tab = QWidget()
        stats_layout = QVBoxLayout(self.stats_tab)
        self.stats_text = QTextEdit()
        self.stats_text.setReadOnly(True)
        stats_layout.addWidget(self.stats_text)
        
        # Threats tab
        self.threats_tab = QWidget()
        threats_layout = QVBoxLayout(self.threats_tab)
        self.threats_table = QTableWidget()
        self.threats_table.setColumnCount(5)
        self.threats_table.setHorizontalHeaderLabels(["Domain", "Type", "Severity", "Reasons", "Entropy"])
        threats_layout.addWidget(self.threats_table)
        
        self.dns_tabs.addTab(self.queries_tab, "Queries")
        self.dns_tabs.addTab(self.stats_tab, "Statistics")
        self.dns_tabs.addTab(self.threats_tab, "Threats")
        
        layout.addWidget(self.dns_tabs)
    
    def update(self, dns_results):
        """Update DNS analysis"""
        if not dns_results:
            return
        
        # Update queries table
        queries = dns_results.get('queries', [])
        self.queries_table.setRowCount(min(len(queries), 100))
        for i, query in enumerate(queries[:100]):
            self.queries_table.setItem(i, 0, QTableWidgetItem(query.get('domain', '')))
            self.queries_table.setItem(i, 1, QTableWidgetItem(query.get('type', '')))
            self.queries_table.setItem(i, 2, QTableWidgetItem(query.get('src_ip', '')))
            self.queries_table.setItem(i, 3, QTableWidgetItem(str(query.get('timestamp', ''))))
        
        # Update statistics
        stats_text = f"""
DNS ANALYSIS STATISTICS
{'='*40}
Total Queries: {dns_results.get('total_queries', 0):,}
Total Responses: {dns_results.get('total_responses', 0):,}
Unique Domains: {dns_results.get('unique_domains', 0):,}

QUERY TYPES:
{'-'*30}"""
        
        for qtype, count in dns_results.get('query_types', {}).items():
            stats_text += f"\n{qtype}: {count:,}"
        
        stats_text += f"\n\nTOP DOMAINS:"
        for domain, count in dns_results.get('top_queried_domains', [])[:10]:
            stats_text += f"\n{domain[:50]:50s}: {count:,}"
        
        self.stats_text.setText(stats_text)
        
        # Update threats table
        threats = dns_results.get('suspicious_queries', [])
        self.threats_table.setRowCount(len(threats))
        for i, threat in enumerate(threats):
            reasons = ', '.join(threat.get('reasons', [])[:2])
            self.threats_table.setItem(i, 0, QTableWidgetItem(threat.get('domain', '')))
            self.threats_table.setItem(i, 1, QTableWidgetItem(threat.get('type', '')))
            self.threats_table.setItem(i, 2, QTableWidgetItem("SUSPICIOUS"))
            self.threats_table.setItem(i, 3, QTableWidgetItem(reasons))
            self.threats_table.setItem(i, 4, QTableWidgetItem(f"{threat.get('entropy', 0):.2f}"))
    
    def clear(self):
        """Clear DNS tables"""
        self.queries_table.setRowCount(0)
        self.stats_text.clear()
        self.threats_table.setRowCount(0)


class SecurityTab(QWidget):
    """Security findings tab"""
    
    def __init__(self):
        super().__init__()
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout(self)
        
        # Security summary
        self.summary_text = QTextEdit()
        self.summary_text.setReadOnly(True)
        self.summary_text.setFont(QFont("Consolas", 10))
        
        # Threats table
        self.threats_table = QTableWidget()
        self.threats_table.setColumnCount(4)
        self.threats_table.setHorizontalHeaderLabels(["Type", "Severity", "Description", "Count"])
        
        layout.addWidget(QLabel("🛡️ SECURITY FINDINGS"))
        layout.addWidget(self.summary_text, 1)
        layout.addWidget(QLabel("🔍 DETECTED THREATS"))
        layout.addWidget(self.threats_table, 2)
    
    def update(self, security_findings, dns_results):
        """Update security findings"""
        threats = []
        
        # Collect all threats
        if security_findings:
            for category, findings in security_findings.items():
                if findings:
                    threats.append({
                        'type': category.upper(),
                        'severity': 'HIGH' if category in ['syn_flood', 'port_scan'] else 'MEDIUM',
                        'description': category.replace('_', ' ').title(),
                        'count': len(findings)
                    })
        
        # Add DNS threats
        if dns_results:
            if dns_results.get('suspicious_queries'):
                threats.append({
                    'type': 'DNS',
                    'severity': 'MEDIUM',
                    'description': 'Suspicious DNS Queries',
                    'count': len(dns_results['suspicious_queries'])
                })
            
            if dns_results.get('dns_tunneling_suspects'):
                threats.append({
                    'type': 'DNS',
                    'severity': 'HIGH',
                    'description': 'DNS Tunneling Suspects',
                    'count': len(dns_results['dns_tunneling_suspects'])
                })
        
        # Update table
        self.threats_table.setRowCount(len(threats))
        for i, threat in enumerate(threats):
            self.threats_table.setItem(i, 0, QTableWidgetItem(threat['type']))
            self.threats_table.setItem(i, 1, QTableWidgetItem(threat['severity']))
            self.threats_table.setItem(i, 2, QTableWidgetItem(threat['description']))
            self.threats_table.setItem(i, 3, QTableWidgetItem(str(threat['count'])))
        
        # Update summary
        total_threats = sum(t['count'] for t in threats)
        severity_counts = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for t in threats:
            if t['severity'] in severity_counts:
                severity_counts[t['severity']] += t['count']
        
        summary = f"""
SECURITY ASSESSMENT
{'='*40}
Total Threats Detected: {total_threats}

Severity Breakdown:
{'-'*30}
🔴 HIGH: {severity_counts['HIGH']} threats
🟡 MEDIUM: {severity_counts['MEDIUM']} threats
🟢 LOW: {severity_counts['LOW']} threats

Threat Categories:
{'-'*30}"""
        
        for threat in threats:
            summary += f"\n{threat['type']}: {threat['count']} ({threat['severity']})"
        
        self.summary_text.setText(summary)
    
    def clear(self):
        """Clear security data"""
        self.summary_text.clear()
        self.threats_table.setRowCount(0)


class HTTPAnalysisTab(QWidget):
    """HTTP analysis tab"""
    
    def __init__(self):
        super().__init__()
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout(self)
        
        # HTTP requests table
        self.requests_table = QTableWidget()
        self.requests_table.setColumnCount(5)
        self.requests_table.setHorizontalHeaderLabels(["Source IP", "Method", "Host", "Path", "User Agent"])
        
        # Statistics
        self.stats_text = QTextEdit()
        self.stats_text.setReadOnly(True)
        self.stats_text.setMaximumHeight(150)
        
        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.addWidget(self.requests_table)
        splitter.addWidget(self.stats_text)
        splitter.setSizes([500, 200])
        
        layout.addWidget(splitter)
    
    def update(self, http_results):
        """Update HTTP analysis"""
        if not http_results:
            return
        
        from collections import Counter
        
        # Update requests table
        requests = http_results.get('requests', [])
        self.requests_table.setRowCount(min(len(requests), 100))
        for i, req in enumerate(requests[:100]):
            self.requests_table.setItem(i, 0, QTableWidgetItem(req.get('src_ip', '')))
            self.requests_table.setItem(i, 1, QTableWidgetItem(req.get('method', '')))
            self.requests_table.setItem(i, 2, QTableWidgetItem(req.get('host', '')))
            self.requests_table.setItem(i, 3, QTableWidgetItem(req.get('path', '')))
            self.requests_table.setItem(i, 4, QTableWidgetItem(req.get('user_agent', '')[:50]))
        
        # Update statistics
        stats_text = f"""
    HTTP TRAFFIC ANALYSIS
    {'='*40}
    Total Requests: {len(requests):,}

    Top Hosts:
    {'-'*30}"""
        
        # Handle both Counter and dict types
        hosts = http_results.get('hosts', {})
        if isinstance(hosts, Counter):
            top_hosts = hosts.most_common(5)
        elif isinstance(hosts, dict):
            top_hosts = sorted(hosts.items(), key=lambda x: x[1], reverse=True)[:5]
        else:
            top_hosts = []
        
        for host, count in top_hosts:
            stats_text += f"\n{host[:50]:50s}: {count:,}"
        
        stats_text += f"\n\nMethods Used:"
        
        methods = http_results.get('methods', {})
        if isinstance(methods, Counter):
            method_items = methods.most_common()
        elif isinstance(methods, dict):
            method_items = sorted(methods.items(), key=lambda x: x[1], reverse=True)
        else:
            method_items = []
        
        for method, count in method_items:
            stats_text += f"\n{method}: {count:,}"
        
        self.stats_text.setText(stats_text)
    
    def clear(self):
        """Clear HTTP data"""
        self.requests_table.setRowCount(0)
        self.stats_text.clear()