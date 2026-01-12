# Enhanced Advanced PCAP File Analyzer v3.0

A comprehensive network packet capture analysis tool featuring both GUI and CLI interfaces with advanced security detection, DNS analysis, visualization, and professional reporting capabilities.

## 🌟 Key Features

### 🖥️ Dual Interface Design
- **Modern GUI**: Built with PyQt6 featuring dark theme, real-time progress tracking, and interactive analysis tabs
- **Powerful CLI**: Full-featured command-line interface for automation and scripting
- **Seamless Switching**: Use the interface that fits your workflow

### 🔍 Core Analysis Capabilities
- **Protocol Distribution**: Comprehensive TCP, UDP, ICMP, ARP, DNS statistics with visual breakdowns
- **IP Intelligence**: Top source/destination IPs with geolocation, ISP, and ASN information
- **Port Analysis**: Active TCP/UDP ports with automatic service identification
- **Conversation Tracking**: Bidirectional communication pattern analysis
- **Timeline Analysis**: Traffic burst detection and timing pattern identification
- **Packet Statistics**: Size distribution, data volume, and throughput analysis

### 🌐 Advanced DNS Analysis
- **TLD Analysis**: Top-level domain distribution with suspicious TLD flagging
- **DNS Tunneling Detection**: Multi-factor analysis including:
  - Shannon entropy calculations for domain randomness
  - Query pattern analysis (volume, length, frequency)
  - TXT record monitoring for data exfiltration
  - Regular interval beaconing detection
- **Fast-Flux Detection**: Multiple IP resolution patterns with TTL analysis
- **DGA Detection**: Domain Generation Algorithm pattern recognition
- **Suspicious Query Detection**: 
  - Unusually long domain names (>50 characters)
  - High entropy domains (>4.5 Shannon entropy)
  - Hex-like and Base64 patterns
  - Consonant cluster analysis
- **Query Type Distribution**: A, AAAA, TXT, CNAME, MX, PTR, SRV records
- **Response Code Analysis**: NOERROR, NXDOMAIN, SERVFAIL, REFUSED tracking

### 🛡️ Security Threat Detection
- **Network Reconnaissance**: Port scanning detection (>50 unique targets)
- **DoS Attacks**: SYN flood and ICMP flood detection
- **DNS Security Threats**: 
  - Tunneling attempts with configurable sensitivity
  - Fast-flux botnet infrastructure
  - Domain generation algorithms
- **C2 Communications**: Statistical beaconing detection with coefficient of variation analysis
- **Web Application Attacks**: SQL injection, XSS, directory traversal, command injection patterns
- **Data Exfiltration**: Large outbound packet detection to external IPs
- **ARP Spoofing**: MAC/IP address conflict detection
- **Credential Exposure**: Plaintext password, API key, and token detection
- **Malicious Ports**: Known malware-associated port usage (4444, 31337, 1337, etc.)

### 📊 Reporting & Export
- **Interactive GUI Tabs**: 
  - Overview with key metrics
  - Protocol distribution
  - IP analysis with geolocation
  - DNS deep-dive
  - Security findings
  - HTTP traffic analysis
- **Console Reports**: Color-coded terminal output with emoji indicators
- **JSON Export**: Complete machine-readable analysis data
- **CSV Export**: Multiple CSV files for different data categories:
  - IP statistics with enrichment data
  - Protocol distribution
  - Port usage
  - Security findings
  - DNS analysis
  - HTTP traffic
- **HTML Reports**: Professional web-based reports with:
  - Interactive visualizations (matplotlib charts)
  - Security threat summary
  - Detailed findings tables
  - Base64-embedded charts (no external dependencies)
- **Visual Plots**: Automatic chart generation for protocol, IP, port, and DNS data

## 📋 Requirements

### System Requirements
- **Python**: 3.6 or higher
- **Operating System**: Windows, macOS, Linux
- **Memory**: Minimum 2GB RAM (4GB+ recommended for large captures)
- **Disk Space**: ~100MB for installation + space for exports

### Required Dependencies
```bash
pip install scapy requests
```

### GUI Dependencies
```bash
# For GUI mode
pip install PyQt6 pyqtgraph

# Note: GUI mode will automatically fall back to CLI if PyQt6 is not installed
```

### Recommended Dependencies
```bash
# For enhanced DNS analysis and visualizations
pip install matplotlib tldextract

# For advanced IP geolocation (optional)
pip install ipwhois

# Install all dependencies at once
pip install scapy requests PyQt6 pyqtgraph matplotlib tldextract ipwhois

# Or use requirements.txt
pip install -r requirements.txt
```

## 🚀 Installation

### Quick Install
```bash
# Clone or download the repository
git clone https://github.com/yourusername/pcap-analyzer.git
cd pcap-analyzer

# Install dependencies
pip install -r requirements.txt

# Run the analyzer
python main.py
```

### Manual Installation
```bash
# Core dependencies (required)
pip install scapy>=2.4.5 requests>=2.25.0

# GUI dependencies
pip install PyQt6>=6.0.0 pyqtgraph>=0.12.0

# Analysis enhancements
pip install matplotlib>=3.3.0 tldextract>=3.1.0

# Optional IP enrichment
pip install ipwhois>=1.2.0
```

## 💻 Usage

### GUI Mode (Default)
```bash
# Launch GUI (default behavior)
python main.py

# The GUI provides:
# - File browser for PCAP selection
# - Real-time analysis progress
# - Interactive result tabs
# - One-click export to multiple formats
# - Configurable analysis options
```

### CLI Mode

#### Basic Analysis
```bash
# Analyze a PCAP file
python main.py capture.pcap

# Verbose output with progress
python main.py capture.pcap -v

# Quick mode for large files (basic stats only)
python main.py large_capture.pcap --quick
```

#### Security Analysis
```bash
# Comprehensive security scan
python main.py capture.pcap --security-scan

# Security scan with verbose output
python main.py capture.pcap -v --security-scan

# Security-focused quick analysis
python main.py suspicious.pcap --quick --security-scan
```

#### Export Options
```bash
# Export to JSON
python main.py capture.pcap --export json

# Export to CSV (multiple files)
python main.py capture.pcap --export csv

# Generate HTML report with charts
python main.py capture.pcap --export html

# Export all formats
python main.py capture.pcap --export all

# Export with security findings
python main.py capture.pcap --export all --security-scan
```

#### Visualization
```bash
# Generate matplotlib plots
python main.py capture.pcap --generate-plots

# Complete analysis with all visualizations
python main.py capture.pcap --export all --generate-plots

# Security analysis with visual reports
python main.py capture.pcap --security-scan --export html --generate-plots
```

#### Combined Analysis
```bash
# Full comprehensive analysis
python main.py capture.pcap --export all --security-scan --generate-plots -v

# Memory-efficient large file analysis
python main.py huge.pcap --quick --export json -v

# Focused DNS security audit
python main.py dns_traffic.pcap --security-scan --export html
```

## 📁 Output Files

The analyzer generates organized output in the `exports/` directory:

### JSON Export
- `capture_analysis.json` - Complete analysis data including:
  - All packet statistics
  - Security findings
  - DNS analysis results
  - HTTP traffic data
  - Enriched IP information

### CSV Exports
- `capture_ip_stats.csv` - IP addresses with packet counts, geolocation, ISP, ASN
- `capture_protocols.csv` - Protocol distribution with percentages
- `capture_ports.csv` - TCP/UDP ports with service names
- `capture_security.csv` - Security findings by category
- `capture_dns.csv` - DNS queries, responses, and threats
- `capture_http.csv` - HTTP requests with suspicious activity flags

### HTML Report
- `capture_report.html` - Professional report featuring:
  - Executive summary with key metrics
  - Interactive protocol distribution pie chart
  - Top IPs bar chart
  - TCP/UDP port analysis charts
  - DNS TLD distribution
  - Security threat assessment
  - HTTP traffic analysis
  - Embedded base64 charts (no external files needed)

### Visualization
- `capture_plots.png` - Comprehensive 4-panel visualization:
  - Protocol distribution pie chart
  - Top 10 source IPs
  - Top 10 TCP ports
  - DNS TLD distribution

## 🎯 Use Cases

### 🔍 Incident Response
```bash
# Comprehensive incident analysis
python main.py incident_traffic.pcap --security-scan --export all -v

# Detects: Port scans, DoS attacks, data exfiltration, C2 communications
```

### 🔧 Network Troubleshooting
```bash
# Analyze connectivity issues
python main.py network_issue.pcap --generate-plots --export json

# Review: Protocol distribution, conversation patterns, error responses
```

### 📈 Performance Analysis
```bash
# Quick performance metrics
python main.py performance_capture.pcap --quick --generate-plots

# Analyze: Packet rates, size distribution, bandwidth usage
```

### 🕵️‍♂️ Security Monitoring
```bash
# Continuous security monitoring
python main.py daily_traffic.pcap --security-scan --export html

# Monitor: Attack patterns, suspicious domains, unauthorized access
```

### 🦠 Malware Analysis
```bash
# Deep malware traffic investigation
python main.py malware.pcap --security-scan --export html --generate-plots

# Identify: C2 beacons, DNS tunneling, fast-flux networks, DGA domains
```

### 🔒 DNS Security Audit
```bash
# Specialized DNS security analysis
python main.py dns_traffic.pcap -v --security-scan

# Examine: Query patterns, tunneling attempts, suspicious TLDs, fast-flux
```

### 📊 Forensic Investigation
```bash
# Complete forensic capture analysis
python main.py evidence.pcap --export all --security-scan --generate-plots -v

# Document: All traffic, security events, visual timeline, detailed reports
```

## 🔧 Configuration

### GUI Configuration
The GUI provides checkboxes for analysis options:
- **TCP Analysis**: Enable/disable TCP traffic analysis
- **UDP Analysis**: Enable/disable UDP traffic analysis
- **DNS Deep Analysis**: Advanced DNS threat detection
- **HTTP Analysis**: Web traffic and attack pattern detection
- **Security Scan**: Comprehensive security threat detection
- **Quick Mode**: Faster analysis with basic statistics

### CLI Arguments Reference
```
usage: main.py [-h] [-v] [--export {json,csv,html,all}] [--security-scan]
               [--generate-plots] [--quick]
               [pcap_file]

positional arguments:
  pcap_file             Path to PCAP file (omit for GUI mode)

optional arguments:
  -h, --help            Show help message
  -v, --verbose         Enable verbose output with progress
  --export {json,csv,html,all}
                        Export results to format(s)
  --security-scan       Enable comprehensive security detection
  --generate-plots      Generate matplotlib visualizations
  --quick               Quick mode for large files
```

### Configuration File
Create `config.yaml` to customize analysis behavior:
```yaml
analysis:
  quick_mode: false
  enable_dns_analysis: true
  enable_security_scan: true
  enable_http_analysis: true
  max_packets_display: 100
  geolocation_enabled: true

security:
  port_scan_threshold: 50
  syn_flood_threshold: 1000
  dns_entropy_threshold: 4.5
  beacon_variance_threshold: 0.1
  suspicious_ports: [4444, 31337, 1337, 9999]

gui:
  theme: 'dark'
  font_size: 10
  auto_export: false
  show_progress_bar: true
```

## 🔐 Security Detection Details

### DNS Tunneling Detection Algorithm
1. **Entropy Analysis**: Calculate Shannon entropy for each domain
   - Threshold: >4.5 indicates high randomness
2. **Query Pattern Analysis**: 
   - Volume: >100 queries to same base domain
   - Length: Average >40 characters
   - Frequency: Regular intervals with low variance
3. **TXT Record Monitoring**: High ratio of TXT queries (>30%)
4. **Scoring System**: Multi-factor threat score (0-10)
   - Score ≥6: HIGH severity
   - Score 4-5: MEDIUM severity

### Beacon Detection Algorithm
1. **Connection Tracking**: Monitor timestamp intervals for each IP pair/port combination
2. **Statistical Analysis**:
   - Calculate mean interval between connections
   - Compute coefficient of variation (CV = σ/μ)
3. **Threshold Detection**:
   - CV <0.1: Regular beaconing detected
   - CV <0.05 + interval <60s: HIGH severity C2

### Fast-Flux Detection
1. **Resolution Tracking**: Monitor unique IPs per domain
2. **Criteria**:
   - ≥10 unique IPs: Suspicious
   - ≥50 unique IPs: HIGH severity
   - Low TTL values (<300s): Additional indicator

### DGA Detection Features
- High entropy domain names (>4.5)
- Long numeric sequences (≥8 digits)
- Unusual consonant clusters (≥5 consecutive)
- Hex-like patterns (20+ hex characters)
- Base64-like patterns (30+ characters)
- Low query frequency (single queries)

## 📊 Analysis Metrics

### Protocol Statistics
- Packet counts and percentages for TCP, UDP, ICMP, ARP, DNS
- TCP flag distribution (SYN, ACK, FIN, RST, PSH, URG)
- Service identification for 30+ common ports
- Protocol-specific deep inspection

### DNS Metrics (Enhanced)
- Query type distribution (A, AAAA, TXT, CNAME, MX, PTR, SRV, SOA)
- Response codes (NOERROR, NXDOMAIN, SERVFAIL, REFUSED, NOTIMP)
- TLD distribution with suspicious TLD flagging
- Query length statistics (min, max, mean, median, std dev)
- Domain-to-IP resolution mapping
- IP-to-domain reverse mapping
- Entropy calculations for all queries
- Temporal query patterns

### IP Analysis
- Top source and destination IPs
- Geolocation (country, city)
- ISP and organization information
- ASN (Autonomous System Number)
- Private vs. public IP classification
- Conversation frequency analysis
- Data volume per IP

### Traffic Patterns
- Capture start/end timestamps
- Duration and packet rates
- Traffic burst detection
- Packet size distribution
- Data volume calculations (MB/GB)
- Time-bucketed packet counts

### Security Scoring
- Threat severity levels (HIGH, MEDIUM, LOW, INFO)
- Category-based threat counts
- Confidence scores for detections
- False positive indicators

## ⚡ Performance Optimization

### Memory Management
- Stream-based packet processing
- Configurable sample limits for large captures
- Quick mode for basic statistics without deep inspection

### API Rate Limiting
- IP geolocation limited to top 15 IPs
- 2-second timeout per lookup
- Graceful fallback for failed lookups

### Processing Speed
- **Small files** (<100MB): Full analysis ~5-30 seconds
- **Medium files** (100MB-1GB): Full analysis ~30-300 seconds
- **Large files** (>1GB): Quick mode recommended ~60-600 seconds
- **GUI progress**: Real-time updates every 1000 packets

### File Size Recommendations
| File Size | Mode | Expected Time | Recommended Options |
|-----------|------|---------------|---------------------|
| <100 MB | Full | 5-30s | All features enabled |
| 100MB-500MB | Full | 30-120s | All features enabled |
| 500MB-1GB | Full/Quick | 2-5min | Consider quick mode |
| 1GB-5GB | Quick | 5-20min | Quick mode recommended |
| >5GB | Quick | 20-60min | Quick mode, limit exports |

## 🐛 Troubleshooting

### Common Issues

#### "Module not found" errors
```bash
# Fix missing Scapy
pip install scapy

# Fix missing PyQt6 (for GUI)
pip install PyQt6

# Fix missing matplotlib (for plots)
pip install matplotlib

# Install all dependencies
pip install -r requirements.txt
```

#### Memory errors with large files
```bash
# Use quick mode
python main.py huge_capture.pcap --quick

# Limit analysis scope
python main.py huge_capture.pcap --quick --export json
```

#### Slow geolocation lookups
```bash
# Disable geolocation in config.yaml
geolocation_enabled: false

# Or use quick mode
python main.py capture.pcap --quick
```

#### GUI won't start
```bash
# Check PyQt6 installation
pip install PyQt6 pyqtgraph

# Use CLI mode instead
python main.py capture.pcap
```

#### No visualizations generated
```bash
# Install matplotlib
pip install matplotlib

# Verify with
python -c "import matplotlib; print('OK')"
```

### Permission Issues
```bash
# Linux/Mac: Scapy may require root for live capture
sudo pip install scapy

# For file analysis, root is NOT required
python main.py capture.pcap  # No sudo needed
```

### File Format Issues
```bash
# Supported formats
✓ .pcap (standard)
✓ .pcapng (next generation)
✓ .cap (Wireshark)

# Not supported
✗ .txt (requires conversion)
✗ .log (requires conversion)

# Convert using tshark or Wireshark
tshark -r input.pcapng -w output.pcap
```

## 🏗️ Architecture

### Core Components
- `core/analyzer.py`: Main analysis engine with PCAPAnalyzer class
- `core/dns_analyzer.py`: Advanced DNS analysis (AdvancedDNSAnalyzer)
- `core/security_detector.py`: Security threat detection (SecurityDetector)
- `core/beacon_detector.py`: C2 beaconing detection (BeaconDetector)
- `core/exporter.py`: Multi-format report generation (ReportExporter)

### GUI Components
- `gui/main_window.py`: Main application window (MainWindow)
- `gui/analysis_tabs.py`: Result display tabs (AnalysisTabs, OverviewTab, etc.)
- `gui/widgets.py`: Custom widgets (tables, trees, progress bars)

### Utilities
- `utils/config.py`: Configuration management
- `utils/logger.py`: Logging system
- `utils/helpers.py`: Helper functions

### Entry Point
- `main.py`: Application entry point with CLI/GUI routing

## 🤝 Contributing

Contributions are welcome! Areas for enhancement:
- Additional protocol analyzers (SMTP, FTP, etc.)
- Machine learning-based anomaly detection
- Real-time live capture analysis
- Additional export formats (PDF, Excel)
- Cloud integration for large-scale analysis
- Custom detection rule engine

## 📄 License

This tool is provided for educational and security research purposes. Users are responsible for complying with all applicable laws and regulations regarding network traffic analysis.

**Important**: Always obtain proper authorization before analyzing network traffic. Unauthorized interception of network communications may be illegal in your jurisdiction.

## 🔗 Additional Resources

- **Wireshark**: For live capture and conversion
- **tcpdump**: Command-line packet capture
- **Scapy Documentation**: https://scapy.readthedocs.io/
- **PyQt6 Documentation**: https://www.riverbankcomputing.com/static/Docs/PyQt6/

## 📞 Support

For issues, questions, or feature requests:
1. Check the troubleshooting section above
2. Review the documentation
3. Submit an issue on GitHub with:
   - Python version (`python --version`)
   - OS and version
   - Complete error message
   - Steps to reproduce

---

**Version**: 3.0  
**Architecture**: Dual GUI/CLI Interface  
**Key Features**: Advanced DNS Analysis, Security Detection, Professional Reporting  
**License**: Educational/Research Use  

**⚠️ Note**: This tool analyzes existing packet captures. It does not perform live capture or man-in-the-middle attacks. Always use responsibly and with proper authorization.