```markdown
# Enhanced Advanced PCAP File Analyzer

A comprehensive network packet capture analysis tool with advanced security detection, visualization, and reporting capabilities.

## Features

### 🔍 Core Analysis
- **Protocol Distribution**: TCP, UDP, ICMP, ARP, DNS statistics
- **IP Analysis**: Top source/destination IPs with geolocation
- **Port Analysis**: Most active TCP/UDP ports with service identification
- **Conversation Tracking**: Bidirectional communication patterns
- **Timeline Analysis**: Traffic bursts and timing patterns
- **Packet Size Statistics**: Size distribution and data volume analysis

### 🛡️ Security Detection
- **Port Scanning**: Detection of reconnaissance activities
- **SYN Floods**: Denial-of-service attack detection
- **DNS Tunneling**: Suspicious large DNS packets
- **Unusual Ports**: Malware-associated port usage
- **Data Exfiltration**: Large outbound transfers
- **ARP Spoofing**: MAC/IP address conflicts
- **HTTP Attack Patterns**: XSS, SQL injection, directory traversal
- **Credential Exposure**: Plaintext passwords and API keys

### 📊 Reporting & Export
- **Console Reports**: Color-coded terminal output
- **JSON Export**: Machine-readable analysis data
- **CSV Export**: IP statistics for spreadsheets
- **HTML Reports**: Professional web-based reports
- **Visualizations**: Charts and graphs (requires matplotlib)

## Installation

### Prerequisites
- Python 3.6+
- pip package manager

### Required Dependencies
```bash
pip install scapy requests
```

### Optional Dependencies
```bash
# For visualizations
pip install matplotlib numpy

# For IP geolocation
pip install ipwhois

# Install all dependencies
pip install scapy requests matplotlib numpy ipwhois
```

## Usage

### Basic Analysis
```bash
python pcap_analyzer.py capture.pcap
```

### Security-Focused Analysis
```bash
# Comprehensive security scan
python pcap_analyzer.py capture.pcap --security-scan

# Security scan with verbose output
python pcap_analyzer.py capture.pcap -v --security-scan
```

### Export Options
```bash
# Export to JSON format
python pcap_analyzer.py capture.pcap --export json

# Export to CSV format
python pcap_analyzer.py capture.pcap --export csv

# Generate HTML report
python pcap_analyzer.py capture.pcap --export html

# Export all formats
python pcap_analyzer.py capture.pcap --export all
```

### Visualization
```bash
# Generate visual plots and charts
python pcap_analyzer.py capture.pcap --generate-plots

# Complete analysis with visuals
python pcap_analyzer.py capture.pcap --export all --generate-plots
```

### Performance Options
```bash
# Quick mode for large files (basic stats only)
python pcap_analyzer.py large_capture.pcap --quick

# Verbose output with progress indicators
python pcap_analyzer.py capture.pcap -v
```

### Complete Analysis
```bash
# Full comprehensive analysis with all features
python pcap_analyzer.py capture.pcap --export all --security-scan --generate-plots -v
```

## Output Files

The analyzer generates the following output files:

- `capture_analysis.json` - Complete analysis data in JSON format
- `capture_ip_stats.csv` - IP statistics in CSV format
- `capture_report.html` - Professional HTML report
- `capture_plots.png` - Visualization charts (with `--generate-plots`)

## Use Cases

### 🎯 Incident Response
```bash
python pcap_analyzer.py incident_traffic.pcap --security-scan --export all -v
```

### 🔧 Network Troubleshooting
```bash
python pcap_analyzer.py network_issue.pcap --generate-plots --export json
```

### 📈 Performance Analysis
```bash
python pcap_analyzer.py performance_capture.pcap --quick --generate-plots
```

### 🕵️‍♂️ Security Monitoring
```bash
python pcap_analyzer.py suspicious_traffic.pcap --security-scan --export html
```

## Security Detection Capabilities

### Network Attacks
- **Port Scanning**: >50 unique destination ports from single source
- **SYN Flood**: >1000 SYN packets from single source
- **ICMP Flood**: >500 ICMP packets from single source
- **DNS Tunneling**: DNS packets >512 bytes
- **Data Exfiltration**: Large packets (>1400 bytes) to external IPs

### Application Layer Threats
- **HTTP Attacks**: XSS, SQL injection, command injection patterns
- **Credential Exposure**: Plaintext passwords, API keys, tokens
- **Suspicious Ports**: Known malware ports (4444, 31337, 1337, etc.)

### Layer 2 Security
- **ARP Spoofing**: Multiple IPs for one MAC or multiple MACs for one IP

## Analysis Metrics

### Protocol Statistics
- Packet counts and percentages for all major protocols
- TCP flag distribution analysis
- Service identification for common ports

### IP Analysis
- Top talkers (source and destination)
- Geolocation data for external IPs
- ISP and organization information
- Conversation frequency analysis

### Traffic Patterns
- Capture duration and packet rates
- Traffic bursts and anomalies
- Packet size distribution
- Data volume calculations

## Performance Notes

- **Quick Mode**: Skips deep packet inspection for faster analysis of large files
- **Memory Efficient**: Processes packets in streams to handle large captures
- **API Rate Limiting**: Limits external IP lookups to avoid service abuse
- **Progress Indicators**: Verbose mode shows processing status for large files

## Troubleshooting

### Common Issues
```bash
# File not found
python pcap_analyzer.py nonexistent.pcap

# Memory issues with large files
python pcap_analyzer.py huge_capture.pcap --quick

# Missing dependencies
pip install scapy  # Fix missing scapy error

# Visualization errors
pip install matplotlib numpy  # Install plotting dependencies
```

### File Size Recommendations
- **Small files** (<100MB): Use all features
- **Medium files** (100MB-1GB): Consider quick mode for faster results
- **Large files** (>1GB): Use quick mode and limit exports

## License

This tool is provided for educational and security research purposes. Users are responsible for complying with all applicable laws and regulations.

## Contributing

Feel free to submit issues and enhancement requests to improve the analyzer's capabilities.

---

**Note**: Always ensure you have proper authorization before analyzing network traffic captures.
```