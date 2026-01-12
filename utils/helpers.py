import os
import re
import json
import math
import ipaddress
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
import socket


def validate_ip_address(ip: str) -> bool:
    """Validate IP address format"""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def is_private_ip(ip: str) -> bool:
    """Check if IP is in private range"""
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except ValueError:
        return False


def calculate_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string"""
    if not data:
        return 0.0
    
    entropy = 0.0
    for char in set(data):
        freq = data.count(char) / len(data)
        entropy -= freq * math.log2(freq)
    
    return entropy


def format_bytes(size: int) -> str:
    """Format bytes to human readable string"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024.0:
            return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{size:.2f} PB"


def format_duration(seconds: float) -> str:
    """Format duration to human readable string"""
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.1f}m"
    elif seconds < 86400:
        hours = seconds / 3600
        return f"{hours:.1f}h"
    else:
        days = seconds / 86400
        return f"{days:.1f}d"


def get_service_name(port: int, protocol: str = 'tcp') -> str:
    """Get service name for port number"""
    services = {
        (20, 'tcp'): 'FTP-Data',
        (21, 'tcp'): 'FTP',
        (22, 'tcp'): 'SSH',
        (23, 'tcp'): 'Telnet',
        (25, 'tcp'): 'SMTP',
        (53, 'tcp'): 'DNS',
        (53, 'udp'): 'DNS',
        (67, 'udp'): 'DHCP',
        (68, 'udp'): 'DHCP',
        (80, 'tcp'): 'HTTP',
        (110, 'tcp'): 'POP3',
        (123, 'udp'): 'NTP',
        (143, 'tcp'): 'IMAP',
        (443, 'tcp'): 'HTTPS',
        (445, 'tcp'): 'SMB',
        (993, 'tcp'): 'IMAPS',
        (995, 'tcp'): 'POP3S',
        (1433, 'tcp'): 'MSSQL',
        (1521, 'tcp'): 'Oracle',
        (3306, 'tcp'): 'MySQL',
        (3389, 'tcp'): 'RDP',
        (5432, 'tcp'): 'PostgreSQL',
        (5900, 'tcp'): 'VNC',
        (6379, 'tcp'): 'Redis',
        (8080, 'tcp'): 'HTTP-Alt',
        (8443, 'tcp'): 'HTTPS-Alt',
        (27017, 'tcp'): 'MongoDB',
    }
    
    return services.get((port, protocol.lower()), 'Unknown')


def extract_domain_from_url(url: str) -> str:
    """Extract domain from URL"""
    try:
        # Remove protocol
        if '://' in url:
            url = url.split('://', 1)[1]
        
        # Remove path and query
        url = url.split('/', 1)[0]
        
        # Remove port
        url = url.split(':', 1)[0]
        
        return url
    except Exception:
        return url


def detect_encoding(data: bytes) -> str:
    """Detect encoding of bytes data"""
    try:
        # Try UTF-8
        data.decode('utf-8')
        return 'utf-8'
    except UnicodeDecodeError:
        try:
            # Try Latin-1
            data.decode('latin-1')
            return 'latin-1'
        except UnicodeDecodeError:
            return 'unknown'


def sanitize_filename(filename: str) -> str:
    """Sanitize filename for safe saving"""
    # Remove invalid characters
    invalid_chars = '<>:"/\\|?*'
    for char in invalid_chars:
        filename = filename.replace(char, '_')
    
    # Remove leading/trailing spaces and dots
    filename = filename.strip(' .')
    
    # Limit length
    if len(filename) > 255:
        name, ext = os.path.splitext(filename)
        filename = name[:250 - len(ext)] + ext
    
    return filename


def parse_timestamp(timestamp: float) -> Dict[str, Any]:
    """Parse timestamp to datetime components"""
    dt = datetime.fromtimestamp(timestamp)
    return {
        'datetime': dt,
        'date': dt.date(),
        'time': dt.time(),
        'year': dt.year,
        'month': dt.month,
        'day': dt.day,
        'hour': dt.hour,
        'minute': dt.minute,
        'second': dt.second,
        'weekday': dt.strftime('%A'),
        'iso': dt.isoformat(),
        'human': dt.strftime('%Y-%m-%d %H:%M:%S')
    }


def group_by_interval(timestamps: List[float], interval_seconds: int = 60) -> Dict[int, int]:
    """Group timestamps by time intervals"""
    if not timestamps:
        return {}
    
    min_time = min(timestamps)
    groups = {}
    
    for ts in timestamps:
        bucket = int((ts - min_time) // interval_seconds)
        groups[bucket] = groups.get(bucket, 0) + 1
    
    return groups


def calculate_statistics(data: List[float]) -> Dict[str, float]:
    """Calculate basic statistics for a list of numbers"""
    if not data:
        return {}
    
    n = len(data)
    mean = sum(data) / n
    variance = sum((x - mean) ** 2 for x in data) / n
    std_dev = math.sqrt(variance)
    
    sorted_data = sorted(data)
    median = sorted_data[n // 2] if n % 2 == 1 else (sorted_data[n // 2 - 1] + sorted_data[n // 2]) / 2
    
    return {
        'count': n,
        'min': min(data),
        'max': max(data),
        'mean': mean,
        'median': median,
        'std_dev': std_dev,
        'variance': variance,
        'sum': sum(data)
    }


def extract_email_addresses(text: str) -> List[str]:
    """Extract email addresses from text"""
    email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    return re.findall(email_pattern, text)


def extract_urls(text: str) -> List[str]:
    """Extract URLs from text"""
    url_pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+(?:[/?#][-\w\.~!$&\'()*+,;=:@%#?&//=]*)?'
    return re.findall(url_pattern, text)


def extract_ip_addresses(text: str) -> List[str]:
    """Extract IP addresses from text"""
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    ips = re.findall(ip_pattern, text)
    return [ip for ip in ips if validate_ip_address(ip)]


def safe_json_dump(data: Any, filename: str, indent: int = 2) -> bool:
    """Safely dump data to JSON file"""
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(make_serializable(data), f, indent=indent, default=str)
        return True
    except Exception as e:
        print(f"Error saving JSON: {e}")
        return False


def make_serializable(obj):
    """Convert object to JSON serializable format"""
    if isinstance(obj, (str, int, float, bool, type(None))):
        return obj
    elif isinstance(obj, dict):
        return {str(k): make_serializable(v) for k, v in obj.items()}
    elif isinstance(obj, (list, tuple, set)):
        return [make_serializable(item) for item in obj]
    elif hasattr(obj, '__dict__'):
        return make_serializable(obj.__dict__)
    elif hasattr(obj, 'isoformat'):  # datetime
        return obj.isoformat()
    else:
        try:
            return str(obj)
        except:
            return None


def format_threat_level(score: float) -> Tuple[str, str]:
    """Format threat level based on score (0-1)"""
    if score >= 0.8:
        return "CRITICAL", "#e74c3c"
    elif score >= 0.6:
        return "HIGH", "#e67e22"
    elif score >= 0.4:
        return "MEDIUM", "#f39c12"
    elif score >= 0.2:
        return "LOW", "#f1c40f"
    else:
        return "INFO", "#3498db"


def get_file_info(filename: str) -> Dict[str, Any]:
    """Get information about a file"""
    try:
        stat = os.stat(filename)
        return {
            'size': stat.st_size,
            'created': datetime.fromtimestamp(stat.st_ctime),
            'modified': datetime.fromtimestamp(stat.st_mtime),
            'accessed': datetime.fromtimestamp(stat.st_atime),
            'size_human': format_bytes(stat.st_size)
        }
    except Exception as e:
        return {'error': str(e)}