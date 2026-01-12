import yaml
import os
from typing import Dict, Any

class Config:
    """Configuration manager for PCAP Analyzer"""
    
    DEFAULT_CONFIG = {
        'analysis': {
            'quick_mode': False,
            'enable_dns_analysis': True,
            'enable_security_scan': True,
            'enable_http_analysis': True,
            'max_packets_display': 100,
            'geolocation_enabled': True
        },
        'security': {
            'port_scan_threshold': 50,
            'syn_flood_threshold': 1000,
            'dns_entropy_threshold': 4.5,
            'beacon_variance_threshold': 0.1,
            'suspicious_ports': [4444, 31337, 1337, 9999]
        },
        'gui': {
            'theme': 'dark',
            'font_size': 10,
            'auto_export': False,
            'show_progress_bar': True
        }
    }
    
    def __init__(self, config_file: str = 'config.yaml'):
        self.config_file = config_file
        self.config = self.load_config()
    
    def load_config(self) -> Dict[str, Any]:
        """Load configuration from file or create default"""
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    return yaml.safe_load(f) or self.DEFAULT_CONFIG
            except Exception:
                return self.DEFAULT_CONFIG
        else:
            self.save_config(self.DEFAULT_CONFIG)
            return self.DEFAULT_CONFIG
    
    def save_config(self, config: Dict[str, Any] = None):
        """Save configuration to file"""
        if config is None:
            config = self.config
        
        try:
            with open(self.config_file, 'w') as f:
                yaml.dump(config, f, default_flow_style=False)
        except Exception:
            pass
    
    def get(self, key: str, default=None):
        """Get configuration value"""
        keys = key.split('.')
        value = self.config
        
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        
        return value
    
    def set(self, key: str, value: Any):
        """Set configuration value"""
        keys = key.split('.')
        config = self.config
        
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
        
        config[keys[-1]] = value
        self.save_config()