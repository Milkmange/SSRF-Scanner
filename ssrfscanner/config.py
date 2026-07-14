"""Runtime configuration and progress tracking."""

import logging
from pathlib import Path
from typing import Any, Dict

import yaml


class Config:
    def __init__(self):
        self.scanner = {
            'concurrency': 200,  # Increased for better throughput
            'timeout': 15,  # Increased for reliability
            'retry_count': 2,
            'debug': False,
            'verify_ssl': False,
            'follow_redirects': True,
            'max_redirects': 3,
            'output_dir': "output",
            'user_agent': "SSRF-Scanner/1.0",
            'max_pool_size': 200,  # Reduced connection pool
            'capture_cookies': True,
            'proxy': None,  # Proxy URL
            'proxy_auth': None  # Proxy authentication
        }
        self.rate_limiting = {
            'requests_per_second': 100,  # Increased default rate
            'burst_size': 200,
            'min_rate': 10,
            'max_rate': 1000
        }
        self.output = {
            'format': 'json',  # json, csv, html, txt, all
            'verbose': False
        }

    def get(self, key, default=None):
        return self.scanner.get(key, default)



class ConfigManager:
    def __init__(self, config_file: str = 'config.yaml'):
        self.config_file = Path(config_file)
        self.config = self._load_default_config()
        if self.config_file.exists():
            self.load_config()

    def _load_default_config(self) -> Dict[str, Any]:
        """Load default configuration"""
        return {
            'scanner': {
                'threads': 40,
                'timeout': 3,
                'retry_count': 2,
                'verify_ssl': False,
                'follow_redirects': True,
                'max_redirects': 3,
                'user_agent': 'SSRF-Scanner/1.0',
                'max_pool_size': 100
            },
            'rate_limiting': {
                'requests_per_second': 10,
                'burst_size': 20,
                'min_rate': 0.5,
                'max_rate': 50
            },
            'attacks': {
                'enabled': {
                    'local_ip': True,
                    'cloud_metadata': True,
                    'protocol': True,
                    'encoded': True,
                    'parameter': True,
                    'port_scan': True,
                    'dns_rebinding': True
                },
                'custom_payloads': []
            },
            'reporting': {
                'output_dir': 'output',
                'formats': ['html', 'csv', 'json'],
                'include_charts': True
            },
            'logging': {
                'level': 'INFO',
                'file': 'ssrf_scanner.log',
                'format': '%(asctime)s - %(levelname)s - %(message)s'
            }
        }

    def load_config(self):
        """Load configuration from file"""
        try:
            with self.config_file.open('r') as f:
                file_config = yaml.safe_load(f)
                self.config = self._merge_configs(self.config, file_config)
        except Exception as e:
            logging.error(f"Error loading config file: {e}")

    def save_config(self):
        """Save current configuration to file"""
        try:
            with self.config_file.open('w') as f:
                yaml.dump(self.config, f, default_flow_style=False)
        except Exception as e:
            logging.error(f"Error saving config file: {e}")

    def _merge_configs(self, default: Dict, override: Dict) -> Dict:
        """Deep merge two configurations"""
        merged = default.copy()
        
        for key, value in override.items():
            if key in merged and isinstance(merged[key], dict) and isinstance(value, dict):
                merged[key] = self._merge_configs(merged[key], value)
            else:
                merged[key] = value
                
        return merged

    def update_config(self, section: str, key: str, value: Any):
        """Update specific configuration value"""
        if section in self.config:
            if isinstance(self.config[section], dict):
                self.config[section][key] = value
            else:
                self.config[section] = {key: value}
        else:
            self.config[section] = {key: value}

    def get_config(self, section: str = None) -> Any:
        """Get configuration section or full config"""
        if section:
            return self.config.get(section, {})
        return self.config

