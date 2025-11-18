"""
Configuration management for UCS-T
"""

import os
import json
from pathlib import Path


class Config:
    """Central configuration manager"""

    def __init__(self):
        self.config_dir = Path.home() / ".ucs-t"
        self.config_file = self.config_dir / "config.json"
        self.default_config = {
            "api_keys": {
                "virustotal": "",
                "abuseipdb": "",
                "otx": "",
                "phishtank": ""
            },
            "theme": "dark",
            "auto_update": True,
            "log_level": "INFO"
        }
        self.load_config()

    def load_config(self):
        """Load configuration from file or create default"""
        try:
            if self.config_file.exists():
                with open(self.config_file, 'r') as f:
                    self.data = json.load(f)
            else:
                self.data = self.default_config
                self.save_config()
        except Exception:
            self.data = self.default_config

    def save_config(self):
        """Save configuration to file"""
        self.config_dir.mkdir(exist_ok=True)
        with open(self.config_file, 'w') as f:
            json.dump(self.data, f, indent=4)

    def get(self, key, default=None):
        """Get configuration value"""
        keys = key.split('.')
        value = self.data
        for k in keys:
            value = value.get(k, {})
        return value if value != {} else default

    def set(self, key, value):
        """Set configuration value"""
        keys = key.split('.')
        config = self.data
        for k in keys[:-1]:
            config = config.setdefault(k, {})
        config[keys[-1]] = value
        self.save_config()


# Global config instance
config = Config()