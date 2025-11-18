"""
Simple API Key Management for UCS-T
No cryptography dependency - uses plain text for now
"""

import json
import os
from pathlib import Path

class SimpleConfigManager:
    def __init__(self):
        self.config_dir = Path.home() / ".ucs-t"
        self.config_file = self.config_dir / "config.json"
        self.config_dir.mkdir(exist_ok=True)

    def save_api_keys(self, api_keys):
        """Save API keys to JSON file"""
        config_data = {
            'virustotal': api_keys.get('virustotal', ''),
            'abuseipdb': api_keys.get('abuseipdb', ''),
            'otx': api_keys.get('otx', ''),
            'alienvault': api_keys.get('alienvault', ''),
            'phishtank': api_keys.get('phishtank', '')
        }

        with open(self.config_file, 'w') as f:
            json.dump(config_data, f, indent=4)

    def get_api_keys(self):
        """Get API keys from JSON file"""
        if not self.config_file.exists():
            return {}

        try:
            with open(self.config_file, 'r') as f:
                return json.load(f)
        except:
            return {}

    def has_configured_keys(self):
        """Check if any API keys are configured"""
        keys = self.get_api_keys()
        return any(value for value in keys.values() if value.strip())

# Global instance
config_manager = SimpleConfigManager()