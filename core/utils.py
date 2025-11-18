"""
Common utility functions
"""

import re
import socket
from urllib.parse import urlparse

def is_valid_domain(domain: str) -> bool:
    """Validate domain format"""
    pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$'
    return bool(re.match(pattern, domain))

def is_valid_ip(ip: str) -> bool:
    """Validate IP address format"""
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

def normalize_url(url: str) -> str:
    """Normalize URL for processing"""
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    return url.lower().strip()

def extract_domain(url: str) -> str:
    """Extract domain from URL"""
    parsed = urlparse(normalize_url(url))
    return parsed.netloc