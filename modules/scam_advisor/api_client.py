"""
Enhanced API Client for ScamAdvisor with REAL API integrations
"""

import requests
import json
from core.api_config import APIConfig

class ScamAPI:
    """Wrapper for various security APIs with real implementations"""

    def __init__(self):
        self.config = APIConfig()
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'UCS-T Security Toolkit/1.0'
        })

    def check_virustotal_domain(self, domain: str) -> dict:
        """Check domain reputation with REAL VirusTotal API"""
        if not self.config.VIRUSTOTAL_API_KEY or self.config.VIRUSTOTAL_API_KEY.startswith("YOUR_"):
            return {"status": "error", "message": "VirusTotal API key not configured"}

        try:
            params = {
                'apikey': self.config.VIRUSTOTAL_API_KEY,
                'domain': domain
            }

            response = self.session.get(
                f"{self.config.VIRUSTOTAL_URL}domain/report",
                params=params,
                timeout=30
            )

            if response.status_code == 200:
                data = response.json()

                # Extract meaningful information
                detected_urls = data.get('detected_urls', [])
                undetected_urls = data.get('undetected_urls', [])
                total_scans = len(detected_urls) + len(undetected_urls)
                detection_ratio = f"{len(detected_urls)}/{total_scans}" if total_scans > 0 else "0/0"

                return {
                    'status': 'success',
                    'detected_unsafe': detected_urls,
                    'detection_ratio': detection_ratio,
                    'categories': data.get('categories', {}),
                    'response_code': data.get('response_code', 0),
                    'verbose_msg': data.get('verbose_msg', '')
                }
            elif response.status_code == 204:
                return {"status": "error", "message": "VirusTotal API quota exceeded"}
            else:
                return {"status": "error", "message": f"API returned status {response.status_code}"}

        except Exception as e:
            return {"status": "error", "message": f"VirusTotal check failed: {str(e)}"}

    def check_abuseipdb(self, ip: str) -> dict:
        """Check IP reputation with REAL AbuseIPDB API"""
        if not self.config.ABUSEIPDB_API_KEY or self.config.ABUSEIPDB_API_KEY.startswith("YOUR_"):
            return {"status": "error", "message": "AbuseIPDB API key not configured"}

        try:
            headers = {
                'Key': self.config.ABUSEIPDB_API_KEY,
                'Accept': 'application/json'
            }

            params = {
                'ipAddress': ip,
                'maxAgeInDays': 90
            }

            response = self.session.get(
                f"{self.config.ABUSEIPDB_URL}check",
                headers=headers,
                params=params,
                timeout=30
            )

            if response.status_code == 200:
                data = response.json()
                result = data.get('data', {})
                return {
                    'status': 'success',
                    'abuse_confidence': result.get('abuseConfidenceScore', 0),
                    'country': result.get('countryCode', 'Unknown'),
                    'isp': result.get('isp', 'Unknown'),
                    'domain': result.get('domain', 'Unknown'),
                    'total_reports': result.get('totalReports', 0),
                    'last_reported': result.get('lastReportedAt', 'Unknown')
                }
            else:
                return {"status": "error", "message": f"AbuseIPDB API error: {response.status_code}"}

        except Exception as e:
            return {"status": "error", "message": f"AbuseIPDB check failed: {str(e)}"}

    def check_otx_domain(self, domain: str) -> dict:
        """Check domain with REAL AlienVault OTX API"""
        if not self.config.OTX_API_KEY or self.config.OTX_API_KEY.startswith("YOUR_"):
            return {"status": "error", "message": "OTX API key not configured"}

        try:
            headers = {
                'X-OTX-API-KEY': self.config.OTX_API_KEY
            }

            response = self.session.get(
                f"{self.config.OTX_URL}indicators/domain/{domain}/general",
                headers=headers,
                timeout=30
            )

            if response.status_code == 200:
                data = response.json()
                pulse_info = data.get('pulse_info', {})
                return {
                    'status': 'success',
                    'pulse_count': pulse_info.get('count', 0),
                    'malware_families': data.get('malware_families', []),
                    'reputation': data.get('reputation', 0),
                    'base_indicator': data.get('base_indicator', {})
                }
            else:
                return {"status": "error", "message": f"OTX API error: {response.status_code}"}

        except Exception as e:
            return {"status": "error", "message": f"OTX check failed: {str(e)}"}

    # PhishTank is optional - no problem if not available
    def check_phish_tank(self, url: str) -> dict:
        """Check URL with PhishTank (optional)"""
        return {"status": "info", "message": "PhishTank registration currently disabled"}