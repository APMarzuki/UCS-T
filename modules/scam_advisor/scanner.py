"""
ScamAdvisor scanning logic with real API integrations
"""

import whois
import dns.resolver
import ssl
import socket
import requests
from datetime import datetime
from urllib.parse import urlparse
import time

from .api_client import ScamAPI
from core.utils import normalize_url, extract_domain
from core.config_manager import config_manager


class ScamScanner:
    """Advanced website security scanner"""

    def __init__(self):
        self.api = ScamAPI()
        self.results = {}

    def scan(self, url: str) -> str:
        """Perform comprehensive website security scan"""
        start_time = time.time()
        url = normalize_url(url)
        domain = extract_domain(url)

        self.results = {
            'target': url,
            'domain': domain,
            'checks': {},
            'risk_score': 0,
            'warnings': [],
            'recommendations': []
        }

        # Perform security checks
        self.check_domain_age(domain)
        self.check_ssl_certificate(domain)
        self.check_dns_security(domain)
        self.check_blacklist_status(domain)
        self.check_reputation(domain)

        # Calculate overall risk
        self.calculate_risk_score()

        # Generate report
        report = self.generate_report()
        report += f"\n⏱️ Scan completed in {time.time() - start_time:.2f} seconds"

        return report

    def check_domain_age(self, domain):
        """Check domain registration age - FIXED VERSION"""
        try:
            w = whois.whois(domain)
            creation_date = w.creation_date

            if isinstance(creation_date, list):
                creation_date = creation_date[0]

            if creation_date:
                # FIX: Handle timezone-aware datetime comparison
                from datetime import datetime, timezone

                # Make both datetimes timezone-aware or both naive
                if creation_date.tzinfo is not None:
                    # creation_date is timezone-aware, make now aware too
                    now = datetime.now(timezone.utc)
                else:
                    # creation_date is naive, make now naive too
                    now = datetime.now()

                days_old = (now - creation_date).days

                self.results['checks']['domain_age'] = {
                    'status': 'safe' if days_old > 30 else 'suspicious',
                    'age_days': days_old,
                    'details': f"Domain is {days_old} days old"
                }

                if days_old < 30:
                    self.results['warnings'].append("New domain (less than 30 days old)")
        except Exception as e:
            self.results['checks']['domain_age'] = {
                'status': 'error',
                'details': f"WHOIS lookup failed: {str(e)}"
            }

    def check_ssl_certificate(self, domain):
        """Check SSL certificate validity"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()

                    # Check certificate expiration
                    exp_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_to_expire = (exp_date - datetime.now()).days

                    status = 'safe' if days_to_expire > 30 else 'warning'

                    self.results['checks']['ssl_certificate'] = {
                        'status': status,
                        'details': f"SSL valid, expires in {days_to_expire} days",
                        'expiration_days': days_to_expire
                    }

                    if days_to_expire <= 30:
                        self.results['warnings'].append(f"SSL certificate expires in {days_to_expire} days")
        except Exception as e:
            self.results['checks']['ssl_certificate'] = {
                'status': 'danger',
                'details': f"No valid SSL certificate: {str(e)}"
            }
            self.results['risk_score'] += 30

    def check_dns_security(self, domain):
        """Check DNS records and security"""
        try:
            # Check A records
            a_records = dns.resolver.resolve(domain, 'A')
            ips = [str(ip) for ip in a_records]

            self.results['checks']['dns_records'] = {
                'status': 'safe',
                'details': f"Found {len(ips)} A records",
                'ip_addresses': ips
            }
        except Exception as e:
            self.results['checks']['dns_records'] = {
                'status': 'error',
                'details': f"DNS resolution failed: {str(e)}"
            }

    def check_blacklist_status(self, domain):
        """Check domain against real blacklists using your APIs - IMPROVED VERSION"""
        api_keys_configured = any([
            self.api.config.VIRUSTOTAL_API_KEY and not self.api.config.VIRUSTOTAL_API_KEY.startswith("YOUR_"),
            self.api.config.OTX_API_KEY and not self.api.config.OTX_API_KEY.startswith("YOUR_")
        ])

        if not api_keys_configured:
            self.results['checks']['blacklist'] = {
                'status': 'info',
                'details': 'Configure API keys in core/api_config.py for blacklist checks'
            }
            return

        # Run actual API checks
        vt_result = self.api.check_virustotal_domain(domain)
        otx_result = self.api.check_otx_domain(domain)

        # Process results with better interpretation
        detected_threats = []
        vt_detection_ratio = "0/0"
        otx_pulse_count = 0

        if vt_result.get('status') == 'success':
            detected_urls = vt_result.get('detected_unsafe', [])
            undetected_urls = vt_result.get('undetected_urls', [])
            total_scans = len(detected_urls) + len(undetected_urls)
            vt_detection_ratio = f"{len(detected_urls)}/{total_scans}"

            # Only consider it a real threat if detection ratio is significant
            if len(detected_urls) > 10 and len(detected_urls) / total_scans > 0.1:
                detected_threats.append(f"VirusTotal: {vt_detection_ratio} unsafe URLs")

        if otx_result.get('status') == 'success':
            otx_pulse_count = otx_result.get('pulse_count', 0)
            # OTX pulses are often just mentions - only consider high counts as suspicious
            if otx_pulse_count > 20:
                detected_threats.append(f"OTX: {otx_pulse_count} threat mentions")

        if detected_threats:
            self.results['checks']['blacklist'] = {
                'status': 'danger',
                'details': 'Suspicious activity: ' + ', '.join(detected_threats)
            }
            self.results['risk_score'] += 40
        else:
            # Provide informative details even when no threats
            details = []
            if vt_detection_ratio != "0/0":
                details.append(f"VirusTotal: {vt_detection_ratio} historical scans")
            if otx_pulse_count > 0:
                details.append(f"OTX: {otx_pulse_count} intelligence mentions")

            if details:
                self.results['checks']['blacklist'] = {
                    'status': 'safe',
                    'details': 'No active threats. ' + ', '.join(details)
                }
            else:
                self.results['checks']['blacklist'] = {
                    'status': 'safe',
                    'details': 'No threats detected in security databases'
                }

    def check_reputation(self, domain):
        """Check domain reputation using real APIs - FINAL IMPROVEMENT"""
        # Extract IP for AbuseIPDB check
        ip_address = None
        try:
            import socket
            ip_address = socket.gethostbyname(domain)
        except:
            pass

        api_results = {}

        # VirusTotal reputation
        vt_result = self.api.check_virustotal_domain(domain)
        if vt_result.get('status') == 'success':
            api_results['virustotal'] = vt_result

        # AbuseIPDB reputation (if we have IP)
        if ip_address:
            abuse_result = self.api.check_abuseipdb(ip_address)
            if abuse_result.get('status') == 'success':
                api_results['abuseipdb'] = abuse_result

        # OTX reputation
        otx_result = self.api.check_otx_domain(domain)
        if otx_result.get('status') == 'success':
            api_results['otx'] = otx_result

        # Generate reputation summary - IMPROVED LOGIC
        if api_results:
            real_threats = []
            intelligence_mentions = []

            for api_name, result in api_results.items():
                if api_name == 'abuseipdb' and result.get('abuse_confidence', 0) > 70:
                    real_threats.append(f"AbuseIPDB: {result['abuse_confidence']}% confidence")
                elif api_name == 'virustotal' and result.get('detected_unsafe'):
                    # Only consider significant VirusTotal detections
                    detected = len(result.get('detected_unsafe', []))
                    if detected > 20:  # Significant number of detections
                        real_threats.append(f"VirusTotal: {result['detection_ratio']} unsafe")
                    else:
                        intelligence_mentions.append(f"VirusTotal: {result['detection_ratio']} historical scans")
                elif api_name == 'otx' and result.get('pulse_count', 0) > 0:
                    # OTX pulses are intelligence mentions, not necessarily threats
                    if result['pulse_count'] > 30:
                        intelligence_mentions.append(f"OTX: {result['pulse_count']} intelligence mentions")

            if real_threats:
                self.results['checks']['reputation'] = {
                    'status': 'danger',
                    'details': 'Reputation concerns: ' + ', '.join(real_threats)
                }
                self.results['risk_score'] += 30
            elif intelligence_mentions:
                self.results['checks']['reputation'] = {
                    'status': 'info',
                    'details': 'Intelligence data: ' + ', '.join(intelligence_mentions)
                }
            else:
                self.results['checks']['reputation'] = {
                    'status': 'safe',
                    'details': 'Good reputation across threat intelligence'
                }
        else:
            self.results['checks']['reputation'] = {
                'status': 'info',
                'details': 'Configure API keys for reputation analysis'
            }

    def calculate_risk_score(self):
        """Calculate overall risk score based on checks - ENHANCED THREAT DETECTION"""
        risk_factors = {
            'domain_age': {'safe': 0, 'suspicious': 25, 'error': 10},
            'ssl_certificate': {'safe': 0, 'warning': 20, 'danger': 40, 'error': 15},
            'dns_records': {'safe': 0, 'error': 15},
            'blacklist': {'safe': 0, 'suspicious': 30, 'danger': 70, 'pending': 5, 'info': 0},
            'reputation': {'safe': 0, 'suspicious': 25, 'danger': 60, 'pending': 5, 'info': 0}
        }

        total_risk = 0
        for check_name, check_data in self.results['checks'].items():
            risk_value = risk_factors.get(check_name, {}).get(check_data['status'], 0)
            total_risk += risk_value

        # ENHANCE: Major risk factors for suspicious sites
        domain = self.results['domain'].lower()

        # High risk for "gift", "reward", "free" in domain names
        suspicious_keywords = ['gift', 'reward', 'free', 'claim', 'prize', 'win', 'bonus']
        if any(keyword in domain for keyword in suspicious_keywords):
            total_risk += 25

        # Very high risk for no SSL certificate
        ssl_check = self.results['checks'].get('ssl_certificate', {})
        if ssl_check.get('status') in ['danger', 'error']:
            total_risk += 35

        # High risk for domain that doesn't resolve
        dns_check = self.results['checks'].get('dns_records', {})
        if dns_check.get('status') == 'error':
            total_risk += 30

        # High risk for very new domains (< 1 year)
        domain_age_check = self.results['checks'].get('domain_age', {})
        if domain_age_check.get('status') == 'suspicious':
            total_risk += 20
        elif domain_age_check.get('status') == 'error':
            total_risk += 15

        # Reduce risk only for well-known legitimate domains
        known_legitimate_domains = [
            'google.com', 'microsoft.com', 'apple.com', 'github.com',
            'wikipedia.org', 'stackoverflow.com', 'whoxy.com'
        ]

        if self.results['domain'] in known_legitimate_domains:
            total_risk = max(0, total_risk - 40)

        self.results['risk_score'] = min(total_risk, 100)

    def generate_report(self):
        """Generate comprehensive scan report - ENHANCED RECOMMENDATIONS"""
        risk_levels = {
            (0, 20): '🟢 LOW RISK',
            (21, 50): '🟡 MEDIUM RISK',
            (51, 75): '🟠 HIGH RISK',
            (76, 100): '🔴 CRITICAL RISK'
        }

        risk_category = '🟢 LOW RISK'
        for (min_score, max_score), category in risk_levels.items():
            if min_score <= self.results['risk_score'] <= max_score:
                risk_category = category
                break

        report = f"""
    🔍 **ScamAdvisor Security Report**
    ────────────────────────────────────────
    📋 **Target**: {self.results['target']}
    🌐 **Domain**: {self.results['domain']}
    ⚠️ **Risk Score**: {self.results['risk_score']}/100 - {risk_category}

    📊 **Security Checks**:
    ────────────────────────────────────────
    """

        for check_name, check_data in self.results['checks'].items():
            status_icon = {
                'safe': '✅',
                'warning': '⚠️',
                'danger': '❌',
                'suspicious': '🟡',
                'error': '🔧',
                'pending': '⏳',
                'info': 'ℹ️'
            }.get(check_data['status'], '❓')

            report += f"{status_icon} **{check_name.replace('_', ' ').title()}**: {check_data['details']}\n"

        # Enhanced recommendations based on specific risks
        report += f"\n💡 **Security Recommendations**:\n"

        # Domain doesn't exist
        dns_check = self.results['checks'].get('dns_records', {})
        if dns_check.get('status') == 'error':
            report += "• 🚨 DOMAIN DOES NOT EXIST - Likely fake or scam site\n"

        # No SSL certificate
        ssl_check = self.results['checks'].get('ssl_certificate', {})
        if ssl_check.get('status') in ['danger', 'error']:
            report += "• 🔒 NO SSL CERTIFICATE - Unsafe for any data entry\n"

        # Suspicious keywords in domain
        domain = self.results['domain'].lower()
        suspicious_keywords = ['gift', 'reward', 'free', 'claim', 'prize', 'win', 'bonus']
        if any(keyword in domain for keyword in suspicious_keywords):
            report += "• ⚠️ SUSPICIOUS DOMAIN NAME - Common in scam sites\n"

        # General risk-based recommendations
        if self.results['risk_score'] >= 70:
            report += "• 🚫 CRITICAL RISK - Avoid this website completely\n"
            report += "• 🔐 Do not enter any personal information\n"
            report += "• 📵 Do not download anything from this site\n"
        elif self.results['risk_score'] >= 50:
            report += "• ⚠️ HIGH RISK - Exercise extreme caution\n"
            report += "• 🔒 Avoid entering sensitive information\n"
            report += "• 🔍 Verify site legitimacy through other means\n"
        elif self.results['risk_score'] >= 30:
            report += "• 🟡 MEDIUM RISK - Be cautious\n"
            report += "• 📝 Avoid unnecessary personal data entry\n"
            report += "• 🌐 Check for official company websites\n"
        else:
            report += "• 🟢 LOW RISK - Appears relatively safe\n"
            report += "• ✅ Continue practicing general internet safety\n"

        return report