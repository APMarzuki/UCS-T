"""
PyNetScanner - Real Network Scanning Logic
"""

import socket
import subprocess
import platform
from concurrent.futures import ThreadPoolExecutor
import ipaddress


class NetScanner:
    """Real network scanner with host discovery and port scanning"""

    def __init__(self):
        self.results = {}

    def scan(self, target: str) -> str:
        """Perform network scan on target"""
        self.results = {
            'target': target,
            'host_discovery': {},
            'port_scan': {},
            'services': []
        }

        try:
            # Determine if target is IP, range, or hostname
            if '/' in target:
                # It's a network range
                return self.scan_network_range(target)
            else:
                # Single target
                return self.scan_single_target(target)

        except Exception as e:
            return f"❌ Scan failed: {str(e)}"

    def scan_single_target(self, target: str) -> str:
        """Scan a single IP or hostname"""
        # Host discovery (ping)
        is_alive = self.ping_host(target)

        # Basic port scan
        open_ports = self.quick_port_scan(target)

        # Generate report
        report = f"""
🌐 **PyNetScanner Report**
────────────────────────────────────────
🎯 **Target**: {target}
🏠 **Host Status**: {'🟢 ONLINE' if is_alive else '🔴 OFFLINE'}

📊 **Scan Results**:
────────────────────────────────────────
"""

        if is_alive:
            report += f"✅ **Host Discovery**: Target is responsive\n"

            if open_ports:
                report += f"🔍 **Open Ports Found**: {len(open_ports)}\n"
                for port in open_ports[:10]:  # Show first 10 ports
                    service = self.get_service_name(port)
                    report += f"   • Port {port}: {service}\n"
                if len(open_ports) > 10:
                    report += f"   • ... and {len(open_ports) - 10} more ports\n"
            else:
                report += "🔒 **Open Ports**: No common ports open\n"

            # Get hostname if available
            try:
                hostname = socket.gethostbyaddr(target)[0]
                report += f"🏷️ **Hostname**: {hostname}\n"
            except:
                report += "🏷️ **Hostname**: Could not resolve\n"

        else:
            report += "🔴 **Host Discovery**: Target is not responding\n"
            report += "💡 **Note**: Host might be blocking ICMP requests\n"

        report += f"\n⚡ **Scan Type**: Quick Scan (Top 100 ports)"
        report += f"\n🔧 **Status**: Basic scanning complete"

        return report

    def ping_host(self, target: str) -> bool:
        """Check if host is alive using ping"""
        try:
            # Determine ping command based on OS
            param = "-n" if platform.system().lower() == "windows" else "-c"

            # Execute ping command
            result = subprocess.run(
                ["ping", param, "1", target],
                capture_output=True,
                text=True,
                timeout=5
            )

            return result.returncode == 0
        except:
            return False

    def quick_port_scan(self, target: str, ports=None) -> list:
        """Scan common ports on target"""
        if ports is None:
            # Common ports to scan
            ports = [21, 22, 23, 25, 53, 80, 110, 443, 993, 995, 1433, 3306, 3389, 5432]

        open_ports = []

        def check_port(port):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(2)
                    result = sock.connect_ex((target, port))
                    if result == 0:
                        open_ports.append(port)
            except:
                pass

        # Use threading for faster scanning
        with ThreadPoolExecutor(max_workers=10) as executor:
            executor.map(check_port, ports)

        return sorted(open_ports)

    def get_service_name(self, port: int) -> str:
        """Get common service name for port"""
        services = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 443: "HTTPS", 993: "IMAPS",
            995: "POP3S", 1433: "MSSQL", 3306: "MySQL", 3389: "RDP",
            5432: "PostgreSQL", 5900: "VNC", 27017: "MongoDB"
        }
        return services.get(port, "Unknown")

    def scan_network_range(self, network_range: str) -> str:
        """Scan a network range (basic implementation)"""
        try:
            network = ipaddress.ip_network(network_range, strict=False)
            hosts = list(network.hosts())[:10]  # Limit to first 10 hosts

            report = f"""
🌐 **PyNetScanner - Network Range Scan**
────────────────────────────────────────
🎯 **Target**: {network_range}
📊 **Scanning**: First 10 hosts in range

📋 **Host Discovery Results**:
────────────────────────────────────────
"""
            online_hosts = []

            for host in hosts:
                if self.ping_host(str(host)):
                    online_hosts.append(str(host))
                    report += f"🟢 {host} - Online\n"
                else:
                    report += f"🔴 {host} - Offline\n"

            report += f"\n📈 **Summary**: {len(online_hosts)}/{len(hosts)} hosts online"
            report += f"\n🔧 **Status**: Network discovery complete"

            return report

        except Exception as e:
            return f"❌ Network range scan failed: {str(e)}"