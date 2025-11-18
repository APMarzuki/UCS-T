"""
HashVigil - Real Hash Analysis Logic
"""

import hashlib
import os
from core.api_config import APIConfig
import requests


class HashAnalyzer:
    """Real hash analysis with file checking and malware lookup"""

    def __init__(self):
        self.config = APIConfig()

    def analyze(self, input_data: str) -> str:
        """Analyze hash or file"""
        # Check if input is a file path or hash
        if os.path.exists(input_data):
            return self.analyze_file(input_data)
        else:
            return self.analyze_hash(input_data)

    def analyze_file(self, file_path: str) -> str:
        """Analyze a file - generate hashes and check reputation"""
        try:
            # Generate file hashes
            hashes = self.generate_file_hashes(file_path)
            file_size = os.path.getsize(file_path)
            file_name = os.path.basename(file_path)

            report = f"""
🔢 **HashVigil File Analysis Report**
────────────────────────────────────────
📁 **File**: {file_name}
📊 **Size**: {file_size} bytes

🔑 **Generated Hashes**:
────────────────────────────────────────
"""
            for hash_type, hash_value in hashes.items():
                report += f"• **{hash_type}**: {hash_value}\n"

            # Check hash with VirusTotal
            vt_result = self.check_virustotal_hash(hashes['SHA256'])

            report += f"\n🛡️ **Security Analysis**:\n"
            report += f"────────────────────────────────────────\n"

            if vt_result.get('status') == 'success':
                positives = vt_result.get('positives', 0)
                total = vt_result.get('total', 0)
                report += f"✅ **VirusTotal**: {positives}/{total} engines detected threats\n"

                if positives > 0:
                    report += f"⚠️ **Warning**: File detected as potentially malicious!\n"
                else:
                    report += f"🟢 **Status**: No threats detected\n"
            else:
                report += f"ℹ️ **VirusTotal**: {vt_result.get('message', 'Check not available')}\n"

            report += f"\n💡 **Recommendations**:\n"
            if 'Warning' in report:
                report += "• Do not execute this file\n"
                report += "• Delete the file immediately\n"
                report += "• Scan with additional antivirus software\n"
            else:
                report += "• File appears safe\n"
                report += "• Continue to practice safe computing\n"

            return report

        except Exception as e:
            return f"❌ File analysis failed: {str(e)}"

    def analyze_hash(self, hash_input: str) -> str:
        """Analyze a hash string"""
        hash_type = self.detect_hash_type(hash_input)

        report = f"""
🔢 **HashVigil Hash Analysis Report**
────────────────────────────────────────
🔑 **Hash**: {hash_input}
📏 **Type**: {hash_type}
📏 **Length**: {len(hash_input)} characters

🛡️ **Security Analysis**:
────────────────────────────────────────
"""
        # Check hash with VirusTotal
        vt_result = self.check_virustotal_hash(hash_input)

        if vt_result.get('status') == 'success':
            positives = vt_result.get('positives', 0)
            total = vt_result.get('total', 0)
            report += f"✅ **VirusTotal**: {positives}/{total} engines detected threats\n"

            if positives > 0:
                report += f"🔴 **THREAT DETECTED**: Hash is associated with malware!\n"
                report += f"📋 **Scan Date**: {vt_result.get('scan_date', 'Unknown')}\n"
            else:
                report += f"🟢 **Status**: No threats detected in VirusTotal database\n"
        else:
            report += f"ℹ️ **VirusTotal**: {vt_result.get('message', 'Check not available')}\n"

        report += f"\n💡 **Recommendations**:\n"
        if 'THREAT DETECTED' in report:
            report += "• Do not download or execute files with this hash\n"
            report += "• This hash is associated with known malware\n"
            report += "• Delete any files matching this hash immediately\n"
        else:
            report += "• Hash appears clean in VirusTotal database\n"
            report += "• Exercise normal caution with unknown files\n"

        return report

    def generate_file_hashes(self, file_path: str) -> dict:
        """Generate MD5, SHA1, SHA256 hashes for a file"""
        hashes = {
            'MD5': hashlib.md5(),
            'SHA1': hashlib.sha1(),
            'SHA256': hashlib.sha256()
        }

        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                for hash_obj in hashes.values():
                    hash_obj.update(chunk)

        return {name: hash_obj.hexdigest() for name, hash_obj in hashes.items()}

    def detect_hash_type(self, hash_input: str) -> str:
        """Detect hash type based on length"""
        length = len(hash_input)
        if length == 32:
            return "MD5"
        elif length == 40:
            return "SHA1"
        elif length == 64:
            return "SHA256"
        else:
            return "Unknown"

    def check_virustotal_hash(self, file_hash: str) -> dict:
        """Check file hash with VirusTotal"""
        if not self.config.VIRUSTOTAL_API_KEY or self.config.VIRUSTOTAL_API_KEY.startswith("YOUR_"):
            return {"status": "error", "message": "VirusTotal API key not configured"}

        try:
            params = {
                'apikey': self.config.VIRUSTOTAL_API_KEY,
                'resource': file_hash
            }

            response = requests.get(
                f"{self.config.VIRUSTOTAL_URL}file/report",
                params=params,
                timeout=30
            )

            if response.status_code == 200:
                data = response.json()
                if data.get('response_code') == 1:
                    return {
                        'status': 'success',
                        'positives': data.get('positives', 0),
                        'total': data.get('total', 0),
                        'scan_date': data.get('scan_date', 'Unknown')
                    }
                else:
                    return {"status": "info", "message": "Hash not found in VirusTotal database"}
            else:
                return {"status": "error", "message": f"API returned status {response.status_code}"}

        except Exception as e:
            return {"status": "error", "message": f"VirusTotal check failed: {str(e)}"}