# 🛡️ UCS-T - Unified Cybersecurity Toolkit

A professional, modular cybersecurity application bundling multiple security tools into one unified interface. UCS-T provides comprehensive threat analysis for websites, files, networks, and systems.

![UCS-T Screenshot](assets/screenshots/main_window.png)

## 🚀 Features

### 🔍 Website Security Analyzer
- Domain reputation and age analysis
- SSL certificate validation
- DNS security checks
- Threat intelligence lookup (VirusTotal, OTX)
- Risk scoring and actionable recommendations

### 🔢 File Hash Analyzer (HashVigil)
- Multi-hash generation (MD5, SHA1, SHA256)
- VirusTotal malware detection
- File reputation analysis
- Security threat assessment

### 🌐 Network Security Scanner
- Host discovery and availability checking
- Port scanning (common services)
- Network range scanning
- Service detection

### 🛡️ System Security Auditor
- Quick security assessment
- Comprehensive system audit
- Security posture evaluation
- Hardening recommendations

## 📦 Installation

### Method 1: Download Executable (Recommended)
1. Download `UCS-T.exe` from [Releases](../../releases)
2. Run directly - no installation required
3. Portable and standalone

### Method 2: Build from Source
```bash
# Clone repository
git clone https://github.com/APMarzuki/UCS-T.git
cd UCS-T

# Install dependencies
pip install -r requirements.txt

# Run application
python app.py

# Build executable
pyinstaller --onefile --name "UCS-T" --add-data "core;core" --add-data "modules;modules" --add-data "gui;gui" --noconsole app.py

Usage
Launch UCS-T.exe

Select security module tab

Enter target analysis

Review comprehensive security report

Example Analyses:
Website Security: google.com, free-gift-cards.com

File Analysis: Any file or hash d41d8cd98f00b204e9800998ecf8427e

Network Scan: 127.0.0.1, 192.168.1.1/24

System Audit: Click audit buttons

🔧 Technology Stack
Frontend: PyQt6 (Modern GUI)

Backend: Python 3.8+

APIs: VirusTotal, AlienVault OTX, AbuseIPDB

Security: cryptography, ssl, dns

Packaging: PyInstaller

📁 Project Structure
text
UCS-T/
├── core/                 # Shared utilities & configuration
├── modules/              # Security tool implementations
│   ├── scam_advisor/     # Website security
│   ├── hashvigil/        # File analysis
│   ├── pynetscanner/     # Network scanning
│   └── cyberaudit/       # System auditing
├── gui/                  # User interface components
├── assets/               # Resources & screenshots
├── dist/                 # Built executables
└── tests/                # Test suites
🔑 API Configuration
Edit core/api_config.py to add your API keys:

python
# Get free API keys from:
VIRUSTOTAL_API_KEY = "your_virustotal_key"    # https://virustotal.com
ABUSEIPDB_API_KEY = "your_abuseipdb_key"      # https://abuseipdb.com  
OTX_API_KEY = "your_otx_key"                  # https://otx.alienvault.com
🎯 Real-World Testing
UCS-T has been tested with:

✅ Known malware hashes (62/65 VirusTotal detection)

✅ Phishing/scam websites (100/100 risk scoring)

✅ Suspicious IP addresses

✅ Legitimate sites (0/100 risk scoring)

🤝 Contributing
Contributions welcome! Please feel free to submit pull requests or open issues for:

New security features

Additional API integrations

UI/UX improvements

Bug fixes

📄 License
MIT License - see LICENSE file for details.

🏆 Achievements
Professional-grade cybersecurity application

Real threat detection capabilities

Modular, extensible architecture

Production-ready distribution

Built with ❤️ for the cybersecurity community

text

**2. Create `.gitignore`** (Important!):
Python
pycache/
*.py[cod]
*$py.class
*.so
.Python
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
lib/
lib64/
parts/
sdist/
var/
wheels/
*.egg-info/
.installed.cfg
*.egg

PyInstaller
*.manifest
*.spec

Installer logs
pip-log.txt
pip-delete-this-directory.txt

Unit test / coverage reports
htmlcov/
.tox/
.nox/
.coverage
.coverage.*
.cache
nosetests.xml
coverage.xml
*.cover
.hypothesis/
.pytest_cache/

Environments
.env
.venv
env/
venv/
ENV/
env.bak/
venv.bak/

IDE
.vscode/
.idea/
*.swp
*.swo

OS
.DS_Store
Thumbs.db

Logs
*.log
logs/

UCS-T specific
*.exe
!dist/UCS-T.exe
config.encrypted
key.key

text

**3. Create `LICENSE`** (MIT License):
MIT License

Copyright (c) 2025 APMarzuki

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

text

## 🚀 **Step 2: GitHub Upload Process**

### **Option A: Using GitHub Desktop (Easiest)**
1. Download GitHub Desktop
2. Create new repository "UCS-T"
3. Drag your project folder into GitHub Desktop
4. Commit with message "Initial commit: UCS-T Cybersecurity Toolkit"
5. Publish to GitHub

### **Option B: Using Git Commands**
```bash
# Initialize git
git init

# Add all files
git add .

# Initial commit
git commit -m "Initial commit: UCS-T Unified Cybersecurity Toolkit"

# Create repository on GitHub.com, then:
git remote add origin https://github.com/APMarzuki/UCS-T.git
git branch -M main
git push -u origin main