#!/usr/bin/env python3
"""
UCS-T Module Usage Guide
Shows how to use each security module correctly
"""


def print_module_guide():
    print("🛡️ UCS-T MODULE USAGE GUIDE")
    print("=" * 70)

    guide = {
        "🔍 WEBSITE SECURITY (ScamAdvisor Tab)": {
            "Purpose": "Analyze website safety and reputation",
            "Input Examples": [
                "google.com",
                "github.com",
                "microsoft.com",
                "free-gift-cards.com",
                "https://example.com"
            ],
            "What it checks": [
                "Domain age and registration",
                "SSL certificate security",
                "DNS records and configuration",
                "Threat intelligence databases",
                "Blacklist status"
            ],
            "Expected Output": "Risk score, SSL status, domain info, recommendations"
        },
        "🌐 NETWORK SCANNER (Net Scanner Tab)": {
            "Purpose": "Scan networks and check host availability",
            "Input Examples": [
                "127.0.0.1 (your computer)",
                "192.168.1.1 (your router)",
                "8.8.8.8 (Google DNS)",
                "192.168.1.0/24 (local network range)",
                "scanme.nmap.org (test site)"
            ],
            "What it checks": [
                "Host availability (ping)",
                "Open ports and services",
                "Network range discovery",
                "Basic service detection"
            ],
            "Expected Output": "Online/offline status, open ports, network info"
        },
        "🔢 FILE ANALYSIS (HashVigil Tab)": {
            "Purpose": "Analyze files and check for malware",
            "Input Examples": [
                "File hashes (MD5, SHA1, SHA256)",
                "Use 'Browse File' to select files",
                "d41d8cd98f00b204e9800998ecf8427e (test MD5)",
                "Any file from your computer"
            ],
            "What it checks": [
                "File hash generation",
                "VirusTotal malware detection",
                "File reputation analysis",
                "Security recommendations"
            ],
            "Expected Output": "Hash values, malware detection, safety recommendations"
        },
        "🛡️ SYSTEM AUDIT (Cyber Audit Tab)": {
            "Purpose": "Check your system security",
            "Input Examples": [
                "Click 'Quick Audit'",
                "Click 'Full Security Audit'"
            ],
            "What it checks": [
                "User accounts and privileges",
                "Network configuration",
                "System security settings",
                "Security recommendations"
            ],
            "Expected Output": "System security assessment, recommendations"
        }
    }

    for module, info in guide.items():
        print(f"\n{module}")
        print("-" * 50)
        print(f"🎯 Purpose: {info['Purpose']}")
        print(f"📥 Input Examples:")
        for example in info['Input Examples']:
            print(f"   • {example}")
        print(f"🔍 What it checks:")
        for check in info['What it checks']:
            print(f"   • {check}")
        print(f"📊 Expected Output: {info['Expected Output']}")

    print("\n" + "=" * 70)
    print("🚀 QUICK START TESTING:")
    print("1. Website Security Tab → Enter: google.com")
    print("2. Network Scanner Tab → Enter: 127.0.0.1")
    print("3. File Analysis Tab → Enter any file hash")
    print("4. System Audit Tab → Click audit buttons")
    print("\n❌ COMMON MISTAKE:")
    print("   Don't use IP addresses in Website Security tab")
    print("   Use Network Scanner tab for IP addresses!")
    print("\n🎯 Each module is designed for specific security tasks!")


if __name__ == "__main__":
    print_module_guide()