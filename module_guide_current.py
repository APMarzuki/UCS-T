#!/usr/bin/env python3
"""
UCS-T Module Usage Guide - CURRENT TAB NAMES
"""


def print_module_guide():
    print("🛡️ UCS-T MODULE USAGE GUIDE (Current Tab Names)")
    print("=" * 70)

    guide = {
        "🔍 Scam Advisor Tab": {
            "Purpose": "Analyze WEBSITES and DOMAINS for security",
            "Input Examples": [
                "google.com",
                "github.com",
                "microsoft.com",
                "free-gift-cards.com"
            ],
            "Do NOT use": "IP addresses like 127.0.0.1 or 192.168.1.1",
            "Expected": "Risk score, SSL status, domain age, threat intelligence"
        },
        "🌐 Net Scanner Tab": {
            "Purpose": "Scan NETWORKS and IP ADDRESSES",
            "Input Examples": [
                "127.0.0.1 (your computer)",
                "192.168.1.1 (your router)",
                "8.8.8.8 (Google DNS)",
                "192.168.1.0/24 (network range)"
            ],
            "Do NOT use": "Website domains like google.com",
            "Expected": "Online/offline status, open ports, network info"
        },
        "🔢 HashVigil Tab": {
            "Purpose": "Analyze FILES and HASHES for malware",
            "Input Examples": [
                "File hashes (MD5, SHA1, SHA256)",
                "Use 'Browse File' to select files",
                "d41d8cd98f00b204e9800998ecf8427e"
            ],
            "Expected": "Hash analysis, VirusTotal results, safety recommendations"
        },
        "🛡️ Cyber Audit Tab": {
            "Purpose": "Check YOUR COMPUTER's security",
            "Input Examples": [
                "Click 'Quick Audit' button",
                "Click 'Full Security Audit' button"
            ],
            "Expected": "System security assessment, recommendations"
        }
    }

    for tab, info in guide.items():
        print(f"\n{tab}")
        print("-" * 50)
        print(f"🎯 {info['Purpose']}")
        print(f"✅ USE FOR: {', '.join(info['Input Examples'][:2])}...")
        if 'Do NOT use' in info:
            print(f"❌ DO NOT USE: {info['Do NOT use']}")
        print(f"📊 EXPECTED: {info['Expected']}")

    print("\n" + "=" * 70)
    print("🚀 TESTING SEQUENCE:")
    print("1. Scam Advisor Tab → Enter: google.com")
    print("2. Net Scanner Tab → Enter: 127.0.0.1")
    print("3. HashVigil Tab → Enter any file hash")
    print("4. Cyber Audit Tab → Click audit buttons")
    print("\n💡 TIP: Each tab is designed for specific types of security analysis!")


if __name__ == "__main__":
    print_module_guide()