#!/usr/bin/env python3
"""
Test Real Domain Scanning with Your API Keys
"""

import sys
import os

sys.path.append(os.path.dirname(__file__))

from modules.scam_advisor.scanner import ScamScanner


def test_real_scan():
    print("🔍 Testing Real Domain Scanning...")
    print("=" * 60)

    scanner = ScamScanner()

    # Test domains (safe for testing)
    test_domains = [
        "google.com",  # Known safe
        "github.com",  # Known safe
        "example.com",  # Test domain
        "microsoft.com"  # Known safe
    ]

    for domain in test_domains[:2]:  # Test just first 2 to save time
        print(f"\n🎯 Scanning: {domain}")
        print("-" * 40)

        try:
            result = scanner.scan(domain)
            print(result)
            print("-" * 60)
        except Exception as e:
            print(f"❌ Scan failed: {e}")

    print("🎉 Real scan test completed!")


if __name__ == "__main__":
    test_real_scan()