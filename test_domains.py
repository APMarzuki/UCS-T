#!/usr/bin/env python3
"""
Comprehensive Domain Testing for UCS-T
Test various types of websites
"""

import sys
import os
import time

sys.path.append(os.path.dirname(__file__))

from modules.scam_advisor.scanner import ScamScanner


def test_domains():
    print("🔍 UCS-T Comprehensive Domain Testing")
    print("=" * 70)

    scanner = ScamScanner()

    # Test domains - different categories
    test_categories = {
        "🟢 Known Safe": [
            "microsoft.com",
            "apple.com",
            "python.org",
            "stackoverflow.com"
        ],
        "🌐 Government & Education": [
            "whitehouse.gov",
            "harvard.edu",
            "wikipedia.org"
        ],
        "🛒 E-commerce": [
            "amazon.com",
            "ebay.com"
        ],
        "❓ Suspicious/New": [
            "example.com",  # Test domain
            "test.com"  # Generic test domain
        ]
    }

    for category, domains in test_categories.items():
        print(f"\n{category}")
        print("=" * 50)

        for domain in domains:
            print(f"\n🎯 Scanning: {domain}")
            print("-" * 40)

            try:
                start_time = time.time()
                result = scanner.scan(domain)
                scan_time = time.time() - start_time

                print(result)
                print(f"⏱️ Scan time: {scan_time:.2f}s")
                print("-" * 60)

            except Exception as e:
                print(f"❌ Scan failed: {e}")

            # Small delay to be respectful to APIs
            time.sleep(2)

    print("\n🎉 Comprehensive testing completed!")
    print("💡 Analyze the risk scores and recommendations")


if __name__ == "__main__":
    test_domains()