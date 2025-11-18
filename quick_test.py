#!/usr/bin/env python3
"""
Quick UCS-T Testing Script
Tests each module with proper inputs
"""


def quick_test():
    print("🚀 UCS-T QUICK TEST SCRIPT")
    print("=" * 60)

    tests = [
        {
            "module": "🔍 Website Security (ScamAdvisor)",
            "tab": "Scam Advisor",
            "test_input": "google.com",
            "expected": "LOW RISK with SSL certificate info"
        },
        {
            "module": "🌐 Network Scanner (PyNetScanner)",
            "tab": "Net Scanner",
            "test_input": "127.0.0.1",
            "expected": "Your computer showing as ONLINE"
        },
        {
            "module": "🔢 File Analysis (HashVigil)",
            "tab": "HashVigil",
            "test_input": "d41d8cd98f00b204e9800998ecf8427e",
            "expected": "Hash analysis with VirusTotal results"
        },
        {
            "module": "🛡️ System Audit (CyberAudit)",
            "tab": "Cyber Audit",
            "test_input": "Click 'Quick Audit'",
            "expected": "System security assessment"
        }
    ]

    print("Follow these steps to test UCS-T:")
    print("-" * 50)

    for i, test in enumerate(tests, 1):
        print(f"\n{i}. {test['module']}")
        print(f"   Tab: {test['tab']}")
        print(f"   Input: {test['test_input']}")
        print(f"   Expected: {test['expected']}")

    print("\n" + "=" * 60)
    print("🎯 INSTRUCTIONS:")
    print("1. Launch UCS-T: .\\dist\\UCS-T.exe")
    print("2. Follow the test sequence above")
    print("3. Use the RIGHT tab for each test!")
    print("4. Report any issues or unexpected results")


if __name__ == "__main__":
    quick_test()