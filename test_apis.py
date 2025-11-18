#!/usr/bin/env python3
"""
Test API Integrations for UCS-T - UPDATED VERSION
"""

import sys
import os

# Add current directory to path
sys.path.append(os.path.dirname(__file__))


def test_apis():
    print("🔧 Testing UCS-T API Configuration...")
    print("=" * 60)

    try:
        # Test API config import
        from core.api_config import APIConfig

        print("✅ API config imported successfully!")
        print("\n📋 API Key Status:")
        print("-" * 30)

        # Manual check instead of using missing function
        config = APIConfig()

        apis = [
            ("VirusTotal", config.VIRUSTOTAL_API_KEY),
            ("AbuseIPDB", config.ABUSEIPDB_API_KEY),
            ("OTX", config.OTX_API_KEY)
        ]

        for name, key in apis:
            if key and "YOUR_" not in key:
                print(f"✅ {name} - Configured")
            else:
                print(f"❌ {name} - Not configured")

        print("\n🧪 Testing API Client...")
        print("-" * 30)

        # Test ScamAPI
        from modules.scam_advisor.api_client import ScamAPI

        api = ScamAPI()
        print("✅ ScamAPI initialized successfully")

        # Test with a safe domain
        test_domain = "google.com"
        print(f"\n🔍 Testing APIs with: {test_domain}")
        print("-" * 40)

        # Test VirusTotal
        print("1. Testing VirusTotal...")
        vt_result = api.check_virustotal_domain(test_domain)
        print(f"   Result: {vt_result.get('status', 'unknown')}")
        if vt_result.get('status') == 'success':
            detection_ratio = vt_result.get('detection_ratio', 'N/A')
            print(f"   ✅ VirusTotal working! Historical scans: {detection_ratio}")
            print(f"   💡 Note: These are historical URL scans, not current malware")
        else:
            print(f"   ⚠️ {vt_result.get('message', 'Check API key')}")

        # Test OTX
        print("\n2. Testing AlienVault OTX...")
        otx_result = api.check_otx_domain(test_domain)
        print(f"   Result: {otx_result.get('status', 'unknown')}")
        if otx_result.get('status') == 'success':
            pulse_count = otx_result.get('pulse_count', 0)
            print(f"   ✅ OTX working! Threat pulses: {pulse_count}")
        else:
            print(f"   ⚠️ {otx_result.get('message', 'Check API key')}")

        print("\n" + "=" * 60)
        print("🎉 API Testing Complete!")

        # Summary
        print("\n📊 Summary:")
        working_apis = []
        if vt_result.get('status') == 'success':
            working_apis.append("VirusTotal")
        if otx_result.get('status') == 'success':
            working_apis.append("OTX")

        if working_apis:
            print(f"✅ Working APIs: {', '.join(working_apis)}")
            print(f"🎯 Your UCS-T is ready for real cybersecurity work!")
        else:
            print("❌ No APIs working. Check your API keys.")

    except ImportError as e:
        print(f"❌ Import error: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")


if __name__ == "__main__":
    test_apis()