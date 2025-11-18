"""
API Key Configuration for UCS-T
ADD YOUR REAL API KEYS HERE
"""

class APIConfig:
    """
    REPLACE THE PLACEHOLDERS WITH YOUR ACTUAL API KEYS!
    """

    # ==== YOUR REAL API KEYS ====
    VIRUSTOTAL_API_KEY = "0e73289b7682d6c147a2b67e017d5959e1b41acdf70f2098028cb9ebbea0c20c"  # Your 64-character VT key
    ABUSEIPDB_API_KEY = "32945ece2a822c4f22dd17f0926c090cdb1fd042c3fd7566546aaaecfb13ae2b370c1b2a978cd41d"    # Your AbuseIPDB key
    OTX_API_KEY = "1ed829b654dea2cfb2cb3f5c81009ec611e4d2f69747ee3cc06fc93180988848"      # Your OTX key
    # Add any other API keys you have

    # ==== API Endpoints ====
    VIRUSTOTAL_URL = "https://www.virustotal.com/vtapi/v2/"
    ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/"
    OTX_URL = "https://otx.alienvault.com/api/v1/"


def check_api_status():
    """Check which APIs are configured - ADD THIS FUNCTION"""
    config = APIConfig()
    status = []

    apis = [
        ("VirusTotal", config.VIRUSTOTAL_API_KEY),
        ("AbuseIPDB", config.ABUSEIPDB_API_KEY),
        ("OTX", config.OTX_API_KEY)
    ]

    for name, key in apis:
        if key and "YOUR_" not in key:
            status.append(f"✅ {name}")
        else:
            status.append(f"❌ {name} (not configured)")

    return status