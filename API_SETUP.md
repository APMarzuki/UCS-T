# 🔑 API Key Setup Guide for UCS-T

## Step 1: Get Your API Keys

### VirusTotal
1. Go to https://www.virustotal.com/
2. Create free account
3. Go to your profile → API Key
4. Copy your personal API key

### AbuseIPDB  
1. Go to https://www.abuseipdb.com/
2. Register for free account
3. Go to Account → API Key
4. Generate and copy your API key

### AlienVault OTX
1. Go to https://otx.alienvault.com/
2. Sign up for free account
3. Go to Settings → API Key
4. Copy your API key

## Step 2: Configure API Keys

Edit `core/api_config.py` and replace:

```python
# Replace these placeholder values with your actual API keys:

VIRUSTOTAL_API_KEY = "YOUR_ACTUAL_VIRUSTOTAL_API_KEY_HERE"
ABUSEIPDB_API_KEY = "YOUR_ACTUAL_ABUSEIPDB_API_KEY_HERE"  
OTX_API_KEY = "YOUR_ACTUAL_OTX_API_KEY_HERE"