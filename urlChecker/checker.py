import requests
import urllib
import sqlite3  

class IPQS:
    def __init__(self, api_key: str, strictness: int = 0):
        self.api_key = api_key
        self.strictness = strictness

    def check_url(self, url: str) -> bool:
        """Check if the URL is safe using IPQualityScore."""
        try:
            endpoint = f'https://www.ipqualityscore.com/api/json/url/{self.api_key}/{urllib.parse.quote_plus(url)}'
            params = {'strictness': self.strictness}

            response = requests.get(endpoint, params=params, timeout=10)
            data = response.json()

            if not data.get('success'):
                print(f"[IPQS] ❌ API error: {data.get('message', 'Unknown error')}")
                return False

            if data.get('suspicious') or data.get('phishing') or data.get('malware'):
                print(f"[IPQS] ⚠️ Threat detected ({data.get('risk_score')}): {url}")
                return False

            print(f"[IPQS] ✅ URL is clean: {url}")
            return True

        except Exception as e:
            print(f"[IPQS] ❌ Exception: {e}")
            return False


class GoogleSafeBrowsing:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={self.api_key}"

    def check_url(self, url: str) -> bool:
        """Check if the URL is safe using Google Safe Browsing."""
        payload = {
            "client": {
                "clientId": "aiagent",
                "clientVersion": "1.0"
            },
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }

        try:
            response = requests.post(self.endpoint, json=payload, timeout=10)
            if response.status_code == 200:
                result = response.json()
                if result.get("matches"):
                    print(f"[GSB] ⚠️ Threat detected: {url}")
                    for match in result["matches"]:
                        print("  - Type:", match["threatType"])
                    return False
                else:
                    print(f"[GSB] ✅ URL is clean: {url}")
                    return True
            else:
                print(f"[GSB] ❌ API error: {response.status_code} - {response.text}")
                return False

        except Exception as e:
            print(f"[GSB] ❌ Exception: {e}")
            return False


def is_url_safe(url: str, ipqs_key: str, gsb_key: str) -> bool:
    """Returns True if the URL passes both IPQS and GSB checks."""
    ipqs = IPQS(api_key=ipqs_key)
    gsb = GoogleSafeBrowsing(api_key=gsb_key)

    print(f"\n🔍 Checking URL: {url}")
    ipqs_result = ipqs.check_url(url)
    gsb_result = gsb.check_url(url)

    is_safe = ipqs_result and gsb_result
    print("✅ Final verdict: SAFE" if is_safe else "❌ Final verdict: UNSAFE")
    return is_safe


# Example usage
if __name__ == "__main__":
    IPQS_API_KEY = "YOUR_IPQS_API_KEY"
    GSB_API_KEY = "YOUR_GSB_API_KEY"

    test_url = "https://testsafebrowsing.appspot.com/s/phishing.html"

    if is_url_safe(test_url, ipqs_key=IPQS_API_KEY, gsb_key=GSB_API_KEY):
        print("URL is safe. Saving results in db ....")
    else
        print("Malicious URL. Saving results in db ....")
