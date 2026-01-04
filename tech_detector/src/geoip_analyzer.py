import requests
import socket
from urllib.parse import urlparse
from .utils import DetectionResult

# User-Agent to avoid blocking
HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
}

class GeoIPAnalyzer:
    def analyze(self, url: str) -> list[DetectionResult]:
        results = []
        try:
            domain = urlparse(url).netloc
            if ":" in domain:
                domain = domain.split(":")[0]
                
            # Resolve IP
            ip_address = socket.gethostbyname(domain)
            results.append(DetectionResult(
                technology=f"IP: {ip_address}",
                category="Infrastructure",
                confidence=100,
                evidence=f"DNS Resolution for {domain}"
            ))
            
            # Query free GeoIP API (ip-api.com is common for free use)
            # Note: Rate limited to 45 requests per minute
            api_url = f"http://ip-api.com/json/{ip_address}"
            resp = requests.get(api_url, headers=HEADERS, timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                if data.get('status') == 'success':
                    country = data.get('country', 'Unknown')
                    city = data.get('city', 'Unknown')
                    isp = data.get('isp', 'Unknown')
                    org = data.get('org', 'Unknown')
                    
                    location = f"{city}, {country}"
                    
                    results.append(DetectionResult(
                        technology=f"Location: {location}",
                        category="Geo-Location",
                        confidence=100,
                        evidence=f"GeoIP Lookup"
                    ))
                    
                    results.append(DetectionResult(
                        technology=f"ISP: {isp}",
                        category="Infrastructure",
                        confidence=100,
                        evidence=f"Organization: {org}"
                    ))
                    
        except Exception as e:
            # results.append(DetectionResult("GeoIP Failed", "Error", 0, str(e)))
            pass
            
        return results
