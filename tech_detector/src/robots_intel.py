import requests
from urllib.parse import urljoin
from .utils import DetectionResult

class RobotsIntelligence:
    def analyze(self, url: str) -> list[DetectionResult]:
        robots_url = urljoin(url, "/robots.txt")
        results = []
        hidden_paths = []
        
        try:
            # Use a basic fetch (or pass fetcher)
            HEADERS = {
                'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
            }
            resp = requests.get(robots_url, headers=HEADERS, timeout=5, verify=False)
            if resp.status_code == 200:
                lines = resp.text.splitlines()
                for line in lines:
                    line = line.strip()
                    if line.lower().startswith("disallow:"):
                        path = line.split(":", 1)[1].strip()
                        if path and path != "/":
                            # Basic checking for sensitive keywords
                            if any(x in path.lower() for x in ['admin', 'backend', 'config', 'backup', 'private', 'api', 'dashboard']):
                                hidden_paths.append(path)
                                
        except:
            pass
            
        if hidden_paths:
            # Dedup
            hidden_paths = list(set(hidden_paths))
            results.append(DetectionResult(
                technology=f"Found {len(hidden_paths)} Hidden Paths",
                category="Reconnaissance",
                confidence=100,
                evidence=f"Robots.txt Disallow: {', '.join(hidden_paths[:5])}..."
            ))
            
        return results
