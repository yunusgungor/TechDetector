import requests
import uuid
from urllib.parse import urljoin
from .utils import DetectionResult
import re

class ErrorFingerprinter:
    def analyze(self, url: str) -> list[DetectionResult]:
        # Generate a random non-existent path
        error_url = urljoin(url, f"/{uuid.uuid4()}")
        results = []
        
        try:
            resp = requests.get(error_url, timeout=5, verify=False)
            # We expect 404, but the headers or body might reveal info
            
            evidence = []
            
            # Check Server Header (often revealed on defaults)
            server = resp.headers.get("Server")
            if server:
                evidence.append(f"Server Header: {server}")
                
            # Check Body for version patterns (e.g. Apache/2.4.5)
            # Simple regex for common servers
            patterns = [
                r"Apache/[\d\.]+",
                r"nginx/[\d\.]+",
                r"Microsoft-IIS/[\d\.]+",
                r"Tomcat/[\d\.]+"
            ]
            
            for pat in patterns:
                match = re.search(pat, resp.text)
                if match:
                    evidence.append(f"Body Leak: {match.group(0)}")
            
            if evidence:
                results.append(DetectionResult(
                    technology="Server Leaks (Error Page)",
                    category="Infrastructure",
                    confidence=100,
                    evidence=", ".join(evidence)
                ))
                
        except:
            pass
            
        return results
