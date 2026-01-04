import requests
import concurrent.futures
from urllib.parse import urljoin
from typing import List
from .utils import DetectionResult

class APIDiscovery:
    # Common endpoints for API Docs and Interfaces
    ENDPOINTS = [
        '/swagger.json',
        '/openapi.json',
        '/api/docs',
        '/api/v1/docs',
        '/docs',
        '/documentation',
        '/swagger-ui.html',
        '/swagger/index.html',
        '/graphql',
        '/graphiql',
        '/api-docs',
        '/v2/api-docs',
        '/actuator',
        '/actuator/health'
    ]

    def scan(self, url: str) -> List[DetectionResult]:
        results = []
        
        def check_endpoint(path):
            target = urljoin(url, path)
            try:
                # Use a short timeout
                resp = requests.get(target, timeout=3, verify=False, allow_redirects=True)
                if resp.status_code == 200:
                    # Basic validation to ensure it's not just a custom 200 page
                    content_type = resp.headers.get('Content-Type', '').lower()
                    text = resp.text.lower()
                    
                    is_valid = False
                    
                    # Swagger/OpenAPI validation
                    if 'json' in path and ('swagger' in text or 'openapi' in text):
                        is_valid = True
                    elif 'graphql' in path and ('query' in text or 'graphql' in text or 'json' in content_type):
                         is_valid = True
                    elif 'actuator' in path and 'status' in text:
                        is_valid = True
                    elif 'html' in path and ('swagger' in text or 'api' in text):
                        is_valid = True
                        
                    if is_valid:
                        return DetectionResult(
                            technology="Exposed API Endpoint",
                            category="API Discovery",
                            confidence=100,
                            evidence=f"Found accessible {path} (Status: 200)"
                        )
            except:
                pass
            return None

        # Threaded scan
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            future_to_path = {executor.submit(check_endpoint, p): p for p in self.ENDPOINTS}
            for future in concurrent.futures.as_completed(future_to_path):
                res = future.result()
                if res:
                    results.append(res)
        
        return results
