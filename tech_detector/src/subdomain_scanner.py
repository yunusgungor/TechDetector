import socket
from urllib.parse import urlparse
from typing import List
from .utils import DetectionResult
import concurrent.futures

class SubdomainScanner:
    COMMON_SUBS = ['www', 'mail', 'remote', 'blog', 'webmail', 'server', 'ns1', 'ns2', 'smtp', 'secure', 'vpn', 'm', 'shop', 'ftp', 'mail2', 'test', 'portal', 'ns', 'ww1', 'host', 'support', 'dev', 'web', 'bbs', 'ww2', 'error', 'ww3', 'www1', 'www2', 'www3', 'www4', 'www5', 'www6', 'www7', 'www8', 'www9', 'beta', 'admin', 'api', 'cdn', 'app', 'staging']

    def scan(self, url: str) -> List[DetectionResult]:
        domain = urlparse(url).netloc
        # remove www. if present to get base domain
        if domain.startswith('www.'):
            domain = domain[4:]
            
        found_subs = []
        
        def check_sub(sub):
            target = f"{sub}.{domain}"
            try:
                socket.gethostbyname(target)
                return target
            except:
                return None

        # Parallel check
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            future_to_sub = {executor.submit(check_sub, sub): sub for sub in self.COMMON_SUBS}
            for future in concurrent.futures.as_completed(future_to_sub):
                result = future.result()
                if result:
                    found_subs.append(result)
        
        if found_subs:
            return [DetectionResult(
                technology=f"Found {len(found_subs)} Subdomains",
                category="Reconnaissance",
                confidence=100,
                evidence=", ".join(found_subs[:5]) + ("..." if len(found_subs) > 5 else "")
            )]
        return []
