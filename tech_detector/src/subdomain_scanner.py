import requests
import socket
import dns.resolver
from urllib.parse import urlparse
from typing import List
from .utils import DetectionResult
import concurrent.futures

class SubdomainScanner:
    COMMON_SUBS = ['www', 'mail', 'remote', 'blog', 'webmail', 'server', 'ns1', 'ns2', 'smtp', 'secure', 'vpn', 'm', 'shop', 'ftp', 'mail2', 'test', 'portal', 'ns', 'ww1', 'host', 'support', 'dev', 'web', 'bbs', 'ww2', 'error', 'ww3', 'www1', 'www2', 'www3', 'www4', 'www5', 'www6', 'www7', 'www8', 'www9', 'beta', 'admin', 'api', 'cdn', 'app', 'staging', 'jenkins', 'jira', 'gitlab']

    TAKEOVER_SIGNATURES = {
        'github.io': 'GitHub Pages',
        'herokuapp.com': 'Heroku',
        'amazonaws.com': 'AWS (S3/ElasticBeanstalk)',
        'azurewebsites.net': 'Azure App Service',
        'cloudapp.net': 'Azure Cloud Service',
        'elasticbeanstalk.com': 'AWS Elastic Beanstalk',
        'cloudfront.net': 'AWS CloudFront',
        'trafficmanager.net': 'Azure Traffic Manager',
        'shop.myshopify.com': 'Shopify',
        'wpengine.com': 'WP Engine'
    }

    def scan(self, url: str) -> List[DetectionResult]:
        domain = urlparse(url).netloc
        if domain.startswith('www.'):
            domain = domain[4:]
            
        found_subs = set()
        
        # 1. Bruteforce common subdomains
        def check_sub(sub):
            target = f"{sub}.{domain}"
            try:
                socket.gethostbyname(target)
                return target
            except:
                return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            future_to_sub = {executor.submit(check_sub, sub): sub for sub in self.COMMON_SUBS}
            for future in concurrent.futures.as_completed(future_to_sub):
                if future.result():
                    found_subs.add(future.result())

        # 2. CRT.sh (Certificate Transparency)
        try:
            r = requests.get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=10)
            if r.status_code == 200:
                data = r.json()
                for entry in data:
                    name_value = entry.get('name_value', '')
                    for sub in name_value.split('\n'):
                        if '*' not in sub and domain in sub:
                            found_subs.add(sub)
        except Exception:
            pass # Fail silently if crt.sh is down

        results = []
        
        if found_subs:
            # Sort and limit evidence
            sorted_subs = sorted(list(found_subs))
            results.append(DetectionResult(
                technology=f"Found {len(found_subs)} Subdomains",
                category="Reconnaissance",
                confidence=100,
                evidence=",".join(sorted_subs[:10]) + ("..." if len(found_subs) > 10 else "")
            ))
            
            # 3. Check for Subdomain Takeover
            # Only check a subset to avoid massive DNS queries if 1000 subs found
            takeover_candidates = []
            
            for sub in list(found_subs)[:20]:
                try:
                    answers = dns.resolver.resolve(sub, 'CNAME')
                    for rdata in answers:
                        cname = str(rdata.target).rstrip('.')
                        for fingerprint, platform in self.TAKEOVER_SIGNATURES.items():
                            if fingerprint in cname:
                                takeover_candidates.append(f"{sub} -> {cname} ({platform})")
                except:
                    pass
            
            if takeover_candidates:
                results.append(DetectionResult(
                    technology="Potential Subdomain Takeover",
                    category="Security Risk",
                    confidence=90,
                    evidence="; ".join(takeover_candidates)
                ))

        return results
