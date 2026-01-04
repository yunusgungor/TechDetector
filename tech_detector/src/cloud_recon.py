import requests
import concurrent.futures
from typing import List
from urllib.parse import urlparse
from .utils import DetectionResult

class CloudRecon:
    # Common bucket naming patterns
    PATTERNS = [
        '{domain}',
        '{domain}-assets',
        '{domain}-static',
        '{domain}-backup',
        '{domain}-media',
        '{domain}-logs',
        '{name}',
        '{name}-assets',
        '{name}-backup'
    ]
    
    # Cloud Providers
    PROVIDERS = {
        'AWS S3': 'https://{bucket}.s3.amazonaws.com',
        'Azure Blob': 'https://{bucket}.blob.core.windows.net',
        'GCP Storage': 'https://storage.googleapis.com/{bucket}'
    }
    
    # Stealth Headers
    HEADERS = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    }

    def scan(self, url: str) -> List[DetectionResult]:
        domain = urlparse(url).netloc
        if domain.startswith('www.'):
            domain = domain[4:]
        
        name = domain.split('.')[0]
        results = []
        
        # Generate candidates
        candidates = []
        for pat in self.PATTERNS:
            candidates.append(pat.format(domain=domain, name=name))
            
        def check_bucket(bucket_name, provider_name, url_template):
            target = url_template.format(bucket=bucket_name)
            try:
                # Fast checking
                resp = requests.head(target, headers=self.HEADERS, timeout=3, verify=False)
                
                if resp.status_code in [200, 403]: # 200 (Open), 403 (Exists but Private)
                    return (provider_name, bucket_name, resp.status_code, target)
            except:
                pass
            return None

        # Threaded Scan
        tasks = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            for bucket in candidates:
                for prov, templ in self.PROVIDERS.items():
                    tasks.append(executor.submit(check_bucket, bucket, prov, templ))
                    
            for future in concurrent.futures.as_completed(tasks):
                res = future.result()
                if res:
                    prov, buck, status, link = res
                    
                    access_level = "Public (Open)" if status == 200 else "Private (Exists)"
                    severity = 100 if status == 200 else 50
                    
                    results.append(DetectionResult(
                        technology=f"{prov} Bucket Found",
                        category="Cloud Assets",
                        confidence=severity,
                        evidence=f"Bucket: {buck} ({access_level}) - {link}"
                    ))
                    
        return results
