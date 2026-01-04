import re
from typing import List, Dict
from .utils import DetectionResult, SiteData

class SecretScanner:
    # High-confidence patterns for common secrets
    PATTERNS = {
        'Amazon AWS Access Key': r'(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}',
        'Google API Key': r'AIza[0-9A-Za-z\\-_]{35}',
        'Google OAuth': r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com',
        'Stripe Publishable Key': r'pk_live_[0-9a-zA-Z]{24}',
        'Stripe Secret Key': r'sk_live_[0-9a-zA-Z]{24}',
        'Facebook Access Token': r'EAACEdEose0cBA[0-9A-Za-z]+',
        'Slack Token': r'xox[baprs]-[0-9a-zA-Z]{10,48}',
        'GitHub Personal Access Token': r'ghp_[0-9a-zA-Z]{36}',
        'Mailgun API Key': r'key-[0-9a-zA-Z]{32}',
        'Twilio API Key': r'SK[0-9a-fA-F]{32}',
        'Firebase URL': r'[a-z0-9.-]+\.firebaseio\.com',
        'Algolia Application ID': r'algoliasearch\s*\(\s*["\']([A-Z0-9]{10})["\']', # Context-aware
        'Heroku API Key': r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
        'RSA Private Key': r'-----BEGIN RSA PRIVATE KEY-----',
        'SSH Private Key': r'-----BEGIN OPENSSH PRIVATE KEY-----',
        'Generic API Key': r'(?i)(api_key|apikey|access_token|auth_token)\s*[:=]\s*[\"\']([a-z0-9\\-]{32,})[\"\']'
    }

    def scan(self, data: SiteData) -> List[DetectionResult]:
        results = []
        found_secrets = set()
        
        # Helper to scan text content
        def scan_text(text, source_name):
            if not text: return
            
            for name, pattern in self.PATTERNS.items():
                try:
                    matches = re.finditer(pattern, text) # Use finditer for grouping
                except re.error:
                    continue # Skip bad regexes
                hit_count = 0
                
                for match_obj in matches:
                    if hit_count >= 3: # Limit false positive flooding
                        break
                        
                    # Handle groups - simplified logic
                    if match_obj.groups():
                        match = match_obj.group(1) 
                    else:
                        match = match_obj.group(0)

                    # Obfuscate part of the key for the report/evidence
                    visible_part = match[:4] + "..." + match[-4:] if len(match) > 8 else match
                    key = f"{name}:{match}" # Use full match for strict dedup
                    
                    if key not in found_secrets:
                        found_secrets.add(key)
                        results.append(DetectionResult(
                            technology="Leaked Secret",
                            category="Security Risk",
                            confidence=100,
                            evidence=f"Found {name} in {source_name}: {visible_part}"
                        ))
                        hit_count += 1

        # 1. Scan HTML
        scan_text(data.html, "HTML")

        # 2. Scan JS Bundles
        for url, content in data.js_bundles.items():
            filename = url.split('/')[-1]
            scan_text(content, f"JS File ({filename})")

        return results
