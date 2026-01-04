import dns.resolver
from typing import List, Dict
from urllib.parse import urlparse
from .utils import DetectionResult

class DNSIntelligence:
    def analyze(self, url: str) -> List[DetectionResult]:
        results = []
        domain = urlparse(url).netloc
        
        try:
            # 1. Check MX Records (Email Providers)
            mx_records = dns.resolver.resolve(domain, 'MX')
            for mx in mx_records:
                exchange = str(mx.exchange).lower()
                if 'google.com' in exchange or 'googlemail.com' in exchange:
                    results.append(DetectionResult("Google Workspace", "Email", 100, f"MX: {exchange}"))
                    break # Avoid duplicates
                elif 'outlook.com' in exchange or 'protection.outlook.com' in exchange:
                    results.append(DetectionResult("Microsoft 365", "Email", 100, f"MX: {exchange}"))
                    break
                elif 'zoho.com' in exchange:
                    results.append(DetectionResult("Zoho Mail", "Email", 100, f"MX: {exchange}"))
                    break
                elif 'yandex.net' in exchange:
                    results.append(DetectionResult("Yandex Mail", "Email", 100, f"MX: {exchange}"))
                    break

            # 2. Check TXT Records (Verifications)
            txt_records = dns.resolver.resolve(domain, 'TXT')
            for txt in txt_records:
                # content is a list of byte strings usually
                content = b"".join(txt.strings).decode('utf-8').lower()
                
                if 'facebook-domain-verification' in content:
                    results.append(DetectionResult("Facebook Business", "Marketing", 100, "TXT Verification"))
                elif 'google-site-verification' in content:
                    results.append(DetectionResult("Google Search Console", "SEO", 100, "TXT Verification"))
                elif 'stripe-verification' in content:
                    results.append(DetectionResult("Stripe", "Payment Processors", 100, "TXT Verification"))
                elif 'atlassian-domain-verification' in content:
                    results.append(DetectionResult("Atlassian Cloud", "SaaS", 100, "TXT Verification"))
                elif 'ms=' in content: # MS verification
                    results.append(DetectionResult("Microsoft 365", "Email", 80, "TXT Verification"))
                elif 'spf.protection.outlook.com' in content:
                     # SPF record also indicates usage
                     pass 

        except Exception as e:
            # DNS errors happen (no records, timeout)
            pass
            
        return results
