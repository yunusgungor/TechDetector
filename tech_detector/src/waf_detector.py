from typing import List, Dict
from .utils import DetectionResult

class WAFDetector:
    # Known WAF Signatures in Headers or Cookies
    SIGNATURES = {
        'Cloudflare': {
            'headers': ['cf-ray', 'cf-cache-status', 'server:cloudflare'],
            'cookies': ['__cfduid']
        },
        'AWS WAF': {
            'headers': ['x-amzn-requestid', 'x-amz-id-2'],
            'cookies': ['aws-waf-token']
        },
        'Akamai': {
            'headers': ['x-akamai-transformed', 'x-akamai-request-id'],
        },
        'Imperva Incapsula': {
            'headers': ['x-cdn:incapsula'],
            'cookies': ['incap_ses', 'visid_incap']
        },
        'F5 BIG-IP': {
            'cookies': ['bigipserver', 'f5_cspm']
        },
        'Sucuri': {
            'headers': ['x-sucuri-id'],
            'cookies': ['sucuri_cloudproxyid']
        },
        'Barracuda WAF': {
            'cookies': ['barra_counter_session']
        },
        'Citrix NetScaler': {
            'headers': ['ns_af'],
            'cookies': ['ns_af']
        }
    }

    def detect(self, headers: Dict[str, str], cookies: Dict[str, str]) -> List[DetectionResult]:
        if not headers: headers = {}
        if not cookies: cookies = {}
        
        results = []
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
        
        for waf_name, signs in self.SIGNATURES.items():
            confidence = 0
            evidence = []
            
            # Check Headers
            if 'headers' in signs:
                for sign in signs['headers']:
                    if ':' in sign:
                        key, val = sign.split(':', 1)
                        if key in headers_lower and val in headers_lower[key]:
                            confidence += 100
                            evidence.append(f"Header: {key}={val}")
                    else:
                        if sign in headers_lower:
                            confidence += 80
                            evidence.append(f"Header: {sign}")

            # Check Cookies
            if 'cookies' in signs:
                for cookie in signs['cookies']:
                    if any(cookie in c for c in cookies):
                        confidence += 60
                        evidence.append(f"Cookie: {cookie}")
            
            if confidence > 0:
                results.append(DetectionResult(
                    technology=waf_name,
                    category="WAF / Firewall",
                    confidence=min(100, confidence),
                    evidence=", ".join(evidence)
                ))
                
        return results
