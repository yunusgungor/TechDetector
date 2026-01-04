import requests
from urllib.parse import urlparse
from typing import List
from .utils import DetectionResult

class RDAPClient:
    def analyze(self, url: str) -> List[DetectionResult]:
        results = []
        try:
            domain = urlparse(url).netloc
            if ":" in domain:
                domain = domain.split(":")[0]
            
            # Use rdap.org as a bootstrap/proxy or query IANA/Regional RIRs
            # rdap.org is a reliable open redirector
            rdap_url = f"https://rdap.org/domain/{domain}"
            
            resp = requests.get(rdap_url, timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                
                # 1. Registrar
                registrar = "Unknown"
                if 'entities' in data:
                    for entity in data['entities']:
                        if 'roles' in entity and 'registrar' in entity['roles']:
                            if 'vcardArray' in entity and len(entity['vcardArray']) > 1:
                                # Parse vcard junk: ['vcard', [['version', {}, 'text', '4.0'], ['fn', {}, 'text', 'Name']]]
                                for item in entity['vcardArray'][1]:
                                    if item[0] == 'fn':
                                        registrar = item[3]
                                        break
                
                if registrar != "Unknown":
                    results.append(DetectionResult(
                        technology=f"Registrar: {registrar}",
                        category="Domain Intelligence",
                        confidence=100,
                        evidence="RDAP Query"
                    ))
                
                # 2. Dates
                if 'events' in data:
                    for event in data['events']:
                        action = event.get('eventAction')
                        date = event.get('eventDate')
                        if action == 'registration':
                            results.append(DetectionResult(
                                technology=f"Registered: {date[:10]}",
                                category="Domain Intelligence",
                                confidence=100,
                                evidence="RDAP Registration Date"
                            ))
                        elif action == 'expiration':
                             results.append(DetectionResult(
                                technology=f"Expires: {date[:10]}",
                                category="Domain Intelligence",
                                confidence=100,
                                evidence="RDAP Expiration Date"
                            ))

        except Exception:
            pass
            
        return results
