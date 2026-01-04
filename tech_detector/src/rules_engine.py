import re
import json
import os
from typing import List, Dict, Any
from .utils import SiteData, DetectionResult

class RulesEngine:
    def __init__(self, fingerprints_path: str):
        with open(fingerprints_path, 'r') as f:
            self.data = json.load(f)
        self.technologies = self.data.get('technologies', {})
        self.categories = self.data.get('categories', {})

    def analyze(self, site_data: SiteData) -> List[DetectionResult]:
        results = []
        
        for tech_name, rules in self.technologies.items():
            confidence = 0
            evidence = []
            
            # 1. Check Headers
            if 'headers' in rules:
                for h_key, h_pattern in rules['headers'].items():
                    # Case insensitive header search
                    site_header_val = next((v for k, v in site_data.headers.items() if k.lower() == h_key.lower()), None)
                    if site_header_val:
                        if h_pattern == "" or re.search(h_pattern, site_header_val, re.IGNORECASE):
                            confidence += 50
                            evidence.append(f"Header: {h_key}")

            # 2. Check Cookies
            if 'cookies' in rules:
                for c_key, c_pattern in rules['cookies'].items():
                    if c_key in site_data.cookies:
                        confidence += 50
                        evidence.append(f"Cookie: {c_key}")

            # 3. Check Meta Tags
            if 'meta' in rules:
                for m_key, m_pattern in rules['meta'].items():
                    if m_key.lower() in site_data.meta_tags:
                        val = site_data.meta_tags[m_key.lower()]
                        if re.search(m_pattern, val, re.IGNORECASE):
                            confidence += 60
                            evidence.append(f"Meta: {m_key}")

            # 4. Check HTML (Regex on raw body)
            if 'html' in rules: # List of patterns
                for pattern in rules['html']:
                    if re.search(pattern, site_data.html, re.IGNORECASE):
                        confidence += 40
                        evidence.append(f"HTML Pattern: {pattern[:20]}...")

            # 5. Check Script Src
            if 'scriptSrc' in rules:
                for pattern in rules['scriptSrc']:
                    for script_url in site_data.scripts:
                        if re.search(pattern, script_url, re.IGNORECASE):
                            confidence += 50
                            # Deduce version if possible?
                            evidence.append(f"Script: {pattern}")
                            break

            # 6. Check JS Global Variables / Content in Bundles
            if 'js' in rules:
                for pattern in rules['js']:
                    # Check in downloaded bundles
                    found_in_bundle = False
                    for bundle_content in site_data.js_bundles.values():
                        if re.search(pattern, bundle_content):
                            confidence += 80
                            found_in_bundle = True
                            evidence.append(f"JS Bundle Pattern: {pattern}")
                            break
                    if found_in_bundle: 
                        break

            # 7. Check Favicon Hash
            if 'icon_hash' in rules and site_data.favicon_hash:
                # Can be a single string or list?
                # fingerprints often use string for hash
                if str(site_data.favicon_hash) == str(rules['icon_hash']):
                    confidence += 100
                    evidence.append("Favicon Hash Match")

            # 8. Check Probes
            if 'probe' in rules:
                for path, keyword in rules['probe'].items():
                    content = site_data.probe_content.get(path, "")
                    if content and keyword in content:
                        confidence += 100
                        evidence.append(f"Probe {path} confirmed")

            if confidence > 0:
                # Cap at 100
                confidence = min(confidence, 100)
                cat_id = str(rules.get('cats', [0])[0])
                cat_name = self.categories.get(cat_id, "Unknown")
                
                results.append(DetectionResult(
                    technology=tech_name,
                    category=cat_name,
                    confidence=confidence,
                    evidence=", ".join(evidence)
                ))

        # Handle 'implies'
        self._process_implications(results)
        
        return results

    def _process_implications(self, results: List[DetectionResult]):
        # Simple pass to add implied techs
        existing_techs = {r.technology for r in results}
        new_results = []
        
        for res in results:
            tech_rules = self.technologies.get(res.technology, {})
            if 'implies' in tech_rules:
                for implied in tech_rules['implies']:
                    if implied not in existing_techs:
                        # Add implied tech with slightly lower confidence
                        # We need to find the category for implied tech
                        implied_rules = self.technologies.get(implied, {})
                        cat_id = str(implied_rules.get('cats', [0])[0])
                        cat_name = self.categories.get(cat_id, "Unknown")
                        
                        new_results.append(DetectionResult(
                            technology=implied,
                            category=cat_name,
                            confidence=res.confidence - 10,
                            evidence=f"Implied by {res.technology}"
                        ))
                        existing_techs.add(implied)
        
        results.extend(new_results)
