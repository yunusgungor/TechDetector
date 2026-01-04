import re
import json
import os
from typing import List, Dict, Any
from .utils import SiteData, DetectionResult

class RulesEngine:
    def __init__(self, fingerprints_path: str):
        with open(fingerprints_path, 'r') as f:
            self.data = json.load(f)
        self.technologies = self.data.get('technologies', [])
        # self.categories is no longer needed as category name is embedded

    def analyze(self, site_data: SiteData) -> List[DetectionResult]:
        results = []
        
        for rule in self.technologies:
            tech_name = rule.get('name')
            confidence = 0
            evidence = []
            version = None

            # Helper to update version if found
            def update_version(match):
                nonlocal version
                if match and match.groups():
                    version = match.group(1)

            # 1. Check Headers
            if 'headers' in rule:
                for h_key, h_pattern in rule['headers'].items():
                    # Case insensitive header search
                    site_header_val = next((v for k, v in site_data.headers.items() if k.lower() == h_key.lower()), None)
                    if site_header_val:
                        if h_pattern == "":
                            confidence += 50
                            evidence.append(f"Header: {h_key}")
                        else:
                            match = re.search(h_pattern, site_header_val, re.IGNORECASE)
                            if match:
                                confidence += 50
                                evidence.append(f"Header: {h_key}")
                                update_version(match)

            # 2. Check Cookies
            if 'cookies' in rule:
                for c_key, c_pattern in rule['cookies'].items():
                    if c_key in site_data.cookies:
                        confidence += 50
                        evidence.append(f"Cookie: {c_key}")

            # 3. Check Meta Tags
            if 'meta' in rule:
                for m_key, m_pattern in rule['meta'].items():
                    if m_key.lower() in site_data.meta_tags:
                        val = site_data.meta_tags[m_key.lower()]
                        match = re.search(m_pattern, val, re.IGNORECASE)
                        if match:
                            confidence += 60
                            evidence.append(f"Meta: {m_key}")
                            update_version(match)

            # 4. Check HTML
            if 'html' in rule: 
                for pattern in rule['html']:
                    match = re.search(pattern, site_data.html, re.IGNORECASE)
                    if match:
                        confidence += 40
                        evidence.append(f"HTML Pattern: {pattern[:20]}...")
                        update_version(match)

            # 5. Check Script Src
            if 'script_src' in rule:
                for pattern in rule['script_src']:
                    for script_url in site_data.scripts:
                        match = re.search(pattern, script_url, re.IGNORECASE)
                        if match:
                            confidence += 50
                            evidence.append(f"Script: {pattern}")
                            update_version(match)
                            break

            # 6. Check JS Global Variables / Content in Bundles
            if 'js' in rule:
                for pattern in rule['js']:
                    # Check in downloaded bundles
                    found_in_bundle = False
                    for bundle_content in site_data.js_bundles.values():
                        match = re.search(pattern, bundle_content)
                        if match:
                            confidence += 80
                            found_in_bundle = True
                            evidence.append(f"JS Bundle Pattern: {pattern}")
                            update_version(match)
                            break
                    if found_in_bundle: 
                        break

            # 7. Check Favicon Hash
            if 'icon_hash' in rule and site_data.favicon_hash:
                if str(site_data.favicon_hash) == str(rule['icon_hash']):
                    confidence += 100
                    evidence.append("Favicon Hash Match")

            # 8. Check Probes
            if 'probe' in rule:
                for path, keyword in rule['probe'].items():
                    content = site_data.probe_content.get(path, "")
                    if content and keyword in content:
                        confidence += 100
                        evidence.append(f"Probe {path} confirmed")

            if confidence > 0:
                confidence = min(confidence, 100)
                cat_name = rule.get('category', "Unknown")
                
                results.append(DetectionResult(
                    technology=tech_name,
                    category=cat_name,
                    confidence=confidence,
                    evidence=", ".join(evidence),
                    version=version
                ))

        # Handle 'implies'
        self._process_implications(results)
        
        return results

    def _process_implications(self, results: List[DetectionResult]):
        # Simple pass to add implied techs
        existing_techs = {r.technology for r in results}
        new_results = []
        
        # Create a lookup for rules by name
        rules_by_name = {r['name']: r for r in self.technologies}
        
        for res in results:
            tech_rule = rules_by_name.get(res.technology)
            if tech_rule and 'imply' in tech_rule: # Changed from implies to imply based on JSON
                for implied in tech_rule['imply']:
                    if implied not in existing_techs:
                        implied_rule = rules_by_name.get(implied)
                        if implied_rule:
                            new_results.append(DetectionResult(
                                technology=implied,
                                category=implied_rule.get('category', 'Unknown'),
                                confidence=max(res.confidence - 10, 50),
                                evidence=f"Implied by {res.technology}"
                            ))
                            existing_techs.add(implied)
        
        results.extend(new_results)
