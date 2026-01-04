from typing import Dict, List, Tuple
from .utils import DetectionResult
import json
import os
import re

class SecurityAuditor:
    def __init__(self):
         base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
         vuln_path = os.path.join(base_dir, 'data', 'vulnerabilities.json')
         try:
             with open(vuln_path, 'r') as f:
                 self.vuln_db = json.load(f)
         except:
             self.vuln_db = {}

    def audit(self, headers: Dict[str, str]) -> List[DetectionResult]:
        score = 100
        findings = []
        
        # Headers to check
        checks = {
            'Strict-Transport-Security': 20,
            'Content-Security-Policy': 25,
            'X-Frame-Options': 15,
            'X-Content-Type-Options': 10,
            'Referrer-Policy': 10,
            'Permissions-Policy': 10
        }
        
        missing_count = 0
        
        for header, weight in checks.items():
            # Case insensitive check
            val = next((v for k, v in headers.items() if k.lower() == header.lower()), None)
            if not val:
                score -= weight
                missing_count += 1
            else:
                findings.append(f"{header} Present")

        # Determine Grade
        grade = "F"
        if score >= 90: grade = "A+"
        elif score >= 80: grade = "A"
        elif score >= 70: grade = "B"
        elif score >= 60: grade = "C"
        elif score >= 50: grade = "D"
        
        return [DetectionResult(
            technology=f"Security Grade: {grade}",
            category="Security Audit",
            confidence=100,
            evidence=f"Score: {score}/100. Missing {missing_count} critical headers."
        )]

    def check_vulnerabilities(self, detected_techs: List[DetectionResult]) -> List[DetectionResult]:
        vuln_results = []
        
        # Helper to strict version compare
        def is_vulnerable(current_ver, max_ver):
            try:
                # Simple loose comparison for demo (ideal: packaging.version)
                parts_cur = [int(x) for x in current_ver.split('.') if x.isdigit()]
                parts_max = [int(x) for x in max_ver.split('.') if x.isdigit()]
                return parts_cur < parts_max
            except:
                return False

        for tech in detected_techs:
            if tech.technology in self.vuln_db and tech.version:
                entries = self.vuln_db[tech.technology]['rules']
                for entry in entries:
                    if is_vulnerable(tech.version, entry['max_version']):
                        vuln_results.append(DetectionResult(
                            technology=f"Vulnerable {tech.technology}",
                            category="Vulnerability",
                            confidence=90,
                            evidence=f"Ver: {tech.version} < {entry['max_version']} | {entry['severity']} | {entry['cve']}: {entry['description']}"
                        ))
                        break # One vuln per tech is enough for noise reduction
        return vuln_results
