from typing import Dict, List, Tuple
from .utils import DetectionResult

class SecurityAuditor:
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
        
        # We return a special 'Technology' result representing the grade
        return [DetectionResult(
            technology=f"Security Grade: {grade}",
            category="Security Audit",
            confidence=100,
            evidence=f"Score: {score}/100. Missing {missing_count} critical headers."
        )]
