import re
from typing import List
from .utils import DetectionResult

class OSINTCollector:
    def collect(self, html: str) -> List[DetectionResult]:
        if not html:
            return []
        results = []
        
        # Email Regex (Simple but effective)
        # Avoid common false positives like "bootstrap@5.0.0" or "image@2x.png"
        email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        
        # Social Media Patterns
        socials = {
            'LinkedIn': r'linkedin\.com/in/([a-zA-Z0-9\-_]+)',
            'Twitter/X': r'(twitter\.com|x\.com)/([a-zA-Z0-9_]{1,15})',
            'Facebook': r'facebook\.com/([a-zA-Z0-9\.]+)',
            'Instagram': r'instagram\.com/([a-zA-Z0-9_\.]+)',
            'GitHub': r'github\.com/([a-zA-Z0-9\-]+)',
            'YouTube': r'youtube\.com/(channel/|user/|c/|@)([a-zA-Z0-9\-_]+)'
        }
        
        # Phone Extensions (Loose)
        phone_pattern = r'(\+\d{1,3}[\s-]?\d{1,4}[\s-]?\d{3,4}[\s-]?\d{3,4})'

        # 1. Extract Emails
        try:
            potential_emails = set(re.findall(email_pattern, html))
            valid_emails = []
            for email in potential_emails:
                # Filter out obvious non-emails often found in code
                if any(x in email.lower() for x in ['.png', '.jpg', '.svg', '.js', '.css', 'node_modules', 'example.com', 'yourdomain.com', 'user@']):
                    continue
                valid_emails.append(email)
            
            if valid_emails:
                results.append(DetectionResult(
                    technology=f"Found {len(valid_emails)} Emails",
                    category="OSINT",
                    confidence=100,
                    evidence=", ".join(valid_emails[:5]) + ("..." if len(valid_emails) > 5 else "")
                ))
        except:
            pass
            
        # 2. Extract Socials
        for platform, pattern in socials.items():
            try:
                matches = re.findall(pattern, html)
                if matches:
                    profiles = set()
                    for m in matches:
                        # Normalize groups
                        if isinstance(m, tuple):
                             profiles.add(m[-1]) # Take the username part
                        else:
                             profiles.add(m)
                    
                    if profiles:
                         results.append(DetectionResult(
                            technology=f"{platform} Profile",
                            category="OSINT",
                            confidence=100,
                            evidence=", ".join(profiles)
                        ))
            except:
                pass

        # 3. Extract Phones (Very distinctive ones only usually)
        # Skipped for now to avoid high False Positives in HTML source
        
        return results
