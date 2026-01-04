from .utils import SiteData, DetectionResult
import re
from collections import Counter

class ContextAnalyzer:
    CATEGORIES = {
        'E-Commerce': ['cart', 'shop', 'store', 'checkout', 'price', 'product', 'sale', 'buy', 'shipping', 'order'],
        'News/Media': ['news', 'article', 'blog', 'read more', 'published', 'author', 'latest', 'breaking', 'editorial'],
        'Corporate': ['about us', 'services', 'solutions', 'contact', 'team', 'careers', 'mission', 'vision', 'clients'],
        'Educational': ['course', 'learn', 'student', 'university', 'academic', 'research', 'tutorial', 'lesson'],
        'Medical': ['health', 'patient', 'doctor', 'treatment', 'medical', 'clinic', 'hospital', 'care'],
        'Government': ['ministry', 'department', 'gov', 'citizen', 'public', 'law', 'regulation'],
        'Technology': ['software', 'app', 'download', 'platform', 'developer', 'api', 'tech', 'saas']
    }

    def analyze(self, data: SiteData) -> DetectionResult:
        text_content = data.soup.get_text(" ", strip=True).lower()
        meta_desc = data.meta_tags.get('description', '').lower()
        title = ""
        if data.soup.title:
            title = data.soup.title.string.lower() if data.soup.title.string else ""
            
        full_text = f"{title} {meta_desc} {text_content[:5000]}" # Analyze first 5k chars
        
        scores = {cat: 0 for cat in self.CATEGORIES}
        
        for cat, keywords in self.CATEGORIES.items():
            for kw in keywords:
                count = len(re.findall(f"\\b{kw}\\b", full_text))
                scores[cat] += count
                
        # Get top category
        best_cat = max(scores, key=scores.get)
        score_val = scores[best_cat]
        
        if score_val < 3: # Threshold
            best_cat = "General / Unknown"
            score_val = 0
            
        return DetectionResult(
            technology=best_cat,
            category="Context Analysis",
            confidence=max(score_val * 10, 50) if best_cat != "General / Unknown" else 0, # Rough confidence
            evidence=f"Keyword Score: {score_val}"
        )
