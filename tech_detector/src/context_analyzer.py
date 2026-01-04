from .utils import SiteData, DetectionResult
import re
from collections import Counter

class ContextAnalyzer:
    CATEGORIES = {
        'E-Commerce': ['cart', 'shop', 'store', 'checkout', 'price', 'product', 'sale', 'buy', 'shipping', 'order', 'sepet', 'magaza', 'satin al', 'odeme', 'fiyat', 'urun', 'alisveris'],
        'News/Media': ['news', 'article', 'blog', 'read more', 'published', 'author', 'latest', 'breaking', 'editorial', 'haber', 'yazar', 'gundem', 'son dakika', 'makale'],
        'Corporate': ['about us', 'services', 'solutions', 'contact', 'team', 'careers', 'mission', 'vision', 'clients', 'hakkimizda', 'iletisim', 'hizmetler', 'cozumler', 'ekip', 'kariyer'],
        'Educational': ['course', 'learn', 'student', 'university', 'academic', 'research', 'tutorial', 'lesson', 'egitim', 'ogrenci', 'ders', 'akademi', 'arastirma', 'universite'],
        'Medical': ['health', 'patient', 'doctor', 'treatment', 'medical', 'clinic', 'hospital', 'care', 'saglik', 'doktor', 'tedavi', 'hastane', 'klinik', 'hasta'],
        'Government': ['ministry', 'department', 'gov', 'citizen', 'public', 'law', 'regulation', 'bakanlik', 'belediye', 'mudurluk', 'vatandas', 'resmi', 'kanun'],
        'Technology': ['software', 'app', 'download', 'platform', 'developer', 'api', 'tech', 'saas', 'yazilim', 'uygulama', 'indir', 'teknoloji', 'gelistirici']
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
