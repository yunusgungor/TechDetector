import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from typing import List

class SitemapParser:
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.sitemap_urls = [
            urljoin(base_url, "sitemap.xml"),
            urljoin(base_url, "sitemap_index.xml"),
            urljoin(base_url, "wp-sitemap.xml")
        ]

    def get_urls(self, limit=20) -> List[str]:
        found_urls = []
        
        for sitemap_url in self.sitemap_urls:
            try:
                print(f"[*] Checking sitemap: {sitemap_url}")
                # Use a specific, common User-Agent
                headers = {
                    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
                }
                response = requests.get(sitemap_url, headers=headers, timeout=10, verify=False)
                
                if response.status_code == 200:
                    soup = BeautifulSoup(response.content, 'xml')
                    urls = soup.find_all('loc')
                    if urls:
                        print(f"[*] Found sitemap with {len(urls)} entries.")
                        # Extract text and filter images/other non-pages
                        for url_tag in urls:
                            loc = url_tag.text.strip()
                            if not any(loc.endswith(ext) for ext in ['.jpg', '.png', '.pdf', '.css', '.js']):
                                found_urls.append(loc)
                                if len(found_urls) >= limit:
                                    return found_urls
                        
                        # If we found URLs, we can stop checking other sitemap variants
                        if found_urls:
                            return found_urls
            except Exception as e:
                # print(f"[-] Sitemap error {sitemap_url}: {e}")
                pass
                
        return found_urls
