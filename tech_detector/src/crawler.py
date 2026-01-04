import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from typing import Set, List

class Crawler:
    def __init__(self, start_url: str, max_pages=5):
        self.start_url = start_url
        self.max_pages = max_pages
        self.visited: Set[str] = set()
        self.queue: List[str] = [start_url]
        self.domain = urlparse(start_url).netloc

    def get_next_url(self) -> str:
        if not self.queue or len(self.visited) >= self.max_pages:
            return None
        
        url = self.queue.pop(0)
        self.visited.add(url)
        return url

    def extract_links(self, html: str, current_url: str):
        if len(self.visited) + len(self.queue) >= self.max_pages * 2: # Limit queue size
            return

        soup = BeautifulSoup(html, 'html.parser')
        for a in soup.find_all('a', href=True):
            href = a['href']
            full_url = urljoin(current_url, href)
            
            # Internal links only
            parsed = urlparse(full_url)
            if parsed.netloc == self.domain:
                # Normalize (strip fragments)
                full_url = full_url.split('#')[0]
                
                if full_url not in self.visited and full_url not in self.queue:
                    # Filter static files checks
                    if not any(full_url.endswith(ext) for ext in ['.png', '.jpg', '.pdf', '.css', '.js']):
                        self.queue.append(full_url)
