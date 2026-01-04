import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import mmh3
import codecs
import concurrent.futures
import dns.resolver
from .utils import SiteData
import warnings

# Suppress SSL warnings
warnings.filterwarnings("ignore")

class Fetcher:
    def __init__(self, timeout=10, max_assets=20):
        self.timeout = timeout
        self.max_assets = max_assets
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        }

    def fetch(self, url: str) -> SiteData:
        try:
            if not url.startswith('http'):
                url = 'https://' + url
                
            response = requests.get(url, headers=self.headers, timeout=self.timeout, verify=False)
            
            soup = BeautifulSoup(response.text, 'html.parser')
            
            data = SiteData(
                url=url,
                final_url=response.url,
                status_code=response.status_code,
                headers=dict(response.headers),
                cookies=response.cookies.get_dict(),
                html=response.text,
                soup=soup
            )
            
            # Parse Assets
            self._parse_assets(data, soup)
            
            # Download Assets (Parallel)
            self._download_assets(data)
            
            # Get Favicon
            self._fetch_favicon(data)

            # Probes
            self.probe_paths(data)
            
            # DNS
            self.resolve_dns(data)
            
            return data
            
        except requests.RequestException as e:
            print(f"Error fetching {url}: {e}")
            return SiteData(url=url, final_url=url, status_code=0, headers={}, cookies={}, html="")

    def _parse_assets(self, data: SiteData, soup: BeautifulSoup):
        # Scrape Scripts
        for script in soup.find_all('script', src=True):
            src = script['src']
            full_url = urljoin(data.final_url, src)
            data.scripts.append(full_url)
            
        # Scrape Styles
        for link in soup.find_all('link', rel='stylesheet', href=True):
            href = link['href']
            full_url = urljoin(data.final_url, href)
            data.styles.append(full_url)
            
        # Meta tags
        for meta in soup.find_all('meta'):
            name = meta.get('name') or meta.get('property')
            content = meta.get('content')
            if name and content:
                data.meta_tags[name.lower()] = content

    def _download_assets(self, data: SiteData):
        # Limit assets to avoid slow scans
        target_scripts = data.scripts[:self.max_assets]
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            future_to_url = {executor.submit(self._fetch_content, url): url for url in target_scripts}
            for future in concurrent.futures.as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    content = future.result()
                    if content:
                        data.js_bundles[url] = content
                except Exception:
                    pass

    def _fetch_content(self, url: str) -> str:
        try:
            r = requests.get(url, headers=self.headers, timeout=5, verify=False)
            if r.status_code == 200:
                return r.text
        except:
            pass
        return ""

    def _fetch_favicon(self, data: SiteData):
        # Try finding icon in link tags
        icon_link = data.soup.find("link", rel=lambda x: x and 'icon' in x.lower(), href=True)
        if icon_link:
            favicon_url = urljoin(data.final_url, icon_link['href'])
        else:
            favicon_url = urljoin(data.final_url, '/favicon.ico')
            
        try:
            r = requests.get(favicon_url, headers=self.headers, timeout=5, verify=False)
            if r.status_code == 200:
                favicon = codecs.encode(r.content, "base64")
                data.favicon_hash = mmh3.hash(favicon)
        except:
            pass

    def probe_paths(self, data: SiteData):
        paths = ['/robots.txt', '/sitemap.xml', '/manifest.json', '/feed', '/rss', '/atom.xml', '/graphql', '/.well-known/security.txt', '/.well-known/apple-app-site-association']
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            future_to_path = {executor.submit(self._fetch_content, urljoin(data.final_url, p)): p for p in paths}
            for future in concurrent.futures.as_completed(future_to_path):
                path = future_to_path[future]
                try:
                    content = future.result()
                    if content:
                        data.probe_content[path] = content
                except:
                    pass

    def resolve_dns(self, data: SiteData):
        if not data.final_url:
            return
        try:
            domain = urlparse(data.final_url).netloc
            # CNAME
            try:
                answers = dns.resolver.resolve(domain, 'CNAME')
                data.dns_records['CNAME'] = [str(r.target) for r in answers]
            except:
                pass
                
            # A
            try:
                answers = dns.resolver.resolve(domain, 'A')
                data.dns_records['A'] = [str(r) for r in answers]
            except:
                pass
            
            # MX
            try:
                answers = dns.resolver.resolve(domain, 'MX')
                data.dns_records['MX'] = [str(r.exchange) for r in answers]
            except:
                pass
        except:
            pass
