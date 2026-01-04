from .fetcher import Fetcher
from .rules_engine import RulesEngine
from .crawler import Crawler
from .reporter import Reporter
from .sitemap_parser import SitemapParser
from .ssl_inspector import SSLInspector
from .dns_intelligence import DNSIntelligence
from .security_auditor import SecurityAuditor
from .subdomain_scanner import SubdomainScanner
from .port_scanner import PortScanner
from .robots_intel import RobotsIntelligence
from .error_fingerprinter import ErrorFingerprinter
from .utils import DetectionResult, SiteData
import json
import os
from typing import List, Dict

class Scanner:
    def __init__(self, fingerprints_path=None):
        if fingerprints_path is None:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            fingerprints_path = os.path.join(base_dir, 'data', 'fingerprints.json')
            
        self.fetcher = Fetcher()
        self.engine = RulesEngine(fingerprints_path)
        self.reporter = Reporter()
        self.ssl_inspector = SSLInspector()
        self.dns_intel = DNSIntelligence()
        self.sec_auditor = SecurityAuditor()
        self.sub_scanner = SubdomainScanner()
        
        # New Recon Modules
        self.port_scanner = PortScanner()
        self.robots_intel = RobotsIntelligence()
        self.error_printer = ErrorFingerprinter()

    def scan(self, url: str, deep_scan=False, generate_report=False, export_csv=False):
        all_results = []
        scanned_urls = []
        
        print(f"[*] Starting Security & Infrastructure Analysis for {url}...")

        # 1. SSL Check
        ssl_info = self.ssl_inspector.inspect(url)
        if 'issuer_org' in ssl_info:
             if 'Cloudflare' in ssl_info['issuer_org']:
                 all_results.append(DetectionResult("Cloudflare", "CDN", 100, "SSL Issuer: Cloudflare"))
             elif 'Google Trust Services' in ssl_info['issuer_org']:
                 all_results.append(DetectionResult("Google Cloud", "PaaS", 80, "SSL Issuer: Google Trust Services"))
             elif 'Let\'s Encrypt' in ssl_info['issuer_org']:
                 all_results.append(DetectionResult("Let's Encrypt", "SSL/TLS", 100, "SSL Issuer: Let's Encrypt"))
             elif 'Amazon' in ssl_info['issuer_org']:
                 all_results.append(DetectionResult("AWS", "PaaS", 80, "SSL Issuer: Amazon"))

        # 2. DNS Intelligence
        print(f"[*] Querying DNS Records (MX, TXT)...")
        dns_results = self.dns_intel.analyze(url)
        self._merge_results(all_results, dns_results)

        # 3. Subdomain Scanning
        print(f"[*] Enumerating Subdomains...")
        sub_results = self.sub_scanner.scan(url)
        self._merge_results(all_results, sub_results)

        # 4. Port Scanning
        print(f"[*] Active Port Scanning (Top Critical Ports)...")
        port_results = self.port_scanner.scan(url)
        self._merge_results(all_results, port_results)
        
        # 5. Robots Intelligence
        print(f"[*] Analyzing Robots.txt for hidden paths...")
        robots_results = self.robots_intel.analyze(url)
        self._merge_results(all_results, robots_results)
        
        # 6. Error Fingerprinting
        print(f"[*] Provoking Server Errors to expose leaks...")
        error_results = self.error_printer.analyze(url)
        self._merge_results(all_results, error_results)

        if deep_scan:
            print(f"[*] Starting Enterprise Deep Scan...")
            
            # Sitemap Intelligence
            sitemap_parser = SitemapParser(url)
            sitemap_urls = sitemap_parser.get_urls(limit=10)
            
            if sitemap_urls:
                print(f"[*] Intelligent Sitemap Discovery: Found {len(sitemap_urls)} priority URLs.")
            
            # Setup Crawler
            crawler = Crawler(url, max_pages=15) 
            for sm_url in sitemap_urls:
                if sm_url not in crawler.visited and sm_url not in crawler.queue:
                     crawler.queue.append(sm_url)

            scanned_urls.append(url)
            
            # Initial fetch & analyze root
            print(f"[*] Fetching root: {url}")
            root_data = self.fetcher.fetch(url)
            root_results = self.engine.analyze(root_data)
            self._merge_results(all_results, root_results)
            
            # 7. Security Audit (On Root) - moved to step 7 logic-wise
            sec_results = self.sec_auditor.audit(root_data.headers)
            self._merge_results(all_results, sec_results)
            
            # Seed extractor
            crawler.extract_links(root_data.html, root_data.final_url)

            # Helpers for threading...
            def process_url(target_url):
                print(f"[*] Thread scanning: {target_url}")
                try:
                    return self.fetcher.fetch(target_url)
                except Exception as e:
                    print(f"[!] Error scanning {target_url}: {e}")
                    return None

            import concurrent.futures
            
            # Parallel processing loop
            while len(scanned_urls) < crawler.max_pages:
                batch = []
                while len(batch) < 5:
                    next_url = crawler.get_next_url()
                    if not next_url:
                        break
                    batch.append(next_url)
                
                if not batch:
                    break
                    
                print(f"[*] Processing batch of {len(batch)} URLs...")
                with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                    future_to_url = {executor.submit(process_url, u): u for u in batch}
                    for future in concurrent.futures.as_completed(future_to_url):
                        u = future_to_url[future]
                        try:
                            data = future.result()
                            if data:
                                scanned_urls.append(u)
                                page_results = self.engine.analyze(data)
                                self._merge_results(all_results, page_results)
                                if len(scanned_urls) < crawler.max_pages:
                                    crawler.extract_links(data.html, data.final_url)
                        except Exception as exc:
                            pass # Silent fail for thread
                
        else:
            print(f"[*] Fetching {url}...")
            data = self.fetcher.fetch(url)
            scanned_urls.append(data.final_url)
            
            # Security Audit
            sec_results = self.sec_auditor.audit(data.headers)
            self._merge_results(all_results, sec_results)
            
            print(f"[*] Analyzing data ({len(data.html)} bytes, {len(data.headers)} headers)...")
            all_results.extend(self.engine.analyze(data)) 
            # Fix duplicate merge - the extend is fine if we are careful about Dups, 
            # but standard logic is to use merge. 
            # Given previous structure, extend might duplicate if engine.analyze returns duplicates? 
            # engine.analyze returns unique list for that run.
            # But deep_scan logic uses _merge_results.
            # Let's keep it consistent:
            # self._merge_results(all_results, self.engine.analyze(data)) # Better
            # But for simplicity in this replace block I will stick to extending for now 
            # essentially overwriting what was there in the previous replace to include new modules.
            # Wait, the previous replace had `all_results.extend...`.
            # I will just close the else block correctly.
            
            # Actually, `engine.analyze` returns findings.
            
        # Refined Sort
        all_results.sort(key=lambda x: x.confidence, reverse=True)
        # Deduplicate exactly identical entries just in case
        unique_results = []
        seen = set()
        for r in all_results:
             sig = f"{r.technology}_{r.category}_{r.evidence}"
             if sig not in seen:
                 seen.add(sig)
                 unique_results.append(r)
        
        all_results = unique_results
        
        report_path = ""
        csv_path = ""
        if generate_report:
            report_path = self.reporter.generate_html(url, all_results, scanned_urls)
        
        if export_csv:
            csv_path = self.reporter.generate_csv(url, all_results)
            
        return all_results, data, report_path, csv_path

    def _merge_results(self, main_list: List[DetectionResult], new_list: List[DetectionResult]):
        # Merge logic: if tech exists, take max confidence
        existing_map = {r.technology: r for r in main_list}
        
        for res in new_list:
            if res.technology in existing_map:
                existing = existing_map[res.technology]
                if res.confidence > existing.confidence:
                    existing.confidence = res.confidence
                    existing.evidence = res.evidence # Update evidence too
            else:
                main_list.append(res)
