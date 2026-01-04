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
from .geoip_analyzer import GeoIPAnalyzer
from .secret_scanner import SecretScanner
from .api_discovery import APIDiscovery
from .utils import DetectionResult, SiteData
import json
import os
from typing import List, Dict
import concurrent.futures

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
        
        # reconnaissance modules
        self.port_scanner = PortScanner()
        self.robots_intel = RobotsIntelligence()
        self.error_printer = ErrorFingerprinter()
        self.geoip = GeoIPAnalyzer()
        self.secret_scanner = SecretScanner()
        self.api_discovery = APIDiscovery()

    def scan(self, url: str, deep_scan=False, passive_mode=False, threads=5, generate_report=False, export_csv=False):
        all_results = []
        scanned_urls = []
        
        print(f"[*] Starting Analysis for {url} [Deep={deep_scan}, Passive={passive_mode}, Threads={threads}]...")

        # --- Phase 1: Infrastructure (Always Safe-ish) ---
        print(f"[*] performing GeoIP & Infrastructure Analysis...")
        geo_results = self.geoip.analyze(url)
        self._merge_results(all_results, geo_results)

        # SSL Check
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

        # DNS 
        print(f"[*] Querying DNS Records...")
        dns_results = self.dns_intel.analyze(url)
        self._merge_results(all_results, dns_results)

        # --- Phase 2: Active Recon (Skip if Passive) ---
        if not passive_mode:
            # Subdomains (DNS enumeration is semi-passive but can be noisy if bruteforce, here it's simple check)
            # We treat subdomain check as okay-ish but Port/Error are definitely active.
            print(f"[*] Enumerating Subdomains...")
            sub_results = self.sub_scanner.scan(url)
            self._merge_results(all_results, sub_results)

            print(f"[*] Active Port Scanning...")
            port_results = self.port_scanner.scan(url)
            self._merge_results(all_results, port_results)
            
            print(f"[*] Analyzing Robots.txt...")
            robots_results = self.robots_intel.analyze(url)
            self._merge_results(all_results, robots_results)
            
            print(f"[*] Error Fingerprinting...")
            error_results = self.error_printer.analyze(url)
            self._merge_results(all_results, error_results)
            
            print(f"[*] Discovering API Endpoints...")
            api_results = self.api_discovery.scan(url)
            self._merge_results(all_results, api_results)
        else:
            print("[*] Passive Mode: Skipping Port Scan, Subdomains, Error Provocation, API Discovery.")

        # --- Phase 3: Content Analysis (Crawling) ---
        if deep_scan:
            print(f"[*] Starting Deep Scan using {threads} threads...")
            
            # Sitemap Intelligence (Safe to do in passive too ideally, just fetching xml)
            sitemap_parser = SitemapParser(url)
            sitemap_urls = sitemap_parser.get_urls(limit=10)
            
            if sitemap_urls:
                print(f"[*] Sitemap found {len(sitemap_urls)} priority URLs.")
            
            crawler = Crawler(url, max_pages=15) 
            for sm_url in sitemap_urls:
                if sm_url not in crawler.visited and sm_url not in crawler.queue:
                     crawler.queue.append(sm_url)

            # Fetch Root
            scanned_urls.append(url)
            print(f"[*] Fetching root: {url}")
            root_data = self.fetcher.fetch(url)
            root_results = self.engine.analyze(root_data)
            self._merge_results(all_results, root_results)
            
            # Security Audit
            sec_results = self.sec_auditor.audit(root_data.headers)
            self._merge_results(all_results, sec_results)
            
            # Secret Scanning
            print("[*] Scanning for Secrets (Keys/Tokens)...")
            secret_results = self.secret_scanner.scan(root_data)
            self._merge_results(all_results, secret_results)
            
            crawler.extract_links(root_data.html, root_data.final_url)

            # Threaded crawling
            def process_url(target_url):
                # print(f"[*] Thread: {target_url}")
                try:
                    return self.fetcher.fetch(target_url)
                except Exception:
                    return None

            while len(scanned_urls) < crawler.max_pages:
                batch = []
                while len(batch) < threads:
                    next_url = crawler.get_next_url()
                    if not next_url:
                        break
                    batch.append(next_url)
                
                if not batch:
                    break
                    
                print(f"[*] Processing batch of {len(batch)} URLs...")
                with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
                    future_to_url = {executor.submit(process_url, u): u for u in batch}
                    for future in concurrent.futures.as_completed(future_to_url):
                        u = future_to_url[future]
                        try:
                            data = future.result()
                            if data:
                                scanned_urls.append(u)
                                page_results = self.engine.analyze(data)
                                self._merge_results(all_results, page_results)
                                
                                # Scan secrets in subpages
                                page_secrets = self.secret_scanner.scan(data)
                                self._merge_results(all_results, page_secrets)
                                
                                if len(scanned_urls) < crawler.max_pages:
                                    crawler.extract_links(data.html, data.final_url)
                        except Exception:
                            pass
                
        else:
            # Single Page
            print(f"[*] Fetching {url}...")
            data = self.fetcher.fetch(url)
            scanned_urls.append(data.final_url)
            
            sec_results = self.sec_auditor.audit(data.headers)
            self._merge_results(all_results, sec_results)
            
            print(f"[*] Analyzing content...")
            all_results.extend(self.engine.analyze(data)) 
            
            print("[*] Scanning for Secrets...")
            secret_results = self.secret_scanner.scan(data)
            self._merge_results(all_results, secret_results)

        # --- Phase 4: Reporting ---
        all_results.sort(key=lambda x: x.confidence, reverse=True)
        # Dedup
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
            
        return all_results, (root_data if deep_scan else data), report_path, csv_path

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
