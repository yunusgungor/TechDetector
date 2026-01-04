from .fetcher import Fetcher
from .rules_engine import RulesEngine
from .crawler import Crawler
from .reporter import Reporter
from .utils import DetectionResult, SiteData
import json
import os
from typing import List, Dict

class Scanner:
    def __init__(self, fingerprints_path=None):
        if fingerprints_path is None:
            # Default to data/fingerprints.json relative to this file
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            fingerprints_path = os.path.join(base_dir, 'data', 'fingerprints.json')
            
        self.fetcher = Fetcher()
        self.engine = RulesEngine(fingerprints_path)
        self.reporter = Reporter()

    def scan(self, url: str, deep_scan=False, generate_report=False):
        all_results = []
        scanned_urls = []
        
        if deep_scan:
            print(f"[*] Starting Deep Scan on {url} (High-Speed Mode)...")
            crawler = Crawler(url, max_pages=10) # Increased max pages due to higher speed
            
            # Initial fetch
            print(f"[*] Fetching root: {url}")
            root_data = self.fetcher.fetch(url)
            scanned_urls.append(url)
            
            # Helper for thread workers
            def process_url(target_url):
                print(f"[*] Thread scanning: {target_url}")
                try:
                    return self.fetcher.fetch(target_url)
                except Exception as e:
                    print(f"[!] Error scanning {target_url}: {e}")
                    return None

            # Seed crawler with root
            crawler.extract_links(root_data.html, root_data.final_url)
            
            # Analyze root
            root_results = self.engine.analyze(root_data)
            self._merge_results(all_results, root_results)

            import concurrent.futures
            
            # Parallel processing loop
            # We fetch in batches
            while len(scanned_urls) < crawler.max_pages:
                # Get next batch of URLs
                batch = []
                while len(batch) < 5: # Batch size
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
                                crawler.extract_links(data.html, data.final_url)
                        except Exception as exc:
                            print(f"[!] {u} generated an exception: {exc}")
                
        else:
            print(f"[*] Fetching {url}...")
            data = self.fetcher.fetch(url)
            scanned_urls.append(data.final_url)
            
            print(f"[*] Analyzing data ({len(data.html)} bytes, {len(data.headers)} headers)...")
            all_results = self.engine.analyze(data)

        # Sort by confidence
        all_results.sort(key=lambda x: x.confidence, reverse=True)
        
        report_path = ""
        if generate_report:
            report_path = self.reporter.generate_html(url, all_results, scanned_urls)
            
        return all_results, data, report_path

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
