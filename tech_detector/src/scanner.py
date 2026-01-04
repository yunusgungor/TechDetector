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
            print(f"[*] Starting Deep Scan on {url}...")
            crawler = Crawler(url, max_pages=5)
            
            target = url
            while target:
                print(f"[*] Scanning page: {target}")
                data = self.fetcher.fetch(target)
                scanned_urls.append(target)
                
                page_results = self.engine.analyze(data)
                
                # Deduplicate results
                self._merge_results(all_results, page_results)
                
                # Extract next links
                if len(scanned_urls) < 5: # Limit depth
                    crawler.extract_links(data.html, data.final_url)
                    
                target = crawler.get_next_url()
                
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
