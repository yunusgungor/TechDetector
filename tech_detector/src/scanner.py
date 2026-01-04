from .fetcher import Fetcher
from .rules_engine import RulesEngine
import json
import os

class Scanner:
    def __init__(self, fingerprints_path=None):
        if fingerprints_path is None:
            # Default to data/fingerprints.json relative to this file
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            fingerprints_path = os.path.join(base_dir, 'data', 'fingerprints.json')
            
        self.fetcher = Fetcher()
        self.engine = RulesEngine(fingerprints_path)

    def scan(self, url: str):
        print(f"[*] Fetching {url}...")
        data = self.fetcher.fetch(url)
        
        print(f"[*] Analyzing data ({len(data.html)} bytes, {len(data.headers)} headers)...")
        results = self.engine.analyze(data)
        
        # Sort by confidence
        results.sort(key=lambda x: x.confidence, reverse=True)
        return results, data
