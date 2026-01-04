import json
import os
from datetime import datetime
from typing import List, Dict
from urllib.parse import urlparse
from .utils import DetectionResult

class Reporter:
    def __init__(self, output_dir="reports"):
        self.output_dir = output_dir
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

    def generate_html(self, url: str, results: List[DetectionResult], sub_page_count: int):
        filename = f"report_{urlparse(url).netloc}_{int(datetime.now().timestamp())}.html"
        path = os.path.join(self.output_dir, filename)
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Tech Scan: {url}</title>
            <style>
                body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f7; color: #1d1d1f; }}
                .container {{ max-width: 900px; margin: 0 auto; background: white; padding: 40px; border-radius: 18px; box-shadow: 0 4px 20px rgba(0,0,0,0.05); }}
                h1 {{ font-size: 24px; margin-bottom: 10px; }}
                .meta {{ color: #86868b; font-size: 14px; margin-bottom: 30px; }}
                .tech-card {{ padding: 20px; border-bottom: 1px solid #e5e5e5; display: flex; align-items: start; }}
                .tech-card:last-child {{ border-bottom: none; }}
                .tech-name {{ font-weight: 600; font-size: 18px; min-width: 200px; }}
                .tech-cat {{ background: #e8ecf3; padding: 4px 10px; border-radius: 6px; font-size: 12px; font-weight: 500; color: #4b5563; margin-right: 20px; min-width: 100px; text-align: center; }}
                .tech-conf {{ font-weight: 700; color: #34d399; min-width: 60px; }}
                .tech-evidence {{ color: #6e6e73; font-size: 13px; margin-top: 5px; font-family: monospace; }}
                .scan-stats {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; margin-bottom: 40px; }}
                .stat-box {{ background: #fbfbfd; padding: 15px; border-radius: 12px; text-align: center; border: 1px solid #e5e5e5; }}
                .stat-num {{ font-size: 24px; font-weight: 700; display: block; }}
                .stat-label {{ font-size: 12px; color: #86868b; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Tech Detection Report</h1>
                <div class="meta">Target: {url} | Date: {datetime.now().strftime('%Y-%m-%d %H:%M')}</div>
                
                <div class="scan-stats">
                    <div class="stat-box">
                        <span class="stat-num">{len(results)}</span>
                        <span class="stat-label">Technologies Found</span>
                    </div>
                    <div class="stat-box">
                        <span class="stat-num">{sub_page_count}</span>
                        <span class="stat-label">Pages Scanned</span>
                    </div>
                    <div class="stat-box">
                        <span class="stat-num">100+</span>
                        <span class="stat-label">Checks Performed</span>
                    </div>
                </div>

                <h2>Detected Stack</h2>
                <div class="results">
        """
        
        for res in results:
            html += f"""
                    <div class="tech-card">
                        <div>
                            <div style="display:flex; align-items:center;">
                                <div class="tech-name">{res.technology}</div>
                                <div class="tech-cat">{res.category}</div>
                                <div class="tech-conf">{res.confidence}%</div>
                            </div>
                            <div class="tech-evidence">{res.evidence}</div>
                        </div>
                    </div>
            """
            
        html += """
                </div>
            </div>
        </body>
        </html>
        """
        
        with open(path, 'w') as f:
            f.write(html)
        return path
