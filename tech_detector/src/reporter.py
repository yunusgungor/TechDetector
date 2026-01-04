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

    def generate_html(self, url: str, results: List[DetectionResult], scanned_urls: List[str]):
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
                
                /* Cards */
                .tech-card {{ padding: 20px; border-bottom: 1px solid #e5e5e5; display: flex; align-items: start; transition: background 0.2s; }}
                .tech-card:hover {{ background: #fafafa; }}
                .tech-card:last-child {{ border-bottom: none; }}
                .tech-name {{ font-weight: 600; font-size: 18px; min-width: 200px; }}
                .tech-cat {{ background: #e8ecf3; padding: 4px 10px; border-radius: 6px; font-size: 12px; font-weight: 500; color: #4b5563; margin-right: 20px; min-width: 100px; text-align: center; }}
                .tech-conf {{ font-weight: 700; color: #34d399; min-width: 60px; }}
                .tech-evidence {{ color: #6e6e73; font-size: 13px; margin-top: 5px; font-family: monospace; white-space: pre-wrap; }}
                
                /* Stats */
                .scan-stats {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; margin-bottom: 40px; }}
                .stat-box {{ background: #fbfbfd; padding: 20px; border-radius: 12px; text-align: center; border: 1px solid #e5e5e5; cursor: pointer; transition: all 0.2s; }}
                .stat-box:hover {{ transform: translateY(-2px); box-shadow: 0 4px 12px rgba(0,0,0,0.05); border-color: #d1d1d6; }}
                .stat-num {{ font-size: 32px; font-weight: 700; display: block; color: #1d1d1f; }}
                .stat-label {{ font-size: 13px; color: #86868b; text-transform: uppercase; letter-spacing: 0.5px; margin-top: 5px; }}
                
                /* Modal */
                .modal {{ display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); z-index: 1000; justify-content: center; align-items: center; }}
                .modal.active {{ display: flex; }}
                .modal-content {{ background: white; width: 500px; max-height: 80vh; border-radius: 18px; padding: 30px; position: relative; overflow-y: auto; box-shadow: 0 10px 40px rgba(0,0,0,0.2); animation: popIn 0.3s cubic-bezier(0.175, 0.885, 0.32, 1.275); }}
                @keyframes popIn {{ from {{ transform: scale(0.9); opacity: 0; }} to {{ transform: scale(1); opacity: 1; }} }}
                .close-btn {{ position: absolute; top: 20px; right: 20px; font-size: 24px; cursor: pointer; color: #86868b; line-height: 1; }}
                .modal-list {{ list-style: none; padding: 0; margin: 20px 0 0 0; }}
                .modal-list li {{ padding: 12px 0; border-bottom: 1px solid #f0f0f0; font-size: 14px; word-break: break-all; }}
                .modal-list li:last-child {{ border-bottom: none; }}
                .modal-title {{ font-size: 20px; font-weight: 600; margin-bottom: 10px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Tech Detection Report</h1>
                <div class="meta">Target: {url} | Date: {datetime.now().strftime('%Y-%m-%d %H:%M')}</div>
                
                <div class="scan-stats">
                    <div class="stat-box" onclick="showModal('techModal')">
                        <span class="stat-num">{len(results)}</span>
                        <span class="stat-label">Technologies Found</span>
                    </div>
                    <div class="stat-box" onclick="showModal('pagesModal')">
                        <span class="stat-num">{len(scanned_urls)}</span>
                        <span class="stat-label">Pages Scanned</span>
                    </div>
                    <div class="stat-box" onclick="alert('Analysis performed on HTML, Headers, Cookies, DNS, SSL, and Assets.')">
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
                        <div style="width:100%">
                            <div style="display:flex; align-items:center; justify-content:space-between; width:100%">
                                <div style="display:flex; align-items:center;">
                                    <div class="tech-name">{res.technology}</div>
                                    <div class="tech-cat">{res.category}</div>
                                </div>
                                <div class="tech-conf">{res.confidence}%</div>
                            </div>
                            <div class="tech-evidence">{res.evidence}</div>
                        </div>
                    </div>
            """
            
        urls_list_html = "".join([f"<li><a href='{u}' target='_blank' style='color:#0066cc;text-decoration:none;'>{u}</a></li>" for u in scanned_urls])
        tech_list_html = "".join([f"<li><b>{r.technology}</b> ({r.category}) - {r.confidence}%</li>" for r in results])

        html += f"""
                </div>
            </div>
            
            <!-- Modals -->
            <div id="pagesModal" class="modal" onclick="if(event.target === this) this.classList.remove('active')">
                <div class="modal-content">
                    <span class="close-btn" onclick="this.closest('.modal').classList.remove('active')">&times;</span>
                    <div class="modal-title">Scanned Pages</div>
                    <ul class="modal-list">
                        {urls_list_html}
                    </ul>
                </div>
            </div>
            
            <div id="techModal" class="modal" onclick="if(event.target === this) this.classList.remove('active')">
                <div class="modal-content">
                    <span class="close-btn" onclick="this.closest('.modal').classList.remove('active')">&times;</span>
                    <div class="modal-title">Detected Technologies</div>
                    <ul class="modal-list">
                        {tech_list_html}
                    </ul>
                </div>
            </div>

            <script>
                function showModal(id) {{
                    document.getElementById(id).classList.add('active');
                }}
            </script>
        </body>
        </html>
        """
        
        with open(path, 'w') as f:
            f.write(html)
        return path
