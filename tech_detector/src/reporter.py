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

    def generate_csv(self, url: str, results: List[DetectionResult]):
        import csv
        safe_loc = urlparse(url).netloc.replace(":", "_")
        filename = f"report_{safe_loc}_{int(datetime.now().timestamp())}.csv"
        path = os.path.join(self.output_dir, filename)
        
        with open(path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(["Technology", "Category", "Confidence", "Version", "Evidence"])
            for res in results:
                writer.writerow([res.technology, res.category, f"{res.confidence}%", res.version or "", res.evidence])
                
        return path

    def generate_html(self, url: str, results: List[DetectionResult], scanned_urls: List[str]):
        safe_loc = urlparse(url).netloc.replace(":", "_")
        filename = f"report_{safe_loc}_{int(datetime.now().timestamp())}.html"
        path = os.path.join(self.output_dir, filename)
        
        # Prepare Data for Charts
        categories = {}
        for r in results:
            categories[r.category] = categories.get(r.category, 0) + 1
            
        risk_score = 100
        # Find security grade to set risk score visualization
        sec_grade = "Unknown"
        for r in results:
            if r.category == "Security Audit":
                 if "Grade: F" in r.technology: risk_score = 20; sec_grade="F"
                 elif "Grade: D" in r.technology: risk_score = 40; sec_grade="D"
                 elif "Grade: C" in r.technology: risk_score = 60; sec_grade="C"
                 elif "Grade: B" in r.technology: risk_score = 80; sec_grade="B"
                 elif "Grade: A" in r.technology: risk_score = 95; sec_grade="A"
        
        # Color coding
        grade_color = "#ef4444" # red
        if risk_score > 50: grade_color = "#eab308" # yellow
        if risk_score > 80: grade_color = "#22c55e" # green

        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>TechIntel: {url}</title>
            <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
            <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700&display=swap" rel="stylesheet">
            <style>
                body {{ font-family: 'Inter', sans-serif; margin: 0; padding: 0; background: #f3f4f6; color: #1f2937; }}
                .container {{ max-width: 1200px; margin: 0 auto; padding: 40px 20px; }}
                
                /* Header */
                .header {{ background: white; padding: 30px; border-radius: 16px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1); margin-bottom: 30px; display: flex; justify-content: space-between; align-items: center; }}
                .title h1 {{ margin: 0; font-size: 28px; color: #111827; }}
                .title p {{ margin: 5px 0 0; color: #6b7280; }}
                .grade-badge {{ background: {grade_color}; color: white; padding: 10px 20px; border-radius: 12px; font-size: 32px; font-weight: 800; text-align: center; min-width: 60px; }}
                .grade-label {{ font-size: 12px; opacity: 0.9; font-weight: 500; display: block; }}

                /* Grid */
                .grid {{ display: grid; grid-template-columns: 2fr 1fr; gap: 30px; }}
                
                /* Cards */
                .card {{ background: white; padding: 25px; border-radius: 16px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.05); margin-bottom: 30px; }}
                .card h2 {{ margin-top: 0; font-size: 18px; border-bottom: 1px solid #e5e7eb; padding-bottom: 15px; margin-bottom: 20px; color: #374151; }}
                
                /* List */
                .tech-item {{ display: flex; justify-content: space-between; align-items: start; padding: 15px 0; border-bottom: 1px solid #f3f4f6; }}
                .tech-item:last-child {{ border-bottom: none; }}
                .tech-left {{ display: flex; gap: 15px; }}
                .tech-icon {{ width: 40px; height: 40px; background: #eff6ff; border-radius: 8px; display: flex; align-items: center; justify-content: center; font-weight: bold; color: #3b82f6; }}
                .tech-info h3 {{ margin: 0; font-size: 16px; font-weight: 600; }}
                .tech-info span {{ font-size: 12px; color: #6b7280; background: #f3f4f6; padding: 2px 8px; border-radius: 4px; }}
                .tech-evidence {{ font-size: 12px; color: #9ca3af; margin-top: 4px; font-family: monospace; max-width: 500px; word-break: break-all; }}
                .tech-conf {{ font-weight: 700; color: #059669; font-size: 14px; }}
                
                .cve-link {{ display: inline-block; margin-left: 10px; font-size: 12px; color: #ef4444; text-decoration: none; border: 1px solid #fca5a5; padding: 2px 6px; border-radius: 4px; }}
                .cve-link:hover {{ background: #fef2f2; }}

                /* Stats Row */
                .stats-row {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin-bottom: 30px; }}
                .stat-card {{ background: white; padding: 20px; border-radius: 12px; text-align: center; box-shadow: 0 2px 4px rgba(0,0,0,0.05); cursor: pointer; transition: transform 0.2s; }}
                .stat-card:hover {{ transform: translateY(-2px); box-shadow: 0 10px 15px -3px rgba(0,0,0,0.1); }}
                .stat-val {{ font-size: 24px; font-weight: 700; color: #111827; display: block; }}
                .stat-key {{ font-size: 13px; color: #6b7280; text-transform: uppercase; font-weight: 600; }}

                /* Modal */
                .modal {{ display: none; position: fixed; inset: 0; background: rgba(0,0,0,0.5); z-index: 50; justify-content: center; align-items: center; backdrop-filter: blur(2px); }}
                .modal.active {{ display: flex; }}
                .modal-content {{ background: white; width: 600px; max-height: 80vh; border-radius: 16px; padding: 24px; position: relative; display: flex; flex-direction: column; box-shadow: 0 20px 25px -5px rgba(0,0,0,0.1); animation: modalPop 0.2s ease-out; }}
                @keyframes modalPop {{ from {{ opacity: 0; transform: scale(0.95); }} to {{ opacity: 1; transform: scale(1); }} }}
                .modal-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; border-bottom: 1px solid #e5e7eb; padding-bottom: 15px; }}
                .modal-title {{ font-size: 20px; font-weight: 700; color: #111827; margin: 0; }}
                .close-btn {{ background: none; border: none; font-size: 24px; color: #9ca3af; cursor: pointer; transition: color 0.2s; }}
                .close-btn:hover {{ color: #111827; }}
                .modal-body {{ overflow-y: auto; padding-right: 5px; }}
                .list-group {{ list-style: none; padding: 0; margin: 0; }}
                .list-item {{ padding: 12px 16px; border-bottom: 1px solid #f3f4f6; display: flex; justify-content: space-between; align-items: center; }}
                .list-item:hover {{ background: #f9fafb; }}
                .list-item:last-child {{ border-bottom: none; }}
                .item-main {{ font-weight: 500; font-size: 14px; color: #374151; }}
                .item-sub {{ font-size: 12px; color: #6b7280; display: block; }}
                .badge {{ padding: 2px 8px; border-radius: 9999px; font-size: 11px; font-weight: 600; background: #e0f2fe; color: #0369a1; }}

            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <div class="title">
                        <h1>Cyber Intelligence Report (Grade: {sec_grade})</h1>
                        <p>{url} | {datetime.now().strftime('%Y-%m-%d %H:%M')}</p>
                    </div>
                    <div class="grade-badge">
                        {sec_grade}
                        <span class="grade-label">SECURITY</span>
                    </div>
                </div>

                <div class="stats-row">
                    <div class="stat-card" onclick="openModal('techModal')">
                        <span class="stat-val">{len(results)}</span>
                        <span class="stat-key">Techs Detected</span>
                    </div>
                    <div class="stat-card" onclick="openModal('pageModal')">
                        <span class="stat-val">{len(scanned_urls)}</span>
                        <span class="stat-key">Pages Crawled</span>
                    </div>
                    <div class="stat-card" onclick="openModal('catModal')">
                        <span class="stat-val">{len(categories)}</span>
                        <span class="stat-key">Categories</span>
                    </div>
                    <div class="stat-card" onclick="alert('Scan completed successfully.')">
                        <span class="stat-val">Active</span>
                        <span class="stat-key">Scan Mode</span>
                    </div>
                </div>

                <div class="grid">
                    <div>
                        <div class="card">
                            <h2>Detailed Findings</h2>
                            <div class="tech-list">
        """
        
        tech_list_html = ""
        for res in results:
            version_str = f" v{res.version}" if res.version else ""
            cve_html = ""
            if res.version:
                cve_query = f"{res.technology} {res.version} vulnerabilities"
                cve_link = f"https://www.google.com/search?q={cve_query}"
                cve_html = f"<a href='{cve_link}' target='_blank' class='cve-link'>Check CVEs</a>"
            
            icon_char = res.technology[0].upper()
            
            html += f"""
                                <div class="tech-item">
                                    <div class="tech-left">
                                        <div class="tech-icon">{icon_char}</div>
                                        <div class="tech-info">
                                            <h3>{res.technology}{version_str} {cve_html}</h3>
                                            <span>{res.category}</span>
                                            <div class="tech-evidence">{res.evidence}</div>
                                        </div>
                                    </div>
                                    <div class="tech-conf">{res.confidence}%</div>
                                </div>
            """
            
            # Populate Tech Modal List
            tech_list_html += f"""
            <li class="list-item">
                <div>
                    <span class="item-main">{res.technology}{version_str}</span>
                    <span class="item-sub">{res.category}</span>
                </div>
                <span class="badge" style="background:#dcfce7; color:#166534;">{res.confidence}%</span>
            </li>
            """

        page_list_html = "".join([f'<li class="list-item"><a href="{u}" target="_blank" class="item-main" style="text-decoration:none; color:#2563eb; overflow-wrap:anywhere;">{u}</a></li>' for u in scanned_urls])
        
        cat_list_html = ""
        for cat, count in categories.items():
            cat_list_html += f"""
            <li class="list-item">
                <span class="item-main">{cat}</span>
                <span class="badge">{count}</span>
            </li>
            """

        html += f"""
                            </div>
                        </div>
                    </div>
                    
                    <div>
                        <div class="card">
                            <h2>Technology Distribution</h2>
                            <canvas id="catChart"></canvas>
                        </div>
                        <div class="card">
                             <h2>Scanned Coverage</h2>
                             <div style="max-height: 300px; overflow-y: auto;">
                                 {"".join([f"<div style='padding:5px 0; border-bottom:1px solid #eee; font-size:12px; color:#666;'>{u}</div>" for u in scanned_urls])}
                             </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- MODALS -->
            <div id="techModal" class="modal" onclick="if(event.target === this) closeModal('techModal')">
                <div class="modal-content">
                    <div class="modal-header">
                        <h3 class="modal-title">Detected Technologies</h3>
                        <button class="close-btn" onclick="closeModal('techModal')">&times;</button>
                    </div>
                    <div class="modal-body">
                        <ul class="list-group">
                            {tech_list_html}
                        </ul>
                    </div>
                </div>
            </div>

            <div id="pageModal" class="modal" onclick="if(event.target === this) closeModal('pageModal')">
                <div class="modal-content">
                    <div class="modal-header">
                        <h3 class="modal-title">Scanned Pages</h3>
                        <button class="close-btn" onclick="closeModal('pageModal')">&times;</button>
                    </div>
                    <div class="modal-body">
                        <ul class="list-group">
                            {page_list_html}
                        </ul>
                    </div>
                </div>
            </div>

            <div id="catModal" class="modal" onclick="if(event.target === this) closeModal('catModal')">
                <div class="modal-content">
                    <div class="modal-header">
                        <h3 class="modal-title">Categories</h3>
                        <button class="close-btn" onclick="closeModal('catModal')">&times;</button>
                    </div>
                    <div class="modal-body">
                        <ul class="list-group">
                            {cat_list_html}
                        </ul>
                    </div>
                </div>
            </div>

            <script>
                function openModal(id) {{
                    document.getElementById(id).classList.add('active');
                    document.body.style.overflow = 'hidden';
                }}
                
                function closeModal(id) {{
                    document.getElementById(id).classList.remove('active');
                    document.body.style.overflow = '';
                }}

                document.addEventListener('keydown', function(event) {{
                    if (event.key === "Escape") {{
                        document.querySelectorAll('.modal').forEach(m => m.classList.remove('active'));
                        document.body.style.overflow = '';
                    }}
                }});

                const ctx = document.getElementById('catChart').getContext('2d');
                new Chart(ctx, {{
                    type: 'doughnut',
                    data: {{
                        labels: {json.dumps(list(categories.keys()))},
                        datasets: [{{
                            data: {json.dumps(list(categories.values()))},
                            backgroundColor: [
                                '#3b82f6', '#10b981', '#f59e0b', '#ef4444', 
                                '#8b5cf6', '#ec4899', '#6366f1', '#14b8a6'
                            ]
                        }}]
                    }},
                    options: {{
                        responsive: true,
                        plugins: {{
                            legend: {{
                                position: 'bottom',
                                labels: {{
                                    font: {{ family: 'Inter', size: 11 }}
                                }}
                            }}
                        }}
                    }}
                }});
            </script>
        </body>
        </html>
        """
        
        with open(path, 'w') as f:
            f.write(html)
        return path
