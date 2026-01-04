import requests
import concurrent.futures
from urllib.parse import urljoin
from typing import List
from .utils import DetectionResult

class FileFuzzer:
    # Critical files to check
    SENSITIVE_FILES = [
        '/.env',
        '/.git/config',
        '/.DS_Store',
        '/config.php.bak',
        '/web.config',
        '/docker-compose.yml',
        '/backup.sql',
        '/database.sql',
        '/dump.sql',
        '/id_rsa',
        '/id_rsa.pub',
        '/server.js',
        '/package.json',
        '/ws_settings.xml',
        '/sftp-config.json'
    ]

    def scan(self, url: str) -> List[DetectionResult]:
        results = []
        
        def check_file(path):
            target = urljoin(url, path)
            try:
                # Disable stream to get content
                HEADERS = {
                    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
                }
                resp = requests.get(target, headers=HEADERS, timeout=3, verify=False, stream=False)
                
                # Only trust 200 OK
                if resp.status_code == 200:
                    content = resp.text.lower()
                    
                    # False Positive reduction: check if it's just the homepage or a custom 404
                    # Heuristic: if content length is too large (like full html page), skip
                    # Most config files are small (< 10KB)
                    if len(resp.content) > 50000: 
                        return None
                        
                    is_leak = False
                    evidence = ""
                    
                    if '.env' in path and ('db_password=' in content or 'api_key=' in content):
                        is_leak = True
                        evidence = "Exposed Environment Variables"
                    elif '.git/config' in path and 'repositoryformatversion' in content:
                        is_leak = True
                        evidence = "Exposed Git Config"
                    elif '.ds_store' in path: 
                        # Binary match
                        if b'Bud1' in resp.content or b'DSDB' in resp.content:
                            is_leak = True
                            evidence = "Exposed macOS Metadata"
                    elif 'id_rsa' in path and 'private key' in content:
                        is_leak = True
                        evidence = "Exposed Private Key"
                    elif 'backup.sql' in path and ('create table' in content or 'insert into' in content):
                        is_leak = True
                        evidence = "Exposed Database Backup"
                    elif 'package.json' in path and 'dependencies' in content:
                        is_leak = True
                        evidence = "Exposed Node.js Config"
                    elif resp.status_code == 200:
                         # Generic match for other files if 200 OK and not HTML
                         if '<html' not in content and '<body' not in content:
                             is_leak = True
                             evidence = f"Accessible Sensitive File"

                    if is_leak:
                        return DetectionResult(
                            technology="Sensitive File Risk",
                            category="Security Risk",
                            confidence=100,
                            evidence=f"Found {path}: {evidence}"
                        )
            except:
                pass
            return None

        # Threaded scan
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            future_to_path = {executor.submit(check_file, p): p for p in self.SENSITIVE_FILES}
            for future in concurrent.futures.as_completed(future_to_path):
                res = future.result()
                if res:
                    results.append(res)
        
        return results
