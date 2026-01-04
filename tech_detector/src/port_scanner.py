import socket
import concurrent.futures
from urllib.parse import urlparse
from .utils import DetectionResult

class PortScanner:
    # Common ports of interest
    PORTS = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        3306: "MySQL",
        5432: "PostgreSQL",
        6379: "Redis",
        8080: "HTTP-Alt",
        8443: "HTTPS-Alt",
        9200: "Elasticsearch"
    }

    def scan(self, url: str) -> list[DetectionResult]:
        domain = urlparse(url).netloc
        if ":" in domain:
            domain = domain.split(":")[0]
            
        open_ports = []

        def check_port(port):
            try:
                # Short timeout for speed
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(1.0) 
                    result = sock.connect_ex((domain, port))
                    if result == 0:
                        return port
            except:
                pass
            return None

        # Threaded scan
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            future_to_port = {executor.submit(check_port, port): port for port in self.PORTS}
            for future in concurrent.futures.as_completed(future_to_port):
                p = future.result()
                if p:
                    open_ports.append(p)
        
        results = []
        if open_ports:
            services = [f"{p}/{self.PORTS[p]}" for p in open_ports]
            results.append(DetectionResult(
                technology=f"Open Ports: {', '.join(services)}",
                category="Infrastructure",
                confidence=100,
                evidence="Active TCP Connect Scan"
            ))
            
        return results
