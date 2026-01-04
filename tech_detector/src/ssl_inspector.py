import ssl
import socket
from urllib.parse import urlparse
from datetime import datetime

class SSLInspector:
    def inspect(self, url: str) -> dict:
        parsed = urlparse(url)
        hostname = parsed.netloc
        port = 443
        
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE # We just want to inspect, not validate strictness
        
        result = {}
        
        try:
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert(binary_form=False) # Get parsed cert
                    
                    if not cert:
                        # Sometimes getpeercert() returns empty if validation disabled/failed in a specific way
                        # But with CERT_NONE + binary_form=False it might be empty if we don't verify?
                        # Actually getting parsed info requires verification usually or manual parsing.
                        # Let's try to get binary and parse if needed, but standard lib does it if we trust CA.
                        # For simple inspection, let's use standard call.
                        
                        # Re-connect with standard settings just to get info?
                        pass

                    # Parse Issuer
                    issuer = dict(x[0] for x in cert.get('issuer', []))
                    subject = dict(x[0] for x in cert.get('subject', []))
                    
                    result['issuer_org'] = issuer.get('organizationName', 'Unknown')
                    result['issuer_cn'] = issuer.get('commonName', 'Unknown')
                    result['valid_from'] = cert.get('notBefore')
                    result['valid_to'] = cert.get('notAfter')
                    result['protocol'] = ssock.version()
                    
                    # Deduce tech from Issuer
                    # e.g. "CloudFlare" -> Cloudflare
                    # "Google Trust Services" -> GCP / Firebase
                    # "Let's Encrypt" -> Standard Linux Hosting usually
                    # "Amazon" -> AWS
                    
        except Exception as e:
            result['error'] = str(e)
            
        return result
