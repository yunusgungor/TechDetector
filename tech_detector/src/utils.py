from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from bs4 import BeautifulSoup

@dataclass
class SiteData:
    url: str
    final_url: str
    status_code: int
    headers: Dict[str, str]
    cookies: Dict[str, str]
    html: str
    soup: Optional[BeautifulSoup] = None
    
    # Assets
    scripts: List[str] = field(default_factory=list) # URLs
    styles: List[str] = field(default_factory=list) # URLs
    
    # Asset Content (URL -> Content)
    js_bundles: Dict[str, str] = field(default_factory=dict)
    css_content: Dict[str, str] = field(default_factory=dict)
    
    # Meta
    meta_tags: Dict[str, str] = field(default_factory=dict)
    
    # Extra
    favicon_hash: int = 0
    cert_issuer: str = ""
    dns_records: Dict[str, List[str]] = field(default_factory=dict)
    
    # Probes
    probe_content: Dict[str, str] = field(default_factory=dict) # path -> content
    graphql_endpoint: str = ""

@dataclass
class DetectionResult:
    technology: str
    category: str
    confidence: int  # 0-100
    version: str = ""
    evidence: str = ""
