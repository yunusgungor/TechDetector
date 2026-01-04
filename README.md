<div align="center">

# 🛡️ TechDetector
### Advanced Cyber Intelligence & Surveillance System

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Stable%20(Military%20Grade)-red?style=for-the-badge)]()
[![Security](https://img.shields.io/badge/Security-A%2B-success?style=for-the-badge)]()

**TechDetector** is a next-generation reconnaissance tool designed to provide "Military-Grade" intelligence on web assets. It goes beyond simple technology fingerprinting to reveal the hidden infrastructure, security posture, and human footprint behind any target.

[Features](#-key-features) • [Installation](#-installation) • [Usage](#-usage) • [Intelligence Modules](#-intelligence-modules) • [Reporting](#-reporting)

</div>

---

## 🚀 Key Features

*   **🛡️ WAF & Firewall Identification**: Bypasses obfuscation to detect hidden defense layers like **Cloudflare**, **AWS WAF**, **Akamai**, and **Imperva**. Automatically infers hidden upstream providers.
*   **🕵️ Human OSINT**: Extracts "Human Intelligence" from targets, including **Email Addresses** and **Social Media Profiles** (LinkedIn, X/Twitter, Instagram), crucial for social engineering context.
*   **☁️ Cloud Asset Recon**: Actively fuzzes and validates exposed cloud storage buckets across **AWS S3**, **Azure Blob**, and **Google Cloud Storage**.
*   **🧠 Intelligent Fingerprinting**: Powered by a rule engine with **3,000+ signatures**, detecting CMSs, frameworks, analytics, and obscure server technologies.
*   **⚡ Active & Passive Scanning**: seamlessly blends passive header analysis with active payload testing (Port Scanning, DNS Enumeration, Fuzzing).
*   **💎 Military-Grade Stability**: Engineered with a "Zero-Error" philosophy. Robust guard clauses and error handling ensure continuous operation even against hostile targets.

---

## 📥 Installation

TechDetector requires **Python 3.8+**.

```bash
# Clone the repository
git clone https://github.com/yunusgungor/TechDetector.git

# Navigate to the directory
cd TechDetector

# Install dependencies
pip install -r requirements.txt
```

---

## 💻 Usage

### ⚡ Quick Scan
Perform a rapid assessment of a target's technology stack.
```bash
python3 tech_detector/main.py https://example.com
```

### 🛰️ Full-Spectrum Intelligence Scan (Recommended)
Unleash the full power of the system: Deep Crawling, WAF Detection, OSINT, and Report Generation.
```bash
python3 tech_detector/main.py \
    https://example.com \
    --deep \
    --report \
    --csv \
    --threads 10
```

### 🥷 Stealth Mode
Operate undetected by rotating User-Agents and routing traffic through a proxy.
```bash
python3 tech_detector/main.py \
    https://example.com \
    --proxy http://127.0.0.1:8080 \
    --user-agent "Googlebot/2.1"
```

---

## 🧩 Intelligence Modules

### 1. WAF Detector
Identifies the "Invisible Wall". Even if a site claims to be running on Nginx, TechDetector analyzes specific HTTP headers (e.g., `cf-ray`, `x-amz-id-2`) and cookies to reveal the true guardian (Cloudflare, AWS).

### 2. OSINT Collector
Scrapes the target's HTML content to build a profile of the organization's digital footprint.
*   **Emails**: Harvesting contact points for phishing simulation contexts.
*   **Social Graphs**: Mapping corporate presence on LinkedIn, YouTube, etc.

### 3. Cloud Recon
Generates permutations of the target domain to discover unsecured cloud buckets.
*   *Target*: `example.com`
*   *Probes*: `example-assets.s3.amazonaws.com`, `example-backup.blob.core.windows.net`...

### 4. Security Auditor
Assigns a real-time **Security Grade (A-F)** based on:
*   Missing Security Headers (HSTS, CSP, X-Frame-Options).
*   Leaked API Keys (Google Maps, AWS, Heroku).
*   Exposed Sensitive Files (`.env`, `.git`, backups).

### 5. Secret Scanner & Vulnerability Map
*   **Secret Analysis**: Scans HTML and JavaScript files for accidentally exposed **API Keys** (Google Maps, Stripe, AWS, Heroku, Mailgun) and **Private Tokens**.
*   **Vulnerability Correlation**: Automatically maps detected versions (e.g., *startrails v1.1*) to known CVEs.

### 6. Context & Infrastructure Mapping
*   **Context Analysis**: Classifies the target's industry (e.g., E-Commerce, Corporate, News) for threat modeling.
*   **Infrastructure Recon**:
    *   **Asset Mapping**: Subdomain Enumeration, Active Port Scanning, and DNS Analysis.
    *   **Domain Intelligence**: Registrar details, Registration Date, and Expiration Date checks via RDAP.
    *   **Geo-Intelligence**: Physical Server Location, ASN, and ISP details.
    *   **Discovery**: Robots.txt and Sitemap.xml analysis for hidden paths.
*   **API Discovery**: Automatically identifies exposed API documentation endpoints (Swagger UI, Redoc, GraphQL) to reveal backend logic.

---

## 📊 Reporting

The system generates executive-ready reports in multiple formats.

### HTML Interactive Report
A stunning, responsive dashboard featuring:
*   **Executive Summary**: Security Grade and Threat Level.
*   **Visual Analytics**: Technology distribution charts and confidence scores.
*   **Evidence Logs**: Raw data proofs for every finding.

### Data Export (CSV / JSON)
Export raw data for SIEM integration or further analysis.
```bash
--csv   # Excel-compatible format
--json  # Machine-readable format
```

---

## ⚠️ Disclaimer

This tool is designed for legal security auditing, educational purposes, and system administration. The authors are not responsible for any misuse or damage caused by this program. **Always obtain permission before scanning a target.**

---

<div align="center">

**Developed by Yunus Güngör**  
*Precision. Reliability. Intelligence.*

</div>
