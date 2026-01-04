# 🛡️ TechDetector - User Guide

**Version:** 2.0 (Military-Grade Edition)  
**Status:** Stable  
**Date:** January 04, 2026

---

## 1. Introduction
**TechDetector** is an advanced **Cyber Intelligence** tool designed to gather deep intelligence on web assets, identify security vulnerabilities, and map technology infrastructure down to the finest detail.

Unlike ordinary scanners, **TechDetector**:
*   Combines **Active and Passive** scanning.
*   Detects technologies hidden behind **WAFs (Web Application Firewalls)**.
*   Analyzes the human factor (emails, social media) using **OSINT (Open Source Intelligence)** methods.
*   Discovers **Cloud Assets** via fuzzing.

This tool operates on a **"Zero Error"** principle and provides **Military-Grade** precision in reporting.

---

## 2. Installation

Python 3.8+ is required to run the system. Install the necessary libraries:

```bash
pip install -r requirements.txt
```

*(Core dependencies: `requests`, `beautifulsoup4`, `dnspython`, `urllib3`)*

---

## 3. Basic Usage

To scan a target in its simplest form:

```bash
python3 tech_detector/main.py https://target-site.com
```

This command:
1.  Connects to the site.
2.  Analyzes basic technologies.
3.  Prints the results to the screen.

---

## 4. Advanced Commands and Strategies

Use the following parameters to unleash the system's full power:

### 🚀 Full-Spectrum Intelligence Scan (Recommended)
Runs everything including WAF detection, OSINT, Cloud Recon, and deep file analysis.

```bash
python3 tech_detector/main.py https://target-site.com --deep --report --csv --threads 10
```

*   `--deep`: Crawls internal links to find technologies and leaks on sub-pages, not just the homepage.
*   `--report`: Generates an interactive **HTML Report** at the end of the scan.
*   `--csv`: Saves results in Excel-compatible CSV format.
*   `--threads 10`: Accelarates the scan with 10 concurrent processes.

### Other Parameters

| Parameter | Description |
| :--- | :--- |
| `--proxy http://1.2.3.4:8080` | Routes the scan through a proxy server to hide your identity. |
| `--user-agent "MyBot/1.0"` | Uses a custom User-Agent string (System uses random modern browser agents by default). |
| `--timeout 15` | Sets the connection timeout (seconds). Increase for slow sites. |
| `--verbose` | Prints more detailed (debug) output to the screen. |

---

## 5. Interpreting Reports

The system leaves HTML and CSV files in the `reports/` folder after the scan.

### 🛡️ Security Grade
You will see a grade from A to F in the report header:
*   **A (80-100)**: Very Secure. All security headers (HSTS, CSP, X-Frame, etc.) are present.
*   **B/C**: Moderate. Some missing measures.
*   **D/F (0-49)**: Critical Risk. Insufficient security measures, potential sensitive data leaks.

### 🔍 Confidence Score
Each detection comes with a percentage (%) and evidence:
*   **100%**: Definite Detection. (e.g., `server: nginx` header or `wp-content` HTML structure).
*   **80%**: High Probability. (e.g., `jquery` appearing in JS filenames).
*   **70% (Implied)**: Inference. (e.g., Since `Shopify` is detected, `Cloudflare` and `Nginx` are assumed. This reveals hidden technologies behind WAFs).

### 🧠 Special Modules
Look for these in the "Detailed Findings" section:
*   **WAF / Firewall**: Protection shields like Cloudflare, AWS WAF, Akamai.
*   **OSINT**: Email addresses and Social Media profiles scraped from the site.
*   **Cloud Assets**: Open cloud storage areas like `s3.amazonaws.com` or `blob.core.windows.net`.
*   **Leaked Secret**: API Keys, Tokens, or passwords forgotten inside HTML or JS code.

---

## 6. Frequently Asked Questions

**Q: Does the system work outside of `ticaretus.com`?**
**A:** Yes. The system is universal. It can analyze any website in the world using the 3000+ rule set in the `fingerprints.json` file.

**Q: Why do some technologies appear as "Implied"?**
**A:** Some modern infrastructures (e.g., Shopify, Wix) use Cloudflare or AWS in the background but hide it. When TechDetector recognizes the parent technology (Shopify), it automatically adds the child technology (Cloudflare) via "Inference". This gives you insight into the invisible infrastructure.

**Q: The scan takes too long, what should I do?**
**A:** Increase the `--threads` count (e.g., 20). However, very high values might cause the target site to block you (WAF Block). The ideal range is 5-15.

---

**Yunus Güngör | TechDetector**
*Advanced Cyber Surveillance System*
