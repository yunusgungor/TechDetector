import argparse
import sys
import json
import webbrowser
from src.scanner import Scanner

def main():
    parser = argparse.ArgumentParser(description="Advanced Web Technology Detector (Professional Edition)")
    parser.add_argument("url", help="Target URL to scan")
    parser.add_argument("--json", action="store_true", help="Output in JSON format")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show detailed evidence")
    parser.add_argument("--deep", "-d", action="store_true", help="Enable Deep Crawler (scans sub-pages)")
    parser.add_argument("--report", "-r", action="store_true", help="Generate HTML Report")
    
    args = parser.parse_args()
    
    scanner = Scanner()
    results, data, report_path = scanner.scan(args.url, deep_scan=args.deep, generate_report=args.report)
    
    if args.json:
        output = [
            {
                "technology": r.technology, 
                "category": r.category, 
                "confidence": r.confidence,
                "evidence": r.evidence if args.verbose else ""
            } 
            for r in results
        ]
        print(json.dumps(output, indent=2))
    else:
        print(f"\nTarget: {data.final_url}")
        print(f"Status: {data.status_code}")
        print("-" * 50)
        print(f"{'Technology':<20} | {'Category':<20} | {'Conf':<5} | {'Evidence'}")
        print("-" * 50)
        
        for r in results:
            evidence = r.evidence[:40] + "..." if len(r.evidence) > 40 and not args.verbose else r.evidence
            print(f"{r.technology:<20} | {r.category:<20} | {r.confidence:<5}% | {evidence}")
        print("-" * 50)

    if report_path:
        print(f"\n[+] Report Generated: {report_path}")
        webbrowser.open('file://' + os.path.abspath(report_path))

if __name__ == "__main__":
    import os
    main()
