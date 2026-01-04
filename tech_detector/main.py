import argparse
import sys
import json
from src.scanner import Scanner

def main():
    parser = argparse.ArgumentParser(description="Advanced Web Technology Detector")
    parser.add_argument("url", help="Target URL to scan")
    parser.add_argument("--json", action="store_true", help="Output in JSON format")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show detailed evidence")
    
    args = parser.parse_args()
    
    scanner = Scanner()
    results, data = scanner.scan(args.url)
    
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

if __name__ == "__main__":
    main()
