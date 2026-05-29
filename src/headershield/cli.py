"""
CLI orchestration layer.
NO analysis logic. Only coordinates scanner -> analyzer -> evidence -> report.
"""

import argparse
import sys
import json
from datetime import datetime
from pathlib import Path

from headershield.scanner.http_client import fetch_headers
from headershield.analyzer.risk_engine import analyze
from headershield.evidence.capture import capture_evidence
from headershield.evidence.store import save_finding, save_evidence
from headershield.reports.builder import build_audit_report, save_report


def run_scan(url: str, save: bool = True) -> dict:
    """Orchestrate a single scan: fetch -> analyze -> evidence -> report."""
    print(f"Scanning: {url}")
    
    # 1. Fetch raw data
    raw = fetch_headers(url)
    if "error" in raw and raw["error"]:
        print(f"Fetch failed: {raw['error']}")
        return {"error": raw["error"], "url": url}
    
    # 2. Analyze
    print("Analyzing headers...")
    metadata = {
        "status_code": raw["status_code"],
        "final_url": raw["final_url"],
        "response_time_ms": raw["response_time_ms"],
        "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
    }
    result = analyze(url, raw["headers"], metadata)
    
    # 3. Capture evidence
    evidence = capture_evidence(url, raw)
    
    # 4. Build report
    report = build_audit_report(result)
    
    # 5. Save outputs
    if save:
        result_dict = result.to_dict()
        result_dict["evidence"] = evidence
        
        finding_path = save_finding(result_dict)
        evidence_path = save_evidence(evidence, url)
        report_path = save_report(report, url)
        
        print(f"Finding: {finding_path}")
        print(f"Evidence: {evidence_path}")
        print(f"Report: {report_path}")
    
    # 6. Console summary
    print(f"\nScan Complete: {result.url}")
    print(f"   Issues: {result.total_issues()} | Score: {result.severity_score()}")
    print(f"   P0: {result.critical_count()} | P1: {result.high_count()} | P2: {result.medium_count()} | P3: {result.low_count()}")
    
    if result.active_risk_paths():
        print(f"\nActive Risk Paths:")
        for rp in result.active_risk_paths():
            print(f"   - {rp}")
    
    return result.to_dict()


def run_batch(csv_path: str):
    """Batch scan from CSV."""
    import csv
    
    urls = []
    with open(csv_path, 'r', newline='', encoding='utf-8') as f:
        reader = csv.reader(f)
        for row in reader:
            if row and not row[0].startswith('#'):
                urls.append(row[0].strip())
    
    results = []
    print(f"Batch scan: {len(urls)} targets\n")
    
    for i, url in enumerate(urls, 1):
        print(f"[{i}/{len(urls)}] {'='*50}")
        result = run_scan(url, save=True)
        results.append(result)
        print()
    
    # Save batch summary
    summary = {
        "batch_timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        "total_targets": len(urls),
        "successful": len([r for r in results if "error" not in r]),
        "failed": len([r for r in results if "error" in r]),
        "results": results,
    }
    
    summary_path = Path("outputs/findings") / "_batch_summary.json"
    with open(summary_path, 'w', encoding='utf-8') as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)
    
    print(f"Batch summary: {summary_path}")
    return summary


def main():
    parser = argparse.ArgumentParser(
        prog="headershield",
        description="HeaderShield v2 - Security Header Audit Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  headershield scan https://example.com
  headershield batch targets.csv
        """
    )
    
    subparsers = parser.add_subparsers(dest="command")
    
    scan_parser = subparsers.add_parser("scan", help="Scan single URL")
    scan_parser.add_argument("url", help="Target URL")
    
    batch_parser = subparsers.add_parser("batch", help="Batch scan from CSV")
    batch_parser.add_argument("csv", help="CSV file with URLs")
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    if args.command == "scan":
        run_scan(args.url)
    elif args.command == "batch":
        run_batch(args.csv)


if __name__ == "__main__":
    main()
