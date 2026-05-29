"""
headershield.cli
Command-line interface for HeaderShield.
"""

import argparse
import sys
from pathlib import Path

from .scanner.headers import scan_url, get_risk_summary
from .scanner.batch import scan_single, scan_from_csv
from .scanner.evidence import generate_evidence_package
from .reports.markdown import generate_report, generate_batch_report


def main():
    parser = argparse.ArgumentParser(
        prog="headershield",
        description="Lightweight security header audit tool for web infrastructure",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  headershield scan https://example.com          # Single URL scan
  headershield batch urls.csv                    # Batch scan from CSV
  headershield scan https://example.com --report  # Scan + generate markdown report
        """
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Scan command
    scan_parser = subparsers.add_parser("scan", help="Scan a single URL")
    scan_parser.add_argument("url", help="Target URL to scan")
    scan_parser.add_argument("--report", "-r", action="store_true", help="Generate markdown report")
    scan_parser.add_argument("--output", "-o", default="data/findings", help="Output directory for findings")
    scan_parser.add_argument("--no-verify", action="store_true", help="Disable SSL verification")

    # Batch command
    batch_parser = subparsers.add_parser("batch", help="Batch scan from CSV file")
    batch_parser.add_argument("csv", help="Path to CSV file containing URLs")
    batch_parser.add_argument("--output", "-o", default="data/findings", help="Output directory")
    batch_parser.add_argument("--report", "-r", action="store_true", help="Generate batch markdown report")

    # Report command
    report_parser = subparsers.add_parser("report", help="Generate report from existing JSON findings")
    report_parser.add_argument("json", help="Path to JSON findings file")
    report_parser.add_argument("--output", "-o", help="Output markdown file path")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.command == "scan":
        print(f"🔍 Scanning: {args.url}")
        result = scan_single(args.url, save=True, output_dir=args.output)

        if "error" in result:
            print(f"❌ Error: {result['error']}")
            sys.exit(1)

        # Print quick summary
        risk = result.get("risk_summary", {})
        issues = risk.get("total_issues", 0)
        print(f"
📊 Results: {issues} issues found")

        for sev, count in risk.get("severity_count", {}).items():
            if count > 0:
                print(f"   {sev}: {count}")

        if args.report:
            safe_name = args.url.replace("https://", "").replace("http://", "").replace("/", "_")
            report_path = Path(args.output) / f"{safe_name}.md"
            generate_report(result, str(report_path))

        # Print active risk paths
        active = risk.get("active_risk_paths", {})
        if active:
            print(f"
⚠️  Active Risk Paths:")
            for rp in active:
                print(f"   - {rp}")

    elif args.command == "batch":
        print(f"📁 Batch scanning from: {args.csv}")
        results = scan_from_csv(args.csv, output_dir=args.output)

        successful = len([r for r in results if "error" not in r])
        failed = len([r for r in results if "error" in r])

        print(f"
✅ Complete: {successful} successful, {failed} failed")
        print(f"💾 Findings saved to: {args.output}/")

        if args.report:
            summary_path = Path(args.output) / "_summary.json"
            report_path = Path(args.output) / "_batch_report.md"
            generate_batch_report(str(summary_path), str(report_path))

    elif args.command == "report":
        import json
        with open(args.json, 'r', encoding='utf-8') as f:
            result = json.load(f)

        output = args.output or args.json.replace(".json", ".md")
        generate_report(result, output)

    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
