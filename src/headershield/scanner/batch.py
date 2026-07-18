"""
headershield.scanner.batch
Batch scanning for multiple URLs with CSV/JSON I/O (v2 model).
"""

import csv
import json
from typing import List, Dict
from pathlib import Path
from headershield.cli import run_scan


def scan_from_csv(csv_path: str, output_dir: str = "outputs/findings") -> List[Dict]:
    """
    Read URLs from CSV, scan each using the v2 pipeline, write individual JSON findings.
    CSV format: single column 'url' or first column treated as URL.
    """
    urls = []
    with open(csv_path, 'r', newline='', encoding='utf-8') as f:
        reader = csv.reader(f)
        header = next(reader, None)

        # Detect if first row is header
        if header and any(h.lower() in ['url', 'domain', 'website', 'target'] for h in header):
            url_col_idx = [h.lower() for h in header].index(
                next(h for h in header if h.lower() in ['url', 'domain', 'website', 'target'])
            )
            for row in reader:
                if len(row) > url_col_idx:
                    urls.append(row[url_col_idx].strip())
        else:
            # No header, first column is URL
            urls.append(header[0].strip() if header else "")
            for row in reader:
                if row:
                    urls.append(row[0].strip())

    urls = [u for u in urls if u and not u.startswith('#')]
    results = []

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    for i, url in enumerate(urls, 1):
        print(f"[{i}/{len(urls)}] Scanning: {url}")
        result = run_scan(url, save=True)
        results.append(result)

    # Write summary
    summary = {
        "total_scanned": len(urls),
        "successful": len([r for r in results if "error" not in r]),
        "failed": len([r for r in results if "error" in r]),
        "results": results,
    }

    summary_path = output_path / "_summary.json"
    with open(summary_path, 'w', encoding='utf-8') as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)

    print(f"Batch summary: {summary_path}")
    return results


def scan_single(url: str, save: bool = True) -> Dict:
    """Scan a single URL using the v2 pipeline and optionally save to JSON."""
    return run_scan(url, save=save)
