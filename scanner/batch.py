"""
headershield.scanner.batch
Batch scanning for multiple URLs with CSV/JSON I/O.
"""

import csv
import json
from typing import List, Dict
from pathlib import Path
from .headers import scan_url, get_risk_summary
from .evidence import generate_evidence_package


def scan_from_csv(csv_path: str, output_dir: str = "data/findings") -> List[Dict]:
    """
    Read URLs from CSV, scan each, write individual JSON findings.
    CSV format: single column 'url' or first column treated as URL.
    """
    urls = []
    with open(csv_path, 'r', newline='', encoding='utf-8') as f:
        reader = csv.reader(f)
        header = next(reader, None)

        # Detect if first row is header
        if header and any(h.lower() in ['url', 'domain', 'website', 'target'] for h in header):
            url_col_idx = [h.lower() for h in header].index(next(h for h in header if h.lower() in ['url', 'domain', 'website', 'target']))
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

        result = scan_url(url)

        if "error" not in result:
            findings_dict = [
                {
                    "header": f.header_name,
                    "present": f.present,
                    "value": f.value,
                    "expected": f.expected,
                    "severity": f.severity.value,
                    "risk_paths": [rp.value for rp in f.risk_paths],
                    "remediation": f.remediation,
                    "evidence": f.evidence,
                }
                for f in result["findings"]
            ]

            result["risk_summary"] = get_risk_summary(result["findings"])

            # Write individual finding
            safe_name = url.replace("https://", "").replace("http://", "").replace("/", "_")
            out_file = output_path / f"{safe_name}.json"
            with open(out_file, 'w', encoding='utf-8') as f:
                json.dump(result, f, indent=2, ensure_ascii=False)

        results.append(result)

    # Write summary
    summary = {
        "total_scanned": len(urls),
        "successful": len([r for r in results if "error" not in r]),
        "failed": len([r for r in results if "error" in r]),
        "results": results,
    }

    with open(output_path / "_summary.json", 'w', encoding='utf-8') as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)

    return results


def scan_single(url: str, save: bool = True, output_dir: str = "data/findings") -> Dict:
    """Scan a single URL and optionally save to JSON."""
    result = scan_url(url)

    if save and "error" not in result:
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        safe_name = url.replace("https://", "").replace("http://", "").replace("/", "_")
        out_file = output_path / f"{safe_name}.json"

        result["risk_summary"] = get_risk_summary(result["findings"])

        with open(out_file, 'w', encoding='utf-8') as f:
            json.dump(result, f, indent=2, ensure_ascii=False)

        print(f"Saved: {out_file}")

    return result
