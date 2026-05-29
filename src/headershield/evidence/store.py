"""
Persistent storage for findings and evidence.
"""

import json
from pathlib import Path
from typing import Dict


def save_finding(scan_result: Dict, output_dir: str = "outputs/findings") -> Path:
    """Save scan result as JSON."""
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    url = scan_result.get("url", "unknown")
    safe_name = url.replace("https://", "").replace("http://", "").replace("/", "_")
    filepath = out / f"{safe_name}.json"

    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(scan_result, f, indent=2, ensure_ascii=False)

    return filepath


def save_evidence(evidence: Dict, url: str, output_dir: str = "outputs/findings") -> Path:
    """Save raw evidence package."""
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    safe_name = url.replace("https://", "").replace("http://", "").replace("/", "_")
    filepath = out / f"{safe_name}_evidence.json"

    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(evidence, f, indent=2, ensure_ascii=False)

    return filepath
