"""
headershield.scanner.evidence
Raw capture and reproducibility for audit-grade artifacts.
"""

import json
import time
from typing import Dict, List
import requests


def capture_raw_response(url: str, timeout: int = 10, verify_ssl: bool = True) -> Dict:
    """
    Capture full raw response for evidence documentation.
    """
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    try:
        response = requests.get(url, timeout=timeout, verify=verify_ssl, allow_redirects=True)
    except requests.exceptions.SSLError:
        url = url.replace("https://", "http://")
        response = requests.get(url, timeout=timeout, verify=False, allow_redirects=True)
    except Exception as e:
        return {
            "url": url,
            "error": str(e),
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        }

    return {
        "url": url,
        "final_url": response.url,
        "status_code": response.status_code,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "request_headers": dict(response.request.headers),
        "response_headers": dict(response.headers),
        "response_size_bytes": len(response.content),
        "redirect_history": [r.url for r in response.history],
        "reproducible_curl": f'curl -I -L "{url}"',
    }


def generate_evidence_package(url: str, findings: List[Dict]) -> Dict:
    """
    Generate a complete evidence package combining scan results and raw capture.
    """
    raw = capture_raw_response(url)

    return {
        "scan_metadata": {
            "tool": "headershield",
            "version": "2.0.0",
            "scan_type": "passive_header_audit",
            "timestamp": raw.get("timestamp"),
        },
        "target": {
            "url": raw.get("url"),
            "final_url": raw.get("final_url"),
            "status_code": raw.get("status_code"),
        },
        "evidence": raw,
        "findings": findings,
    }
