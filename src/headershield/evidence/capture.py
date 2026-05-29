"""
Reproducibility and audit-grade evidence capture.
"""

import json
from datetime import datetime
from typing import Dict


def capture_evidence(url: str, raw_response: Dict) -> Dict:
    """
    Capture complete evidence package for a single scan.
    """
    final_url = raw_response.get("final_url", url)
    redirect_count = raw_response.get("redirect_count", 0)
    
    return {
        "scan_metadata": {
            "tool": "HeaderShield",
            "version": "2.1.0",
            "scan_type": "passive_header_audit",
            "timestamp": datetime.utcnow().isoformat() + "Z",
        },
        "target": {
            "requested_url": url,
            "final_url": final_url,
            "status_code": raw_response.get("status_code", 0),
            "response_time_ms": raw_response.get("response_time_ms", 0),
            "redirect_count": redirect_count,
        },
        "raw_response": {
            "headers": raw_response.get("headers", {}),
            "merged_headers": raw_response.get("merged_headers", {}),
            "redirect_history": raw_response.get("history", []),
            "redirect_chain": raw_response.get("redirect_chain", []),
        },
        "reproducibility": {
            "curl_command": 'curl -I -L "' + final_url + '"',
            "verification": "Re-run the curl command to reproduce this exact response",
        },
    }
