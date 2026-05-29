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
    final_url = raw_response.get('final_url', url)
    
    return {
        "scan_metadata": {
            "tool": "HeaderShield",
            "version": "2.0.0",
            "scan_type": "passive_header_audit",
            "timestamp": datetime.utcnow().isoformat() + "Z",
        },
        "target": {
            "requested_url": url,
            "final_url": final_url,
            "status_code": raw_response.get("status_code", 0),
            "response_time_ms": raw_response.get("response_time_ms", 0),
        },
        "raw_response": {
            "headers": raw_response.get("headers", {}),
            "redirect_history": raw_response.get("history", []),
        },
        "reproducibility": {
            "curl_command": 'curl -I -L "' + final_url + '"',
            "verification": "Re-run the curl command to reproduce this exact response",
        },
    }
