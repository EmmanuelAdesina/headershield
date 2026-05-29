"""
Raw HTTP extraction layer with redirect chain inspection.
NO security logic. Only data fetch and chain capture.
"""

import requests
import time
from typing import Dict, List


def fetch_headers(url: str, timeout: int = 10, verify_ssl: bool = True, allow_redirects: bool = True) -> Dict:
    """
    Fetch raw HTTP response headers with full redirect chain capture.
    Returns structured dict with metadata and merged headers across chain.
    """
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"
    
    start = time.time()
    
    try:
        response = requests.get(url, timeout=timeout, verify=verify_ssl, allow_redirects=allow_redirects)
    except requests.exceptions.SSLError:
        url = url.replace("https://", "http://")
        response = requests.get(url, timeout=timeout, verify=False, allow_redirects=allow_redirects)
    except Exception as e:
        return {
            "url": url,
            "error": str(e),
            "status_code": 0,
            "headers": {},
            "response_time_ms": 0,
            "final_url": url,
            "redirect_chain": [],
            "merged_headers": {},
        }
    
    # Build redirect chain
    redirect_chain = []
    for i, r in enumerate(response.history):
        redirect_chain.append({
            "step": i + 1,
            "url": r.url,
            "status_code": r.status_code,
            "headers": dict(r.headers),
        })
    
    # Final response
    redirect_chain.append({
        "step": len(response.history) + 1,
        "url": response.url,
        "status_code": response.status_code,
        "headers": dict(response.headers),
    })
    
    # Merge headers across chain: final response wins, but HSTS from any hop applies
    merged = {}
    for hop in redirect_chain:
        for k, v in hop["headers"].items():
            k_lower = k.lower()
            # HSTS is sticky: if any hop sends it, it applies to the whole domain
            if k_lower == "strict-transport-security" and k_lower not in merged:
                merged[k_lower] = v
            # CSP from final response only
            elif k_lower == "content-security-policy":
                merged[k_lower] = v
            # Other headers: final wins
            elif k_lower not in merged or hop["step"] == len(redirect_chain):
                merged[k_lower] = v
    
    return {
        "url": url,
        "status_code": response.status_code,
        "headers": dict(response.headers),
        "response_time_ms": round((time.time() - start) * 1000, 3),
        "final_url": response.url,
        "history": [r.url for r in response.history],
        "redirect_count": len(response.history),
        "redirect_chain": redirect_chain,
        "merged_headers": merged,
    }
