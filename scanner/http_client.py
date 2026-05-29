"""
Raw HTTP extraction layer.
NO security logic. Only data fetch.
"""

import requests
import time
from typing import Dict


def fetch_headers(url: str, timeout: int = 10, verify_ssl: bool = True, allow_redirects: bool = True) -> Dict:
    """
    Fetch raw HTTP response headers.
    Returns structured dict with metadata.
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
        }

    return {
        "url": url,
        "status_code": response.status_code,
        "headers": dict(response.headers),
        "response_time_ms": round((time.time() - start) * 1000, 3),
        "final_url": response.url,
        "history": [r.url for r in response.history],
    }
