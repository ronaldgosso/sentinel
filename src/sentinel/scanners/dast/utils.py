import httpx
from urllib.parse import urljoin
import time
from typing import Optional, Dict, Any

# Default headers to mimic a real browser
DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate",
    "Connection": "keep-alive",
}


class HTTPClient:
    def __init__(self, base_url: str, timeout: int = 10, delay: float = 0.5) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.delay = delay
        self.session = httpx.Client(timeout=timeout, headers=DEFAULT_HEADERS, follow_redirects=True)

    def get(self, path: str, params: Optional[Dict[str, Any]] = None) -> Optional[httpx.Response]:
        """GET request with rate limiting."""
        time.sleep(self.delay)  # be polite
        url = urljoin(self.base_url + "/", path.lstrip("/"))
        try:
            resp = self.session.get(url, params=params)
            return resp
        except Exception:
            return None

    def post(self, path: str, data: Optional[Dict[str, Any]] = None) -> Optional[httpx.Response]:
        """POST request with rate limiting."""
        time.sleep(self.delay)
        url = urljoin(self.base_url + "/", path.lstrip("/"))
        try:
            resp = self.session.post(url, data=data)
            return resp
        except Exception:
            return None

    def close(self) -> None:
        self.session.close()
