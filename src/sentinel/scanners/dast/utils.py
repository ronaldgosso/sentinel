import time
from typing import Any
from urllib.parse import urljoin

import httpx

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

    def get(self, path: str, params: dict[str, Any] | None = None) -> httpx.Response | None:
        """GET request with rate limiting."""
        time.sleep(self.delay)  # be polite
        if path.startswith(("http://", "https://")):
            url = path
        else:
            url = urljoin(self.base_url + "/", path.lstrip("/"))
        try:
            resp = self.session.get(url, params=params)
            return resp
        except Exception:  # noqa: BLE001
            return None

    def post(self, path: str, data: dict[str, Any] | None = None) -> httpx.Response | None:
        """POST request with rate limiting."""
        time.sleep(self.delay)
        if path.startswith(("http://", "https://")):
            url = path
        else:
            url = urljoin(self.base_url + "/", path.lstrip("/"))
        try:
            resp = self.session.post(url, data=data)
            return resp
        except Exception:  # noqa: BLE001
            return None

    def close(self) -> None:
        self.session.close()
