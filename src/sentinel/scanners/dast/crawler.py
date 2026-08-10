import logging
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from .utils import HTTPClient

logger = logging.getLogger(__name__)


class Crawler:
    def __init__(self, base_url: str, max_pages: int = 20) -> None:
        self.base_url = base_url.rstrip("/")
        self.max_pages = max_pages
        self.visited: set[str] = set()
        self.to_visit: list[str] = [self.base_url]
        self.client = HTTPClient(self.base_url)

    def extract_links(self, html: str, current_url: str) -> list[str]:
        """Extract all href links from HTML, filter to same domain."""
        soup = BeautifulSoup(html, "html.parser")
        links = []
        for a in soup.find_all("a", href=True):
            href_val = a["href"]
            href = href_val[0] if isinstance(href_val, list) else str(href_val)
            full_url = urljoin(current_url, href)
            # Only keep links to the same domain and same scheme
            parsed = urlparse(full_url)
            base_parsed = urlparse(self.base_url)
            if parsed.netloc == base_parsed.netloc and parsed.scheme in ("http", "https"):
                # remove fragments and query strings for simplicity (but we keep them for scanning)
                # We'll keep full URL for now
                links.append(full_url)
        return links

    def crawl(self) -> list[str]:
        """Crawl the base URL and return list of discovered URLs."""
        discovered = []
        while self.to_visit and len(self.visited) < self.max_pages:
            url = self.to_visit.pop(0)
            if url in self.visited:
                continue
            self.visited.add(url)
            logger.info("[DAST] Crawling: %s", url)
            resp = self.client.get(url)
            if resp and resp.status_code == 200:
                discovered.append(url)
                # Extract new links
                new_links = self.extract_links(resp.text, url)
                for link in new_links:
                    if link not in self.visited and link not in self.to_visit:
                        self.to_visit.append(link)
        self.client.close()
        return discovered
