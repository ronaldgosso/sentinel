from typing import Any
from unittest.mock import MagicMock
import pytest

from sentinel.scanners.dast.crawler import Crawler
from sentinel.scanners.dast.engine import DASTScanner
from sentinel.scanners.dast.utils import HTTPClient


def test_crawler_extract_links() -> None:
    html = '<a href="/page1">Link1</a><a href="http://other.com">Other</a>'
    crawler = Crawler("http://example.com")
    links = crawler.extract_links(html, "http://example.com")
    assert "/page1" in links[0]
    # Should not include external link


def test_dast_scan_no_vuln() -> None:
    # Mock target that doesn't respond
    scanner = DASTScanner("http://localhost:9999")
    findings = scanner.scan()
    # Should handle gracefully
    assert isinstance(findings, list)


def test_dast_url_validation() -> None:
    with pytest.raises(ValueError, match="Invalid target URL"):
        DASTScanner("ftp://example.com")

    with pytest.raises(ValueError, match="Invalid target URL"):
        DASTScanner("javascript:alert(1)")

    with pytest.raises(ValueError, match="Invalid target URL"):
        DASTScanner("file:///etc/passwd")

    with pytest.raises(ValueError, match="Invalid base URL"):
        Crawler("gopher://localhost")

    with pytest.raises(ValueError, match="Invalid base URL"):
        HTTPClient("file:///tmp")


def test_dast_tests_all_query_params() -> None:
    scanner = DASTScanner("http://example.com")
    # Mock HTTPClient responses
    def mock_get(url: str, params: dict[str, Any] | None = None) -> MagicMock:
        resp = MagicMock()
        resp.headers = {}
        # If url contains param q with payload, trigger SQL error
        if "q=" in url and "OR" in url:
            resp.text = "Error: SQL syntax error near OR"
        elif "cat=" in url and "OR" in url:
            resp.text = "Error: sqlite3.OperationalError"
        else:
            resp.text = "Normal response"
        return resp

    scanner.client.get = mock_get  # type: ignore[assignment]
    scanner._test_sql_injection("http://example.com/search?q=test&cat=books")

    # Both parameters 'q' and 'cat' should have been tested and found
    params_found = [f.location for f in scanner.findings]
    assert any("param: q" in loc for loc in params_found)
    assert any("param: cat" in loc for loc in params_found)
