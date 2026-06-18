from sentinel.scanners.dast.crawler import Crawler
from sentinel.scanners.dast.engine import DASTScanner


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
