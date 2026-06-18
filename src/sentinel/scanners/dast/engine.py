from typing import List, Dict, Any
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from .crawler import Crawler
from .payloads import SQLI_PAYLOADS, XSS_PAYLOADS
from .utils import HTTPClient
import re


class DASTFinding:
    def __init__(self, severity: str, location: str, message: str, fix: str, cwe: str = "N/A"):
        self.severity = severity
        self.location = location
        self.message = message
        self.fix = fix
        self.cwe = cwe
        self.rule_id = "dast_vulnerability"
        self.line = 0
        self.code_snippet = location
        self.ai_confirmed = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.rule_id,
            "severity": self.severity,
            "location": self.location,
            "line": 0,
            "code": self.code_snippet,
            "message": self.message,
            "fix": self.fix,
            "cwe": self.cwe,
            "ai_confirmed": self.ai_confirmed,
        }


class DASTScanner:
    def __init__(self, target_url: str, max_pages: int = 20) -> None:
        self.target_url = target_url.rstrip("/")
        self.max_pages = max_pages
        self.findings: List[DASTFinding] = []

    def scan(self) -> List[DASTFinding]:
        """Run the DAST scan: crawl + test endpoints."""
        # Step 1: Crawl
        crawler = Crawler(self.target_url, self.max_pages)
        urls = crawler.crawl()
        if not urls:
            # If crawl failed, just test the base URL
            urls = [self.target_url]

        # Step 2: For each URL, test for vulnerabilities
        for url in urls:
            self._test_sql_injection(url)
            self._test_xss(url)
            self._check_security_headers(url)

        return self.findings

    def _test_sql_injection(self, url: str) -> None:
        """Test for SQL injection by modifying query parameters."""
        parsed = urlparse(url)
        if not parsed.query:
            return  # no query parameters to test

        params = parse_qs(parsed.query)
        # Get list of parameter names
        param_names = list(params.keys())

        for param in param_names:
            for payload, payload_type in SQLI_PAYLOADS:
                # Create new query string with payload
                new_params = params.copy()
                new_params[param] = [payload]
                new_query = urlencode(new_params, doseq=True)
                new_url = urlunparse(parsed._replace(query=new_query))

                # Send request
                client = HTTPClient(self.target_url)
                resp = client.get(new_url)
                if not resp:
                    client.close()
                    continue

                # Check for error-based SQLi (database error messages)
                if payload_type == "error":
                    if self._check_sql_error(resp.text):
                        finding = DASTFinding(
                            severity="High",
                            location=f"{url} (param: {param})",
                            message=f"SQL Injection vulnerability detected in parameter '{param}' using payload '{payload}'",
                            fix="Use parameterised queries or an ORM. Never concatenate user input into SQL.",
                            cwe="CWE-89",
                        )
                        self.findings.append(finding)
                        client.close()
                        return  # stop testing this param once found

                # Time-based detection is harder; we skip for simplicity
                client.close()

    def _check_sql_error(self, html: str) -> bool:
        """Heuristic to detect SQL error messages in response."""
        error_patterns = [
            r"SQL syntax",
            r"MySQLSyntaxErrorException",
            r"SQLSTATE",
            r"ORA-",
            r"PostgreSQL",
            r"sqlite3\.OperationalError",
            r"Microsoft OLE DB Provider for ODBC Drivers",
            r"Unclosed quotation mark",
            r"You have an error in your SQL syntax",
            r"Division by zero",
            r"Column.*not found",
            r"Table.*doesn\'t exist",
        ]
        for pattern in error_patterns:
            if re.search(pattern, html, re.IGNORECASE):
                return True
        return False

    def _test_xss(self, url: str) -> None:
        """Test for reflected XSS by injecting payloads into query params and checking if reflected."""
        parsed = urlparse(url)
        if not parsed.query:
            return

        params = parse_qs(parsed.query)
        param_names = list(params.keys())

        for param in param_names:
            for payload, _ in XSS_PAYLOADS:
                new_params = params.copy()
                new_params[param] = [payload]
                new_query = urlencode(new_params, doseq=True)
                new_url = urlunparse(parsed._replace(query=new_query))

                client = HTTPClient(self.target_url)
                resp = client.get(new_url)
                if not resp:
                    client.close()
                    continue

                # Check if payload is reflected in the response
                if payload in resp.text:
                    # Confirm it's not just escaped
                    # If payload appears as is (not HTML escaped)
                    if payload in resp.text and not self._is_escaped(payload, resp.text):
                        finding = DASTFinding(
                            severity="High",
                            location=f"{url} (param: {param})",
                            message=f"Reflected XSS vulnerability detected in parameter '{param}' using payload '{payload}'",
                            fix="Ensure all user input is HTML-escaped before rendering. Use autoescaping in templates.",
                            cwe="CWE-79",
                        )
                        self.findings.append(finding)
                        client.close()
                        return  # stop testing this param
                client.close()

    def _is_escaped(self, payload: str, text: str) -> bool:
        """Check if the payload is HTML-escaped in the response."""
        # Simple check: if '<' becomes '&lt;' etc.
        escaped = payload.replace("<", "&lt;").replace(">", "&gt;")
        return escaped in text

    def _check_security_headers(self, url: str) -> None:
        """Check for missing security headers."""
        client = HTTPClient(self.target_url)
        resp = client.get(url)
        if not resp:
            client.close()
            return

        headers = resp.headers
        missing = []
        if "Content-Security-Policy" not in headers:
            missing.append("Content-Security-Policy")
        if "X-Frame-Options" not in headers:
            missing.append("X-Frame-Options")
        if "X-Content-Type-Options" not in headers:
            missing.append("X-Content-Type-Options")
        if "Strict-Transport-Security" not in headers:
            missing.append("Strict-Transport-Security")

        if missing:
            finding = DASTFinding(
                severity="Medium",
                location=url,
                message=f"Missing security headers: {', '.join(missing)}",
                fix="Add these headers to your HTTP responses. Use a security middleware.",
                cwe="CWE-693",
            )
            self.findings.append(finding)
        client.close()
