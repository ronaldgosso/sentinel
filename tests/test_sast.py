from pathlib import Path
from sentinel.scanners.sast.engine import SASTScanner
from sentinel.scanners.sast.detectors import (
    detect_sql_injection,
    detect_hardcoded_secrets,
    detect_frontend_vulnerabilities,
)


def test_sql_injection_detector() -> None:
    code = """
import sqlite3
email = "test"
cursor.execute(f"SELECT * FROM users WHERE email = '{email}'")
"""
    import ast

    tree = ast.parse(code)
    findings = detect_sql_injection(tree, code, "test.py")
    assert len(findings) >= 1
    assert "SQL" in findings[0]["message"]


def test_secrets_detector() -> None:
    code = 'API_KEY = "sk-1234567890abcdef"'
    import ast

    tree = ast.parse(code)
    findings = detect_hardcoded_secrets(tree, code, "test.py")
    assert len(findings) >= 1
    assert "Hardcoded" in findings[0]["message"]


def test_full_scanner() -> None:
    scanner = SASTScanner()
    # Create temp file
    import tempfile

    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        f.write("""
import hashlib
SECRET_KEY = "topsecret"
def foo():
    return hashlib.md5(b"test").hexdigest()
""")
        f.flush()
        findings = scanner.scan_file(Path(f.name))
        assert len(findings) >= 2  # Should catch secrets + crypto


def test_frontend_vulnerabilities_detector() -> None:
    # Test React dangerouslySetInnerHTML
    react_code = '<div dangerouslySetInnerHTML={{ __html: clean }} />'
    findings_react = detect_frontend_vulnerabilities(None, react_code, "test.jsx")
    assert len(findings_react) == 1
    assert "dangerouslySetInnerHTML" in findings_react[0]["message"]

    # Test reverse tabnabbing
    html_code = '<a href="https://example.com" target="_blank">Link</a>'
    findings_html = detect_frontend_vulnerabilities(None, html_code, "test.html")
    assert len(findings_html) == 1
    assert "noopener noreferrer" in findings_html[0]["message"]

    # Test inline script without CSP
    inline_script = '<script>alert(1);</script>'
    findings_script = detect_frontend_vulnerabilities(None, inline_script, "test.html")
    assert len(findings_script) == 1
    assert "Inline <script>" in findings_script[0]["message"]

    # Test iframe sandbox
    insecure_iframe = '<iframe src="test"></iframe>'
    findings_iframe = detect_frontend_vulnerabilities(None, insecure_iframe, "test.html")
    assert len(findings_iframe) == 1
    assert "sandbox attribute" in findings_iframe[0]["message"]

    # Test inline event handler
    inline_event = '<button onclick="run()">Click</button>'
    findings_event = detect_frontend_vulnerabilities(None, inline_event, "test.html")
    assert len(findings_event) == 1
    assert "Inline event handler" in findings_event[0]["message"]
