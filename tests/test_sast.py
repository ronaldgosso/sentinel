from pathlib import Path
from sentinel.scanners.sast.engine import SASTScanner
from sentinel.scanners.sast.detectors import (
    detect_sql_injection,
    detect_hardcoded_secrets,
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
