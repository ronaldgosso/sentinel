import json
from pathlib import Path
from typing import Any

import pytest

from sentinel.report.formatters import to_html, to_json, to_markdown, to_sarif


@pytest.fixture
def sample_findings() -> list[dict[str, Any]]:
    return [
        {
            "id": "sql_injection",
            "severity": "Critical",
            "location": "app/auth.py",
            "line": 42,
            "code": "query = f'SELECT * FROM users WHERE id={uid}'",
            "cwe": "CWE-89",
            "message": "Direct user input interpolated into SQL query.",
            "attack_scenario": "Attacker supplies ' OR 1=1 -- to dump users table.",
            "justification": "SQL syntax injection vulnerability.",
            "fix": "cursor.execute('SELECT * FROM users WHERE id=?', (uid,))",
            "ai_confirmed": True,
        },
        {
            "id": "hardcoded_secret",
            "severity": "High",
            "location": "config/settings.py",
            "line": 10,
            "code": "API_KEY = 'supersecret123'",
            "cwe": "CWE-798",
            "message": "Hardcoded secret key in source code.",
            "fix": "API_KEY = os.getenv('API_KEY')",
            "ai_confirmed": False,
        },
    ]


def test_to_markdown(tmp_path: Path, sample_findings: list[dict[str, Any]]) -> None:
    out_file = tmp_path / "sentinel-report.md"
    to_markdown(sample_findings, out_file)
    assert out_file.exists()
    content = out_file.read_text(encoding="utf-8")

    # Verify key markdown elements
    assert "## 🔍 Sentinel Security Scan Report" in content
    assert "🔴 **Vulnerabilities Detected (2 total)**" in content
    assert "| **1** | **1** | **0** | **0** |" in content  # Critical=1, High=1
    assert "Sql Injection" in content or "SQL Injection" in content
    assert "app/auth.py" in content
    assert "CWE-89" in content
    assert "✅ Confirmed" in content
    assert "Hardcoded Secret" in content
    assert "ℹ️ Offline Rule" in content


def test_to_markdown_clean(tmp_path: Path) -> None:
    out_file = tmp_path / "clean-report.md"
    to_markdown([], out_file)
    assert out_file.exists()
    content = out_file.read_text(encoding="utf-8")
    assert "🟢 **No Security Issues Detected**" in content
    assert "### ✅ Scan Clean" in content


def test_to_json(tmp_path: Path, sample_findings: list[dict[str, Any]]) -> None:
    out_file = tmp_path / "report.json"
    to_json(sample_findings, out_file)
    assert out_file.exists()
    data = json.loads(out_file.read_text(encoding="utf-8"))
    assert data["total_findings"] == 2
    assert len(data["findings"]) == 2


def test_to_sarif(tmp_path: Path, sample_findings: list[dict[str, Any]]) -> None:
    out_file = tmp_path / "report.sarif"
    to_sarif(sample_findings, out_file)
    assert out_file.exists()
    data = json.loads(out_file.read_text(encoding="utf-8"))
    assert data["version"] == "2.1.0"
    assert len(data["runs"][0]["results"]) == 2


def test_to_html(tmp_path: Path, sample_findings: list[dict[str, Any]]) -> None:
    out_file = tmp_path / "report.html"
    to_html(sample_findings, out_file)
    assert out_file.exists()
    content = out_file.read_text(encoding="utf-8")
    assert "🔍 Sentinel Security Report" in content
    assert "Critical: 1" in content
