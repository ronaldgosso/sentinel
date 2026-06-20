from unittest.mock import patch, MagicMock
from sentinel.scanners.sca.parser import (
    parse_requirements_txt,
    parse_package_json,
    parse_package_lock_json,
    parse_go_mod,
)
from sentinel.scanners.sca.vuln_db import get_vulnerabilities, init_db
from sentinel.scanners.sca.engine import SCAScanner
import tempfile
from pathlib import Path


def test_parser_requirements() -> None:
    content = "requests==2.20.0\nflask>=1.0\n# comment\nDjango==3.0"
    deps = parse_requirements_txt(content)
    assert len(deps) == 3
    assert ("requests", "2.20.0", "PyPI") in deps
    assert ("flask", "1.0", "PyPI") in deps
    assert ("Django", "3.0", "PyPI") in deps


def test_parser_package_json() -> None:
    content = """{
        "dependencies": {
            "lodash": "^4.17.21"
        },
        "devDependencies": {
            "mocha": "10.2.0"
        }
    }"""
    deps = parse_package_json(content)
    assert len(deps) == 2
    assert ("lodash", "4.17.21", "npm") in deps
    assert ("mocha", "10.2.0", "npm") in deps


def test_parser_package_lock_json() -> None:
    content_v2 = """{
        "packages": {
            "node_modules/lodash": {
                "version": "4.17.21"
            }
        }
    }"""
    deps = parse_package_lock_json(content_v2)
    assert len(deps) == 1
    assert ("lodash", "4.17.21", "npm") in deps


def test_parser_go_mod() -> None:
    content = """module example.com/test
    
    go 1.20
    
    require (
        github.com/gin-gonic/gin v1.9.1
        golang.org/x/crypto v0.0.0-20220315160706-3147a52a75dd // indirect
    )
    """
    deps = parse_go_mod(content)
    assert len(deps) == 2
    assert ("github.com/gin-gonic/gin", "v1.9.1", "Go") in deps
    assert ("golang.org/x/crypto", "v0.0.0-20220315160706-3147a52a75dd", "Go") in deps


@patch("sentinel.scanners.sca.vuln_db.query_osv")
@patch("sentinel.scanners.sca.vuln_db.get_cvss_from_nvd")
def test_vuln_db(mock_nvd: MagicMock, mock_osv: MagicMock) -> None:
    mock_osv.return_value = [{"id": "CVE-2018-1000802", "summary": "Mock vulnerability"}]
    mock_nvd.return_value = {"score": 9.8, "severity": "CRITICAL"}
    init_db()
    vulns = get_vulnerabilities("requests", "2.20.0", ecosystem="PyPI", force_refresh=True)
    assert len(vulns) == 1
    assert vulns[0]["id"] == "CVE-2018-1000802"
    assert vulns[0]["cvss_score"] == 9.8
    assert vulns[0]["cvss_severity"] == "CRITICAL"


@patch("sentinel.scanners.sca.vuln_db.query_osv")
def test_sca_scanner_multi_ecosystem(mock_osv: MagicMock) -> None:
    # Set up mock vulnerabilities for different ecosystems
    mock_osv.return_value = [{"id": "VULN-123", "summary": "Test vulnerability"}]

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)

        # Write requirements.txt, package-lock.json, and go.mod
        (tmp_path / "requirements.txt").write_text("requests==2.20.0")
        (tmp_path / "package-lock.json").write_text("""{
            "packages": {
                "node_modules/lodash": {
                    "version": "4.17.21"
                }
            }
        }""")
        (tmp_path / "go.mod").write_text("require github.com/gin-gonic/gin v1.9.1")

        scanner = SCAScanner()
        findings = scanner.scan_directory(tmpdir)

        # Should scan PyPI, npm, and Go ecosystems
        assert len(findings) >= 3
        locations = [f.location for f in findings]
        assert "requests@2.20.0" in locations
        assert "[npm] lodash@4.17.21" in locations
        assert "[Go] github.com/gin-gonic/gin@v1.9.1" in locations
