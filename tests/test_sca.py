from unittest.mock import patch, MagicMock
from sentinel.scanners.sca.parser import parse_requirements_txt
from sentinel.scanners.sca.vuln_db import get_vulnerabilities, init_db


def test_parser_requirements() -> None:
    content = "requests==2.20.0\nflask>=1.0\n# comment\nDjango==3.0"
    deps = parse_requirements_txt(content)
    assert len(deps) == 3
    assert ("requests", "2.20.0") in deps
    assert ("flask", "1.0") in deps
    assert ("Django", "3.0") in deps


@patch("sentinel.scanners.sca.vuln_db.query_osv")
@patch("sentinel.scanners.sca.vuln_db.get_cvss_from_nvd")
def test_vuln_db(mock_nvd: MagicMock, mock_osv: MagicMock) -> None:
    mock_osv.return_value = [{"id": "CVE-2018-1000802", "summary": "Mock vulnerability"}]
    mock_nvd.return_value = {"score": 9.8, "severity": "CRITICAL"}
    init_db()
    vulns = get_vulnerabilities("requests", "2.20.0", force_refresh=True)
    assert len(vulns) == 1
    assert vulns[0]["id"] == "CVE-2018-1000802"
    assert vulns[0]["cvss_score"] == 9.8
    assert vulns[0]["cvss_severity"] == "CRITICAL"
