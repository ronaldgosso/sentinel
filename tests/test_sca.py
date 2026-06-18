from sentinel.scanners.sca.parser import parse_requirements_txt
from sentinel.scanners.sca.vuln_db import get_vulnerabilities, init_db


def test_parser_requirements() -> None:
    content = "requests==2.20.0\nflask>=1.0\n# comment\nDjango==3.0"
    deps = parse_requirements_txt(content)
    assert len(deps) == 3
    assert ("requests", "2.20.0") in deps
    assert ("flask", "1.0") in deps
    assert ("Django", "3.0") in deps


def test_vuln_db() -> None:
    init_db()
    vulns = get_vulnerabilities("requests", "2.20.0")
    # Should have at least one vulnerability (CVE-2018-...)
    assert len(vulns) > 0
    # Check that we have CVSS enrichment
    for v in vulns:
        if "cvss_score" in v:
            assert v["cvss_score"] is not None
