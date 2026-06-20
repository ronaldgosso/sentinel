from pathlib import Path
from typing import List, Dict, Any, Optional
from .parser import find_dependency_files, parse_dependency_file
from .vuln_db import get_vulnerabilities, init_db


class SCAFinding:
    def __init__(
        self,
        package: str,
        version: str,
        vuln_id: str,
        summary: str,
        severity: str,
        cvss_score: Optional[float] = None,
        affected_versions: str = "",
        fix_versions: str = "",
        ecosystem: str = "PyPI",
    ):
        self.package = package
        self.version = version
        self.vuln_id = vuln_id
        self.summary = summary
        self.severity = severity  # Critical, High, Medium, Low
        self.cvss_score = cvss_score
        self.affected_versions = affected_versions
        self.fix_versions = fix_versions
        self.rule_id = "sca_vulnerability"
        self.ecosystem = ecosystem
        if ecosystem != "PyPI":
            self.location = f"[{ecosystem}] {package}@{version}"
        else:
            self.location = f"{package}@{version}"
        self.line = 0
        self.code_snippet = f"Package: {package}=={version}"
        self.message = f"{vuln_id}: {summary}"
        self.remediation = (
            f"Upgrade to a fixed version: {fix_versions}"
            if fix_versions
            else "Check for updated version."
        )
        self.cwe = "N/A"
        self.ai_confirmed = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.rule_id,
            "severity": self.severity,
            "location": self.location,
            "line": 0,
            "code": self.code_snippet,
            "message": self.message,
            "fix": self.remediation,
            "cwe": self.cwe,
            "ai_confirmed": self.ai_confirmed,
        }


class SCAScanner:
    def __init__(self) -> None:
        init_db()

    def scan_directory(self, root_path: str) -> List[SCAFinding]:
        root = Path(root_path).resolve()
        dep_files = find_dependency_files(root)
        all_deps = []
        for file in dep_files:
            deps = parse_dependency_file(file)
            all_deps.extend(deps)

        # Deduplicate (later package wins, but we'll keep unique keying on pkg + ecosystem)
        unique_deps = {}
        for pkg, ver, ecosystem in all_deps:
            if pkg:
                unique_deps[(pkg, ecosystem)] = ver

        findings = []
        for (pkg, ecosystem), ver in unique_deps.items():
            if not ver:
                continue  # skip if no version pinned
            vulns = get_vulnerabilities(pkg, ver, ecosystem)
            for vuln in vulns:
                # Determine severity
                # Check if we have CVSS severity from NVD, else map from OSV's database_specific severity
                severity = "Medium"
                if "cvss_severity" in vuln:
                    sev_map = {
                        "CRITICAL": "Critical",
                        "HIGH": "High",
                        "MEDIUM": "Medium",
                        "LOW": "Low",
                    }
                    severity = sev_map.get(vuln["cvss_severity"].upper(), "Medium")
                elif "severity" in vuln.get("database_specific", {}):
                    sev = vuln["database_specific"]["severity"]
                    sev_map = {
                        "CRITICAL": "Critical",
                        "HIGH": "High",
                        "MEDIUM": "Medium",
                        "LOW": "Low",
                    }
                    severity = sev_map.get(sev.upper(), "Medium")
                elif "details" in vuln.get("severity", {}):
                    sev = vuln["severity"].get("score")
                    if sev and sev >= 9.0:
                        severity = "Critical"
                    elif sev and sev >= 7.0:
                        severity = "High"
                    elif sev and sev >= 4.0:
                        severity = "Medium"
                    else:
                        severity = "Low"

                # Extract affected and fixed versions
                affected = ""
                fixed = ""
                if "affected" in vuln:
                    for aff in vuln["affected"]:
                        if aff.get("package", {}).get("name") == pkg:
                            ranges = aff.get("ranges", [])
                            for r in ranges:
                                if r.get("type") == "ECOSYSTEM":
                                    for event in r.get("events", []):
                                        if "introduced" in event:
                                            affected = event["introduced"]
                                        if "fixed" in event:
                                            fixed = event["fixed"]
                # Create finding
                finding = SCAFinding(
                    package=pkg,
                    version=ver,
                    vuln_id=vuln.get("id", "Unknown"),
                    summary=vuln.get("summary", ""),
                    severity=severity,
                    cvss_score=vuln.get("cvss_score"),
                    affected_versions=affected,
                    fix_versions=fixed,
                    ecosystem=ecosystem,
                )
                findings.append(finding)

        return findings
